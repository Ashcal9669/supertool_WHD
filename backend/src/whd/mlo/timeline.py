"""Boot scoping and association epochs: authentication → association → keys → authorization → links → data.

An epoch is one association attempt (or one association already in progress when WHD started watching). Stages inside
an epoch are labelled by what kind of evidence they are (request / core completion / firmware result / verified
delivery) and are never joined by guesswork: a stage is present only when an event of that kind was observed inside the
epoch's time window on the same boot.
"""

from __future__ import annotations

import re
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Any, Literal

from whd.mlo.kv import fields_of, mac_of, num, tag_of, trace_fields, trace_name
from whd.mlo.lifetime import event_interface_scope
from whd.mlo.models import Epoch, EvidenceRef, Gap, StageClass, StageObs
from whd.model.events import Event

BOOT_TAG = re.compile(r"\(boot ([0-9a-f]+)\)")
LOCAL_ADDR = re.compile(r"local address=([0-9a-f:]{17})", re.I)
ASSOC_STATUS = re.compile(r"status=(\d+)")
TRY = re.compile(r"\(try (\d+)/(\d+)\)")
BOOT_CLUSTER_S = 20.0  # events whose wall-minus-boottime offset differs by more than this are different boots
DELAYED_NOTIFY_MS = (
    500.0  # association response → "associated"/connect notification slower than this is flagged
)

TERMINAL_KINDS = (
    "assoc.deauth_local",
    "assoc.deauth_by_ap",
    "assoc.disassoc_by_ap",
    "assoc.connection_lost",
    "assoc.timeout",
    "nl80211.disconnect",
    "nl80211.deauthenticate",
    "nl80211.disassociate",
    "station.gone",
    "nl80211.del_interface",
    "netdev.removed",
)

# Canonical order of the association/steering pipeline. The id is the key used everywhere in reports.
PIPELINE: list[tuple[str, str]] = [
    ("auth_request", "authentication requested (mac80211)"),
    ("auth_frame_tx", "authentication frame sent"),
    ("authenticated", "authenticated (mac80211 core)"),
    ("assoc_request_tx", "association request sent"),
    ("assoc_response", "association response received"),
    ("associated", "associated (mac80211 core)"),
    ("connect_notified", "connect notification (nl80211)"),
    ("eapol_m1_rx", "EAPOL M1 received (decoded key-info)"),
    ("eapol_m2_tx", "EAPOL M2 sent (decoded key-info)"),
    ("eapol_m3_rx", "EAPOL M3 received (decoded key-info)"),
    ("eapol_m4_tx", "EAPOL M4 sent (decoded key-info)"),
    ("key_install_request", "key install requested"),
    ("key_install_fw", "key install sent to firmware"),
    ("port_authorized", "port authorized"),
    ("links_activated", "link activation"),
    (
        "data_reply_verified",
        "authenticated reply delivered to the stack (requires correlated security evidence)",
    ),
]
STAGE_LABEL = dict(PIPELINE)
ORDER = {sid: i for i, (sid, _) in enumerate(PIPELINE)}

# What would supply each stage: ("log", kind-prefix) | ("kv", tag) | ("tp", "group:event") | ("poll", series-or-kind)
COLLECTORS: dict[str, tuple[str, str]] = {
    "auth_request": ("log", "assoc.authenticate"),
    "auth_frame_tx": ("log", "assoc.auth_tx"),
    "authenticated": ("log", "assoc.authenticated"),
    "assoc_request_tx": ("log", "assoc.assoc_tx"),
    "assoc_response": ("log", "assoc.assoc_resp"),
    "associated": ("log", "assoc.associated"),
    "connect_notified": ("log", "nl80211.connect"),
    "eapol_m1_rx": ("tp", "mt76:mlo_rx"),
    "eapol_m2_tx": ("tp", "mt76:mlo_txwi"),
    "eapol_m3_rx": ("tp", "mt76:mlo_rx"),
    "eapol_m4_tx": ("tp", "mt76:mlo_txwi"),
    "key_install_request": ("kv", "MLO_KEY_INSTALL"),
    "key_install_fw": ("kv", "MLO_KEY_MCU"),
    "port_authorized": ("log", "nl80211.port_authorized"),
    "links_activated": ("log", "mt76.mlo_active_links_changed"),
    "data_reply_verified": ("tp", "mt76:mlo_rx"),
}


@dataclass
class Collectors:
    """What this system can and did collect, used to tell a real gap from a collector that was not running."""

    kv_tags: set[str] = field(default_factory=set)
    log_kinds: set[str] = field(default_factory=set)
    tracepoints: set[str] = field(default_factory=set)  # "group:event" present in the running kernel
    traced_kinds: set[str] = field(default_factory=set)  # trace.* kinds seen in the analysed window
    inventory_known: bool = False
    inventory_groups: set[str] = field(default_factory=set)

    @classmethod
    def from_formats(cls, formats: dict[str, Any] | None) -> Collectors:
        groups = (formats or {}).get("groups")
        if not isinstance(groups, dict):
            return cls()
        return cls(
            inventory_known=True,
            inventory_groups=set(groups),
            tracepoints={
                f"{group}:{name}"
                for group, entries in groups.items()
                if isinstance(entries, (dict, list))
                for name in entries
                if isinstance(name, str)
            },
        )

    def gap_for(self, stage: str) -> Gap:
        kind, name = COLLECTORS.get(stage, ("log", stage))
        what = STAGE_LABEL.get(stage, stage)
        if kind == "tp":
            if name not in self.tracepoints:
                known = self.inventory_known and (
                    not self.inventory_groups or name.split(":")[0] in self.inventory_groups
                )
                return Gap(
                    kind="no_collector" if known else "not_traced",
                    what=what,
                    collector=f"tracepoint {name}",
                    detail="recorded inventory lacks this tracepoint"
                    if known
                    else "collector availability is unknown; no inventory was recorded",
                )
            expected_kind = "trace." + name.replace(":", ".")
            if expected_kind not in self.traced_kinds:
                return Gap(
                    kind="not_traced",
                    what=what,
                    collector=f"tracepoint {name}",
                    detail="no observation from this tracepoint in the window; session coverage is unknown",
                )
            return Gap(
                kind="absent_while_collected",
                what=what,
                collector=f"tracepoint {name}",
                detail="this tracepoint was observed, but the required event or decoding fields were absent",
            )
        if kind == "kv":
            if name not in self.kv_tags:
                return Gap(
                    kind="no_collector",
                    what=what,
                    collector=f"driver tag {name}",
                    detail="this tag was never seen; the running driver may not emit it",
                )
            return Gap(
                kind="absent_while_collected",
                what=what,
                collector=f"driver tag {name}",
                detail="the driver emits this tag but none occurred in the window",
            )
        if name not in self.log_kinds:
            return Gap(
                kind="absent_while_collected",
                what=what,
                collector=f"event {name}",
                detail="no such event in the window",
            )
        return Gap(kind="absent_while_collected", what=what, collector=f"event {name}")


def boot_of(e: Event) -> str | None:
    explicit = e.data.get("boot_id")
    if explicit:
        return str(explicit)
    m = BOOT_TAG.search(e.ts_raw or "")
    return m.group(1) if m else None


def assign_boots(events: list[Event]) -> list[str]:
    """Clock-only observations keep separate provisional scopes, never borrow a known UUID."""
    centers: list[float] = []
    for offset in sorted(e.ts_wall - e.ts_boottime_ns / 1e9 for e in events if not boot_of(e)):
        if not any(abs(offset - center) <= BOOT_CLUSTER_S for center in centers):
            centers.append(offset)
    out: list[str] = []
    for e in events:
        known = boot_of(e)
        if known:
            out.append(known)
            continue
        off = e.ts_wall - e.ts_boottime_ns / 1e9
        center = next(c for c in centers if abs(off - c) <= BOOT_CLUSTER_S)
        out.append(f"boot~{int(center)}")
    return out


def ref(e: Event, text: str | None = None) -> EvidenceRef:
    return EvidenceRef(
        event_id=e.id, ts_boottime_ns=e.ts_boottime_ns, kind=e.kind, text=(text or e.summary)[:200]
    )


def _key_fields(f: dict[str, str]) -> dict[str, str]:
    """Key material is never kept; the driver's key fingerprint is derived from the key, so it is dropped too."""
    return {k: v for k, v in f.items() if k != "keyfp"}


def _stage(e: Event) -> StageObs | None:
    k = e.kind
    t = tag_of(e)
    f = fields_of(e)
    ts = e.ts_boottime_ns

    def S(
        stage: str,
        cls: StageClass,
        result: str | None = None,
        token: str | None = None,
        link: int | None = None,
        note: str | None = None,
    ) -> StageObs:
        return StageObs(
            stage=stage,
            stage_class=cls,
            ts_boottime_ns=ts,
            result=result,
            token=token,
            link_id=link,
            evidence=[ref(e)],
            note=note,
        )

    if k == "assoc.authenticate":
        return S("auth_request", "queued_request")
    if k == "assoc.auth_tx":
        m = TRY.search(e.summary)
        return S("auth_frame_tx", "queued_request", f"try {m.group(1)}/{m.group(2)}" if m else None)
    if k == "assoc.authenticated":
        return S("authenticated", "core_complete")
    if k == "assoc.assoc_tx":
        m = TRY.search(e.summary)
        return S("assoc_request_tx", "queued_request", f"try {m.group(1)}/{m.group(2)}" if m else None)
    if k == "assoc.assoc_resp":
        m = ASSOC_STATUS.search(e.summary)
        return S("assoc_response", "core_complete", f"status={m.group(1)}" if m else None)
    if k == "assoc.associated":
        return S("associated", "core_complete")
    if k == "nl80211.connect":
        sc = (e.data or {}).get("status_code")
        return S("connect_notified", "core_complete", f"status={sc}" if sc is not None else None)
    if k == "nl80211.port_authorized":
        return S("port_authorized", "core_complete")
    if trace_name(e) == "drv_set_key":
        cmd = re.search(r"\bcmd:\s*(\d+)", e.raw)
        if cmd:
            return S(
                "key_install_request" if cmd.group(1) == "0" else "key_remove_request",
                "queued_request",
                result=f"cmd={cmd.group(1)}",
                note="mac80211 driver callback entry; no return value, firmware outcome or key bytes collected",
            )
    if trace_name(e) == "drv_sta_state":
        state = re.search(r"\bstate:\s*(\d+)->(\d+)", e.raw)
        if state and state.group(2) == "4":
            return S(
                "authorization_request",
                "queued_request",
                result=state.group(0),
                note="driver callback entry requesting authorized station state; completion remains unknown",
            )
    if k == "mt76.mlo_active_links_changed":
        return S(
            "links_activated",
            "observation",
            f"0x{(e.data or {}).get('from', 0):x} -> 0x{(e.data or {}).get('to', 0):x}",
            note="observed by polling the driver's mask; the instant is known only to the poll interval",
        )
    if t == "MLO_KEY_INSTALL":
        return S(
            "key_install_request", "queued_request", f"cipher={f.get('cipher')}", link=num(f, "key_link_id")
        )
    if t == "MLO_KEY_MCU":
        kind = "pairwise" if f.get("pairwise") == "1" else "group/other"
        if f.get("stage") == "after_send":
            return S(
                "key_install_fw",
                "firmware_result",
                f"ret={f.get('ret')} ({kind})",
                link=num(f, "key_link"),
                note="the driver's return value for the key command; key bytes are not kept",
            )
        return S(
            "key_install_fw",
            "queued_request",
            f"{f.get('stage')} ({kind})",
            token=f.get("mcu"),
            link=num(f, "key_link"),
            note="metadata only; key bytes and the driver's key fingerprint are not kept",
        )
    return None


def _ts(e: Event) -> int:
    return e.ts_boottime_ns


EAPOL_ETHERTYPE = 0x888E


def parse_icmp(f: dict[str, str]) -> tuple[int, int] | None:
    v = f.get("icmp")
    if v and "/" in v:
        a, _, b = v.partition("/")
        if a.isdigit() and b.isdigit():
            return int(a), int(b)
    return None


def eapol_frames(events: list[Event]) -> list[tuple[str, Event]]:
    """Observed EAPOL frames with explicit direction. Handshake messages require key-info."""
    out: list[tuple[str, Event]] = []
    for e in events:
        if e.kind in ("packet.eapol_rx", "packet.eapol_tx"):
            out.append((e.kind.rsplit("_", 1)[1], e))
            continue
        n = trace_name(e)
        if n not in ("mlo_rx", "mlo_tx_select"):
            continue
        if num(trace_fields(e), "proto") == EAPOL_ETHERTYPE:
            out.append(("rx" if n == "mlo_rx" else "tx", e))
    return out


def is_echo_reply(f: dict[str, str]) -> bool:
    """ICMP/ICMPv6 echo reply by explicit fields (l4 protocol and type), not by 0/0 defaults."""
    ic = parse_icmp(f)
    l4 = num(f, "l4p")
    return ic is not None and ((l4 == 1 and ic[0] == 0) or (l4 == 58 and ic[0] == 129))


def build_epochs(
    events: list[Event],
    device_id: str,
    collectors: Collectors,
    include_unattributed: bool = False,
) -> list[Epoch]:
    """Association epochs for one device, newest last. `events` may span boots; epochs never cross a boot."""
    evs = sorted(events, key=_ts)
    boots = assign_boots(evs)
    by_boot: dict[tuple[str, str | None, str | None], list[Event]] = defaultdict(list)
    for e, b in zip(evs, boots, strict=True):
        name, lifetime = event_interface_scope(e)
        by_boot[(b, name, lifetime)].append(e)
    out: list[Epoch] = []
    for (boot, interface, lifetime), bev in by_boot.items():
        scoped = _epochs_in_boot(boot, bev, device_id, collectors, include_unattributed)
        for epoch in scoped:
            epoch.interface = interface
            epoch.interface_lifetime = lifetime
            if interface is not None or lifetime is not None:
                epoch.id += f":interface={interface}:lifetime={lifetime}"
            if lifetime is None:
                epoch.flags.append(
                    "interface lifetime UNKNOWN; historical observations cannot establish current interface state"
                )
        out.extend(scoped)
    out.sort(key=lambda x: x.start_ns)
    return out


def _epochs_in_boot(
    boot: str, evs: list[Event], device_id: str, col: Collectors, include_unattributed: bool
) -> list[Epoch]:
    own = [e for e in evs if e.device_id == device_id]
    # epoch boundaries come only from this device's own association events
    starts: list[tuple[int, str | None, bool]] = []  # (ts, local address, observed from the start)
    last_local: str | None = None
    open_ = False
    for e in own:
        if e.kind == "assoc.authenticate":
            m = LOCAL_ADDR.search(e.summary)
            local = m.group(1).lower() if m else None
            if not open_ or (local and last_local and local != last_local):
                starts.append((_ts(e), local, True))
                last_local, open_ = local, True
        elif e.kind in ("assoc.associated", "nl80211.connect") and not open_:
            starts.append((_ts(e), None, False))  # already in progress when watching began
            open_ = True
        elif e.kind.startswith(TERMINAL_KINDS):
            open_ = False
    epochs: list[Epoch] = []
    for i, (t0, local, observed) in enumerate(starts):
        t_next = starts[i + 1][0] if i + 1 < len(starts) else None
        window = [e for e in evs if _ts(e) >= t0 and (t_next is None or _ts(e) < t_next)]
        win_own = [e for e in window if e.device_id == device_id]
        end = None
        for e in win_own:
            if e.kind.startswith(TERMINAL_KINDS):
                end = _ts(e)
                break
        if end is None and t_next is not None:
            end = t_next
        scoped = [
            e
            for e in window
            if (e.device_id == device_id or (include_unattributed and e.device_id is None))
            and (end is None or _ts(e) <= end)
        ]
        epochs.append(
            _one_epoch(
                f"{boot}:{i + 1}",
                boot,
                device_id,
                local,
                observed,
                t0,
                end,
                scoped,
                col,
                unattributed_included=include_unattributed,
            )
        )
    return epochs


def _one_epoch(
    eid: str,
    boot: str,
    device_id: str,
    local: str | None,
    observed: bool,
    t0: int,
    end: int | None,
    evs: list[Event],
    col: Collectors,
    unattributed_included: bool,
) -> Epoch:
    stages: list[StageObs] = []
    tokens: list[str] = []
    peer: str | None = None
    for e in evs:
        s = _stage(e)
        if s:
            stages.append(s)
        if e.kind in ("assoc.authenticate", "assoc.assoc_resp", "assoc.associated") and peer is None:
            for w in e.summary.split():
                if mac_of(w):
                    peer = mac_of(w)
                    break
        t = tag_of(e)
        f = fields_of(e)
        if t == "ROC_REQ_START":
            stages.append(
                StageObs(
                    stage="roc_request",
                    stage_class="queued_request",
                    ts_boottime_ns=_ts(e),
                    token=f.get("token"),
                    result=f"duration={f.get('duration')}",
                    evidence=[ref(e)],
                )
            )
            tokens.append(f"roc:{f.get('token')}")
        elif t == "ROCEV GRANT":
            stages.append(
                StageObs(
                    stage="roc_grant",
                    stage_class="firmware_result",
                    ts_boottime_ns=_ts(e),
                    token=f.get("token"),
                    result=f"status={f.get('status')} ch={f.get('ch')}",
                    evidence=[ref(e)],
                )
            )
        elif t == "MLO_RADIO_ABORT":
            stages.append(
                StageObs(
                    stage="roc_abort",
                    stage_class="observation",
                    ts_boottime_ns=_ts(e),
                    token=f.get("token"),
                    result=f.get("reason"),
                    link_id=num(f, "link_id"),
                    evidence=[ref(e)],
                    note="rollback/abort of a channel request",
                )
            )
        elif t == "MLO_MCU_SEND_START":
            tokens.append(f"mcu:{f.get('cmd')}@{f.get('t')}")
        elif t == "MLO_FW_PEER_LIFECYCLE":
            stages.append(
                StageObs(
                    stage="peer_lifecycle",
                    stage_class="firmware_result",
                    ts_boottime_ns=_ts(e),
                    result=f"{f.get('stage')} gen={f.get('generation')} ret={f.get('ret')}",
                    link_id=num(f, "link_id"),
                    evidence=[ref(e)],
                )
            )
        elif t == "MLO_ACTIVATE_DEFER":
            stages.append(
                StageObs(
                    stage="activation_deferred",
                    stage_class="observation",
                    ts_boottime_ns=_ts(e),
                    evidence=[ref(e)],
                    note="driver held link activation until the station is authorized",
                )
            )
        elif e.kind in TERMINAL_KINDS and e.device_id == device_id:
            stages.append(
                StageObs(
                    stage="teardown",
                    stage_class="core_complete",
                    ts_boottime_ns=_ts(e),
                    result=e.kind,
                    evidence=[ref(e)],
                )
            )
    # Ethertype/direction alone cannot distinguish retransmissions or the key handshake.
    frames = eapol_frames(evs)
    want = [("rx", "eapol_m1_rx"), ("tx", "eapol_m2_tx"), ("rx", "eapol_m3_rx"), ("tx", "eapol_m4_tx")]
    for dirn, e in frames:
        fields = trace_fields(e)
        info = num(fields, "key_info")
        msg = None
        if info is not None and info & 8:  # pairwise key, IEEE 802.11 EAPOL-Key Key Information
            ack, mic, install, secure = (bool(info & b) for b in (128, 256, 64, 512))
            if ack and not mic and not install:
                msg = 1
            elif not ack and mic and not secure:
                msg = 2
            elif ack and mic and install:
                msg = 3
            elif not ack and mic and secure:
                msg = 4
        if msg and want[msg - 1][0] == dirn:
            stages.append(
                StageObs(
                    stage=want[msg - 1][1],
                    stage_class="observation",
                    ts_boottime_ns=_ts(e),
                    evidence=[ref(e)],
                    token=fields.get("replay_counter"),
                    note="decoded from pairwise EAPOL-Key key-info; payload/key data not retained",
                )
            )
        else:
            stages.append(
                StageObs(
                    stage="eapol_unclassified",
                    stage_class="observation",
                    ts_boottime_ns=_ts(e),
                    evidence=[ref(e)],
                    note="EAPOL ethertype observed; key-info missing or direction inconsistent",
                )
            )
    # a reply that reached the stack: echo reply, decrypted, no driver drop flags. mlo_rx is emitted in the RX path, so
    # this is "decrypted and handed to mac80211's RX path", not proof of delivery to the network stack.
    for e in evs:
        if trace_name(e) == "mlo_rx":
            f = trace_fields(e)
            if is_echo_reply(f) and f.get("decrypted") == "1" and num(f, "flags") == 0:
                stages.append(
                    StageObs(
                        stage="data_reply_observed",
                        stage_class="observation",
                        ts_boottime_ns=_ts(e),
                        link_id=num(f, "link"),
                        evidence=[ref(e)],
                        result=f"echo reply id={f.get('id')} seq={f.get('seq')}",
                        note="driver reports decryption and no drop flags; replay/security completion and stack delivery remain unestablished (see packet path)",
                    )
                )
                break
    stages.sort(key=lambda s: s.ts_boottime_ns or 0)
    seen = {s.stage for s in stages}
    outcome = _outcome(stages)
    flags = _flags(stages, local, observed)
    if unattributed_included:
        flags.append(
            "unattributed driver lines inside the window were included by time only; with several "
            "MLO-capable adapters they could belong to another"
        )
    missing, first, gaps = _missing(seen, outcome, stages, col)
    return Epoch(
        id=eid,
        boot_id=boot,
        device_id=device_id,
        local_address=local,
        peer=peer,
        start_ns=t0,
        end_ns=end,
        started_observed=observed,
        outcome=outcome,
        stages=stages,
        first_missing=first,
        missing=missing,
        gaps=gaps,
        flags=flags,
        request_tokens=sorted(set(tokens)),
    )


def _outcome(
    stages: list[StageObs],
) -> Literal["associated", "rejected", "timed_out", "disconnected", "in_progress", "unknown"]:
    sid = [s.stage for s in stages]
    torn = [s for s in stages if s.stage == "teardown"]
    resp = [s for s in stages if s.stage == "assoc_response"]
    if any(t.result == "assoc.timeout" for t in torn):
        return "timed_out"
    if "associated" in sid:
        return "disconnected" if torn else "associated"
    if resp and resp[-1].result not in (None, "status=0"):
        return "rejected"
    if torn:
        return "disconnected"
    return "in_progress" if stages else "unknown"


def _flags(stages: list[StageObs], local: str | None, observed: bool) -> list[str]:
    fl: list[str] = []
    if not observed:
        fl.append(
            "association was already in progress when WHD began watching; earlier stages are not in this epoch"
        )
    resp_ok = [s for s in stages if s.stage == "assoc_response" and s.result == "status=0"]
    assoc = [s for s in stages if s.stage in ("associated", "connect_notified")]
    if resp_ok and assoc:
        d = ((assoc[0].ts_boottime_ns or 0) - (resp_ok[0].ts_boottime_ns or 0)) / 1e6
        if d > DELAYED_NOTIFY_MS:
            fl.append(
                f"delayed association notification: {d:.0f} ms from a successful response to the notification"
            )
    bad = [s for s in stages if s.stage == "assoc_response" and s.result not in (None, "status=0")]
    if bad:
        fl.append(f"association response rejected {len(bad)}x: {sorted({s.result for s in bad if s.result})}")
    return fl


def _missing(
    seen: set[str], outcome: str, stages: list[StageObs], col: Collectors
) -> tuple[list[str], str | None, list[Gap]]:
    """Stages that should exist but have no observation. After a rejection or timeout later stages are *not reached*,
    which is a result, not a gap."""
    if outcome in ("rejected", "timed_out"):
        horizon = ORDER["assoc_response"]
    elif outcome == "disconnected" and "associated" not in seen:
        horizon = max((ORDER[s] for s in seen if s in ORDER), default=0)
    elif outcome == "unknown":
        return [], None, []
    else:
        horizon = len(PIPELINE) - 1
    missing = [sid for sid, _ in PIPELINE if ORDER[sid] <= horizon and sid not in seen]
    gaps = [col.gap_for(m) for m in missing]
    return missing, (missing[0] if missing else None), gaps
