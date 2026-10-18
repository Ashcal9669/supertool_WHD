"""Firmware identity and command lifecycle from the driver's own tagged log lines.

What is available: the driver prints the identity it programs (MAC/MLD, OMAC, BSS index, WCID, channel, band) before each
MCU command, brackets each command with a start/done pair (command word, link, return value, duration), and prints the
peer-lifecycle generation. What is not: the command bytes themselves (only their length) and asynchronous firmware events,
so those stay explicit gaps. Command names come from the driver header the tables were generated from; fields the tags do
not carry stay absent, never filled in.
"""

from __future__ import annotations

from typing import Any

from pydantic import Field

from whd.mlo.definitions import cmd_name
from whd.mlo.kv import fields_of, mac_of, num, tag_of, trace_name
from whd.mlo.models import EvidenceRef
from whd.mlo.timeline import ref
from whd.model.common import Model
from whd.model.events import Event

# Identity-bearing tags and the fields each contributes (renamed to one vocabulary).
IDENTITY_TAGS: dict[str, dict[str, str]] = {
    "MLO_FW_BSS_BASIC": {
        "bss_idx": "bss_idx",
        "omac": "omac",
        "assigned_band": "assigned_band",
        "chan_band": "chan_band",
        "control_channel": "channel",
        "freq": "freq_mhz",
        "width": "width_code",
        "sta": "sta_wlan",
        "bmc": "bmc_wlan",
        "active": "bss_active",
        "conn_state": "conn_state",
        "hw_bss": "hw_bss_idx",
        "wmm": "wmm_idx",
        "phy_mode": "phy_mode",
        "phy_ext": "phy_mode_ext",
    },
    "MLO_FW_BSS_MLD": {
        "bss_idx": "bss_idx",
        "group_mld": "group_mld",
        "own_mld": "own_mld",
        "omac": "omac",
        "band": "assigned_band",
        "mac": "mac",
        "eml": "eml",
        "remap": "remap_idx",
    },
    "MLO_FW_BSS_RLM": {
        "bss_idx": "bss_idx",
        "control_channel": "channel",
        "freq": "freq_mhz",
        "width": "width_code",
        "center1": "center1_mhz",
        "center2": "center2_mhz",
        "center_chan": "center_channel",
        "center_chan2": "center_channel2",
        "tx_streams": "tx_streams",
        "rx_streams": "rx_streams",
        "rlm_band": "rlm_band",
        "sco": "sco",
    },
    "MLO_FW_STA_PHY": {
        "bss_idx": "bss_idx",
        "control_channel": "channel",
        "freq": "freq_mhz",
        "width": "width_code",
    },
    "MLO_FW_STA_RET": {
        "bss_idx": "bss_idx",
        "wcid": "wcid",
        "enable": "sta_enable",
        "state": "sta_state",
        "ret": "sta_ret",
    },
    "MLO_FW_STA_RAW": {
        "bss_idx": "bss_idx",
        "wcid": "wcid",
        "phy_idx": "phy_idx",
        "enable": "sta_enable",
        "state": "sta_state",
    },
    "MLO_DEVINFO_TX": {
        "omac": "omac",
        "band": "assigned_band",
        "dev_link_idx": "dev_link_idx",
        "bss": "bss_idx",
        "wcid": "dev_wcid",
        "active": "dev_active",
    },
    "MLO_FW_DEV_BSS_RAW": {"link_idx": "dev_link_idx"},
    "MLO_FW_STA_MLD": {
        "primary": "primary_wcid",
        "secondary": "secondary_wcid",
        "wlan": "mld_wlan_id",
        "link_num": "mld_link_num",
        "l0_wlan": "mld_member0_wcid",
        "l0_bss": "mld_member0_bss",
        "l1_wlan": "mld_member1_wcid",
        "l1_bss": "mld_member1_bss",
    },
    "MLO_BSSINFO_TX": {
        "bss": "bss_idx",
        "omac": "omac",
        "band": "assigned_band",
        "sta": "sta_wlan",
        "active": "bss_active",
        "conn_state": "conn_state",
    },
}
# fields where a value of 255 / 0xff means "none" in the driver, not a real index
SENTINELS = {"remap", "group_mld"}


class FwOp(Model):
    seq: int
    cmd: int | None
    cmd_name: str | None
    link: int | None
    token: str  # request cookie: command word @ the driver's own start timestamp
    ts_start_ns: int | None
    ts_done_ns: int | None
    duration_us: int | None
    ret: int | None
    status: str  # ok | error | incomplete (no done line seen)
    raw_len: int | None = None
    bytes_available: bool = False
    requested: dict[str, Any] = Field(default_factory=dict)
    changed_vs_previous: dict[str, list[Any]] = Field(default_factory=dict)
    evidence: list[EvidenceRef] = Field(default_factory=list)


class LinkIdentity(Model):
    link_id: int
    current: dict[str, Any]
    first_seen_ns: int | None
    last_seen_ns: int | None
    sources: list[str]
    completed_evidence: list[EvidenceRef] = Field(default_factory=list)


class FwReport(Model):
    ops: list[FwOp]
    links: list[LinkIdentity]
    flags: list[str]
    generations: list[int]
    gaps: list[str]


def _link_of(f: dict[str, str]) -> int | None:
    for k in ("link_id", "update_link", "link", "key_link", "link_idx"):
        v = num(f, k)
        if v is not None and 0 <= v < 16:
            return v
    return None


def analyze(events: list[Event]) -> FwReport:
    evs = sorted(events, key=lambda e: e.ts_boottime_ns)
    cur: dict[int, dict[str, Any]] = {}
    completed_refs: dict[int, list[EvidenceRef]] = {}
    pending_station: dict[int, list[dict[str, Any]]] = {}
    latest_station_request: dict[int, dict[str, Any]] = {}
    seen: dict[int, tuple[int, int, set[str]]] = {}
    flags: list[str] = []
    gens: list[int] = []
    ops: list[FwOp] = []
    pending: dict[tuple[int | None, int | None], list[FwOp]] = {}
    since_op: dict[int, dict[str, Any]] = {}
    sta_mld: dict[str, str] | None = None
    sta_ret_ok: set[int] = set()
    alloc: dict[int, int] = {}
    raw_len: dict[tuple[int | None, int | None], int] = {}
    link_generations: dict[int, int] = {}
    generation_high: int | None = None
    retired: set[int] = set()
    lifetime_start: dict[int, int] = {}

    def retire_station(lk: int) -> None:
        # A peer lifetime ends independently of its BSS configuration.
        row = cur.get(lk, {})
        for key in list(row):
            if key in {"wcid", "phy_idx", "primary_wcid", "secondary_wcid"} or key.startswith(
                ("sta_", "mld_")
            ):
                row.pop(key)
        completed_refs.pop(lk, None)
        pending_station.pop(lk, None)
        latest_station_request.pop(lk, None)
        sta_ret_ok.discard(lk)
        alloc.pop(lk, None)
        since_op.pop(lk, None)
        retired.add(lk)
        for raw_key in list(raw_len):
            if raw_key[1] == lk:
                raw_len.pop(raw_key)

    for e in evs:
        t = tag_of(e)
        if trace_name(e) == "whd_mcu_lifecycle":
            phase = fields_of(e).get("stage")
            t = {"start": "MLO_MCU_SEND_START", "done": "MLO_MCU_SEND_DONE"}.get(phase or "")
        if t is None:
            continue
        f = fields_of(e)
        link = _link_of(f)
        if t == "MLO_FW_PEER_LIFECYCLE":
            g = num(f, "generation")
            if g is not None:
                if generation_high is not None and g < generation_high:
                    flags.append(f"stale peer-lifecycle event: generation {g} after {generation_high}")
                if generation_high is not None and g > generation_high:
                    flags.append(f"peer recreated: generation {generation_high} -> {g}")
                generation_high = max(generation_high, g) if generation_high is not None else g
                gens.append(g)
                if link is not None:
                    previous = link_generations.get(link)
                    if previous is not None and g > previous:
                        retire_station(link)
                        lifetime_start[link] = e.ts_boottime_ns
                        sta_mld = None
                    if previous is None or g > previous:
                        link_generations[link] = g
        if t == "MLO_WCID_LIFE" and f.get("stage") == "remove_after" and link is not None:
            old_idx = num(f, "old_idx")
            if old_idx is not None and old_idx == cur.get(link, {}).get("wcid"):
                retire_station(link)
                lifetime_start[link] = e.ts_boottime_ns
                sta_mld = None
            else:
                flags.append(f"link {link}: unscoped or stale WCID removal; identity retained")
        if t in IDENTITY_TAGS and link is not None:
            obs: dict[str, Any] = {}
            for src, dst in IDENTITY_TAGS[t].items():
                v = f.get(src)
                if v is None:
                    continue
                if src == "mac":
                    address = mac_of(v)
                    if address is not None:
                        obs[dst] = address
                    continue
                n = num(f, src)
                if n is None:
                    continue
                if src in SENTINELS and n == 255:
                    obs[dst + "_raw"] = n
                    obs[dst] = None
                    continue
                obs[dst] = n
            row = cur.setdefault(link, {})
            broadcast = "wcid" in obs and row.get("bmc_wlan") == obs["wcid"]
            if t == "MLO_FW_STA_RAW" and not broadcast:
                retired.discard(link)
                sta_ret_ok.discard(link)
                request = dict(obs)
                pending_station.setdefault(link, []).append(request)
                latest_station_request[link] = request
            elif t == "MLO_FW_STA_RET" and not broadcast and link in retired:
                flags.append(
                    f"link {link}: stale station completion after retirement without a fresh request"
                )
                continue
            elif (
                t == "MLO_FW_STA_RET"
                and not broadcast
                and link in latest_station_request
                and any(
                    latest_station_request[link].get(key) != obs.get(key)
                    for key in ("wcid", "bss_idx", "sta_state", "sta_enable")
                    if key in latest_station_request[link] and key in obs
                )
            ):
                flags.append(
                    f"link {link}: stale station completion does not match the latest requested identity"
                )
                continue
            elif t == "MLO_FW_STA_RET" and not broadcast and pending_station.get(link):
                outstanding = pending_station[link]
                matches = [
                    request
                    for request in outstanding
                    if obs.get("wcid") is not None
                    and request.get("wcid") == obs["wcid"]
                    and all(
                        request[key] == obs[key]
                        for key in ("bss_idx", "sta_state", "sta_enable")
                        if key in request and key in obs
                    )
                ]
                if len(matches) != 1 or matches[0] is not outstanding[-1]:
                    flags.append(
                        f"link {link}: unmatched, stale or ambiguous station completion for WCID {obs.get('wcid')}; latest requested identity retained"
                    )
                    continue
                outstanding.remove(matches[0])
            if broadcast:
                obs["bmc_wcid"] = obs.pop("wcid")
                for key in ("sta_state", "sta_ret", "sta_enable"):
                    if key in obs:
                        obs["bmc_" + key] = obs.pop(key)
            elif t == "MLO_FW_STA_RAW" or ("wcid" in obs and row.get("wcid") not in (None, obs["wcid"])):
                row.pop("sta_ret", None)
                completed_refs.pop(link, None)
            if t == "MLO_FW_STA_RET" and not broadcast:
                completed_refs[link] = [ref(e)]
                sta_ret_ok.discard(link)
                if obs.get("sta_ret") == 0 and obs.get("sta_enable") == 0:
                    retire_station(link)
                    lifetime_start[link] = e.ts_boottime_ns
                    sta_mld = None
            # a station update can target the peer or the BSS's broadcast/multicast entry (its wcid is bmc_wlan):
            # those are different stations, not one identity changing
            for k, v in obs.items():
                if k in row and row[k] != v and k in ("mac", "own_mld", "wcid", "bss_idx", "omac", "channel"):
                    flags.append(
                        f"link {link}: {k} changed {row[k]} -> {v} ({t} at {e.ts_boottime_ns} ns); "
                        "an identity that changes without a teardown is a conflict to explain"
                    )
                row[k] = v
            since_op.setdefault(link, {}).update(obs)
            a = seen.get(link)
            seen[link] = (a[0] if a else e.ts_boottime_ns, e.ts_boottime_ns, (a[2] if a else set()) | {t})
        if t == "MLO_FW_STA_MLD":
            sta_mld = f
        if (
            t == "MLO_FW_STA_RET"
            and link is not None
            and num(f, "ret") == 0
            and num(f, "enable") == 1
            and num(f, "wcid") != cur.get(link, {}).get("bmc_wlan")
        ):
            sta_ret_ok.add(link)
        if t in ("MLO_FW_BSS_RAW", "MLO_FW_STA_RAW", "MLO_FW_DEV_BSS_RAW"):
            n = num(f, "len")
            if n is not None:
                raw_len[(num(f, "cmd"), link)] = n
        if t == "MLO_MCU_SEND_START":
            cmd = num(f, "cmd")
            op = FwOp(
                seq=len(ops) + 1,
                cmd=cmd,
                cmd_name=cmd_name(cmd),
                link=link,
                token=f"{f.get('cmd')}@{f.get('cookie') or f.get('t')}",
                ts_start_ns=e.ts_boottime_ns,
                ts_done_ns=None,
                duration_us=None,
                ret=None,
                status="incomplete",
                raw_len=raw_len.pop((cmd, link), None),
                requested=dict(since_op.get(link, {})) if link is not None else {},
                evidence=[ref(e)],
            )
            ops.append(op)
            pending.setdefault((cmd, link), []).append(op)
            if link is not None:
                since_op.pop(link, None)
        elif t == "MLO_MCU_SEND_DONE":
            cmd = num(f, "cmd")
            candidates = pending.get((cmd, link), [])
            cookie = f.get("cookie") or f.get("start_t")
            if cookie:
                candidates = [o for o in candidates if o.token.endswith("@" + cookie)]
            if len(candidates) > 1:
                flags.append(
                    f"ambiguous MCU done for {cmd} link {link}: {len(candidates)} outstanding starts"
                )
                continue
            op2 = candidates[0] if candidates else None
            if op2 is None:
                flags.append(
                    f"MCU done for {f.get('cmd')} link {link} has no matching start (stale or lost start)"
                )
                continue
            pending[(cmd, link)].remove(op2)
            op2.ts_done_ns = e.ts_boottime_ns
            op2.duration_us = num(f, "duration_us")
            op2.ret = num(f, "ret")
            op2.status = "ok" if op2.ret == 0 else "error"
            op2.evidence.append(ref(e))
        if t == "MLO_WCID_LIFE" and f.get("stage") == "add_alloc" and link is not None:
            alloc[link] = alloc.get(link, 0) + 1
            if alloc[link] > 1:
                flags.append(
                    f"link {link}: station entry allocated {alloc[link]}x inside one window "
                    "(unexpected peer recreation unless a teardown preceded it)"
                )
    for op in ops:
        if op.status == "incomplete":
            flags.append(f"MCU command {op.token} (link {op.link}) never completed in this window")
    prev: dict[int, dict[str, Any]] = {}
    for op in ops:
        if op.link is None:
            continue
        before = prev.get(op.link, {})
        op.changed_vs_previous = {
            k: [before.get(k), v] for k, v in op.requested.items() if before.get(k) != v
        }
        prev.setdefault(op.link, {}).update(op.requested)
    # same index used by two links at once
    for key in ("wcid", "bss_idx", "omac"):
        users: dict[Any, list[int]] = {}
        for lk, row in cur.items():
            # only links the driver reports as active in firmware can conflict; an inactive link's slot is free
            if key in row and row.get("bss_active") == 1:
                users.setdefault(row[key], []).append(lk)
        for val, lks in users.items():
            if len(lks) > 1:
                flags.append(
                    f"{key}={val} is used by links {sorted(lks)} while the driver reports them active in firmware: a shared "
                    "index is a conflicting identity unless the firmware keys it per link"
                )
    if sta_mld is not None:
        want = num(sta_mld, "link_num")
        if want is not None and len(sta_ret_ok) < want:
            flags.append(
                f"station MLD announces {want} links but only {sorted(sta_ret_ok)} completed a successful station "
                "update here: missing member(s)"
            )
    # Consumer contract: none of the currently collected tags proves an explicit
    # partner response. Keep driver returns as candidates, never firmware YES.
    # A future YES requires DEV/BSS/STA response.status=0 matched to command,
    # cookie, transport sequence/attempt and this exact identity scope, with
    # no later request/error/disable/retirement. Generic transport 'done' also
    # covers wait_resp=false and cannot satisfy that response requirement.
    for lk, row in cur.items():
        components: dict[str, Any] = {}
        for name, command in (("dev", 0x20001), ("bss", 0x20002)):
            candidates = [
                op
                for op in ops
                if op.cmd == command
                and op.link == lk
                and (op.ts_start_ns or 0) >= lifetime_start.get(lk, 0)
                and op.requested.get("bss_idx") == row.get("bss_idx")
                and op.requested.get("omac") == row.get("omac")
                and row.get("bss_idx") is not None
                and row.get("omac") is not None
            ]
            latest = candidates[-1] if candidates else None
            components[name] = {
                "response_matched": False,
                "driver_return": latest.ret if latest else None,
                "candidate_evidence": [r.model_dump(mode="json") for r in latest.evidence] if latest else [],
            }
        components["sta"] = {
            "response_matched": False,
            "driver_return": row.get("sta_ret"),
            "candidate_evidence": [r.model_dump(mode="json") for r in completed_refs.get(lk, [])],
        }
        scoped = [
            e for e in evs if _link_of(fields_of(e)) == lk and e.ts_boottime_ns >= lifetime_start.get(lk, 0)
        ]

        def unique_scope(key: str, scope_events: list[Event] = scoped) -> str | None:
            values = {
                str(e.device_id if key == "device_id" else e.data.get(key))
                for e in scope_events
                if (e.device_id if key == "device_id" else e.data.get(key)) is not None
            }
            return next(iter(values)) if len(values) == 1 else None

        row["fw_programming"] = {
            "value": "unknown",
            "identity_scope": {
                **{
                    key: unique_scope(key)
                    for key in (
                        "device_id",
                        "boot_id",
                        "association_epoch",
                        "interface",
                        "interface_lifetime",
                    )
                },
                "link_id": lk,
                "generation": link_generations.get(lk),
                **{key: row.get(key) for key in ("wcid", "bss_idx", "omac", "assigned_band")},
            },
            "components": components,
            "evidence": [],
            "missing": ["matched partner DEV/BSS/STA response statuses and transport attempt identity"],
            "matches_loaded_build": None,
        }
    return FwReport(
        ops=ops,
        links=[
            LinkIdentity(
                link_id=lk,
                current=row,
                first_seen_ns=seen[lk][0] if lk in seen else None,
                last_seen_ns=seen[lk][1] if lk in seen else None,
                sources=sorted(seen[lk][2]) if lk in seen else [],
                completed_evidence=completed_refs.get(lk, []),
            )
            for lk, row in sorted(cur.items())
        ],
        flags=flags,
        generations=gens,
        gaps=[
            "outgoing MCU command bytes: only the length is printed (needs an instrumentation extension)",
            "firmware responses beyond the return value and asynchronous firmware events: not collected",
            "DEV/BSS/STA partner completion cannot be derived from driver returns; firmware programming remains unknown",
        ],
    )
