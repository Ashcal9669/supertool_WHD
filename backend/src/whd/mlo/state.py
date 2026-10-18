"""Per-link MLO state with five separate dimensions, each YES / NO / UNKNOWN (or DRIVER_ONLY) and each with its basis.

negotiated        the link is valid for the MLD (driver valid-links mask, else the kernel's nl80211 link list)
active            mac80211 considers it active (driver mask only; `iw` listing a link does not make it active)
fw_programmed     the driver's MCU commands for it returned success (tags); DRIVER_ONLY = only the driver's own
                  station table says valid
authorized        firmware port-secure state for the link's station entry; DRIVER_ONLY = only MLD-level mac80211
                  authorization is known (mac80211 authorizes the station, not individual links)
authenticated     frames resolved to the link were decrypted without errors and are on the link's channel;
delivery          DRIVER_ONLY = only the pre-security packet counter moved

Readings taken now carry no 'historical' mark; anything derived from earlier log lines does.
"""

from __future__ import annotations

import time
from typing import Any

from pydantic import Field

from whd.clock import boottime_ns
from whd.mlo import mask as maskmod
from whd.mlo.fwid import FwReport
from whd.mlo.kv import fields_of, num, tag_of
from whd.mlo.models import Dimension, Epoch, EvidenceRef, LinkState, Scope
from whd.mlo.rx import RxFrame
from whd.mlo.timeline import ref
from whd.model.common import Model
from whd.model.events import Event

LEGEND = {
    "negotiated": "valid for the MLD. From the driver's packed mask when readable, else the kernel's link list.",
    "active": "active in mac80211. Only the driver's packed mask or a logged active-links value counts; being listed "
    "by `iw` does not.",
    "fw_programmed": "the driver's MCU commands for the link returned success. A success return is not proof the "
    "firmware forwards traffic.",
    "authorized": "firmware port-secure state for the link's station entry (mac80211 authorizes the station as a "
    "whole, so a link-level 'yes' needs the firmware state).",
    "authenticated_delivery": "correlated packet evidence of decryption, integrity, replay and correct channel plus stack delivery. "
    "Adjacent RX logs and pre-security counters are DRIVER_ONLY; a buffer release is not delivery.",
}


class MloState(Model):
    device_id: str
    phy: str | None
    interface: str | None = None
    boot_id: str
    association_epoch: str | None
    generated_at: float
    boottime_ns: int
    mask: maskmod.MaskDecode
    mac80211_authorized: bool | None
    links: list[LinkState]
    legend: dict[str, str] = Field(default_factory=lambda: dict(LEGEND))
    sources: list[str]
    perturbations: list[str]
    notes: list[str]


def _dim(
    value: str,
    basis: str,
    ev: list[EvidenceRef] | None = None,
    limits: str | None = None,
    historical: bool = False,
) -> Dimension:
    return Dimension(value=value, basis=basis, evidence=ev or [], limits=limits, historical=historical)  # type: ignore[arg-type]


def _last_kv(events: list[Event], tag: str, key: str) -> tuple[int, Event] | None:
    for e in reversed(events):
        if tag_of(e) == tag:
            v = num(fields_of(e), key)
            if v is not None:
                return v, e
    return None


def build_state(
    *,
    device_id: str,
    phy: str | None,
    boot_id: str,
    epoch: Epoch | None,
    epoch_events: list[Event],
    mask_raw: int | None,
    mask_read_ns: int | None,
    link_stats: list[dict[str, Any]],
    wcid_dump: list[dict[str, Any]],
    nl_links: list[dict[str, Any]],
    nl_connected: bool | None,
    sta_authorized: bool | None,
    fw: FwReport,
    rx_frames: list[RxFrame],
    woke_device: bool,
    sources: list[str],
    interface: str | None = None,
    interface_lifetime: str | None = None,
) -> MloState:
    m = maskmod.decode_active_links(mask_raw)
    eid = epoch.id if epoch else None
    nl_by_id = {int(x["link_id"]): x for x in nl_links if x.get("link_id") is not None}
    fwl = {lk.link_id: lk.current for lk in fw.links}
    completed_refs = {lk.link_id: lk.completed_evidence for lk in fw.links}
    ids: set[int] = set(nl_by_id) | set(fwl)
    for event in epoch_events:
        fields = fields_of(event)
        for key in ("link", "link_id", "resolved_link"):
            observed_id = num(fields, key)
            if observed_id is not None and 0 <= observed_id < 16:
                ids.add(observed_id)
    if m.valid:
        ids |= set(m.valid)
    if m.active:
        ids |= set(m.active)
    ids |= {
        int(r["link"]) for r in link_stats if r.get("valid") and r.get("link") is not None and r["link"] < 16
    }
    mask_ev = [
        EvidenceRef(
            kind="debugfs",
            source="debugfs",
            ts_boottime_ns=mask_read_ns,
            text=f"mlo_active_links = 0x{mask_raw:x}" if mask_raw is not None else "unreadable",
        )
    ]
    logged_active = _last_kv(epoch_events, "MLO_TX_SELECT", "active_links")
    logged_valid = _last_kv(epoch_events, "MLO_CHANCTX_TRACE", "negotiated_links")
    bmc = {int(c["bmc_wlan"]) for c in fwl.values() if "bmc_wlan" in c}
    peer_rows: dict[int, list[dict[str, Any]]] = {}
    for r in link_stats:
        if not r.get("valid") or r.get("link") is None or r["wcid"] in bmc:
            continue
        peer_rows.setdefault(int(r["link"]), []).append(r)
    mac80211_auth = sta_authorized
    if nl_connected is False:
        mac80211_auth = False
    if mac80211_auth is None and epoch is not None:
        if any(s.stage == "port_authorized" for s in epoch.stages):
            mac80211_auth = True
    out: list[LinkState] = []
    for lk in sorted(ids):
        nl = nl_by_id.get(lk, {})
        row = fwl.get(lk, {})
        scope = Scope(
            boot_id=boot_id,
            device_id=device_id,
            association_epoch=eid,
            link_id=lk,
            interface=interface or (epoch.interface if epoch else None),
            interface_lifetime=interface_lifetime or (epoch.interface_lifetime if epoch else None),
            phy=phy,
        )
        conflicts: list[str] = []
        # negotiated / valid
        if m.valid is not None:
            neg = _dim(
                "yes" if lk in m.valid else "no", "driver mask bits 31:16 (valid_links), read now", mask_ev
            )
        elif lk in nl_by_id:
            neg = _dim(
                "yes",
                "listed in the kernel's nl80211 MLO links (valid_links)",
                completed_refs.get(lk, []),
                "the nl80211 list only exists while associated; it says valid, not active",
            )
        elif logged_valid:
            v, e = logged_valid
            neg = _dim(
                "yes" if v & (1 << lk) else "no",
                f"last logged negotiated_links=0x{v:x} in this epoch",
                [ref(e)],
                "a log line, not a current reading",
                historical=True,
            )
        else:
            neg = _dim("unknown", "no readable valid-links source")
        # active
        if m.active is not None:
            act = _dim(
                "yes" if lk in m.active else "no", "driver mask bits 15:0 (active_links), read now", mask_ev
            )
        elif logged_active:
            v, e = logged_active
            act = _dim(
                "yes" if v & (1 << lk) else "no",
                f"last logged active_links=0x{v:x} in this epoch",
                [ref(e)],
                "a log line, not a current reading",
                historical=True,
            )
        else:
            act = _dim(
                "unknown",
                "the driver mask is not readable and no active-links value was logged",
                limits="nl80211 listing a link is not evidence that it is active",
            )
        if m.active is not None and lk in nl_by_id and lk not in m.active:
            conflicts.append("the kernel lists this link (valid) but the driver mask says it is not active")
        # firmware programmed
        ops = [o for o in fw.ops if o.link == lk]
        latest_identity_ns = next(
            (identity.last_seen_ns or 0 for identity in fw.links if identity.link_id == lk), 0
        )
        bad = [o for o in ops if o.status == "error" and (o.ts_done_ns or 0) >= latest_identity_ns]
        peers = peer_rows.get(lk, [])
        if bad:
            fwp = _dim(
                "no",
                f"{len(bad)} MCU command(s) for this link returned an error",
                [o.evidence[0] for o in bad[:3]],
                historical=True,
            )
        elif row.get("sta_ret") == 0 and row.get("sta_enable") == 1 and row.get("bss_active") == 1:
            fwp = _dim(
                "unknown",
                "station update returned 0 (enabled), but an active BSS request does not establish its completion",
                [],
                "matching BSS/DEV completion and peer lifetime are needed before declaring the link firmware-programmed",
                historical=True,
            )
        elif peers:
            fwp = _dim(
                "driver_only",
                "the driver's station table lists a valid entry for the link; no firmware "
                "result was logged for it",
                [EvidenceRef(kind="debugfs", source="debugfs", text="link_stats valid")],
            )
        else:
            fwp = _dim("unknown", "no firmware command result for this link in the window")
        # authorized
        st = row.get("sta_state")
        if row.get("sta_enable") == 0 and row.get("sta_ret") == 0:
            auth = _dim(
                "no",
                "station disable/removal returned 0; prior port-secure state does not authorize a removed entry",
                completed_refs.get(lk, []),
                historical=True,
            )
        elif st == 2 and row.get("sta_ret") == 0 and row.get("sta_enable") == 1:
            auth = _dim(
                "yes",
                "firmware station state = port secure (2), update returned 0",
                completed_refs.get(lk, []),
                historical=True,
            )
        elif st in (0, 1) and row.get("sta_ret") == 0:
            auth = _dim(
                "no",
                f"firmware station state = {st} (not port secure)",
                completed_refs.get(lk, []),
                historical=True,
            )
        elif st == 2 and row.get("sta_ret") == 0:
            auth = _dim(
                "unknown",
                "port-secure state was reported, but station enable/removal information is missing",
                completed_refs.get(lk, []),
                historical=True,
            )
        elif mac80211_auth is not None:
            auth = _dim(
                "driver_only" if mac80211_auth else "no",
                "MLD-level mac80211 authorization" + (" observed" if mac80211_auth else " not observed"),
                limits="applies to the whole station; no firmware per-link state was logged",
            )
        else:
            auth = _dim("unknown", "no authorization evidence")
        # authenticated delivery
        frames = [f for f in rx_frames if f.resolved_link == lk]
        okf = [f for f in frames if f.verdict == "authenticated" and f.delivered]
        wrong = [f for f in frames if f.verdict == "wrong_channel_for_link"]
        cnt = {
            k: sum(int(r.get(k) or 0) for r in peers) for k in ("tx_pkts", "rx_pkts", "tx_bytes", "rx_bytes")
        }
        if okf:
            ad = _dim(
                "driver_only",
                f"{len(okf)} driver frame(s) resolved to this link decrypted without errors on its channel",
                [okf[0].evidence[0]],
                "adjacent-log join; delivery to the network stack is a separate stage",
                historical=True,
            )
        elif any(f.authenticated for f in frames):
            ad = _dim(
                "driver_only",
                "driver security observations; stack delivery unobserved",
                frames[0].evidence,
                "adjacency cannot prove a packet reached the stack",
                historical=True,
            )
        elif frames:
            ad = _dim(
                "unknown",
                f"{len(frames)} frame(s) resolved to this link, none authenticated "
                f"({', '.join(sorted({f.verdict for f in frames}))})",
                [frames[0].evidence[0]],
                historical=True,
            )
        elif cnt["rx_pkts"]:
            ad = _dim(
                "driver_only",
                f"rx_pkts={cnt['rx_pkts']} on this link's station entry, a counter that is "
                "incremented before decryption",
                [EvidenceRef(kind="debugfs", source="debugfs", text="link_stats")],
                "does not show that any frame was authenticated or delivered",
            )
        else:
            ad = _dim("unknown", "no per-frame RX trace and no RX counter movement for this link")
        if wrong:
            conflicts.append(f"{len(wrong)} frame(s) resolved to this link arrived on a different channel")
        if cnt["rx_pkts"] and not okf and frames == []:
            conflicts.append("rx counter is non-zero but no authenticated frame is evidenced for this link")
        if nl_connected is False:
            fresh = [
                EvidenceRef(kind="station_dump", source="nl80211", text="fresh station dump: disconnected")
            ]
            neg = _dim("no", "fresh disconnected reading: no current negotiated association", fresh)
            act = _dim("no", "fresh disconnected reading: no current active association", fresh)
            auth = _dim("no", "fresh disconnected reading: no current authorized association", fresh)
            fwp = _dim(
                "unknown", "disconnected reading does not prove firmware identities were cleared", fresh
            )
        out.append(
            LinkState(
                link_id=lk,
                scope=scope,
                mac=nl.get("mac") or row.get("mac"),
                freq_mhz=nl.get("freq_mhz") or row.get("freq_mhz"),
                channel=nl.get("channel") or row.get("channel"),
                wcid=(peers[0]["wcid"] if peers else row.get("wcid")),
                negotiated=neg,
                active=act,
                fw_programmed=fwp,
                authorized=auth,
                authenticated_delivery=ad,
                counters=cnt | {"note": "driver counters, incremented before decryption"} if peers else {},
                conflicts=conflicts,
            )
        )
    notes = list(m.notes)
    if nl_connected is False:
        notes.append(
            "fresh station reading is disconnected; retained mask/firmware records do not establish a current association"
        )
    return MloState(
        interface=interface,
        device_id=device_id,
        phy=phy,
        boot_id=boot_id,
        association_epoch=eid,
        generated_at=time.time(),
        boottime_ns=boottime_ns(),
        mask=m,
        mac80211_authorized=mac80211_auth,
        links=out,
        sources=sources,
        perturbations=(
            ["debugfs mlo_wcid_dump / tx_stats read wakes the chip from runtime power save"]
            if woke_device
            else []
        ),
        notes=notes,
    )
