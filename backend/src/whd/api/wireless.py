"""Phase 4: live wireless PHY diagnostics (fresh nl80211 GET dumps; never triggers scans or config changes)."""

from __future__ import annotations

import asyncio
import time
from typing import Any

from fastapi import APIRouter, Depends, HTTPException

from whd.api.deps import get_state, require_auth
from whd.model.common import Model
from whd.model.wireless import RegDomain, ScanBss, Station, SurveyEntry, WifiInterface
from whd.platform.netlink import NetlinkError
from whd.state import AppState

router = APIRouter(prefix="/api/v1")
Auth = Depends(require_auth)
State = Depends(get_state)


class LiveInterface(Model):
    interface: WifiInterface
    stations: list[Station]
    survey: list[SurveyEntry]
    scan: list[ScanBss]
    errors: dict[str, str]
    connected: bool
    association_summary: str | None = None


class WirelessLive(Model):
    device_id: str
    taken_at: float
    interfaces: list[LiveInterface]
    other_interfaces_on_wiphy: list[WifiInterface]
    regulatory: list[RegDomain]
    capability_summary: dict[str, Any]
    notes: list[str]


def _capability_summary(dev: Any) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for w in dev.wiphys:
        bands = {}
        for b in w.bands:
            gen = (
                "EHT (Wi-Fi 7)"
                if b.eht
                else "HE (Wi-Fi 6/6E)"
                if b.he
                else "VHT (Wi-Fi 5)"
                if b.vht
                else "HT (Wi-Fi 4)"
                if b.ht
                else "legacy"
            )
            bands[b.name] = {
                "highest": gen,
                "widths": [x.width for x in b.widths],
                "channels_enabled": sum(1 for c in b.channels if not c.disabled),
                "channels_total": len(b.channels),
            }
        out[w.name or str(w.index)] = {
            "bands": bands,
            "mlo_support": w.mlo_support,
            "six_ghz": any(b.name == "6GHZ" for b in w.bands),
        }
    return out


def _collect(st: AppState, dev: Any) -> WirelessLive:
    nl = st.host.nl80211()
    notes: list[str] = ["Scan results are the kernel's cached BSS table; WHD never triggers scans."]
    if nl is None:
        raise HTTPException(409, f"nl80211 unavailable: {st.host.nl80211_error}")
    try:
        all_ifaces = nl.interfaces()
    except (NetlinkError, OSError) as e:
        raise HTTPException(502, f"nl80211 GET_INTERFACE failed: {e}") from e
    wiphy_idx = {w.index for w in dev.wiphys}
    mine = {n.ifindex for n in dev.netdev_info if n.ifindex is not None}
    out: list[LiveInterface] = []
    others: list[WifiInterface] = []
    for i in all_ifaces:
        if i.ifindex not in mine:
            if i.wiphy in wiphy_idx:
                others.append(i)
            continue
        errors: dict[str, str] = {}
        stations: list[Station] = []
        survey: list[SurveyEntry] = []
        scan: list[ScanBss] = []
        try:
            i.power_save = nl.power_save(i.ifindex)
        except (NetlinkError, OSError) as e:
            errors["power_save"] = str(e)
        for name, fn in (("stations", nl.stations), ("survey", nl.survey), ("scan", nl.scan)):
            try:
                res = fn(i.ifindex)
            except (NetlinkError, OSError) as e:
                errors[name] = str(e)
                continue
            if name == "stations":
                stations = res  # type: ignore[assignment]
            elif name == "survey":
                survey = res  # type: ignore[assignment]
            else:
                scan = res  # type: ignore[assignment]
        connected = i.iftype in ("STATION", "P2P_CLIENT") and bool(stations)
        summary = None
        if connected:
            s = stations[0]
            tr = s.tx_rate
            summary = (
                f"{i.ssid or '?'} on {i.freq_mhz or (i.mlo_links[0].freq_mhz if i.mlo_links else '?')} MHz"
                f"{' (' + str(len(i.mlo_links)) + ' MLO links)' if i.mlo_links else ''}, signal {s.signal_dbm} "
                f"dBm, TX {tr.mode if tr else '?'} MCS{tr.mcs if tr else '?'} NSS{tr.nss if tr else '?'} "
                f"{tr.width_mhz if tr else '?'} MHz {tr.bitrate_mbps if tr else '?'} Mb/s"
            )
        out.append(
            LiveInterface(
                interface=i,
                stations=stations,
                survey=survey,
                scan=scan,
                errors=errors,
                connected=connected,
                association_summary=summary,
            )
        )
    try:
        regs = [r for r in nl.regdomains() if r.wiphy is None or r.wiphy in wiphy_idx]
    except (NetlinkError, OSError) as e:
        regs = []
        notes.append(f"regulatory query failed: {e}")
    mon = [o for o in others if o.iftype == "MONITOR"]
    if mon:
        notes.append(
            f"Monitor interface(s) present on this wiphy: {', '.join(m.name or '?' for m in mon)} "
            "(created outside WHD; WHD never creates or reconfigures interfaces)."
        )
    return WirelessLive(
        device_id=dev.id,
        taken_at=time.time(),
        interfaces=out,
        other_interfaces_on_wiphy=others,
        regulatory=regs,
        capability_summary=_capability_summary(dev),
        notes=notes,
    )


@router.get("/devices/{device_id}/wireless/live", response_model=WirelessLive)
async def wireless_live(device_id: str, _: str = Auth, st: AppState = State) -> WirelessLive:
    dev = await st.inventory.device(device_id)
    if dev is None:
        raise HTTPException(404, "unknown device")
    if not dev.present:
        raise HTTPException(409, "device not present")
    return await asyncio.to_thread(_collect, st, dev)
