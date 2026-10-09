"""Decode nl80211 multicast notifications (config/scan/regulatory/mlme groups) into events."""

from __future__ import annotations

import struct
from typing import Any

from whd.model.events import Category, Severity
from whd.platform.kconsts import ieee80211 as IE
from whd.platform.kconsts import nl80211 as C
from whd.platform.netlink import GenlMsg
from whd.platform.nl80211.decode import CMD_NAMES, IFTYPE_NAMES, WIDTH_NAMES, mac_str

REASONS = {v: k.removeprefix("WLAN_REASON_") for k, v in IE.ENUMS.get("ieee80211_reasoncode", {}).items()}
STATUSES = {v: k.removeprefix("WLAN_STATUS_") for k, v in IE.ENUMS.get("ieee80211_statuscode", {}).items()}
CQM_EVENTS = {
    v: k.removeprefix("NL80211_CQM_RSSI_")
    for k, v in C.ENUMS.get("nl80211_cqm_rssi_threshold_event", {}).items()
}

# command name -> (category, severity, explanation)
CMD_INFO: dict[str, tuple[Category, Severity, str]] = {
    "NEW_WIPHY": ("phy", "notice", "cfg80211 registered or updated a wiphy."),
    "DEL_WIPHY": ("phy", "warning", "cfg80211 unregistered a wiphy (driver removed or device gone)."),
    "NEW_INTERFACE": ("netdev", "notice", "A wireless interface was created or changed."),
    "SET_INTERFACE": ("netdev", "notice", "A wireless interface's type was changed."),
    "DEL_INTERFACE": ("netdev", "warning", "A wireless interface was deleted."),
    "TRIGGER_SCAN": ("scan", "info", "A scan was started."),
    "NEW_SCAN_RESULTS": ("scan", "info", "A scan completed; new results are available."),
    "SCAN_ABORTED": ("scan", "warning", "A scan was aborted."),
    "START_SCHED_SCAN": ("scan", "info", "A scheduled scan was started."),
    "SCHED_SCAN_RESULTS": ("scan", "info", "Scheduled scan produced results."),
    "SCHED_SCAN_STOPPED": ("scan", "info", "Scheduled scan stopped."),
    "REG_CHANGE": ("regulatory", "notice", "The regulatory domain changed."),
    "WIPHY_REG_CHANGE": ("regulatory", "notice", "A self-managed wiphy changed its regulatory domain."),
    "REG_BEACON_HINT": ("regulatory", "info", "A beacon hint enabled channels."),
    "AUTHENTICATE": ("association", "info", "802.11 authentication completed (or timed out if flagged)."),
    "ASSOCIATE": ("association", "info", "802.11 association response processed."),
    "DEAUTHENTICATE": ("association", "warning", "Deauthentication (sent or received)."),
    "DISASSOCIATE": ("association", "warning", "Disassociation (sent or received)."),
    "CONNECT": ("association", "notice", "Connection result reported to userspace."),
    "ROAM": ("association", "notice", "The interface roamed to a new AP."),
    "DISCONNECT": ("association", "warning", "The interface disconnected."),
    "PORT_AUTHORIZED": ("association", "notice", "The 802.1X/4-way handshake authorized the port."),
    "NEW_STATION": ("association", "info", "A station entry was added."),
    "DEL_STATION": ("association", "info", "A station entry was removed."),
    "CH_SWITCH_NOTIFY": ("phy", "notice", "The operating channel changed."),
    "CH_SWITCH_STARTED_NOTIFY": ("phy", "notice", "A channel switch announcement started."),
    "NOTIFY_CQM": ("phy", "notice", "Connection quality monitor event."),
    "UNPROT_DEAUTHENTICATE": ("association", "warning", "Unprotected deauth received while MFP is in use."),
    "UNPROT_DISASSOCIATE": ("association", "warning", "Unprotected disassoc received while MFP is in use."),
    "MICHAEL_MIC_FAILURE": ("association", "error", "TKIP Michael MIC failure."),
    "LINKS_REMOVED": ("mlo", "notice", "MLO links were removed from the interface."),
    "ASSOC_MLO_RECONF": ("mlo", "notice", "MLO multi-link reconfiguration completed."),
    "SET_TID_TO_LINK_MAPPING": ("mlo", "notice", "TID-to-link mapping changed."),
    "STA_OPMODE_CHANGED": ("phy", "info", "A station's operating mode (width/NSS) changed."),
    "RADAR_DETECT": ("regulatory", "warning", "Radar/DFS event."),
    "FRAME_TX_STATUS": ("association", "debug", "Management frame TX status."),
    "FRAME": ("association", "debug", "Management frame received."),
    "REMAIN_ON_CHANNEL": ("phy", "debug", "Remain-on-channel started."),
    "CANCEL_REMAIN_ON_CHANNEL": ("phy", "debug", "Remain-on-channel ended."),
}


def _mgmt_status_or_reason(frame: bytes | None, cmd: str) -> dict[str, Any]:
    """Parse status/reason code from a management frame carried in NL80211_ATTR_FRAME (IEEE 802.11 layout)."""
    out: dict[str, Any] = {}
    if not frame or len(frame) < 24:
        return out
    body = frame[24:]
    try:
        if (
            cmd in ("DEAUTHENTICATE", "DISASSOCIATE", "UNPROT_DEAUTHENTICATE", "UNPROT_DISASSOCIATE")
            and len(body) >= 2
        ):
            rc = struct.unpack_from("<H", body)[0]
            out["reason_code"], out["reason"] = rc, REASONS.get(rc, "unknown")
        elif cmd == "AUTHENTICATE" and len(body) >= 6:
            alg, seq, st = struct.unpack_from("<HHH", body)
            out.update(auth_alg=alg, auth_seq=seq, status_code=st, status=STATUSES.get(st, "unknown"))
        elif cmd == "ASSOCIATE" and len(body) >= 6:
            _cap, st, aid = struct.unpack_from("<HHH", body)
            out.update(status_code=st, status=STATUSES.get(st, "unknown"), aid=aid & 0x3FFF)
    except struct.error:
        pass
    return out


def decode_event(payload: bytes) -> tuple[str, Category, Severity, str, str, dict[str, Any]]:
    """Returns (kind, category, severity, summary, explanation, data)."""
    m = GenlMsg.from_payload(payload)
    a = m.attrs
    cmd = CMD_NAMES.get(m.cmd, f"CMD_{m.cmd}").removeprefix("NL80211_CMD_")
    cat, sev, expl = CMD_INFO.get(cmd, ("phy", "debug", "nl80211 notification."))
    d: dict[str, Any] = {"cmd": cmd}
    if (v := a.u32(C.NL80211_ATTR_IFINDEX)) is not None:
        d["ifindex"] = v
    if (v2 := a.str(C.NL80211_ATTR_IFNAME)) is not None:
        d["ifname"] = v2
    if (v := a.u32(C.NL80211_ATTR_WIPHY)) is not None:
        d["wiphy"] = v
    if (mac := mac_str(a.get(C.NL80211_ATTR_MAC))) is not None:
        d["peer"] = mac
    if (v := a.u32(C.NL80211_ATTR_IFTYPE)) is not None:
        d["iftype"] = IFTYPE_NAMES.get(v, v)
    if (v := a.u32(C.NL80211_ATTR_WIPHY_FREQ)) is not None:
        d["freq_mhz"] = v
    if (v := a.u32(C.NL80211_ATTR_CHANNEL_WIDTH)) is not None:
        d["width"] = WIDTH_NAMES.get(v, v)
    if (v := a.u16(C.NL80211_ATTR_REASON_CODE)) is not None:
        d["reason_code"], d["reason"] = v, REASONS.get(v, "unknown")
    if (v := a.u16(C.NL80211_ATTR_STATUS_CODE)) is not None:
        d["status_code"], d["status"] = v, STATUSES.get(v, "unknown")
    if a.has(C.NL80211_ATTR_TIMED_OUT):
        d["timed_out"] = True
        sev = "error"
    if a.has(C.NL80211_ATTR_DISCONNECTED_BY_AP):
        d["by_ap"] = True
    if (v := a.u8(C.NL80211_ATTR_MLO_LINK_ID)) is not None:
        d["link_id"] = v
    links = [la.u8(C.NL80211_ATTR_MLO_LINK_ID) for _, la in a.nested_list(C.NL80211_ATTR_MLO_LINKS)]
    if links:
        d["mlo_links"] = links
        if cat == "association":
            cat = "mlo" if cmd in ("LINKS_REMOVED",) else cat
    if (alpha := a.str(C.NL80211_ATTR_REG_ALPHA2)) is not None:
        d["alpha2"] = alpha
    cqm = a.nested(C.NL80211_ATTR_CQM)
    if cqm is not None:
        ev = cqm.u32(C.NL80211_ATTR_CQM_RSSI_THRESHOLD_EVENT)
        if ev is not None:
            d["cqm"] = CQM_EVENTS.get(ev, ev)
        if (lvl := cqm.s32(C.NL80211_ATTR_CQM_RSSI_LEVEL)) is not None:
            d["rssi_dbm"] = lvl
        if cqm.has(C.NL80211_ATTR_CQM_BEACON_LOSS_EVENT):
            d["cqm"] = "BEACON_LOSS"
            sev = "warning"
        if (pl := cqm.u32(C.NL80211_ATTR_CQM_PKT_LOSS_EVENT)) is not None:
            d["cqm"], d["packets_lost"] = "PACKET_LOSS", pl
            sev = "warning"
    d.update(_mgmt_status_or_reason(a.get(C.NL80211_ATTR_FRAME), cmd))
    if d.get("status_code") not in (None, 0):
        sev = "error"
    ifn = d.get("ifname") or (f"ifindex {d['ifindex']}" if "ifindex" in d else f"wiphy {d.get('wiphy', '?')}")
    parts = [cmd.lower().replace("_", " "), ifn]
    for k in ("peer", "freq_mhz", "width", "reason", "status", "cqm", "rssi_dbm", "alpha2", "mlo_links"):
        if k in d:
            parts.append(f"{k}={d[k]}")
    if d.get("timed_out"):
        parts.append("TIMED OUT")
    summary = " ".join(str(p) for p in parts)
    if "reason" in d:
        expl += f" Reason {d['reason_code']} ({d['reason']})."
    if "status" in d:
        expl += f" Status {d['status_code']} ({d['status']})."
    d["undecoded_attrs"] = [
        t
        for t in a.types()
        if t
        not in (
            C.NL80211_ATTR_IFINDEX,
            C.NL80211_ATTR_IFNAME,
            C.NL80211_ATTR_WIPHY,
            C.NL80211_ATTR_MAC,
            C.NL80211_ATTR_IFTYPE,
            C.NL80211_ATTR_WIPHY_FREQ,
            C.NL80211_ATTR_CHANNEL_WIDTH,
            C.NL80211_ATTR_REASON_CODE,
            C.NL80211_ATTR_STATUS_CODE,
            C.NL80211_ATTR_TIMED_OUT,
            C.NL80211_ATTR_MLO_LINK_ID,
            C.NL80211_ATTR_MLO_LINKS,
            C.NL80211_ATTR_CQM,
            C.NL80211_ATTR_FRAME,
            C.NL80211_ATTR_REG_ALPHA2,
            C.NL80211_ATTR_DISCONNECTED_BY_AP,
        )
    ][:40]
    return f"nl80211.{cmd.lower()}", cat, sev, summary, expl, d
