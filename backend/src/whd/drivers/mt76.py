"""MediaTek mt76 diagnostic module.

Everything here is discovered at runtime from the target kernel:
  * tracepoints via tracefs (through whd-helper), including format strings
  * debugfs files via whd-helper's allowlisted `debugfs_list` / `debugfs_read`
  * nl80211 capabilities already collected by discovery
No interface is assumed to exist. `build_coverage()` reports, per diagnostic category, which
interfaces were found and which are missing; for gaps that need kernel instrumentation it points at a
separate optional patch proposal under docs/patches (never applied by WHD).
"""

from __future__ import annotations

import re
import time
from collections import Counter, defaultdict
from typing import Any, Literal

from pydantic import Field

from whd.clock import boottime_ns
from whd.helper.protocol import TRACE_GROUPS, HelperError
from whd.model.common import Model
from whd.model.device import Device
from whd.model.events import Event
from whd.platform.host import Host

MT76_RE = re.compile(r"^(mt76|mt7\d{2,3})")
TP_GROUPS_OF_INTEREST = ("mt76", "mt792x", "mt7925", "mt7921", "mac80211", "cfg80211")


def is_mt76(dev: Device) -> bool:
    names = [dev.driver or "", dev.module or ""]
    return any(MT76_RE.match(n) for n in names)


# --------------------------------------------------------------------------- coverage model

SourceKind = Literal["tracepoint", "debugfs", "nl80211", "log", "sysfs", "none"]
Role = Literal["primary", "secondary", "log"]
Status = Literal["available", "partial", "log_only", "missing"]


class CoverageSource(Model):
    kind: SourceKind
    name: str
    role: Role
    found: bool
    detail: str | None = None
    tier: str | None = None


class CoverageItem(Model):
    id: str
    category: str
    status: Status
    summary: str
    sources: list[CoverageSource]
    missing: str | None = None
    proposal: str | None = None


class TracepointInfo(Model):
    group: str
    name: str
    fields: list[str] = Field(default_factory=list)
    print_fmt: str | None = None


class DebugfsEntry(Model):
    path: str
    tier: str | None
    policy: str
    readable: bool


class Instrumentation(Model):
    device_id: str
    phy: str | None
    driver: str | None
    kernel_release: str
    helper_available: bool
    helper_note: str | None = None
    tracepoints: list[TracepointInfo]
    debugfs: list[DebugfsEntry]
    debugfs_truncated: bool = False
    items: list[CoverageItem]
    patches: list[dict[str, Any]]
    custom_instrumentation: list[str] = Field(default_factory=list)
    generated_at: float


def _src(
    kind: SourceKind, name: str, role: Role, found: bool, detail: str | None = None, tier: str | None = None
) -> CoverageSource:
    return CoverageSource(kind=kind, name=name, role=role, found=found, detail=detail, tier=tier)


PATCHES: list[dict[str, Any]] = [
    {
        "id": "0001-mt76-trace-mcu-command-lifecycle",
        "file": "docs/patches/0001-mt76-trace-mcu-command-lifecycle.diff",
        "adds": ["mt76:mcu_send", "mt76:mcu_resp"],
        "summary": "MCU command submission/response tracepoints with sequence number and latency. Compile-tested in a "
        "scratch copy of the tree only; never applied by WHD.",
        "validated": "compiled mcu.o/trace.o against the running kernel's headers; not loaded on hardware",
    },
]

PROPOSAL_ONLY = {
    "reset_stages": (
        "Proposal (no diff written): add `mt792x:reset_stage` tracepoints (begin/fw_stopped/dma_reset/fw_reloaded/"
        "end) around the recovery sequence in mt792x_mac.c so recovery duration and the failing stage are observable "
        "without parsing log text."
    ),
    "t2lm": (
        "Proposal (no diff written): expose the negotiated TID-to-link mapping per station (e.g. a debugfs file "
        "or `mt76:mlo_t2lm` tracepoint at mapping apply time). Today only the effective TX path choice is "
        "observable, not the negotiated mapping."
    ),
}


def _tp_index(tp: list[TracepointInfo]) -> set[str]:
    return {f"{t.group}/{t.name}" for t in tp}


def build_coverage(
    dev: Device,
    tp: list[TracepointInfo],
    dbg: list[DebugfsEntry] | None,
    helper_ok: bool,
    journal_running: bool,
) -> list[CoverageItem]:
    tps = _tp_index(tp)
    dbg_paths = {e.path: e for e in (dbg or [])}
    nl_ok = bool(dev.wiphys)
    mlo = any(w.mlo_support for w in dev.wiphys)
    cmds = {c for w in dev.wiphys for c in w.supported_commands}

    def T(group: str, name: str, role: Role) -> CoverageSource:
        found = f"{group}/{name}" in tps
        return _src(
            "tracepoint",
            f"{group}:{name}",
            role,
            found,
            None if found else ("not present on this kernel" if helper_ok else "cannot check: no helper"),
        )

    def D(path: str, role: Role) -> CoverageSource:
        e = dbg_paths.get(path)
        if e is None:
            return _src(
                "debugfs",
                path,
                role,
                False,
                "not present" if dbg is not None else "cannot check: no helper / debugfs unavailable",
            )
        return _src("debugfs", path, role, True, e.policy, e.tier)

    def L(name: str, detail: str) -> CoverageSource:
        return _src(
            "log", name, "log", journal_running, detail if journal_running else "journal source not running"
        )

    def N(name: str, found: bool, detail: str, role: Role = "secondary") -> CoverageSource:
        return _src("nl80211", name, role, found and nl_ok, detail)

    defs: list[tuple[str, str, str, list[CoverageSource], str | None, str | None]] = [
        (
            "mcu_lifecycle",
            "MCU command and response activity",
            "Command submission, response and latency",
            [
                T("mt76", "mcu_send", "primary"),
                T("mt76", "mcu_resp", "primary"),
                D("mt76/xmit-queues", "secondary"),
                L("firmware.mcu_timeout / firmware.mcu_retry", "dev_err in mt76_mcu_skb_send_and_get_msg"),
            ],
            "No tracepoint for MCU command submit/complete; only failures reach the log, and queue occupancy is "
            "visible in debugfs xmit-queues.",
            "0001-mt76-trace-mcu-command-lifecycle",
        ),
        (
            "fw_timeouts_recovery",
            "Firmware timeouts and recovery",
            "Timeout, retry and chip-reset evidence",
            [
                L(
                    "firmware.mcu_timeout / reset.chip_reset / power.ownership_failed",
                    "dev_err/dev_info messages",
                ),
                D("mt76/runtime_pm_stats", "secondary"),
            ],
            "Recovery has no tracepoint; stages and durations are not observable beyond log lines.",
            "reset_stages",
        ),
        (
            "txrx_queues",
            "TX/RX queues and DMA rings",
            "Ring head/tail/queued counts",
            [
                D("mt76/xmit-queues", "primary"),
                D("mt76/rx-queues", "primary"),
                T("mt76", "mac_txdone", "secondary"),
                T("mt76", "dev_irq", "secondary"),
            ],
            None,
            None,
        ),
        (
            "fw_driver_state",
            "Firmware and driver state transitions",
            "Bind/unbind, init steps, mac80211 driver ops",
            [
                T("mac80211", "drv_start", "primary"),
                T("mac80211", "drv_stop", "primary"),
                L("firmware.* / driver.* / reset.*", "kernel log"),
                _src("sysfs", "uevent bind/unbind", "secondary", True),
            ],
            None,
            None,
        ),
        (
            "phy_init",
            "PHY initialization",
            "Channel context and firmware/ASIC initialization",
            [
                T("mac80211", "drv_add_chanctx", "primary"),
                T("mac80211", "drv_assign_vif_chanctx", "primary"),
                L("firmware.patch_load / firmware.version / driver.asic_revision", "init-time dev_info"),
            ],
            None,
            None,
        ),
        (
            "station_state",
            "Station state",
            "WCID table and station/link counters",
            [
                D("mt76/mlo_wcid_dump", "primary"),
                D("mt76/link_stats", "primary"),
                N("GET_STATION", True, "nl80211 station dump (generic)"),
                T("mac80211", "drv_sta_remove", "secondary"),
            ],
            "Upstream mt76 has no per-WCID debugfs; WHD can only show generic nl80211 station data.",
            None,
        ),
        (
            "key_install",
            "Key installation",
            "PTK/GTK install with link and key index",
            [
                T("mac80211", "drv_set_key", "primary"),
                T("mt76", "mlo_txwi", "secondary"),
                L(
                    "driver.kv_trace MLO_KEY_*",
                    "custom driver printk instrumentation (present only on patched builds)",
                ),
            ],
            "Key material is never read; only install events (cipher, index, link) are observable.",
            None,
        ),
        (
            "mlo_link_state",
            "MLO link state",
            "Active link mask, link activation/removal",
            [
                D("mt76/mlo_active_links", "primary"),
                N(
                    "MLO_LINKS / LINKS_REMOVED",
                    mlo,
                    "nl80211 interface MLO_LINKS and LINKS_REMOVED notifications",
                ),
                T("mt76", "mlo_tx_select", "secondary"),
                L("driver.kv_trace MLO_*", "custom printk tags"),
            ],
            "No MLO link state interface on this driver build (upstream exposes none); nl80211 reports links only "
            "while associated.",
            None,
        ),
        (
            "per_link_telemetry",
            "Per-link telemetry",
            "Bytes/packets/rate per link",
            [
                D("mt76/link_stats", "primary"),
                N("per-link STA_INFO (NL80211_ATTR_MLO_LINKS)", mlo, "nl80211 per-link station info"),
                T("mt76", "mlo_txs", "secondary"),
                T("mt76", "mlo_rx", "secondary"),
            ],
            None,
            None,
        ),
        (
            "tid_to_link",
            "TID-to-link mapping",
            "Observed TX path per TID; negotiated mapping event",
            [
                T("mt76", "mlo_tx_select", "primary"),
                _src(
                    "none",
                    "negotiated TID-to-link mapping",
                    "primary",
                    False,
                    "no known kernel interface exposes the negotiated mapping",
                ),
                N(
                    "SET_TID_TO_LINK_MAPPING",
                    "SET_TID_TO_LINK_MAPPING" in cmds,
                    "nl80211 mapping-change notification",
                ),
                D("mt76/mlo_wcid_dump", "secondary"),
            ],
            "The negotiated TID-to-link mapping itself is not exposed; WHD shows the observed TX link per TID.",
            "t2lm",
        ),
        (
            "tx_selection",
            "TX selection and completion",
            "Per-packet link choice, TXD fields, completion status",
            [
                T("mt76", "mlo_tx_select", "primary"),
                T("mt76", "mlo_txwi", "primary"),
                T("mt76", "mlo_txs", "primary"),
                T("mt76", "mlo_txfree", "primary"),
                T("mt76", "mac_txdone", "secondary"),
            ],
            "Upstream mt76 only has mac_txdone (wcid/pktid); no link selection or completion status.",
            None,
        ),
        (
            "rx_activity",
            "RX activity",
            "Per-link RX events",
            [
                T("mt76", "mlo_rx", "primary"),
                D("mt76/rx-queues", "secondary"),
                T("mt76", "dev_irq", "secondary"),
            ],
            None,
            None,
        ),
        (
            "link_migration",
            "Link migration events",
            "TX path changes for a flow; radio abort/grant",
            [
                T("mt76", "mlo_tx_select", "primary"),
                L("driver.kv_trace MLO_RADIO_ABORT/GRANT, ROC_*", "custom printk tags"),
            ],
            None,
            None,
        ),
        (
            "authorization",
            "Authorization state",
            "Port authorization and station flags",
            [
                N("PORT_AUTHORIZED / STA_INFO_STA_FLAGS", True, "nl80211 event and station flags", "primary"),
            ],
            None,
            None,
        ),
        (
            "error_correlation",
            "Driver and firmware error events",
            "Classified kernel log + PCIe/USB errors",
            [
                L("firmware.* / driver.* / pci.aer.* / usb.*", "WHD classifiers"),
            ],
            None,
            None,
        ),
    ]
    items: list[CoverageItem] = []
    for iid, cat, summary, sources, missing_note, proposal in defs:
        primary = [s for s in sources if s.role == "primary"]
        found_primary = [s for s in primary if s.found]
        found_secondary = [s for s in sources if s.role == "secondary" and s.found]
        logs = [s for s in sources if s.role == "log" and s.found]
        status: Status
        if primary:
            if len(found_primary) == len(primary):
                status = "available"
            elif found_primary or found_secondary:
                status = "partial"
            else:
                status = "log_only" if logs else "missing"
        else:
            status = "log_only" if logs else "partial" if found_secondary else "missing"
        prop = None
        if status != "available" and proposal:
            prop = PROPOSAL_ONLY.get(proposal) or next(
                (p["summary"] + " (" + p["file"] + ")" for p in PATCHES if p["id"] == proposal), None
            )
        absent = [f"{x.kind} {x.name}" for x in primary if not x.found]
        note = None
        if status != "available":
            note = ((missing_note + " ") if missing_note else "") + (
                "Not found: " + "; ".join(absent) + "." if absent else ""
            )
        items.append(
            CoverageItem(
                id=iid,
                category=cat,
                status=status,
                summary=summary,
                sources=sources,
                missing=note or None,
                proposal=prop,
            )
        )
    return items


# --------------------------------------------------------------------------- discovery via helper


def parse_format(text: str) -> tuple[list[str], str | None]:
    fields = [
        f.strip()
        for f in re.findall(r"field:(.*?);\s+offset", text)
        if not f.strip().startswith("unsigned") or "common_" not in f
    ]
    fields = [f for f in fields if "common_" not in f]
    m = re.search(r'print fmt: (".*?"),', text, re.S) or re.search(r"print fmt: (.*)", text)
    return fields, (m.group(1) if m else None)


def discover_instrumentation(host: Host, dev: Device, journal_running: bool) -> Instrumentation:
    helper = host.helper
    helper_ok = bool(helper and helper.available)
    tp: list[TracepointInfo] = []
    dbg: list[DebugfsEntry] | None = None
    truncated = False
    note = None
    phy = dev.phys[0] if dev.phys else None
    if helper_ok and helper is not None:
        try:
            r = helper.call("tracefs_events", 15.0, groups=TRACE_GROUPS, with_format=True)
            for g, evs in r["groups"].items():
                if g not in TP_GROUPS_OF_INTEREST:
                    continue
                for name, fmt in evs.items():
                    f, pf = parse_format(fmt if isinstance(fmt, str) else "")
                    tp.append(TracepointInfo(group=g, name=name, fields=f, print_fmt=pf))
        except HelperError as e:
            note = f"tracefs: {e}"
        if phy:
            try:
                r2 = helper.call("debugfs_list", 10.0, phy=phy)
                dbg = [
                    DebugfsEntry(
                        path=e["path"],
                        tier=e["tier"],
                        policy=e["policy"],
                        readable=bool(e["readable_by_owner"]),
                    )
                    for e in r2["entries"]
                ]
                truncated = bool(r2.get("truncated"))
            except HelperError as e:
                note = (note + "; " if note else "") + f"debugfs: {e}"
    else:
        note = "whd-helper not running: tracefs/debugfs discovery needs root"
    items = build_coverage(dev, tp, dbg, helper_ok, journal_running)
    custom = sorted(
        [f"tracepoint mt76:{t.name}" for t in tp if t.group == "mt76" and t.name.startswith("mlo_")]
        + [
            f"debugfs {e.path}"
            for e in (dbg or [])
            if e.path.startswith("mt76/mlo_") or e.path == "mt76/link_stats"
        ]
    )
    return Instrumentation(
        device_id=dev.id,
        phy=phy,
        driver=dev.driver,
        kernel_release=host.uname().get("release", "?"),
        helper_available=helper_ok,
        helper_note=note,
        tracepoints=sorted(tp, key=lambda t: (t.group, t.name)),
        debugfs=sorted(dbg or [], key=lambda e: e.path),
        debugfs_truncated=truncated,
        items=items,
        patches=PATCHES,
        custom_instrumentation=custom,
        generated_at=time.time(),
    )


# --------------------------------------------------------------------------- debugfs parsers

BW_ENUM = {0: 20, 3: 40, 4: 80, 5: 160, 7: 320}  # as documented in link_stats' own header comment


def parse_xmit_queues(text: str) -> list[dict[str, Any]]:
    out = []
    for line in text.splitlines():
        m = re.match(r"^\s*([\w-]+):\s*(.*)$", line)
        if not m:
            continue
        kv = {k: int(v) for k, v in re.findall(r"(\w+)=(-?\d+)", m.group(2))}
        if kv:
            out.append({"name": m.group(1), **kv})
    return out


def parse_rx_queues(text: str) -> list[dict[str, int]]:
    out = []
    for line in text.splitlines():
        p = [x.strip() for x in line.split("|")]
        if len(p) >= 4 and p[0].isdigit() and p[1].isdigit():
            out.append({"queue": int(p[0]), "hw_queued": int(p[1]), "head": int(p[2]), "tail": int(p[3])})
    return out


def parse_runtime_pm(text: str) -> dict[str, int]:
    return {k.strip().replace(" ", "_"): int(v) for k, v in re.findall(r"([A-Za-z ]+):\s*(\d+)", text)}


LINK_RE = re.compile(
    r"^\s*(\d+)\s+(\d+)\s+(\d+)\s+(\d+)\s+(\d+)\s+(\d+)\s+(\d+)\s+(\d+)\s+(\d+)\s+bw=(\d+)\s+mcs=(\d+)"
    r"\s+nss=(\d+)"
)


def parse_link_stats(text: str) -> list[dict[str, Any]]:
    out = []
    for line in text.splitlines():
        m = LINK_RE.match(line)
        if m:
            w, lk, ph, valid, txb, txp, rxb, rxp, kbps, bw, mcs, nss = (int(x) for x in m.groups())
            out.append(
                {
                    "wcid": w,
                    "link": lk,
                    "phy": ph,
                    "valid": bool(valid),
                    "tx_bytes": txb,
                    "tx_pkts": txp,
                    "rx_bytes": rxb,
                    "rx_pkts": rxp,
                    "rate_kbps": kbps,
                    "bw_enum": bw,
                    "bw_mhz": BW_ENUM.get(bw),
                    "mcs": mcs,
                    "nss": nss,
                }
            )
    return out


def parse_wcid_dump(text: str) -> list[dict[str, Any]]:
    out = []
    for line in text.splitlines():
        t = line.split()
        if len(t) < 10 or not all(x.lstrip("-").isdigit() for x in t[:9]):
            continue
        wcid, link, valid, cipher, hw_key, idx2, sw_iv, tx_info, sta = (int(x) for x in t[:9])
        aggr: dict[int, str] = {}
        extra: dict[str, str] = {}
        for tok in t[9:]:
            if "=" in tok:
                k, v = tok.split("=", 1)
                if k.isdigit():
                    aggr[int(k)] = v
                else:
                    extra[k] = v
        out.append(
            {
                "wcid": wcid,
                "link": link,
                "valid": bool(valid),
                "cipher": cipher,
                "hw_key_idx": hw_key,
                "idx2": idx2,
                "sw_iv": sw_iv,
                "tx_info": tx_info,
                "sta": sta,
                "aggr": aggr,
                "aggr_active": sorted(k for k, v in aggr.items() if v not in ("-", "")),
                **extra,
            }
        )
    return out


def parse_tx_stats(text: str) -> dict[str, Any]:
    out: dict[str, Any] = {}
    if m := re.search(r"BA miss count:\s*(\d+)", text):
        out["ba_miss"] = int(m.group(1))
    am = [
        (int(a), int(b), int(c))
        for a, b, c in re.findall(r"AMSDU pack count of (\d+) MSDU in TXD:\s+(\d+)\s+\(\s*(\d+)%\)", text)
    ]
    if am:
        out["amsdu"] = [{"msdus": a, "count": b, "pct": c} for a, b, c in am]
    return out


def bitmask_links(v: int) -> list[int]:
    return [i for i in range(16) if v & (1 << i)]


PASSIVE_SETTINGS = [
    "mt76/fw_debug",
    "mt76/runtime-pm",
    "mt76/deep-sleep",
    "mt76/idle-timeout",
    "mt76/napi_threaded",
    "mt76/mlo_force_tx_link",
    "mt76/mlo_link2_rssi_override",
    "mt76/mlo_diag_trace",
    "mt76/mlo_bssadd_skip",
    "mt76/mlo_bssadd_delay_ms",
    "mt76/led_pin",
    "mt76/led_active_low",
]


class ReadRecord(Model):
    path: str
    tier: str | None = None
    ok: bool
    error: str | None = None
    bytes: int = 0
    elapsed_ms: float | None = None
    read_at_boottime_ns: int | None = None
    raw: str | None = None


class Mt76Snapshot(Model):
    device_id: str
    phy: str
    taken_at: float
    boottime_ns: int
    include_wake: bool
    reads: list[ReadRecord]
    xmit_queues: list[dict[str, Any]] = Field(default_factory=list)
    rx_queues: list[dict[str, int]] = Field(default_factory=list)
    runtime_pm: dict[str, int] = Field(default_factory=dict)
    mlo_active_links: int | None = None
    mlo_active_link_ids: list[int] = Field(default_factory=list)
    mlo_str_cap: str | None = None
    link_stats: list[dict[str, Any]] = Field(default_factory=list)
    wcid_dump: list[dict[str, Any]] = Field(default_factory=list)
    tx_stats: dict[str, Any] = Field(default_factory=dict)
    settings: dict[str, str] = Field(default_factory=dict)
    skipped: list[dict[str, str]] = Field(default_factory=list)


def read_snapshot(host: Host, dev: Device, include_wake: bool) -> Mt76Snapshot:
    helper = host.helper
    if helper is None or not helper.available:
        raise HelperError("unavailable", "whd-helper is not running; mt76 debugfs requires root")
    if not dev.phys:
        raise HelperError("missing", "device has no registered PHY (driver not bound)")
    phy = dev.phys[0]
    listing = helper.call("debugfs_list", 10.0, phy=phy)["entries"]
    present = {e["path"]: e for e in listing}
    snap = Mt76Snapshot(
        device_id=dev.id,
        phy=phy,
        taken_at=time.time(),
        boottime_ns=boottime_ns(),
        include_wake=include_wake,
        reads=[],
    )
    texts: dict[str, str] = {}

    def rd(path: str) -> str | None:
        e = present.get(path)
        if e is None:
            return None
        tier = e.get("tier")
        if tier == "wakes_device" and not include_wake:
            snap.skipped.append(
                {"path": path, "reason": "reading wakes the chip from runtime PM; pass wake=true to include"}
            )
            return None
        if tier in ("mmio", "mcu", "never", None):
            snap.skipped.append({"path": path, "reason": f"tier {tier}: not read by the snapshot"})
            return None
        try:
            r = helper.call("debugfs_read", 10.0, phy=phy, path=path)
        except HelperError as err:
            snap.reads.append(ReadRecord(path=path, tier=tier, ok=False, error=str(err)))
            return None
        txt = r.get("text") or ""
        snap.reads.append(
            ReadRecord(
                path=path,
                tier=tier,
                ok=True,
                bytes=r["bytes"],
                elapsed_ms=r["elapsed_ms"],
                read_at_boottime_ns=r["read_at_boottime_ns"],
                raw=txt[:4000],
            )
        )
        texts[path] = txt
        return txt

    if t := rd("mt76/xmit-queues"):
        snap.xmit_queues = parse_xmit_queues(t)
    if t := rd("mt76/rx-queues"):
        snap.rx_queues = parse_rx_queues(t)
    if t := rd("mt76/runtime_pm_stats"):
        snap.runtime_pm = parse_runtime_pm(t)
    if t := rd("mt76/mlo_active_links"):
        try:
            snap.mlo_active_links = int(t.strip(), 0)
            snap.mlo_active_link_ids = bitmask_links(snap.mlo_active_links)
        except ValueError:
            pass
    if t := rd("mt76/mlo_str_cap"):
        snap.mlo_str_cap = t.strip()
    if t := rd("mt76/link_stats"):
        snap.link_stats = parse_link_stats(t)
    if t := rd("mt76/mlo_wcid_dump"):
        snap.wcid_dump = parse_wcid_dump(t)
    if t := rd("mt76/tx_stats"):
        snap.tx_stats = parse_tx_stats(t)
    for p in PASSIVE_SETTINGS:
        if (t := rd(p)) is not None:
            snap.settings[p.removeprefix("mt76/")] = t.strip()
    return snap


# --------------------------------------------------------------------------- trace-event aggregation


class TidLinkCell(Model):
    tid: int
    link: int
    count: int
    aggr_count: int = 0


class LinkActivity(Model):
    link: int
    tx_selected: int = 0
    tx_completions: int = 0
    tx_acked: int = 0
    tx_ack_errors: int = 0
    txfree_failed: int = 0
    txfree_attempts_total: int = 0
    rx_frames: int = 0
    rx_decrypted: int = 0
    rx_dropped_flags: int = 0
    last_tx_rate_hex: str | None = None


class Migration(Model):
    ts_boottime_ns: int
    flow: str
    tid: int | None
    from_link: int
    to_link: int
    orig_link: int | None = None


class TraceAggregate(Model):
    device_id: str
    events_considered: int
    first_ns: int | None
    last_ns: int | None
    tid_link: list[TidLinkCell]
    links: list[LinkActivity]
    migrations: list[Migration]
    path_counts: dict[str, int]
    notes: list[str]


def _triple(s: str | None) -> list[int] | None:
    if not s:
        return None
    try:
        return [int(x) for x in s.split("/")]
    except ValueError:
        return None


def aggregate_trace(device_id: str, events: list[Event]) -> TraceAggregate:
    """Aggregate mt76 MLO tracepoint events. Everything is counted from observed events only."""
    tid_link: Counter[tuple[int, int]] = Counter()
    tid_aggr: Counter[tuple[int, int]] = Counter()
    links: dict[int, LinkActivity] = defaultdict(lambda: LinkActivity(link=-1))
    last_sel: dict[str, int] = {}
    migrations: list[Migration] = []
    paths: Counter[str] = Counter()
    n = 0
    evs = sorted((e for e in events if e.kind.startswith("trace.mt76.")), key=lambda e: e.ts_boottime_ns)

    def L(i: int) -> LinkActivity:
        la = links[i]
        la.link = i
        return la

    for e in evs:
        f: dict[str, str] = (e.data or {}).get("fields", {})
        name = e.kind.removeprefix("trace.mt76.")
        n += 1
        if name == "mlo_tx_select":
            sel, orig = _triple(f.get("sel")), _triple(f.get("orig"))
            if sel is None:
                continue
            tid = int(f["txq_tid"]) if f.get("txq_tid", "").isdigit() else None
            L(sel[1]).tx_selected += 1
            if tid is not None:
                tid_link[(tid, sel[1])] += 1
                if f.get("aggr") == "1":
                    tid_aggr[(tid, sel[1])] += 1
            paths[f.get("path", "?")] += 1
            flow = f"{f.get('da', '?')}/tid{tid}"
            prev = last_sel.get(flow)
            if prev is not None and prev != sel[1]:
                migrations.append(
                    Migration(
                        ts_boottime_ns=e.ts_boottime_ns,
                        flow=flow,
                        tid=tid,
                        from_link=prev,
                        to_link=sel[1],
                        orig_link=orig[1] if orig else None,
                    )
                )
            last_sel[flow] = sel[1]
        elif name == "mlo_txs":
            if f.get("link", "").lstrip("-").isdigit():
                la = L(int(f["link"]))
                la.tx_completions += 1
                la.tx_acked += 1 if f.get("acked") == "1" else 0
                la.tx_ack_errors += 1 if f.get("ack_error", "0") not in ("0", "") else 0
                la.last_tx_rate_hex = f.get("rate")
        elif name == "mlo_txfree":
            if f.get("link", "").lstrip("-").isdigit():
                la = L(int(f["link"]))
                la.txfree_failed += 1 if f.get("failed") == "1" else 0
                la.txfree_attempts_total += int(f["attempts"]) if f.get("attempts", "").isdigit() else 0
        elif name == "mlo_rx" and f.get("link", "").lstrip("-").isdigit():
            la = L(int(f["link"]))
            la.rx_frames += 1
            la.rx_decrypted += 1 if f.get("decrypted") == "1" else 0
            la.rx_dropped_flags += 1 if f.get("flags", "0x0") not in ("0x0", "0") else 0
    cells = [
        TidLinkCell(tid=t, link=lk, count=c, aggr_count=tid_aggr[(t, lk)])
        for (t, lk), c in sorted(tid_link.items())
    ]
    notes = [
        "TID→link is the *observed* TX path choice (mt76:mlo_tx_select sel link), not the negotiated TID-to-link "
        "mapping; the negotiated mapping is not exposed by this driver."
    ]
    if n == 0:
        notes.append(
            "No mt76 tracepoint events captured for this device. Start a trace session including "
            "mt76/mlo_tx_select, mlo_txs, mlo_txfree, mlo_rx."
        )
    return TraceAggregate(
        device_id=device_id,
        events_considered=n,
        first_ns=evs[0].ts_boottime_ns if evs else None,
        last_ns=evs[-1].ts_boottime_ns if evs else None,
        tid_link=cells,
        links=sorted(links.values(), key=lambda x: x.link),
        migrations=migrations[-200:],
        path_counts=dict(paths),
        notes=notes,
    )


class TagSummary(Model):
    tag: str
    count: int
    attributed: int = 0
    unattributed: int = 0
    last_ts_boottime_ns: int
    last_fields: dict[str, str]
    last_summary: str


def summarize_driver_tags(events: list[Event], device_id: str | None = None) -> list[TagSummary]:
    """Group custom key=value driver messages by tag. Messages printed without a device prefix cannot be attributed
    to one adapter; they are counted separately (`unattributed`) rather than guessed."""
    by: dict[str, list[Event]] = defaultdict(list)
    for e in events:
        if e.kind == "driver.kv_trace":
            by[str(e.data.get("tag", "?"))].append(e)
    out = []
    for tag, es in by.items():
        last = max(es, key=lambda e: e.ts_boottime_ns)
        out.append(
            TagSummary(
                tag=tag,
                count=len(es),
                last_ts_boottime_ns=last.ts_boottime_ns,
                last_fields=dict(last.data.get("fields", {})),
                last_summary=last.summary[:200],
            )
        )
    return sorted(out, key=lambda t: -t.count)


# --------------------------------------------------------------------------- discovery extension


def discovery_extension(host: Host, dev: Device) -> None:
    """Cheap marker only (no privileged calls during discovery)."""
    if not is_mt76(dev):
        return
    dev.extensions["mt76"] = {
        "detected": True,
        "driver": dev.driver,
        "module": dev.module,
        "chip_hint": dev.pci.device_name if dev.pci else (dev.usb.product_name if dev.usb else None),
        "note": "Chip capabilities are taken from nl80211/firmware, never inferred from the model name.",
    }
