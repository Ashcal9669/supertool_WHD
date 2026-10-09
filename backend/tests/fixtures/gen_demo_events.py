#!/usr/bin/env python3
"""Generate SYNTHETIC demo event/telemetry streams for the fixture scenarios.

Events are produced by feeding scripted raw inputs (journal JSON, uevents, nl80211 genl payloads, rtnetlink messages,
ftrace text lines, usbmon lines, sysfs poll deltas) through the same handlers the live sources use, so demo mode
exercises the real parsing/classification code. The *content* is invented (a scripted incident story); fixture.json
records `events_kind: synthetic` and the UI says so.

Usage: uv run python tests/fixtures/gen_demo_events.py
"""

from __future__ import annotations

import json
import math
import random
import struct
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parents[1] / "src"))
sys.path.insert(0, str(HERE.parent))

from whd.discovery import Discovery  # noqa: E402
from whd.events.attrib import DeviceIndex  # noqa: E402
from whd.events.bus import EventBus  # noqa: E402
from whd.events.sources import (  # noqa: E402
    Ctx,
    JournalSource,
    Nl80211Source,
    RtnlSource,
    SysfsPoller,
    UeventSource,
    UsbmonSource,
    trace_event_from_line,
)
from whd.model.events import Event, TelemetrySample  # noqa: E402
from whd.platform.host import FixtureHost  # noqa: E402
from whd.platform.kconsts import if_link as L  # noqa: E402
from whd.platform.kconsts import nl80211 as C  # noqa: E402
from whd.platform.kconsts import rtnetlink as RT  # noqa: E402
from whd.platform.netlink import GENL_HDR, nla, nla_str, nla_u32  # noqa: E402

SR = HERE / "sysroots"
BASE_NS = 5_000 * 10**9  # arbitrary boot-relative origin; replay rebases to "now"
PEER = "02:00:5e:10:00:09"
PEER_B = bytes.fromhex("02005e100009")


class Gen:
    def __init__(self, scenario: str) -> None:
        self.scenario = scenario
        self.host = FixtureHost(SR / scenario)
        res = Discovery(self.host).run()
        self.dev = res.devices[0]
        self.index = DeviceIndex()
        self.index.update(res.devices)

        class _Inv:
            snapshot = type("S", (), {"devices": res.devices})()

        self.ctx = Ctx(
            bus=EventBus(store=None),
            index=self.index,
            host=self.host,
            inventory=_Inv(),  # type: ignore[arg-type]
            request_rescan=lambda _r: None,
            settings=None,
        )
        self.events: list[Event] = []
        self.samples: list[TelemetrySample] = []
        self.rng = random.Random(7)
        self.journal = JournalSource(self.ctx)
        self.uev = UeventSource(self.ctx)
        self.nl = Nl80211Source(self.ctx)
        self.rt = RtnlSource(self.ctx)
        self.poller = SysfsPoller(self.ctx)
        self.usbmon = UsbmonSource(self.ctx, [2])
        self.netdev = self.dev.netdevs[0]
        self.ifindex = self.dev.netdev_info[0].ifindex or 1
        self.phy = self.dev.phys[0]
        self.groups = {
            "mac_txdone": "mt76",
            "dev_irq": "mt76",
            "mlo_tx_select": "mt76",
            "mlo_txs": "mt76",
            "mlo_txfree": "mt76",
            "mlo_rx": "mt76",
            "mcu_send": "mt76",
            "mcu_resp": "mt76",
            "mlo_txwi": "mt76",
        }

    def _add(self, t: float, ev: Event | None) -> None:
        if ev is None:
            return
        ev.ts_boottime_ns = BASE_NS + int(t * 1e9)
        ev.ts_wall = 0.0
        ev.demo = True
        self.events.append(ev)

    # ---- raw input injectors (each goes through the production handler)
    def kernel(self, t: float, msg: str, prio: int = 6, kdev: str | None = None) -> None:
        j = {
            "MESSAGE": msg,
            "PRIORITY": str(prio),
            "_SOURCE_MONOTONIC_TIMESTAMP": str(int((BASE_NS / 1e3) + t * 1e6)),
            "_BOOT_ID": "demo0000",
        }
        if kdev:
            j["_KERNEL_DEVICE"] = kdev
        self._add(t, self.journal.handle(j))

    def uevent(self, t: float, action: str, devpath: str, sub: str, **kv: str) -> None:
        raw = f"{action}@{devpath}\0ACTION={action}\0DEVPATH={devpath}\0SUBSYSTEM={sub}\0" + "".join(
            f"{k}={v}\0" for k, v in kv.items()
        )
        u = self.uev.parse(raw.encode())
        assert u is not None
        self._add(t, self.uev.handle(u))

    def nl80211(self, t: float, cmd: int, *attrs: bytes) -> None:
        payload = GENL_HDR.pack(cmd, 1, 0) + nla_u32(C.NL80211_ATTR_IFINDEX, self.ifindex) + b"".join(attrs)
        self._add(t, self.nl.handle(payload))

    def rtnl(self, t: float, up: bool, oper: int) -> None:
        flags = 0x1003 | (0x10040 if up else 0)
        msg = (
            struct.pack("=BxHiII", 0, 1, self.ifindex, flags, 0)
            + nla_str(L.IFLA_IFNAME, self.netdev)
            + nla(L.IFLA_OPERSTATE, bytes([oper]))
        )
        self._add(t, self.rt.handle(RT.RTM_NEWLINK, msg))

    def poll(self, t: float, old: dict, new: dict) -> None:  # type: ignore[type-arg]
        for e in self.poller.diff(self.dev.id, self.dev.sysfs_path, old, new):
            self._add(t, e)

    def trace(self, t: float, name: str, body: str) -> None:
        line = f"   kworker/u32:2-412     [005] d..1. {(BASE_NS / 1e9) + t:.9f}: {name}: {self.phy} {body}"
        self._add(t, trace_event_from_line(self.index, line, self.groups, "boot", 0))

    def urb(self, t: float, line: str) -> None:
        self._add(t, self.usbmon.handle_line(line))

    # ---- telemetry
    def sample(self, t: float, series: str, **values: float | int | None) -> None:
        self.samples.append(
            TelemetrySample(
                ts_boottime_ns=BASE_NS + int(t * 1e9),
                ts_wall=0.0,
                device_id=self.dev.id,
                series=series,
                values=values,
                demo=True,
            )
        )

    def write(self, period_s: float) -> None:
        d = SR / self.scenario
        self.events.sort(key=lambda e: e.ts_boottime_ns)
        (d / "events.jsonl").write_text("\n".join(e.model_dump_json() for e in self.events) + "\n")
        self.samples.sort(key=lambda s: s.ts_boottime_ns)
        (d / "telemetry.jsonl").write_text("\n".join(s.model_dump_json() for s in self.samples) + "\n")
        meta = json.loads((d / "fixture.json").read_text())
        meta["events_kind"] = "synthetic"
        meta["events_description"] = (
            "SYNTHETIC scripted incident timeline generated by "
            "tests/fixtures/gen_demo_events.py; not measured on hardware"
        )
        meta["demo_loop_seconds"] = period_s
        (d / "fixture.json").write_text(json.dumps(meta, indent=1))
        print(f"{self.scenario}: {len(self.events)} events, {len(self.samples)} samples, loop {period_s}s")


def sel(tid: int, orig: str, s: str, aggr: int = 1, da: str = PEER) -> str:
    return (
        f"path=1 hash={0x1000 + tid:08x} l4=1 sw=0 proto=0x0800 da={da} l3=0x0800 l4p=6 arp_op=0 icmp=0/0 id=0 "
        f"seq=0 pri={tid} txq_tid={tid} qid={tid // 2} aggr={aggr} orig={orig} sel={s} sta=1 vif=1 info_link=1"
    )


# =============================================================================== PCIe MLO incident story


def pcie_story() -> Gen:
    g = Gen("mt7927-pcie-host")
    bdf = "0000:07:00.0"
    kdev = f"+pci:{bdf}"
    drv = "mt7925e_git"
    pre = f"{drv} {bdf}: "
    dp = g.dev.sysfs_path
    wcid_a, wcid_b = 18, 19

    def bring_up(t0: float) -> float:
        g.kernel(t0, pre + "ASIC revision: 7927", kdev=kdev)
        g.kernel(t0 + 0.2, pre + "HW/SW Version: 0x8a108a10, Build Time: 20260414134255", kdev=kdev)
        g.kernel(
            t0 + 0.3,
            pre + "Loading firmware patch: mediatek/mt7927/WIFI_MT6639_PATCH_MCU_2_1_hdr.bin",
            kdev=kdev,
        )
        g.kernel(t0 + 0.9, pre + "WM Firmware Version: ____000000, Build Time: 20260414134255", kdev=kdev)
        g.kernel(t0 + 1.1, pre + "Firmware init done", prio=5, kdev=kdev)
        return t0 + 1.1

    def associate(t0: float, links_after: tuple[int, int] = (0, 3)) -> float:
        g.nl80211(t0, C.NL80211_CMD_TRIGGER_SCAN)
        g.nl80211(t0 + 1.4, C.NL80211_CMD_NEW_SCAN_RESULTS)
        g.kernel(t0 + 1.6, f"{g.netdev}: authenticate with {PEER} (local address=02:00:5e:10:00:01)")
        g.kernel(t0 + 1.62, f"{g.netdev}: send auth to {PEER} (try 1/3)")
        g.kernel(t0 + 1.68, f"{g.netdev}: authenticated")
        g.kernel(t0 + 1.7, f"{g.netdev}: associate with {PEER} (try 1/3)")
        g.kernel(t0 + 1.78, f"{g.netdev}: RX AssocResp from {PEER} (capab=0x1511 status=0 aid=3)")
        g.kernel(t0 + 1.8, f"{g.netdev}: associated", prio=5)
        g.nl80211(
            t0 + 1.82,
            C.NL80211_CMD_CONNECT,
            nla(C.NL80211_ATTR_MAC, PEER_B),
            nla(C.NL80211_ATTR_STATUS_CODE, struct.pack("=H", 0)),
        )
        g.kernel(t0 + 1.9, "MLO_KEY_INSTALL: wcid=18 link=1 cipher=0xfac04 keyidx=0 pairwise=1")
        g.kernel(t0 + 1.92, "MLO_KEY_INSTALL: wcid=19 link=2 cipher=0xfac04 keyidx=0 pairwise=1")
        g.kernel(
            t0 + 2.0,
            "MLO_RADIO_GRANT: kind=mlo token=3 bss_idx=0 link_id=1 dbdcband=0x1 band_idx=0 held_links=0x1",
        )
        g.kernel(
            t0 + 2.05,
            "MLO_RADIO_GRANT: kind=mlo token=4 bss_idx=0 link_id=2 dbdcband=0x2 band_idx=1 held_links=0x3",
        )
        g.nl80211(t0 + 2.3, C.NL80211_CMD_PORT_AUTHORIZED, nla(C.NL80211_ATTR_MAC, PEER_B))
        g.rtnl(t0 + 2.35, True, 6)
        old = 0
        for lk in (1, 2):
            new = old | (1 << lk)
            g._add(t0 + 2.4 + 0.1 * lk, _mlo_event(g, old, new))
            old = new
        return t0 + 2.5

    # t=0: probe / firmware
    g.uevent(0.0, "bind", dp, "pci", DRIVER=drv)
    t = bring_up(0.2)
    g.rtnl(t + 0.2, False, 2)
    t = associate(4.0)

    # steady-state datapath t=8..46 (tracepoints) : TID0 -> link1, TID5 -> link2, with a TX path migration of TID0 at 30s
    def datapath(t: float, p_err: float = 0.0) -> None:
        for tid, link, wcid in ((0, 1, wcid_a), (5, 2, wcid_b), (6, 2, wcid_b)):
            if tid == 0 and 30 <= t < 46:
                link, wcid = 2, wcid_b
            o = f"{wcid_a}/1/0"
            s = f"{wcid}/{link}/{link - 1}"
            g.trace(t, "mlo_tx_select", sel(tid, o, s))
            err = 1 if g.rng.random() < p_err else 0
            g.trace(
                t + 0.004,
                "mlo_txs",
                f"wcid={wcid} link={link} pid=1 ack_error={err} acked={1 - err} rate=0x1a2 bw=4 txs_band={link} wcid_phy_idx={link - 1}",
            )
            if err:
                g.trace(
                    t + 0.005,
                    "mlo_txfree",
                    f"wcid={wcid} link={link} token={int(t * 100) % 900} attempts=3 status=1 failed=1",
                )
            if tid != 6:
                g.trace(
                    t + 0.006,
                    "mlo_rx",
                    f"wcid={wcid} link={link} band={link} chan={36 if link == 1 else 37} sa={PEER} da=02:00:5e:10:00:01 proto=0x0800 l3=0x0800 l4p=6 arp_op=0 icmp=0/0 id=0 seq=0 sec=4 key=0 decrypted=1 flags=0x0",
                )

    for k in range(0, 200):  # ~3 Hz sampling of the datapath
        tt = 6.0 + k * 0.3
        if tt >= 46.0:
            break
        datapath(tt, p_err=0.02 if tt < 40 else 0.12)
    # MCU command traffic (synthetic patched-kernel tracepoints) with latency
    for i in range(1, 12):
        tt = 7 + i * 3.2
        cmd = [0x00020027, 0x0002001B, 0x00020013][i % 3]
        g.trace(tt, "mcu_send", f"cmd={cmd:08x} seq={i} len=64 wait_resp=1 retry=0")
        g.trace(
            tt + 0.0012 + 0.0003 * (i % 4),
            "mcu_resp",
            f"cmd={cmd:08x} seq={i} ret=0 timeout=0 latency_us={1200 + 300 * (i % 4)}",
        )
    # a corrected PCIe error burst at t=25 (polling-detected AER counter bump)
    g.poll(
        25.5,
        {"aer_correctable": {"BadTLP": 0, "TOTAL_ERR_COR": 0}},
        {"aer_correctable": {"BadTLP": 2, "TOTAL_ERR_COR": 2}},
    )
    g.kernel(25.6, "pcieport 0000:00:02.2: AER: Corrected error message received from 0000:07:00.0", prio=4)

    # ===== incident: MCU command never answered -> retry -> timeout -> chip reset -> re-init -> reassociation
    g.trace(46.0, "mcu_send", "cmd=00020027 seq=12 len=64 wait_resp=1 retry=0")
    g.kernel(49.0, pre + "Retry message 00020027 (seq 12)", prio=3, kdev=kdev)
    g.trace(49.0, "mcu_send", "cmd=00020027 seq=12 len=64 wait_resp=1 retry=1")
    g.kernel(52.0, pre + "Message 00020027 (seq 12) timeout", prio=3, kdev=kdev)
    g.trace(52.0, "mcu_resp", "cmd=00020027 seq=12 ret=-110 timeout=1 latency_us=6000000")
    g.kernel(52.1, pre + "chip reset", prio=4, kdev=kdev)
    g._add(52.3, _mlo_event(g, 3, 0))
    g.nl80211(52.4, C.NL80211_CMD_DISCONNECT, nla(C.NL80211_ATTR_REASON_CODE, struct.pack("=H", 3)))
    g.kernel(52.45, f"{g.netdev}: deauthenticating from {PEER} by local choice (Reason: 3=DEAUTH_LEAVING)")
    g.rtnl(52.5, True, 2)
    g.poll(
        52.9,
        {"aer_correctable": {"BadTLP": 2, "TOTAL_ERR_COR": 2}},
        {"aer_correctable": {"BadTLP": 5, "TOTAL_ERR_COR": 5}},
    )
    g.poll(53.0, {"link": ("8.0 GT/s PCIe", "1")}, {"link": ("2.5 GT/s PCIe", "1")})
    g.poll(53.1, {"runtime_status": "active"}, {"runtime_status": "suspended"})
    g.poll(54.2, {"link": ("2.5 GT/s PCIe", "1")}, {"link": ("8.0 GT/s PCIe", "1")})
    g.poll(54.3, {"runtime_status": "suspended"}, {"runtime_status": "active"})
    t = bring_up(54.4)
    t = associate(58.0)
    for k in range(0, 200):
        tt = 62.0 + k * 0.3
        if tt >= 80.0:
            break
        datapath(tt, p_err=0.01)

    # ===== telemetry: 1 Hz, 0..82 s
    mac = PEER
    for s in range(0, 83):
        t = float(s)
        up = (8 <= s < 52) or s >= 62
        base = -52 + 3 * math.sin(s / 7.0) + g.rng.uniform(-1, 1)
        if 44 <= s < 52:
            base -= 6
        if up:
            g.sample(
                t,
                f"station:{g.netdev}:{mac}",
                signal_dbm=round(base),
                signal_avg_dbm=round(base - 0.5),
                chain0_dbm=round(base - 1),
                chain1_dbm=round(base + 1),
                tx_bitrate_mbps=round(2401 - (400 if 44 <= s < 52 else 0) + g.rng.uniform(-40, 40), 1),
                rx_bitrate_mbps=round(2161 + g.rng.uniform(-60, 60), 1),
                tx_mcs=11,
                tx_nss=2,
                tx_retries_per_s=round(g.rng.uniform(0, 4) + (40 if 44 <= s < 52 else 0), 1),
                tx_failed_per_s=round((8 if 46 <= s < 52 else 0) * g.rng.random(), 1),
                rx_bytes_per_s=int(18e6 + g.rng.uniform(-3e6, 3e6)),
                tx_bytes_per_s=int(2.2e6 + g.rng.uniform(-3e5, 3e5)),
                beacon_loss=0,
                rx_drop_misc_per_s=0,
                inactive_ms=int(g.rng.uniform(0, 40)),
            )
            for link, off in ((1, 0), (2, -4)):
                g.sample(
                    t,
                    f"link:{g.netdev}:{mac}:{link}",
                    signal_dbm=round(base + off),
                    tx_bitrate_mbps=round(1200 + g.rng.uniform(-30, 30), 1),
                    rx_bitrate_mbps=round(1080 + g.rng.uniform(-40, 40), 1),
                    tx_bytes_per_s=int(1.1e6 + g.rng.uniform(-1e5, 1e5)),
                    rx_bytes_per_s=int(9e6 + g.rng.uniform(-1e6, 1e6)),
                    tx_retries_per_s=round(g.rng.uniform(0, 2), 1),
                )
        g.sample(
            t,
            f"netdev:{g.netdev}",
            rx_bytes_per_s=int(18e6 if up else 0),
            tx_bytes_per_s=int(2.2e6 if up else 0),
            rx_packets_per_s=14000 if up else 0,
            tx_packets_per_s=2500 if up else 0,
            rx_errors_per_s=0,
            tx_errors_per_s=0,
        )
        if s % 5 == 1:
            g.sample(
                t,
                f"survey:{g.netdev}",
                freq_mhz=5180,
                noise_dbm=-92,
                busy_pct=round(18 + 6 * math.sin(s / 9) + (30 if 46 <= s < 52 else 0), 1),
            )
        sub = 60 if up else 0
        g.sample(
            t,
            f"mt76q:{g.phy}:xmit",
            **{
                "WFDMA0.queued": int(g.rng.uniform(0, 6)) if up else 0,
                "MCUWM.queued": 1 if 46 <= s < 52 else 0,
                "MCUFWQ.queued": 0,
                "WFDMA0.submitted": sub + int(g.rng.uniform(-5, 5)) if up else 0,
                "MCUWM.submitted": 0 if 46 <= s < 52 else (1 if s % 3 == 0 else 0),
            },
        )
        g.sample(
            t,
            f"mt76q:{g.phy}:rx",
            **{
                "rx0.queued": 1535,
                "rx1.queued": 511,
                "rx2.queued": 511,
                "rx0.advanced": int(1400 + g.rng.uniform(-100, 100)) if up else 0,
                "rx1.advanced": 3 if up else 0,
                "rx2.advanced": 0,
            },
        )
    g.write(period_s=84.0)
    return g


def _mlo_event(g: Gen, old: int, new: int) -> Event:
    from whd.drivers import mt76 as m
    from whd.events.sources import make_event

    added = sorted(set(m.bitmask_links(new)) - set(m.bitmask_links(old)))
    removed = sorted(set(m.bitmask_links(old)) - set(m.bitmask_links(new)))
    return make_event(
        ts=0,
        ts_source="poll_boottime",
        source="mt76:debugfs",
        device_id=g.dev.id,
        severity="notice",
        category="mlo",
        kind="mt76.mlo_active_links_changed",
        summary=f"MLO active links 0x{old:x} -> 0x{new:x} (+{added} -{removed})",
        explanation="debugfs mt76/mlo_active_links changed between polls (driver-reported active MLO "
        "link mask). Detected by polling; the exact instant is not known.",
        raw=f"mlo_active_links: {old:#x} -> {new:#x}",
        data={"from": old, "to": new, "added_links": added, "removed_links": removed},
    )


# =============================================================================== USB error story


def usb_story() -> Gen:
    g = Gen("mt7921u-usb")
    port = "2-1"
    drv = "mt7921u"
    peer = PEER
    g.uevent(0.0, "add", g.dev.sysfs_path, "usb", DEVTYPE="usb_device")
    g.kernel(0.1, f"usb {port}: new SuperSpeed USB device number 3 using xhci_hcd")
    g.kernel(0.4, f"usb {port}: New USB device found, idVendor=0e8d, idProduct=7961, bcdDevice= 1.00")
    g.uevent(0.9, "bind", f"{g.dev.sysfs_path}/{port}:1.0", "usb", DRIVER=drv, DEVTYPE="usb_interface")
    upre = f"{drv} {port}:1.0: "
    ukd = f"+usb:{port}:1.0"
    g.kernel(1.2, upre + "Loading firmware patch: mediatek/WIFI_MT7961_patch_mcu_1_2_hdr.bin", kdev=ukd)
    g.kernel(2.6, upre + "Firmware init done", prio=5, kdev=ukd)
    g.rtnl(3.0, True, 6)
    g.nl80211(4.0, C.NL80211_CMD_TRIGGER_SCAN)
    g.nl80211(5.2, C.NL80211_CMD_NEW_SCAN_RESULTS)
    g.kernel(5.5, f"{g.netdev}: authenticate with {peer} (local address=02:00:5e:20:00:01)")
    g.kernel(5.62, f"{g.netdev}: authenticated")
    g.kernel(5.7, f"{g.netdev}: associate with {peer} (try 1/3)")
    g.kernel(5.78, f"{g.netdev}: RX AssocResp from {peer} (capab=0x1511 status=0 aid=2)")
    g.kernel(5.8, f"{g.netdev}: associated", prio=5)
    g.nl80211(
        5.85,
        C.NL80211_CMD_CONNECT,
        nla(C.NL80211_ATTR_MAC, PEER_B),
        nla(C.NL80211_ATTR_STATUS_CODE, struct.pack("=H", 0)),
    )
    g.nl80211(6.3, C.NL80211_CMD_PORT_AUTHORIZED, nla(C.NL80211_ATTR_MAC, PEER_B))
    # steady URB flow summarized by usbmon aggregation (1 Hz samples below); incident:
    for k in range(40):
        g.urb(
            20.0 + k * 0.05,
            f"ffff8800{k:04x} {int(BASE_NS / 1e3 + (20.0 + k * 0.05) * 1e6)} C Bo:2:003:4 -71 512",
        )
    g.kernel(22.2, f"usb {port}: reset SuperSpeed USB device number 3 using xhci_hcd", prio=4)
    g.kernel(22.8, f"usb {port}: reset SuperSpeed USB device number 3 using xhci_hcd", prio=4)
    g.kernel(23.4, "xhci_hcd 0000:00:14.0: WARN: xHCI host controller not responding, assume dead", prio=3)
    g.kernel(23.6, f"usb {port}: USB disconnect, device number 3", prio=4)
    g.uevent(23.62, "unbind", f"{g.dev.sysfs_path}/{port}:1.0", "usb", DRIVER=drv, DEVTYPE="usb_interface")
    g.uevent(23.7, "remove", g.dev.sysfs_path, "usb", DEVTYPE="usb_device")
    g.rtnl(23.75, False, 2)
    g.nl80211(23.7, C.NL80211_CMD_DISCONNECT, nla(C.NL80211_ATTR_REASON_CODE, struct.pack("=H", 3)))
    g.kernel(26.0, f"usb {port}: new SuperSpeed USB device number 4 using xhci_hcd")
    g.uevent(26.1, "add", g.dev.sysfs_path, "usb", DEVTYPE="usb_device")
    g.uevent(26.6, "bind", f"{g.dev.sysfs_path}/{port}:1.0", "usb", DRIVER=drv, DEVTYPE="usb_interface")
    g.kernel(26.8, upre + "Loading firmware patch: mediatek/WIFI_MT7961_patch_mcu_1_2_hdr.bin", kdev=ukd)
    g.kernel(28.4, upre + "Firmware init done", prio=5, kdev=ukd)
    g.rtnl(28.8, True, 6)
    g.kernel(31.0, f"{g.netdev}: authenticate with {peer} (local address=02:00:5e:20:00:01)")
    g.kernel(31.12, f"{g.netdev}: authenticated")
    g.kernel(31.2, f"{g.netdev}: associate with {peer} (try 1/3)")
    g.kernel(31.28, f"{g.netdev}: RX AssocResp from {peer} (capab=0x1511 status=0 aid=2)")
    g.kernel(31.3, f"{g.netdev}: associated", prio=5)
    g.nl80211(31.35, C.NL80211_CMD_PORT_AUTHORIZED, nla(C.NL80211_ATTR_MAC, PEER_B))
    for s in range(0, 45):
        t = float(s)
        up = (6 <= s < 22) or s >= 32
        base = -51 + 2 * math.sin(s / 6.0) + g.rng.uniform(-1, 1)
        if up:
            g.sample(
                t,
                f"station:{g.netdev}:02:00:5e:20:00:02",
                signal_dbm=round(base),
                signal_avg_dbm=round(base),
                tx_bitrate_mbps=round(864.7 + g.rng.uniform(-30, 30), 1),
                rx_bitrate_mbps=round(960.7 + g.rng.uniform(-30, 30), 1),
                tx_mcs=9,
                tx_nss=2,
                tx_retries_per_s=round(g.rng.uniform(0, 5) + (30 if 16 <= s < 22 else 0), 1),
                tx_failed_per_s=round(6 * g.rng.random() if 18 <= s < 22 else 0, 1),
                rx_bytes_per_s=int(9e6 + g.rng.uniform(-1e6, 1e6)),
                tx_bytes_per_s=int(1.2e6 + g.rng.uniform(-1e5, 1e5)),
                beacon_loss=0,
                inactive_ms=int(g.rng.uniform(0, 30)),
            )
        g.sample(
            t,
            f"netdev:{g.netdev}",
            rx_bytes_per_s=int(9e6 if up else 0),
            tx_bytes_per_s=int(1.2e6 if up else 0),
        )
        err = 40 if 20 <= s < 22 else 0
        if up or 20 <= s < 24:
            g.sample(
                t,
                "usbmon",
                **{
                    "ep4o.submit": 700 + int(g.rng.uniform(-30, 30)),
                    "ep4o.complete": 700 - err,
                    "ep4o.bytes": int(1.2e6),
                    "ep4o.errors": err,
                    "ep5o.submit": 40,
                    "ep5o.complete": 40,
                    "ep5o.bytes": 8000,
                    "ep5o.errors": 0,
                    "ep4i.submit": 1100,
                    "ep4i.complete": 1100,
                    "ep4i.bytes": int(9e6),
                    "ep4i.errors": 0,
                    "ep5i.submit": 30,
                    "ep5i.complete": 30,
                    "ep5i.bytes": 4096,
                    "ep5i.errors": 0,
                },
            )
    g.write(period_s=46.0)
    return g


def main() -> int:
    pcie_story()
    usb_story()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
