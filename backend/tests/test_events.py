from __future__ import annotations

import asyncio
import struct
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from conftest import fixture_host
from whd.app import build_state, create_app
from whd.config import Settings
from whd.discovery import Discovery
from whd.events.attrib import DeviceIndex
from whd.events.bus import EventBus
from whd.events.classify import classify_kernel
from whd.events.nl80211_events import decode_event
from whd.events.sources import (
    Ctx,
    JournalSource,
    RtnlSource,
    Source,
    SysfsPoller,
    UeventSource,
    Unavailable,
    make_event,
    parse_trace_line,
)
from whd.model.events import EventFilter
from whd.platform.kconsts import if_link as L
from whd.platform.kconsts import nl80211 as C
from whd.platform.kconsts import rtnetlink as RT
from whd.platform.netlink import GENL_HDR, nla, nla_flag, nla_str, nla_u32
from whd.store.db import Store

DEV = "pci:0000:07:00.0:14c3:7927"


@pytest.fixture
def ctx(tmp_path: Path) -> Ctx:
    host = fixture_host("mt7927-pcie-host")
    devices = Discovery(host).run().devices
    idx = DeviceIndex()
    idx.update(devices)
    bus = EventBus(store=Store(tmp_path / "e.db"))

    class Inv:
        snapshot = type("S", (), {"devices": devices})()

    rescans: list[str] = []
    c = Ctx(
        bus=bus,
        index=idx,
        host=host,
        inventory=Inv(),
        request_rescan=rescans.append,  # type: ignore[arg-type]
        settings=None,
    )
    c.rescans = rescans  # type: ignore[attr-defined]
    return c


def test_classifier_rules() -> None:
    r = classify_kernel("mt7925e_git 0000:07:00.0: Message 00020027 (seq 3) timeout", 3)
    assert (r.kind, r.category, r.severity) == ("firmware.mcu_timeout", "firmware", "error")
    assert r.data["cmd"] == "00020027" and r.data["log_device"] == "0000:07:00.0"
    r = classify_kernel(
        "wlp7s0: deauthenticated from 02:00:5e:10:00:09 (Reason: 7=CLASS3_FRAME_FROM_NONASSOC_STA)", 6
    )
    assert (
        r.kind == "assoc.deauth_by_ap" and r.severity == "warning" and r.data["peer"] == "02:00:5e:10:00:09"
    )
    r = classify_kernel("wlp7s0: RX AssocResp from 02:00:5e:10:00:09 (capab=0x1111 status=17 aid=0)", 6)
    assert r.severity == "error" and "status 17" in r.explanation and r.data["status_name"] != "unknown"
    r = classify_kernel("pcieport 0000:00:1c.0: AER: Corrected error message received from 0000:07:00.0", 4)
    assert r.kind == "pci.aer.received" and r.severity == "warning"
    assert classify_kernel("eno1: Link is Down", 6).kind == "kernel.message"  # NIC link != PCIe link
    assert (
        classify_kernel("Console: switching to colour frame buffer device 160x45", 6).category == "kernel_log"
    )
    r = classify_kernel("MLO_KEY_INSTALL: wcid=12 link=1 cipher=0xfac04 keyidx=0", 6)
    assert r.kind == "driver.kv_trace" and r.category == "mlo" and r.data["fields"]["wcid"] == "12"
    r = classify_kernel("usb 3-3: USB disconnect, device number 3", 6)
    assert r.kind == "usb.disconnect" and r.data["port"] == "3-3"


def test_journal_attribution(ctx: Ctx) -> None:
    js = JournalSource(ctx)
    e = js.handle(
        {
            "MESSAGE": "mt7925e_git 0000:07:00.0: chip reset",
            "PRIORITY": "4",
            "_SOURCE_MONOTONIC_TIMESTAMP": "1000000",
            "_KERNEL_DEVICE": "+pci:0000:07:00.0",
        }
    )
    assert e is not None and e.device_id == DEV and e.kind == "reset.chip_reset"
    assert e.ts_source == "kernel_printk" and e.ts_raw and e.data["attribution"] == "journald _KERNEL_DEVICE"
    e = js.handle({"MESSAGE": "wlp7s0: authenticated", "PRIORITY": "6", "__MONOTONIC_TIMESTAMP": "5"})
    assert e is not None and e.device_id == DEV and e.data["attribution"] == "interface_name_in_message"
    e = js.handle({"MESSAGE": "unrelated thing happened", "PRIORITY": "6"})
    assert e is not None and e.device_id is None and e.ts_source == "receive_boottime"


def test_uevent(ctx: Ctx) -> None:
    us = UeventSource(ctx)
    raw = (
        b"unbind@/devices/pci0000:00/0000:00:02.2/0000:07:00.0\0ACTION=unbind\0"
        b"DEVPATH=/devices/pci0000:00/0000:00:02.2/0000:07:00.0\0SUBSYSTEM=pci\0DRIVER=mt7925e_git\0SEQNUM=9\0"
    )
    u = us.parse(raw)
    assert u is not None
    e = us.handle(u)
    assert e is not None and e.device_id == DEV and e.category == "driver_state" and e.severity == "warning"
    assert ctx.rescans == ["uevent.pci.unbind"]  # type: ignore[attr-defined]
    assert us.parse(b"libudev\0\xfe\xed") is None
    junk = us.parse(b"add@/devices/virtual/block/loop0\0ACTION=add\0SUBSYSTEM=block\0")
    assert junk is not None and us.handle(junk) is None


def genl(cmd: int, *attrs: bytes) -> bytes:
    return GENL_HDR.pack(cmd, 1, 0) + b"".join(attrs)


def test_nl80211_notifications() -> None:
    frame = bytes(24) + struct.pack("<H", 3)  # deauth body: reason 3
    kind, _cat, _sev, _summary, expl, d = decode_event(
        genl(
            C.NL80211_CMD_DEAUTHENTICATE,
            nla_u32(C.NL80211_ATTR_IFINDEX, 12),
            nla(C.NL80211_ATTR_FRAME, frame),
        )
    )
    assert kind == "nl80211.deauthenticate" and d["reason"] == "DEAUTH_LEAVING" and "Reason 3" in expl
    kind, cat, sev, *_, d = decode_event(
        genl(
            C.NL80211_CMD_CONNECT,
            nla_u32(C.NL80211_ATTR_IFINDEX, 12),
            nla(C.NL80211_ATTR_STATUS_CODE, struct.pack("=H", 1)),
        )
    )
    assert sev == "error" and d["status_code"] == 1
    cqm = nla(C.NL80211_ATTR_CQM | 0x8000, nla_flag(C.NL80211_ATTR_CQM_BEACON_LOSS_EVENT))
    kind, cat, sev, *_, d = decode_event(
        genl(C.NL80211_CMD_NOTIFY_CQM, nla_u32(C.NL80211_ATTR_IFINDEX, 12), cqm)
    )
    assert d["cqm"] == "BEACON_LOSS" and sev == "warning"
    kind, cat, *_ = decode_event(genl(C.NL80211_CMD_REG_CHANGE, nla_str(C.NL80211_ATTR_REG_ALPHA2, "US")))
    assert cat == "regulatory"


def test_rtnl_state_changes(ctx: Ctx) -> None:
    rs = RtnlSource(ctx)

    def msg(flags: int, oper: int) -> bytes:
        return (
            struct.pack("=BxHiII", 0, 1, 12, flags, 0)
            + nla_str(L.IFLA_IFNAME, "wlp7s0")
            + nla(L.IFLA_OPERSTATE, bytes([oper]))
        )

    e1 = rs.handle(RT.RTM_NEWLINK, msg(0x1003, 2))
    assert e1 is not None and e1.device_id == DEV and e1.data["operstate"] == "DOWN"
    assert rs.handle(RT.RTM_NEWLINK, msg(0x1003, 2)) is None  # unchanged -> no event
    e2 = rs.handle(RT.RTM_NEWLINK, msg(0x11043, 6))
    assert e2 is not None and e2.data["operstate"] == "UP" and e2.severity == "notice"
    assert rs.handle(RT.RTM_NEWLINK, struct.pack("=BxHiII", 0, 1, 999, 1, 0)) is None  # not a wireless netdev


def test_trace_line_parse() -> None:
    line = "     kworker/u32:2-412     [005] d..1.  10766.704939: mlo_tx_select: phy1 path=2 hash=0x12 sel_wcid=3"
    p = parse_trace_line(line, {"mlo_tx_select": "mt76"}, "boot")
    assert (
        p is not None
        and p["group"] == "mt76"
        and p["ts_ns"] == 10766704939000
        and p["fields"]["sel_wcid"] == "3"
    )
    assert parse_trace_line("garbage", {}, "boot") is None


def test_poller_diffs(ctx: Ctx) -> None:
    p = SysfsPoller(ctx)
    old = {
        "link": ("8.0 GT/s PCIe", "1"),
        "aer_correctable": {"BadTLP": 0, "TOTAL_ERR_COR": 0},
        "runtime_status": "active",
    }
    new = {
        "link": ("2.5 GT/s PCIe", "1"),
        "aer_correctable": {"BadTLP": 2, "TOTAL_ERR_COR": 2},
        "runtime_status": "active",
    }
    kinds = {e.kind: e for e in p.diff(DEV, "/x", old, new)}
    assert set(kinds) == {"pci.link.changed", "pci.aer.counter.correctable"}
    assert kinds["pci.aer.counter.correctable"].data["deltas"] == {"BadTLP": 2, "TOTAL_ERR_COR": 2}
    assert "polling" in kinds["pci.link.changed"].explanation


async def test_source_retries_when_helper_appears_late(ctx: Ctx) -> None:
    class Late(Source):
        name = "late"
        retry_unavailable_s = 0.01
        calls = 0

        async def run(self) -> None:
            Late.calls += 1
            if Late.calls < 3:
                raise Unavailable("whd-helper not running")

    src = Late(ctx)
    await asyncio.wait_for(src.supervise(), 2)
    assert Late.calls == 3
    assert src.status.detail == ""


async def test_on_demand_source_gives_up_when_unavailable(ctx: Ctx) -> None:
    class Once(Source):
        name = "once"

        async def run(self) -> None:
            raise Unavailable("nothing to do")

    src = Once(ctx)
    await asyncio.wait_for(src.supervise(), 2)
    assert (src.status.state, src.status.detail) == ("unavailable", "nothing to do")


async def test_bus_bounded_queue_and_persistence(tmp_path: Path) -> None:
    bus = EventBus(store=Store(tmp_path / "b.db"), queue_size=3)
    sub = bus.subscribe(EventFilter(min_severity="warning"))
    for i in range(6):
        bus.publish(
            make_event(
                ts=i,
                ts_source="receive_boottime",
                source="test",
                category="system",
                kind="t",
                summary=str(i),
                explanation="x",
                raw="r",
                severity="warning",
            )
        )
    bus.publish(
        make_event(
            ts=9,
            ts_source="receive_boottime",
            source="test",
            category="system",
            kind="t",
            summary="low",
            explanation="x",
            raw="r",
            severity="info",
        )
    )
    bus.flush()
    assert sub.queue.qsize() == 3 and sub.dropped == 3  # oldest dropped, filter applied
    got = [sub.queue.get_nowait().summary for _ in range(3)]
    assert got == ["3", "4", "5"]
    evs = bus.store.query_events(EventFilter(), None, 100, "asc")  # type: ignore[union-attr]
    assert [e.summary for e in evs] == ["0", "1", "2", "3", "4", "5", "low"] and all(e.id for e in evs)


def test_websocket_stream_resume(settings: Settings) -> None:
    st = build_state(settings)
    app = create_app(settings, state=st)
    with TestClient(app) as client:
        tok = st.auth.token
        with pytest.raises(Exception), client.websocket_connect("/api/v1/stream") as ws:
            ws.receive_json()
        for i in range(3):
            st.bus.publish(
                make_event(
                    ts=i,
                    ts_source="receive_boottime",
                    source="test",
                    category="system",
                    kind="t",
                    summary=f"old{i}",
                    explanation="x",
                    raw="r",
                    device_id=DEV,
                )
            )
        st.bus.flush()
        first = st.store.query_events(None, None, 10, "asc")[0].id
        with client.websocket_connect(f"/api/v1/stream?token={tok}&since_id={first}") as ws:
            hello = ws.receive_json()
            assert hello["type"] == "hello" and hello["mode"] == "demo"
            backlog = [ws.receive_json() for _ in range(2)]
            assert [m["event"]["summary"] for m in backlog] == ["old1", "old2"]
            assert ws.receive_json()["type"] == "backlog_done"
            st.bus.publish(
                make_event(
                    ts=10,
                    ts_source="receive_boottime",
                    source="test",
                    category="system",
                    kind="t",
                    summary="live",
                    explanation="x",
                    raw="r",
                )
            )
            asyncio.run(asyncio.sleep(0))
            st.bus.flush()
            m = ws.receive_json()
            assert m["type"] == "event" and m["event"]["summary"] == "live" and m["event"]["demo"] is True


def test_usbmon_parse_and_aggregate(ctx: Ctx) -> None:
    from whd.events.sources import UsbmonSource, parse_usbmon_line

    ctrl = "ffff88007c4ec3c0 3010320 S Ci:1:002:0 s 80 06 0100 0000 0012 18 <"
    u = parse_usbmon_line(ctrl)
    assert (
        u
        and u["xfer"] == "Control"
        and u["dir"] == "in"
        and u["setup"] == ["80", "06", "0100", "0000", "0012"]
    )
    assert u["length"] == 18 and u["bus"] == 1 and u["dev"] == 2 and u["ep"] == 0
    c = parse_usbmon_line("ffff88007c4ec3c0 3010350 C Bo:2:003:4 -71 0")
    assert c and c["status"] == -71 and c["event"] == "C" and c["xfer"] == "Bulk"
    assert parse_usbmon_line("garbage line here") is None and parse_usbmon_line("") is None
    assert parse_usbmon_line("a 1 X Bo:1:1:1 0 0") is None
    ctx.index.usb_busdev[(2, 3)] = DEV
    um = UsbmonSource(ctx, [2])
    assert um.handle_line("t 1000 S Bo:2:003:4 -115 512 = aa") is None  # submits aggregate silently
    assert um.handle_line("t 2000 C Bo:2:003:4 0 512") is None  # successful completion: counters only
    ev = um.handle_line("t 3000 C Bi:2:003:5 -71 0")
    assert ev is not None and ev.kind == "usb.urb.error" and ev.severity == "error" and "EPROTO" in ev.summary
    assert ev.device_id == DEV and ev.ts_source == "usbmon_monotonic" and ev.category == "usb_error"
    assert um.handle_line("t 4000 C Bo:9:009:1 0 4") is None  # untracked device ignored
    um.flush()
    s = list(ctx.bus.telemetry)[-1]
    assert s.series == "usbmon" and s.values["ep4o.submit"] == 1 and s.values["ep4o.bytes"] == 512
    assert s.values["ep5i.errors"] == 1
    for i in range(40):
        um.handle_line(f"t {5000 + i} C Bi:2:003:5 -71 0")
    assert um.suppressed == 20  # flush() reset the budget to 20 events/s; 40 errors -> 20 suppressed
