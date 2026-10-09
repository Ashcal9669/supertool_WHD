from __future__ import annotations

from collections.abc import AsyncIterator
from pathlib import Path

import httpx
import pytest

from conftest import fixture_host
from whd.app import build_state, create_app
from whd.config import Settings
from whd.discovery import Discovery
from whd.drivers import mt76, registry
from whd.events.sources import make_event, parse_trace_line
from whd.helper.client import RecordedHelper

DEV = "pci:0000:07:00.0:14c3:7927"
REC = RecordedHelper(Path(__file__).parent / "fixtures/sysroots/mt7927-pcie-host/helper.json")


def rec(path: str) -> str:
    return str(REC.call("debugfs_read", phy="phy1", path=path)["text"])


def discover(name: str = "mt7927-pcie-host"):  # type: ignore[no-untyped-def]
    host = fixture_host(name)
    return host, Discovery(host, registry.extensions()).run().devices[0]


def test_parsers_on_recorded_output() -> None:
    xq = mt76.parse_xmit_queues(rec("mt76/xmit-queues"))
    assert [q["name"] for q in xq] == ["WFDMA0", "MCUWM", "MCUFWQ"] and xq[0]["cpu_idx"] == xq[0]["dma_idx"]
    rx = mt76.parse_rx_queues(rec("mt76/rx-queues"))
    assert [q["queue"] for q in rx] == [0, 1, 2] and rx[0]["hw_queued"] == 1535
    pm = mt76.parse_runtime_pm(rec("mt76/runtime_pm_stats"))
    assert set(pm) == {"awake_time", "doze_time", "low_power_wakes"}
    ls = mt76.parse_link_stats(rec("mt76/link_stats"))
    assert (
        [(r["wcid"], r["link"]) for r in ls] == [(0, 0), (18, 1), (19, 2)]
        and ls[1]["valid"]
        and ls[1]["bw_mhz"] == 20
    )
    wd = mt76.parse_wcid_dump(rec("mt76/mlo_wcid_dump"))
    assert [r["wcid"] for r in wd] == [0, 18, 19] and len(wd[1]["aggr"]) == 16 and wd[1]["aggr_active"] == []
    assert wd[0]["ampdu_state"] == "0x0"
    ts = mt76.parse_tx_stats(rec("mt76/tx_stats"))
    assert ts["ba_miss"] == 0 and ts["amsdu"][0]["msdus"] == 1
    assert mt76.bitmask_links(0b101) == [0, 2]


def test_wcid_dump_active_aggregation() -> None:
    row = "  18    1      1        4         3      3      0 2147483648      1 0=- 1=- 2=A 5=R ampdu_state=0x4 rx_check_pn=1"
    (r,) = mt76.parse_wcid_dump(row)
    assert (
        r["aggr"] == {0: "-", 1: "-", 2: "A", 5: "R"}
        and r["aggr_active"] == [2, 5]
        and r["rx_check_pn"] == "1"
    )


def test_coverage_custom_kernel() -> None:
    host, dev = discover()
    ins = mt76.discover_instrumentation(host, dev, True)
    st = {i.id: i for i in ins.items}
    assert st["tx_selection"].status == "available" and st["txrx_queues"].status == "available"
    assert st["mcu_lifecycle"].status == "partial"
    assert "tracepoint mt76:mcu_send" in (st["mcu_lifecycle"].missing or "")
    assert st["mcu_lifecycle"].proposal and "0001" in st["mcu_lifecycle"].proposal
    t2 = st["tid_to_link"]
    assert t2.status == "partial" and t2.proposal and "negotiated" in t2.proposal.lower()
    assert "tracepoint mt76:mlo_tx_select" in ins.custom_instrumentation
    assert "debugfs mt76/link_stats" in ins.custom_instrumentation
    assert st["fw_timeouts_recovery"].status == "log_only"
    assert not any(t.name in ("mcu_send", "mcu_resp") for t in ins.tracepoints)  # never invented


def test_coverage_without_helper_is_honest(tmp_path: Path) -> None:
    host, dev = discover("mt7927-pcie-host")
    host.helper = None
    ins = mt76.discover_instrumentation(host, dev, False)
    assert not ins.helper_available and ins.tracepoints == [] and ins.debugfs == []
    assert "root" in (ins.helper_note or "")
    st = {i.id: i for i in ins.items}
    assert st["txrx_queues"].status == "missing"  # cannot be shown as available without discovery
    assert st["authorization"].status == "available"  # nl80211-backed, independent of the helper
    assert all("cannot check" in (s.detail or "") for s in st["txrx_queues"].sources if s.kind == "debugfs")


def test_snapshot_tiers() -> None:
    host, dev = discover()
    s = mt76.read_snapshot(host, dev, include_wake=False)
    assert s.xmit_queues and s.rx_queues and s.mlo_active_link_ids == [] and s.link_stats == []
    skipped = {x["path"] for x in s.skipped}
    assert {"mt76/link_stats", "mt76/mlo_wcid_dump", "mt76/tx_stats"} <= skipped
    assert "mt76/acq" not in {r.path for r in s.reads}  # mmio tier never read by the snapshot
    s2 = mt76.read_snapshot(host, dev, include_wake=True)
    assert len(s2.link_stats) == 3 and len(s2.wcid_dump) == 3 and s2.settings["mlo_force_tx_link"] == "255"


def trace_event(name: str, body: str, ts: int):  # type: ignore[no-untyped-def]
    line = f"   kworker/u32:2-412  [005] d..1. {ts / 1e9:.9f}: {name}: {body}"
    p = parse_trace_line(line, {name: "mt76"}, "boot")
    assert p is not None
    return make_event(
        ts=ts,
        ts_source="tracefs_boot",
        source="tracefs:mt76",
        device_id=DEV,
        category="mlo",
        kind=f"trace.mt76.{name}",
        summary=body,
        explanation="x",
        raw=line,
        data={k: v for k, v in p.items() if k != "body"},
    )


def test_trace_aggregation() -> None:
    sel = "phy1 path=1 hash=00000001 l4=1 sw=0 proto=0x0800 da=02:00:5e:10:00:09 l3=0x0800 l4p=6 arp_op=0 icmp=0/0 id=0 seq=0 pri=0 txq_tid={tid} qid=2 aggr=1 orig={o} sel={s} sta=1 vif=1 info_link=1"
    evs = [
        trace_event("mlo_tx_select", sel.format(tid=0, o="18/1/0", s="18/1/0"), 1_000),
        trace_event("mlo_tx_select", sel.format(tid=0, o="18/1/0", s="19/2/1"), 2_000),  # migration 1 -> 2
        trace_event("mlo_tx_select", sel.format(tid=5, o="18/1/0", s="18/1/0"), 3_000),
        trace_event(
            "mlo_txs",
            "phy1 wcid=19 link=2 pid=3 ack_error=0 acked=1 rate=0x1a2 bw=4 txs_band=2 wcid_phy_idx=1",
            4_000,
        ),
        trace_event(
            "mlo_txs",
            "phy1 wcid=19 link=2 pid=4 ack_error=1 acked=0 rate=0x1a2 bw=4 txs_band=2 wcid_phy_idx=1",
            5_000,
        ),
        trace_event("mlo_txfree", "phy1 wcid=19 link=2 token=7 attempts=3 status=1 failed=1", 6_000),
        trace_event(
            "mlo_rx",
            "phy1 wcid=18 link=1 band=1 chan=36 sa=02:00:5e:10:00:09 da=02:00:5e:10:00:01 proto=0x0800 l3=0x0800 l4p=6 arp_op=0 icmp=0/0 id=0 seq=0 sec=4 key=0 decrypted=1 flags=0x0",
            7_000,
        ),
    ]
    a = mt76.aggregate_trace(DEV, evs)
    cells = {(c.tid, c.link): c.count for c in a.tid_link}
    assert cells == {(0, 1): 1, (0, 2): 1, (5, 1): 1}
    assert [(m.from_link, m.to_link, m.tid) for m in a.migrations] == [(1, 2, 0)]
    by = {x.link: x for x in a.links}
    assert by[2].tx_completions == 2 and by[2].tx_acked == 1 and by[2].tx_ack_errors == 1
    assert by[2].txfree_failed == 1 and by[2].txfree_attempts_total == 3 and by[1].rx_decrypted == 1
    assert any("observed" in n for n in a.notes)
    empty = mt76.aggregate_trace(DEV, [])
    assert empty.events_considered == 0 and any("Start a trace session" in n for n in empty.notes)


def test_non_mt76_device_has_no_marker() -> None:
    from whd.model.device import Device

    d = Device(id="x", bus="pci", sysfs_path="/x", title="x", driver="iwlwifi", module="iwlwifi")
    mt76.discovery_extension(fixture_host("empty"), d)
    assert "mt76" not in d.extensions


@pytest.fixture
async def client(settings: Settings) -> AsyncIterator[httpx.AsyncClient]:
    st = build_state(settings)
    app = create_app(settings, state=st)
    async with (
        app.router.lifespan_context(app),
        httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app),
            base_url="http://t",
            headers={"authorization": f"Bearer {st.auth.token}"},
        ) as c,
    ):
        yield c


async def test_mt76_api(client: httpx.AsyncClient) -> None:
    r = await client.get(f"/api/v1/devices/{DEV}/mt76/instrumentation")
    assert r.status_code == 200 and any(i["id"] == "tx_selection" for i in r.json()["items"])
    r = await client.get(f"/api/v1/devices/{DEV}/mt76/snapshot")
    assert r.status_code == 200 and r.json()["include_wake"] is False
    r = await client.get(f"/api/v1/devices/{DEV}/mt76/snapshot?wake=true")
    assert r.status_code == 200 and len(r.json()["link_stats"]) == 3
    r = await client.get(f"/api/v1/devices/{DEV}/mt76/trace-aggregate")
    assert r.status_code == 200 and r.json()["events_considered"] == 0
    assert (await client.get(f"/api/v1/devices/{DEV}/mt76/driver-tags")).status_code == 200
    patches = (await client.get("/api/v1/patches")).json()
    assert patches[0]["id"].startswith("0001") and patches[0]["applied_by_whd"] is False
    body = await client.get(f"/api/v1/patches/{patches[0]['id']}")
    assert "mcu_send" in body.text and body.status_code == 200
    assert (await client.get("/api/v1/devices/nope/mt76/instrumentation")).status_code == 404
