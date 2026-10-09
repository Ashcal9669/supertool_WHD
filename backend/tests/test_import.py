"""Import of captures that did not originate on this host."""

from __future__ import annotations

import io
import json
import zipfile
from collections.abc import AsyncIterator
from pathlib import Path

import httpx
import pytest

from whd.app import build_state, create_app
from whd.capture import importer
from whd.capture.importer import ImportError_, detect_format, finalize, parse_upload
from whd.config import Settings
from whd.diagnostics import engine
from whd.events.sources import make_event

SR = Path(__file__).parent / "fixtures" / "sysroots"
DMESG = """\
[    0.000000] Linux version 6.8.0 (build@host) #1 SMP
[   12.345678] mt7925e 0000:07:00.0: ASIC revision: 7927
[   13.000000] mt7925e 0000:07:00.0: Loading firmware patch: mediatek/mt7927/PATCH.bin
[  100.100000] mt7925e 0000:07:00.0: Message 00020027 (seq 12) timeout
[  100.200000] mt7925e 0000:07:00.0: chip reset
[  101.000000] wlan0: deauthenticated from 02:ee:aa:11:22:33 (Reason: 7=CLASS3_FRAME_FROM_NONASSOC_STA)
"""


def demo_events_jsonl() -> bytes:
    return (SR / "mt7927-pcie-host" / "events.jsonl").read_bytes()


def test_format_detection() -> None:
    assert detect_format(demo_events_jsonl()) == "whd-jsonl"
    assert detect_format(DMESG.encode()) == "dmesg"
    assert detect_format(b"PK\x03\x04rest") == "whd-bundle"
    assert detect_format(b'{"events": [], "capture": {}}') == "whd-json"
    assert detect_format(b'{"MESSAGE":"x","__MONOTONIC_TIMESTAMP":"5"}\n') == "journald-json"
    assert detect_format(b"id,ts_boottime_ns,ts_wall_iso\n1,2,x\n") == "whd-csv"
    assert (
        detect_format(b"[Fri Oct  9 10:00:00 2026] usb 1-1: USB disconnect, device number 3\n")
        == "dmesg-wall"
    )
    ftr = b"# tracer: nop\n  kworker-1  [001] d..1. 20.000000: mac_txdone: phy1 [3:7]\n"
    assert detect_format(ftr) == "ftrace-text"
    with pytest.raises(ImportError_):
        detect_format(b"hello world, this is not a capture\nat all\n")


def test_dmesg_import_classifies_with_production_rules() -> None:
    imp = parse_upload(DMESG.encode(), "old-box.dmesg")
    kinds = [e.kind for e in imp.events]
    assert "firmware.mcu_timeout" in kinds and "reset.chip_reset" in kinds and "assoc.deauth_by_ap" in kinds
    timeout = next(e for e in imp.events if e.kind == "firmware.mcu_timeout")
    assert timeout.ts_boottime_ns == 100_100_000_000 and timeout.ts_source == "kernel_printk"
    assert timeout.device_id == "log:pci:0000:07:00.0"  # pseudo identity: no inventory in a raw log
    assert "origin" in (timeout.ts_raw or "") or "imported" in (timeout.ts_raw or "")
    fin = finalize(imp, "imp-x")
    assert all(e.session == "import:imp-x" and e.id is None for e in fin.events)
    assert all(e.ts_wall > 86400 for e in fin.events), (
        "wall times are anchored, never 1970 or this host's boot"
    )
    assert fin.events[-1].ts_wall - fin.events[0].ts_wall == pytest.approx(101.0, abs=0.01)


def test_journald_json_and_ftrace_and_hint() -> None:
    j = "\n".join(
        json.dumps(x)
        for x in [
            {
                "MESSAGE": "mt7925e 0000:07:00.0: chip reset",
                "PRIORITY": "4",
                "_SOURCE_MONOTONIC_TIMESTAMP": "5000000",
                "_KERNEL_DEVICE": "+pci:0000:07:00.0",
                "__REALTIME_TIMESTAMP": "1791500000000000",
            },
            {"MESSAGE": [104, 105], "PRIORITY": "6", "__MONOTONIC_TIMESTAMP": "6000000"},
            {"nothing": 1},
        ]
    )
    imp = parse_upload(j.encode(), "j.json")
    assert imp.format == "journald-json" and imp.events[0].kind == "reset.chip_reset"
    assert imp.events[0].ts_wall == pytest.approx(1791500000.0)
    ftr = (
        b"# tracer: nop\n  kworker/u32:2-412     [005] d..1. 10766.704939: mlo_tx_select: phy1 path=1 txq_tid=5 "
        b"orig=18/1/0 sel=19/2/1 aggr=1 da=02:00:5e:10:00:09\n"
    )
    e = parse_upload(ftr, "t.txt", group_hint="mt76")
    assert e.events[0].kind == "trace.mt76.mlo_tx_select" and e.events[0].data["fields"]["sel"] == "19/2/1"
    nohint = parse_upload(ftr, "t.txt")
    assert nohint.events[0].kind == "trace.unknown.mlo_tx_select" and any(
        "group" in w for w in nohint.warnings
    )


def test_whd_json_jsonl_csv_roundtrip_and_bad_lines_are_counted() -> None:
    raw = demo_events_jsonl()
    n = len(raw.decode().splitlines())
    jl = parse_upload(raw + b"not json\n{broken\n", "e.jsonl")
    assert (
        len(jl.events) == n and jl.skipped_lines == 2 and any("could not be parsed" in w for w in jl.warnings)
    )
    evs = [json.loads(x) for x in raw.decode().splitlines()[:50]]
    js = parse_upload(
        json.dumps({"capture": {"name": "c", "mode": "demo"}, "whd_version": "x", "events": evs}).encode(),
        "e.json",
    )
    assert js.format == "whd-json" and len(js.events) == 50 and js.origin["demo"] is True
    from whd.capture.manager import events_to_csv

    csv_text = events_to_csv(jl.events[:30])
    cs = parse_upload(csv_text.encode(), "e.csv")
    assert (
        cs.format == "whd-csv"
        and len(cs.events) == 30
        and any("decoded event fields" in w for w in cs.warnings)
    )
    assert [e.kind for e in cs.events] == [e.kind for e in jl.events[:30]]


def make_zip(members: dict[str, bytes]) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        for k, v in members.items():
            z.writestr(k, v)
    return buf.getvalue()


def test_zip_safety_limits() -> None:
    with pytest.raises(ImportError_, match="not a valid zip"):
        parse_upload(b"PK\x03\x04garbage", "x.zip")
    with pytest.raises(ImportError_, match="members"):
        parse_upload(make_zip({f"f{i}.txt": b"x" for i in range(importer.MAX_ZIP_MEMBERS + 1)}), "x.zip")
    bomb = make_zip({"events.jsonl": b"\0" * (importer.MAX_ZIP_MEMBER_BYTES + 10)})
    assert len(bomb) < 1_000_000
    with pytest.raises(ImportError_, match=r"zip bomb|larger"):
        parse_upload(bomb, "bomb.zip")
    z = make_zip({"../evil.txt": b"x", "events.jsonl": demo_events_jsonl()})
    imp = parse_upload(z, "x.zip")
    assert any("suspicious zip member" in w for w in imp.warnings) and imp.events
    with pytest.raises(ImportError_, match="larger than"):
        parse_upload(b"x" * (importer.MAX_UPLOAD_BYTES + 1), "big.txt")
    with pytest.raises(ImportError_, match="empty"):
        parse_upload(b"", "e.txt")


def test_event_cap_and_oversized_data() -> None:
    evs = [
        make_event(
            ts=i,
            ts_source="receive_boottime",
            source="t",
            severity="info",
            category="system",
            kind="k",
            summary="s" * 10000,
            explanation="e",
            raw="r",
            data={"blob": "x" * 40000} if i == 0 else {},
        )
        for i in range(10)
    ]
    imp = importer.Imported(format="whd-jsonl", events=evs)
    fin = finalize(imp, "imp-y", max_events=5)
    assert len(fin.events) == 5 and any("kept the last 5" in w for w in fin.warnings)
    assert all(len(e.summary) <= 4096 for e in fin.events)
    imp2 = finalize(importer.Imported(format="x", events=[evs[0]]), "imp-z")
    assert imp2.events[0].data == {"dropped": "decoded data exceeded the size limit on import"}


@pytest.fixture
async def client(settings: Settings) -> AsyncIterator[tuple[httpx.AsyncClient, object]]:
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
        yield c, st


async def test_upload_bundle_roundtrip_diagnose_and_isolation(client) -> None:  # type: ignore[no-untyped-def]
    c, st = client
    # build a real bundle from a capture of the demo story, then re-import it as if from another machine
    cid = (await c.post("/api/v1/captures", json={"name": "origin"})).json()["id"]
    for line in demo_events_jsonl().decode().splitlines():
        e = importer.Event.model_validate_json(line)
        if e.severity in ("warning", "error", "critical") or e.kind.startswith(
            ("reset.", "netdev.", "assoc.")
        ):
            e.id = None
            e.session = None
            st.bus.publish(e)
    await c.post(f"/api/v1/captures/{cid}/stop")
    st.bus.flush()
    bundle = (await c.get(f"/api/v1/captures/{cid}/bundle")).content
    live_before, ring_before = st.store.event_count(), len(st.bus.ring)
    orig_report = (await c.post("/api/v1/diagnostics/analyze", json={"capture_id": cid})).json()

    r = await c.post(
        "/api/v1/captures/import?filename=other-host.zip&name=From%20other%20box",
        content=bundle,
        headers={"content-type": "application/octet-stream"},
    )
    assert r.status_code == 200, r.text
    res = r.json()
    assert (
        res["format"] == "whd-bundle"
        and res["capture"]["mode"] == "imported"
        and res["capture"]["state"] == "imported"
    )
    assert res["devices_in_snapshot"] >= 1 and res["origin"]["filename"] == "other-host.zip"
    icid = res["capture"]["id"]
    evs = (await c.get(f"/api/v1/captures/{icid}/events?limit=20000")).json()
    assert len(evs) == res["capture"]["stats"]["events_kept"] > 10
    assert all(e["session"] == f"import:{icid}" for e in evs)
    # never pollutes live data
    st.bus.flush()
    assert st.store.event_count() == live_before and len(st.bus.ring) == ring_before
    # analysis of the imported capture uses its own inventory and matches the original's incidents
    rep = (await c.post("/api/v1/diagnostics/analyze", json={"capture_id": icid})).json()
    assert rep["scope"]["imported"] is True and any("Imported capture" in x for x in rep["limits"])
    assert not any(m["id"] == "M-helper" for m in rep["missing_instrumentation"])
    assert {h["id"] for h in rep["hypotheses"]} == {h["id"] for h in orig_report["hypotheses"]}
    assert len(rep["incidents"]) == len(orig_report["incidents"])
    devs = (await c.get(f"/api/v1/captures/{icid}/devices")).json()
    assert devs and devs[0]["id"].startswith("pci:")
    # export / bundle of an imported capture describe the origin, not this host
    b2 = zipfile.ZipFile(io.BytesIO((await c.get(f"/api/v1/captures/{icid}/bundle")).content))
    assert "origin.json" in b2.namelist() and "system.json" not in b2.namelist()
    assert "IMPORTED capture" in b2.read("README.txt").decode()
    assert (await c.get(f"/api/v1/captures/{icid}/export?format=csv")).status_code == 200
    # replay works through the same isolated path
    assert (await c.post(f"/api/v1/captures/{icid}/replay", json={"speed": 20})).status_code == 200
    await c.post("/api/v1/replay/stop")


async def test_upload_errors(client) -> None:  # type: ignore[no-untyped-def]
    c, _ = client
    h = {"content-type": "application/octet-stream"}
    assert (await c.post("/api/v1/captures/import?filename=x.txt", content=b"", headers=h)).status_code == 422
    r = await c.post(
        "/api/v1/captures/import?filename=x.txt", content=b"just some text\nnothing parseable\n", headers=h
    )
    assert r.status_code == 422 and "unrecognized" in r.text
    r = await c.post(
        "/api/v1/captures/import?filename=x.dmesg&group_hint=bad hint!", content=DMESG.encode(), headers=h
    )
    assert r.status_code == 422  # group hint validated
    r = await c.post("/api/v1/captures/import?filename=old.dmesg", content=DMESG.encode(), headers=h)
    assert r.status_code == 200 and r.json()["format"] == "dmesg"
    rep = (await c.post("/api/v1/diagnostics/analyze", json={"capture_id": r.json()["capture"]["id"]})).json()
    assert any(
        h["id"] == "H-fw-unresponsive" for h in rep["hypotheses"]
    )  # raw log from "another box" is diagnosable
    assert (await c.post("/api/v1/captures/import?filename=x", content=b"abc")).status_code in (401, 422)
    no_auth = httpx.AsyncClient(transport=c._transport, base_url="http://t")
    assert (await no_auth.post("/api/v1/captures/import", content=DMESG.encode())).status_code == 401
    await no_auth.aclose()


def test_oversized_content_length_rejected(settings: Settings, monkeypatch: pytest.MonkeyPatch) -> None:
    from fastapi.testclient import TestClient

    from whd.api import captures as cap_api

    monkeypatch.setattr(cap_api, "MAX_UPLOAD_BYTES", 1024)
    st = build_state(settings)
    with TestClient(create_app(settings, state=st)) as c:
        c.headers["authorization"] = f"Bearer {st.auth.token}"
        r = c.post("/api/v1/captures/import", content=b"x" * 5000)
        assert r.status_code == 413
        r = c.post(
            "/api/v1/captures/import", content=iter([b"x" * 600, b"x" * 600])
        )  # chunked, no content-length
        assert r.status_code == 413
    _ = engine
