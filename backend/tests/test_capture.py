from __future__ import annotations

import asyncio
import io
import json
import zipfile
from collections.abc import AsyncIterator

import httpx
import pytest

from whd.app import build_state, create_app
from whd.config import Settings
from whd.events.sources import make_event

DEV = "pci:0000:07:00.0:14c3:7927"


def ev(i: int, sev: str = "info", dev: str | None = DEV, cat: str = "firmware", msg: str | None = None):  # type: ignore[no-untyped-def]
    return make_event(
        ts=10_000 + i,
        ts_source="receive_boottime",
        source="test",
        device_id=dev,
        severity=sev,  # type: ignore[arg-type]
        category=cat,
        kind="t.k",
        summary=msg or f"event {i}",
        explanation="e",
        raw=msg or f"raw {i}",
    )


@pytest.fixture
async def ctx(settings: Settings) -> AsyncIterator[tuple[httpx.AsyncClient, object]]:
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


async def test_capture_lifecycle_filters_and_limits(ctx) -> None:  # type: ignore[no-untyped-def]
    c, st = ctx
    r = await c.post(
        "/api/v1/captures",
        json={
            "name": "t1",
            "device_id": DEV,
            "min_severity": "warning",
            "max_events": 100,
            "max_seconds": 60,
        },
    )
    assert r.status_code == 200, r.text
    cid = r.json()["id"]
    st.bus.publish(ev(1, "info"))  # below severity: filtered out
    st.bus.publish(ev(2, "error", dev="other:dev"))  # other device: filtered out
    for i in range(150):
        st.bus.publish(ev(100 + i, "warning"))
    st.bus.flush()
    r = await c.post(f"/api/v1/captures/{cid}/stop")
    info = r.json()
    assert info["state"] == "stopped" and info["stats"]["events_seen"] == 150
    assert (
        info["stats"]["events_kept"] == 100 and info["stats"]["events_dropped_oldest"] == 50
    )  # circular buffer
    evs = (await c.get(f"/api/v1/captures/{cid}/events")).json()
    assert len(evs) == 100 and evs[0]["summary"] == "event 150" and evs[-1]["summary"] == "event 249"
    assert any(a["name"] == "devices_start.json" for a in info["artifacts"])


async def test_limits_are_validated_and_concurrency_capped(ctx) -> None:  # type: ignore[no-untyped-def]
    c, _ = ctx
    assert (await c.post("/api/v1/captures", json={"max_events": 10**9})).status_code == 422
    assert (await c.post("/api/v1/captures", json={"max_seconds": 10**7})).status_code == 422
    for _i in range(3):
        assert (await c.post("/api/v1/captures", json={})).status_code == 200
    r = await c.post("/api/v1/captures", json={})
    assert r.status_code == 409 and "at most 3" in r.text


async def test_duration_limit_stops_capture(ctx) -> None:  # type: ignore[no-untyped-def]
    c, st = ctx
    cid = (await c.post("/api/v1/captures", json={"max_seconds": 5})).json()["id"]
    lv = st.captures.live[cid]
    lv.deadline = 0.0  # force expiry
    for _ in range(40):
        await asyncio.sleep(0.1)
        if cid not in st.captures.live:
            break
    info = (await c.get(f"/api/v1/captures/{cid}")).json()
    assert info["state"] == "expired" and "duration" in info["stats"]["stop_reason"]


async def test_export_formats_and_bundle(ctx) -> None:  # type: ignore[no-untyped-def]
    c, st = ctx
    cid = (await c.post("/api/v1/captures", json={"name": "ex"})).json()["id"]
    st.bus.publish(
        ev(1, "error", msg="wlp7s0: deauthenticated from 02:ee:aa:11:22:33 (Reason: 3=DEAUTH_LEAVING)")
    )
    tr = make_event(
        ts=20_000,
        ts_source="tracefs_boot",
        source="tracefs:mt76",
        device_id=DEV,
        category="trace",
        kind="trace.mt76.mac_txdone",
        summary="mac_txdone",
        explanation="x",
        raw="  kworker-1  [001] d..1. 20.000000: mac_txdone: phy1 [3:7]",
    )
    st.bus.publish(tr)
    await c.post(f"/api/v1/captures/{cid}/stop")
    j = (await c.get(f"/api/v1/captures/{cid}/export?format=json")).json()
    assert len(j["events"]) == 2 and j["capture"]["id"] == cid and "CLOCK_BOOTTIME" in j["clock_note"]
    jl = (await c.get(f"/api/v1/captures/{cid}/export?format=jsonl")).text.strip().splitlines()
    assert len(jl) == 2 and json.loads(jl[0])["kind"] == "t.k"
    csv_text = (await c.get(f"/api/v1/captures/{cid}/export?format=csv")).text
    assert (
        csv_text.splitlines()[0].startswith("id,ts_boottime_ns,ts_wall_iso") and "DEAUTH_LEAVING" in csv_text
    )
    tx = (await c.get(f"/api/v1/captures/{cid}/export?format=trace")).text
    assert "mac_txdone: phy1 [3:7]" in tx and "not trace.dat" in tx
    assert (await c.get(f"/api/v1/captures/{cid}/export?format=xml")).status_code == 422
    z = zipfile.ZipFile(io.BytesIO((await c.get(f"/api/v1/captures/{cid}/bundle")).content))
    names = set(z.namelist())
    assert {
        "manifest.json",
        "events.jsonl",
        "events.csv",
        "trace.txt",
        "system.json",
        "README.txt",
        "devices_start.json",
    } <= names
    assert any(n.startswith("mt76_instrumentation_") for n in names)
    man = json.loads(z.read("manifest.json"))
    assert man["demo"] is True and man["redacted_macs"] is True
    ev_text = z.read("events.jsonl").decode()
    assert "02:ee:aa:11:22:33" not in ev_text and "02:ee:aa:xx:xx:01" in ev_text  # masked, OUI kept
    assert "DEMO MODE" in z.read("README.txt").decode()
    from whd.capture.manager import hashlib as _h  # noqa: F401

    for n, meta in man["files"].items():
        import hashlib

        assert hashlib.sha256(z.read(n)).hexdigest() == meta["sha256"], n
    assert st.auth.token.encode() not in b"".join(z.read(n) for n in z.namelist())
    raw = (await c.get(f"/api/v1/captures/{cid}/bundle?redact_macs=false")).content
    assert b"02:ee:aa:11:22:33" in zipfile.ZipFile(io.BytesIO(raw)).read("events.jsonl")


async def test_replay_is_not_persisted_and_does_not_enter_ring(ctx) -> None:  # type: ignore[no-untyped-def]
    c, st = ctx
    cid = (await c.post("/api/v1/captures", json={})).json()["id"]
    for i in range(3):
        st.bus.publish(ev(i, "warning"))
    await c.post(f"/api/v1/captures/{cid}/stop")
    st.bus.flush()
    stored_before = st.store.event_count()
    ring_before = len(st.bus.ring)
    sub = st.bus.subscribe(__import__("whd.model.events", fromlist=["EventFilter"]).EventFilter())
    r = await c.post(f"/api/v1/captures/{cid}/replay", json={"speed": 20})
    assert r.status_code == 200
    got = []
    for _ in range(3):
        got.append(await asyncio.wait_for(sub.queue.get(), 5))
    assert [g.ts_source for g in got] == ["recorded"] * 3 and all(g.session == f"replay:{cid}" for g in got)
    assert all(g.id and g.id >= 10**12 for g in got)
    st.bus.flush()
    assert st.store.event_count() == stored_before and len(st.bus.ring) == ring_before
    assert (await c.get("/api/v1/replay/status")).json()["session"] == f"replay:{cid}"
    await c.post("/api/v1/replay/stop")
    assert (await c.post("/api/v1/captures/nope/replay", json={})).status_code == 404


async def test_delete_capture(ctx) -> None:  # type: ignore[no-untyped-def]
    c, _st = ctx
    cid = (await c.post("/api/v1/captures", json={})).json()["id"]
    assert (await c.delete(f"/api/v1/captures/{cid}")).status_code == 200
    assert (await c.get(f"/api/v1/captures/{cid}")).status_code == 404
