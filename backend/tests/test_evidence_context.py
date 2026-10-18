"""Evidence visibility regressions: unknown owner is distinct from absent observations."""

from test_mlo_safety import event
from whd.store.db import Store

pytest_plugins = ["test_mlo_api"]


def test_unassigned_context_is_bounded_and_keeps_owner_missing(tmp_path):
    store = Store(tmp_path / "events.db")
    a, b, c = event(1), event(2), event(3)
    a.device_id = c.device_id = None
    store.insert_events([a, b, c])
    result = store.query_unattributed_context(b.id, limit=10)
    assert [e.id for e in result] == [a.id]
    assert all(e.device_id is None for e in result)
    assert not store.query_unattributed_context(c.id + 20001, limit=10)


async def test_device_evidence_retains_unassigned_facts_without_assigning_them(ctx):
    c, st = ctx
    dev = (await c.get("/api/v1/devices")).json()["devices"][0]["id"]
    unknown = event(1, tag="MLO_FW_STA_RET", link="1", ret="-110")
    unknown.device_id = None
    own = event(2, kind="assoc.associated")
    own.device_id = dev
    st.store.insert_events([unknown, own])
    rep = (await c.get(f"/api/v1/devices/{dev}/mlo/evidence")).json()
    assert rep["unassigned_observations"][0]["id"] == unknown.id
    assert rep["unassigned_observations"][0]["device_id"] is None
    assert all(o["device_id"] == dev for o in rep["observations"])
    assert not any(w["firmware"]["ops"] for w in rep["windows"])
    assert rep["current_observations"]["interface"] == "wlp7s0"
    assert rep["current_observations"]["boot_id"]


async def test_real_nl80211_uppercase_authorization_survives_the_evidence_api(ctx, monkeypatch):
    from conftest import fixture_host
    from whd.discovery import Discovery

    c, st = ctx
    host = fixture_host("mt7921u-usb")
    dev = Discovery(host).run().devices[0]
    st.host = host

    async def device(_):
        return dev

    monkeypatch.setattr(st.inventory, "device", device)
    rep = (await c.get(f"/api/v1/devices/{dev.id}/mlo/evidence")).json()
    assert rep["current_observations"]["station_authorized"] is True
    assert rep["current_observations"]["connected"] is True


async def test_live_evidence_uses_running_collectors_without_sorting_the_historical_store(ctx, monkeypatch):
    c, st = ctx
    dev = (await c.get("/api/v1/devices")).json()["devices"][0]["id"]
    live = event(1, tag="MLO_FW_STA_RET", ret="-110")
    live.device_id = None
    live.raw = "fresh unassigned return"
    st.bus.publish(live)
    st.settings.demo_scenario = None
    st.settings.enable_event_sources = True

    def no_history_scan(*args, **kwargs):
        raise AssertionError("live evidence must not sort millions of historical rows")

    monkeypatch.setattr(st.store, "query_events", no_history_scan)
    rep = (await c.get(f"/api/v1/devices/{dev}/mlo/evidence")).json()
    assert rep["unassigned_observations"][0]["raw"] == "fresh unassigned return"
    assert any("live collector ring" in limit for limit in rep["limits"])
