import struct

from whd.mlo.experiments import counter_delta

pytest_plugins = ["test_mlo_api"]


async def test_comparison_keeps_failed_runs_separate_with_capture_links(ctx):
    c, _ = ctx
    dev = (await c.get("/api/v1/devices")).json()["devices"][0]
    for condition in ("control", "control_after"):
        await c.post(
            "/api/v1/mlo/experiments",
            json={
                "device_id": dev["id"],
                "interface": dev["netdevs"][0],
                "target": "192.0.2.1",
                "comparison_group": "test-comparison",
                "condition": condition,
            },
        )
    r = await c.get("/api/v1/mlo/comparisons?group=test-comparison")
    assert r.status_code == 200
    assert [run["request"]["condition"] for run in r.json()["runs"]] == ["control", "control_after"]
    assert all(run["status"] == "error" and run["capture_id"] for run in r.json()["runs"])


def test_counter_resets_and_missing_members_stay_unknown():
    assert counter_delta({"rx": 10, "tx": 4}, {"rx": 3, "tx": 7}) == {"rx": None, "tx": 3}
    assert counter_delta({"rx": 10}, {}) == {"rx": None}


async def test_unknown_interface_and_non_ip_targets_are_rejected(ctx):
    c, _ = ctx
    dev = (await c.get("/api/v1/devices")).json()["devices"][0]["id"]
    r = await c.post(
        "/api/v1/mlo/experiments",
        json={"device_id": dev, "interface": "wired-or-unknown", "target": "192.0.2.1"},
    )
    assert r.status_code == 422
    r = await c.post(
        "/api/v1/mlo/experiments", json={"device_id": dev, "interface": "x", "target": ";shutdown"}
    )
    assert r.status_code == 422


async def test_fixture_does_not_run_real_network_test_and_preserves_failure(ctx):
    c, _ = ctx
    dev = (await c.get("/api/v1/devices")).json()["devices"][0]
    r = await c.post(
        "/api/v1/mlo/experiments",
        json={"device_id": dev["id"], "interface": dev["netdevs"][0], "target": "192.0.2.1"},
    )
    assert r.status_code == 200, r.text
    info = r.json()
    assert info["status"] == "error" and info["capture_id"]
    art = await c.get(f"/api/v1/captures/{info['capture_id']}/artifacts/experiment.json")
    assert art.status_code == 200 and "fixture" in art.text


async def test_air_upload_preserves_original_pcap_and_health_limits(ctx):
    c, _ = ctx
    cid = (await c.post("/api/v1/captures", json={})).json()["id"]
    data = struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 999)
    r = await c.post(
        f"/api/v1/captures/{cid}/mlo/air?origin=independent",
        content=data,
        headers={"content-type": "application/vnd.tcpdump.pcap"},
    )
    assert r.status_code == 200
    assert not r.json()["can_establish_absence"]
    raw = await c.get(f"/api/v1/captures/{cid}/artifacts/{r.json()['pcap_artifact']}")
    assert raw.content == data
