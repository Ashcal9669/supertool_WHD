import hashlib
import io
import json
import zipfile

import httpx
import pytest

from test_mlo_safety import event
from whd.app import build_state, create_app
from whd.config import Settings
from whd.model.events import Event


@pytest.fixture
async def ctx(settings: Settings):
    st = build_state(settings)
    app = create_app(settings, state=st)
    async with (
        app.router.lifespan_context(app),
        httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app),
            base_url="http://test",
            headers={"authorization": f"Bearer {st.auth.token}"},
        ) as client,
    ):
        yield client, st


async def test_dynamic_device_report_and_unknown_capture(ctx):
    c, _ = ctx
    dev = (await c.get("/api/v1/devices")).json()["devices"][0]["id"]
    result = await c.get(f"/api/v1/devices/{dev}/mlo/evidence")
    assert result.status_code == 200
    assert result.json()["device_id"] == dev and result.json()["mode"] == "demo"
    assert (await c.get("/api/v1/captures/nope/mlo/evidence")).status_code == 404


async def test_capture_report_preserves_boots_and_export_definitions(ctx):
    c, st = ctx
    dev = (await c.get("/api/v1/devices")).json()["devices"][0]["id"]
    cid = (await c.post("/api/v1/captures", json={"device_id": dev})).json()["id"]
    for boot in ["boot-a", "boot-b"]:
        e = event(1, kind="trace.net.net_dev_queue", skbaddr="0xabc", link="4")
        e.device_id = dev
        e.data["boot_id"] = boot
        st.bus.publish(e)
    await c.post(f"/api/v1/captures/{cid}/stop")
    rep = (await c.get(f"/api/v1/captures/{cid}/mlo/evidence?device_id={dev}")).json()
    assert rep["historical"] and len(rep["windows"]) == 2
    assert rep["snapshot_states"] and rep["snapshot_states"][0]["boot_id"] != "boot-a"
    assert {p["scope"]["boot_id"] for p in rep["packets"]} == {"boot-a", "boot-b"}
    z = zipfile.ZipFile(io.BytesIO((await c.get(f"/api/v1/captures/{cid}/bundle")).content))
    assert {
        "provenance_start.json",
        "provenance_end.json",
        "mlo/evidence.json",
        "mlo/definitions.json",
    } <= set(z.namelist())
    manifest = json.loads(z.read("manifest.json"))
    for name, meta in manifest["files"].items():
        assert hashlib.sha256(z.read(name)).hexdigest() == meta["sha256"]


async def test_stack_import_is_immutable_scoped_and_included_in_report(ctx):
    import struct
    from urllib.parse import urlencode

    c, st = ctx
    dev = st.inventory.snapshot.devices[0]
    dev.product_id = 0x0616
    dev.driver = "mt7921e_git"
    cid = (await c.post("/api/v1/captures", json={"device_id": dev.id})).json()["id"]
    await c.post(f"/api/v1/captures/{cid}/stop")
    provenance = await st.captures.artifact_json(cid, "provenance_start.json")
    provenance["boot_id"] = boot = "test-recorded-boot"
    st.store.capture_put_artifact(
        cid, "provenance_start.json", "application/json", json.dumps(provenance).encode()
    )
    wall_ns = provenance["clock"]["wall_ns"]
    offset = wall_ns - provenance["clock"]["boottime_before_ns"]
    frame = bytes.fromhex(
        "00112233445566778899aabb08004500001c00000000400100000a0000010a0000020000000000070003"
    )
    data = (
        bytes.fromhex("d4c3b2a1")
        + struct.pack("<HHIIII", 2, 4, 0, 0, 256, 1)
        + struct.pack("<IIII", wall_ns // 10**9, wall_ns % 10**9 // 1000, len(frame), len(frame))
        + frame
    )
    query = urlencode(
        {"direction": "rx", "interface": dev.netdevs[0], "boot_id": boot, "wall_minus_boot_ns": offset}
    )
    response = await c.post(f"/api/v1/captures/{cid}/wifi/stack?{query}", content=data)
    assert response.status_code == 200, response.text
    assert response.json()["original_retained"]
    rep = (await c.get(f"/api/v1/captures/{cid}/mlo/evidence")).json()
    assert rep["protocol"] == "ordinary" and rep["packets"][0]["delivered"]
    wrong = query.replace(str(boot), "unrelated-boot")
    assert (await c.post(f"/api/v1/captures/{cid}/wifi/stack?{wrong}", content=data)).status_code == 422


def test_event_ingestion_strips_key_material_before_any_storage():
    e = event(1, tag="MLO_KEY_MCU", keyfp="deadbeef", key_bytes="001122", key_link="4")
    e.raw = "MLO_KEY_MCU keyfp=deadbeef key_bytes=001122 key_link=4"
    clean = Event.model_validate(e.model_dump())
    text = clean.model_dump_json()
    assert "deadbeef" not in text and "001122" not in text
    assert clean.data["fields"]["key_link"] == "4"


def test_key_or_unknown_mcu_payload_is_withheld_even_in_imported_trace():
    e = event(1, kind="trace.mt76.whd_mcu_tlv", cmd="0x20003", tag="12", hex="deadbeef")
    e.raw = "whd_mcu_tlv: cmd=0x20003 tag=12 hex=deadbeef"
    clean = Event.model_validate(e.model_dump())
    assert "deadbeef" not in clean.model_dump_json()


async def test_air_sidecar_metadata_is_not_mistaken_for_an_air_import(ctx):
    c, st = ctx
    cid = (await c.post("/api/v1/captures", json={})).json()["id"]
    st.store.capture_put_artifact(
        cid, "air-eapol-metadata.json", "application/json", b'{"observations":[],"limits":["metadata only"]}'
    )
    response = await c.get(f"/api/v1/captures/{cid}/mlo/air")
    assert response.status_code == 200 and response.json() == []


async def test_bundle_includes_actual_air_stack_and_timeline_decoders(ctx):
    c, _ = ctx
    cid = (await c.post("/api/v1/captures", json={})).json()["id"]
    await c.post(f"/api/v1/captures/{cid}/stop")
    z = zipfile.ZipFile(io.BytesIO((await c.get(f"/api/v1/captures/{cid}/bundle")).content))
    assert {
        "analysis/decoders/air.py",
        "analysis/decoders/stack_pcap.py",
        "analysis/decoders/timeline.py",
        "analysis/decoder-manifest.json",
    } <= set(z.namelist())
    defs = json.loads(z.read("analysis/decoder-manifest.json"))
    for name, digest in defs["files"].items():
        assert hashlib.sha256(z.read(name)).hexdigest() == digest


async def test_live_mt7927_wake_measurement_rejected_but_inventory_retained(ctx, monkeypatch):
    c, st = ctx
    device = st.inventory.snapshot.devices[0]
    original = st.host.root

    class LiveView:
        is_live = True

        def __getattr__(self, name):
            return getattr(original, name)

    monkeypatch.setattr(st.host, "root", LiveView())
    response = await c.get(f"/api/v1/devices/{device.id}/mt76/snapshot?wake=true")
    assert response.status_code == 422
    assert "MT7922" in response.json()["detail"]
    assert (await c.get(f"/api/v1/devices/{device.id}")).json()["present"]
