"""Ordinary reuse, interruption and evidence round-trip regressions from final review."""

import importlib.util
import io
import json
import sys
import zipfile
from pathlib import Path
from types import SimpleNamespace

import pytest

from test_mlo_packets import pcap
from test_mlo_safety import event
from whd.capture.importer import parse_upload
from whd.capture.manager import CaptureManager
from whd.mlo import experiments, packets, report
from whd.mlo.timeline import Collectors, assign_boots, build_epochs

pytest_plugins = ["test_mlo_api"]


def scoped(n, stage, **fields):
    e = event(n, kind=f"packet.{stage}", **fields)
    e.data.update(boot_id="boot-a", association_epoch="epoch-a")
    e.data["fields"].update(generation="3", link="4")
    return e


def security(n, **fields):
    return scoped(
        n, "security", decrypted="1", integrity_ok="1", replay_ok="1", channel_matches="1", **fields
    )


def test_reused_rx_and_released_tx_buffers_cannot_inherit_delivery():
    es = [
        scoped(1, "raw_rx", skbaddr="x"),
        security(2, skbaddr="x"),
        scoped(3, "raw_rx", skbaddr="x"),
        scoped(4, "stack_rx", skbaddr="x"),
    ]
    paths = packets.build_paths(es, "device-a")
    assert len(paths) == 2
    assert not any(p.authenticated_delivery for p in paths)
    paths = packets.build_paths(
        [
            scoped(1, "stack_tx", skbaddr="x"),
            scoped(2, "tx_free", skbaddr="x"),
            scoped(3, "stack_rx", skbaddr="x"),
        ],
        "device-a",
    )
    assert len(paths) == 2 and paths[0].delivered is None
    paths = packets.build_paths(
        [scoped(1, "raw_rx", packet_id="x"), security(2, skbaddr="x"), scoped(3, "stack_rx", skbaddr="x")],
        "device-a",
    )
    assert not any(p.authenticated_delivery for p in paths)


def test_ambiguous_clock_boot_never_inherits_an_explicit_boot():
    a, unknown, b = (
        scoped(1, "raw_rx", skbaddr="x"),
        scoped(2, "stack_rx", skbaddr="x"),
        scoped(3, "raw_rx", skbaddr="x"),
    )
    del unknown.data["boot_id"]
    b.data["boot_id"] = "boot-b"
    boots = assign_boots([a, unknown, b])
    assert boots[0] == "boot-a" and boots[2] == "boot-b" and boots[1] not in ("boot-a", "boot-b")
    assert assign_boots([b, unknown, a])[1] == boots[1]
    assert assign_boots([a, unknown])[1] != "boot-a"


def test_new_station_request_does_not_inherit_previous_completion():
    es = [
        event(1, tag="MLO_FW_STA_RET", link="4", wcid="9", state="1", ret="0"),
        event(2, tag="MLO_FW_STA_RAW", link="4", wcid="10", state="2"),
    ]
    r = report.analyze(es, "device-a", "fixture")
    assert r.windows[0].state.links[0].authorized.value == "unknown"
    es.append(event(3, tag="MLO_FW_STA_RET", link="4", wcid="9", state="2", ret="0"))
    stale = report.analyze(es, "device-a", "fixture").windows[0]
    assert stale.state.links[0].authorized.value == "unknown"
    assert stale.firmware.links[0].current["wcid"] == 10
    assert any("unmatched" in flag or "stale" in flag for flag in stale.firmware.flags)
    es.extend(
        [
            event(4, tag="MLO_FW_STA_RET", link="4", wcid="10", state="2", ret="0"),
            event(5, tag="MLO_FW_STA_RET", link="4", wcid="9", state="2", ret="0"),
        ]
    )
    after = report.analyze(es, "device-a", "fixture").windows[0]
    assert after.firmware.links[0].current["wcid"] == 10
    assert after.state.links[0].authorized.evidence[0].event_id == 4
    complete = report.analyze(
        [event(1, tag="MLO_FW_STA_RET", link="4", wcid="9", state="2", ret="0")], "device-a", "fixture"
    )
    assert complete.windows[0].state.links[0].authorized.evidence[0].event_id == 1
    assert complete.windows[0].state.links[0].authorized.value == "unknown"
    disabled = report.analyze(
        [event(1, tag="MLO_FW_STA_RET", link="4", wcid="9", enable="0", state="2", ret="0")],
        "device-a",
        "fixture",
    )
    assert disabled.windows[0].state.links[0].authorized.value == "no"


def test_broadcast_station_completion_cannot_authorize_the_peer():
    es = [
        event(1, tag="MLO_FW_BSS_BASIC", link="4", bmc="8"),
        event(2, tag="MLO_FW_STA_RET", link="4", wcid="9", state="1", ret="0"),
        event(3, tag="MLO_FW_STA_RET", link="4", wcid="8", state="2", ret="0"),
    ]
    state = report.analyze(es, "device-a", "fixture").windows[0].state.links[0]
    assert state.authorized.value == "no" and state.authorized.evidence[0].event_id == 2


def test_firmware_state_does_not_mix_old_errors_or_uncompleted_bss_requests():
    es = [
        event(1, tag="MLO_MCU_SEND_START", link="4", cmd="0x20003", t="100"),
        event(2, tag="MLO_MCU_SEND_DONE", link="4", cmd="0x20003", ret="-5"),
        event(3, tag="MLO_FW_BSS_BASIC", link="4", active="1"),
        event(4, tag="MLO_FW_STA_RET", link="4", wcid="9", enable="1", state="2", ret="0"),
    ]
    assert report.analyze(es, "device-a", "fixture").windows[0].state.links[0].fw_programmed.value != "no"
    assert (
        report.analyze(es[-2:], "device-a", "fixture").windows[0].state.links[0].fw_programmed.value
        == "unknown"
    )


def test_post_terminal_lifecycle_is_not_a_stage_in_the_ended_association():
    es = [
        event(1, kind="assoc.authenticate"),
        event(2, kind="nl80211.disconnect"),
        event(3, tag="MLO_FW_PEER_LIFECYCLE", link_id="4", generation="9", stage="remove"),
    ]
    r = report.analyze(es, "device-a", "fixture")
    assert all(stage.ts_boottime_ns <= r.epochs[0].end_ns for stage in r.epochs[0].stages)
    assert any(e.id == 3 for e in r.observations)
    assert any(w.scope.association_epoch is None for w in r.windows)


def test_later_channel_configuration_cannot_authenticate_an_earlier_frame():
    es = [
        event(1, tag="MLO_FW_BSS_BASIC", link="4", control_channel="69"),
        event(
            2, tag="MLO_RX_UNICAST_TRACE", resolved_wcid="9", resolved_link="4", chfreq="40", packet_id="p"
        ),
        event(
            3,
            tag="MLO_RX_DECRYPT_TRACE",
            wcid="9",
            decrypted="1",
            icv_err="0",
            fcs_err="0",
            tkip_mic_err="0",
            packet_id="p",
        ),
        event(4, tag="MLO_RX_PN_OK", wcid="9", packet_id="p"),
        event(5, tag="MLO_FW_BSS_BASIC", link="4", control_channel="40"),
    ]
    r = report.analyze(es, "device-a", "fixture")
    frame = r.windows[0].rx_frames[0]
    assert frame.expected_channel == 69 and frame.verdict == "wrong_channel_for_link"
    assert not r.windows[0].rx_summary.authenticated_by_link


def test_association_termination_bounds_stages_and_generation():
    es = [
        event(1, kind="assoc.authenticate"),
        event(2, tag="MLO_FW_PEER_LIFECYCLE", link_id="4", generation="9"),
        event(3, kind="nl80211.disconnect"),
        event(4, kind="nl80211.port_authorized"),
        event(5, kind="assoc.authenticate"),
        event(6, kind="packet.raw_rx", link="4", skbaddr="x"),
    ]
    r = report.analyze(es, "device-a", "fixture")
    assert all(
        w.scope.link_lifetime is None for w in r.windows if w.scope.association_epoch == r.epochs[1].id
    )
    assert all(s.ts_boottime_ns <= r.epochs[0].end_ns for s in r.epochs[0].stages)


def test_observed_eapol_collector_is_not_reported_missing():
    r = report.analyze(
        [event(1, kind="assoc.authenticate"), event(2, kind="trace.mt76.mlo_rx", proto="0x888e")],
        "device-a",
        "fixture",
    )
    gaps = [g for g in r.epochs[0].gaps if g.collector == "tracepoint mt76:mlo_rx"]
    assert gaps and all(g.kind != "no_collector" for g in gaps)
    unknown = build_epochs([event(1, kind="assoc.authenticate")], "device-a", Collectors())[0]
    assert not any("does not exist" in g.detail for g in unknown.gaps)


def test_decrypted_reply_without_replay_evidence_is_an_observation():
    es = [
        event(1, kind="assoc.authenticate"),
        event(2, kind="trace.mt76.mlo_rx", l4p="1", icmp="0/0", decrypted="1", flags="0"),
    ]
    epoch = build_epochs(es, "device-a", Collectors())[0]
    assert not any(stage.stage == "data_reply_verified" for stage in epoch.stages)
    assert any(stage.stage == "data_reply_observed" for stage in epoch.stages)


async def make_capture(ctx):
    c, st = ctx
    dev = (await c.get("/api/v1/devices")).json()["devices"][0]["id"]
    cid = (await c.post("/api/v1/captures", json={"device_id": dev})).json()["id"]
    e = event(1, kind="packet.raw_rx")
    e.device_id = dev
    st.bus.publish(e)
    await c.post(f"/api/v1/captures/{cid}/stop")
    return cid


async def test_repeated_air_imports_are_retained_with_immutable_downloads(ctx):
    c, _ = ctx
    cid = await make_capture(ctx)
    blobs = [pcap(bytes.fromhex("0800000002005e20000102005e20000202005e2000030000")), pcap(b"different")]
    results = []
    for i, blob in enumerate(blobs):
        results.append(
            (await c.post(f"/api/v1/captures/{cid}/mlo/air?filename=segment-{i}.pcap", content=blob)).json()
        )
    imports = (await c.get(f"/api/v1/captures/{cid}/mlo/air")).json()
    assert len(imports) == 2
    assert results[0]["import_id"] != results[1]["import_id"]
    for i, result in enumerate(results):
        assert result["filename"] == f"segment-{i}.pcap"
        assert (await c.get(f"/api/v1/captures/{cid}/artifacts/{result['pcap_artifact']}")).content == blobs[
            i
        ]


async def test_masked_bundle_omits_unsanitized_air_bytes_and_hex(ctx):
    c, _ = ctx
    cid = await make_capture(ctx)
    raw = bytes.fromhex("0800000002005e20000102005e20000202005e2000030000")
    await c.post(f"/api/v1/captures/{cid}/mlo/air", content=pcap(raw))
    z = zipfile.ZipFile(io.BytesIO((await c.get(f"/api/v1/captures/{cid}/bundle")).content))
    assert not any(n.endswith(".pcap") for n in z.namelist())
    assert not any(raw.hex().encode() in z.read(n) for n in z.namelist())
    assert json.loads(z.read("manifest.json"))["omitted_artifacts"]
    original = zipfile.ZipFile(
        io.BytesIO((await c.get(f"/api/v1/captures/{cid}/bundle?redact_macs=false")).content)
    )
    assert any(original.read(n) == pcap(raw) for n in original.namelist())


async def test_bundle_import_preserves_original_evidence_artifacts(ctx):
    c, st = ctx
    cid = await make_capture(ctx)
    st.store.capture_put_artifact(cid, "experiment.json", "application/json", b'{"status":"failed"}')
    blob = (await c.get(f"/api/v1/captures/{cid}/bundle?redact_macs=false")).content
    imp = parse_upload(blob, "capture.zip")
    imported = await st.captures.import_capture(imp, "round-trip")
    for name in (
        "experiment.json",
        "provenance_start.json",
        "provenance_end.json",
        "mlo/identity-tlv-decoder.py",
    ):
        assert (
            st.store.capture_artifact(imported.id, name) == st.store.capture_artifact(cid, name)
            if name == "experiment.json"
            else st.store.capture_artifact(imported.id, name) is not None
        )


async def test_import_artifacts_with_key_material_are_withheld(ctx):
    import hashlib

    c, _ = ctx
    cid = await make_capture(ctx)
    original = zipfile.ZipFile(
        io.BytesIO((await c.get(f"/api/v1/captures/{cid}/bundle?redact_macs=false")).content)
    )
    files = {n: original.read(n) for n in original.namelist()}
    secret = b'{"key_bytes":"synthetic-secret"}'
    manifest = json.loads(files["manifest.json"])
    manifest["files"]["unknown.json"] = {"sha256": hashlib.sha256(secret).hexdigest(), "bytes": len(secret)}
    files["manifest.json"] = json.dumps(manifest).encode()
    files["unknown.json"] = secret
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        for n, blob in files.items():
            z.writestr(n, blob)
    imported = parse_upload(buf.getvalue(), "capture.zip")
    assert "unknown.json" not in imported.artifacts
    assert any("key material" in warning for warning in imported.warnings)


async def test_experiment_persists_before_and_command_before_launch(ctx, monkeypatch):
    c, st = ctx
    dev = (await c.get("/api/v1/devices")).json()["devices"][0]
    root = st.host.root

    class LiveView:
        is_live = True

        def attr_int(self, path, *args, **kwargs):
            if path == f"/sys/class/net/{dev['netdevs'][0]}/device/vendor":
                return 0x14C3
            if path == f"/sys/class/net/{dev['netdevs'][0]}/device/device":
                return 0x0616
            return root.attr_int(path, *args, **kwargs)

        def readlink_name(self, path):
            if path == f"/sys/class/net/{dev['netdevs'][0]}/device/driver":
                return "mt7921e_git"
            return root.readlink_name(path)

        def __getattr__(self, name):
            return getattr(root, name)

    monkeypatch.setattr(st.host, "root", LiveView())
    monkeypatch.setattr(st.host, "tool_path", lambda name: name)

    async def measure(*args):
        return {"provenance": {"boot_id": "a"}, "counters": {"rx_packets": 1}, "per_link": []}

    monkeypatch.setattr(experiments, "measurement", measure)

    async def launch(argv, budget):
        rows = st.store.capture_list()
        persisted = json.loads(st.store.capture_artifact(rows[0]["id"], "experiment.json")[1])
        assert persisted["before"] and persisted["command"] == argv
        return 0, "partial output"

    monkeypatch.setattr(experiments, "run_command", launch)
    result = await experiments.run(
        st,
        experiments.ExperimentRequest(device_id=dev["id"], interface=dev["netdevs"][0], target="192.0.2.1"),
    )
    assert result.output == "partial output"


async def test_restart_retains_start_inventory_and_marks_experiment_incomplete(ctx):
    c, st = ctx
    cid = (await c.post("/api/v1/captures", json={})).json()["id"]
    assert st.store.capture_artifact(cid, "devices_start.json")
    st.store.capture_put_artifact(
        cid, "experiment.json", "application/json", b'{"status":"running","before":{"counters":{"rx":1}}}'
    )
    recovery = CaptureManager(st)
    await recovery.start()
    try:
        saved = json.loads(st.store.capture_artifact(cid, "experiment.json")[1])
        assert saved["status"] == "incomplete" and saved["before"]["counters"] == {"rx": 1}
    finally:
        await recovery.stop()


async def test_timeout_keeps_partial_process_output():
    with pytest.raises(TimeoutError) as failure:
        await experiments.run_command(
            [sys.executable, "-c", "import time; print('partial',flush=True); time.sleep(5)"], 0.2
        )
    assert "partial" in getattr(failure.value, "output", "")


async def test_selected_interface_controls_phy_and_authorization(ctx, monkeypatch):
    c, st = ctx
    d = await st.inventory.device((await c.get("/api/v1/devices")).json()["devices"][0]["id"])
    d = d.model_copy(deep=True)
    d.netdevs = ["wifi-a", "wifi-b"]
    d.phys = ["phy20", "phy21"]
    n = d.netdev_info[0]
    d.netdev_info = [
        n.model_copy(update={"name": name, "phy": phy}) for name, phy in zip(d.netdevs, d.phys, strict=True)
    ]

    async def device(_):
        return d

    monkeypatch.setattr(st.inventory, "device", device)
    interfaces = [
        SimpleNamespace(
            name=name,
            ifindex=i,
            iftype="STATION",
            mlo_links=[SimpleNamespace(model_dump=lambda freq=freq: {"link_id": 4, "freq_mhz": freq})],
        )
        for i, (name, freq) in enumerate(zip(d.netdevs, [5200, 6200], strict=True))
    ]
    monkeypatch.setattr(
        st.host,
        "nl80211",
        lambda: SimpleNamespace(
            interfaces=lambda: interfaces, stations=lambda i: [SimpleNamespace(flags={"authorized": bool(i)})]
        ),
    )
    calls = []

    def snap(host, dev, wake, phy=None):
        calls.append(phy)
        return SimpleNamespace(
            phy=phy,
            mlo_active_links=None,
            boottime_ns=1,
            link_stats=[],
            wcid_dump=[],
            model_dump=lambda **kw: {"phy": phy},
        )

    monkeypatch.setattr(experiments.mt76, "read_snapshot", snap)
    ambiguous = (await c.get(f"/api/v1/devices/{d.id}/mlo/evidence")).json()
    assert ambiguous["current_state"] is None
    selected = (await c.get(f"/api/v1/devices/{d.id}/mlo/evidence?interface=wifi-b")).json()["current_state"]
    assert selected["interface"] == "wifi-b" and selected["phy"] == "phy21"
    assert selected["links"][0]["freq_mhz"] == 6200
    assert selected["mac80211_authorized"] is True
    await experiments.measurement(st, d, "wifi-b", "192.0.2.1")
    assert calls[-1] == "phy21"
    interfaces[1].wiphy = 20
    interfaces[0].wiphy = 21
    moved = (await c.get(f"/api/v1/devices/{d.id}/mlo/evidence?interface=wifi-b")).json()["current_state"]
    assert moved["phy"] == "phy20"
    assert (await c.get(f"/api/v1/devices/{d.id}/mlo/evidence?interface=wifi-b&phy=phy21")).status_code == 422
    await experiments.measurement(st, d, "wifi-b", "192.0.2.1")
    assert calls[-1] == "phy20"
    interfaces[0].wiphy = 20
    count = len(calls)
    shared = (await c.get(f"/api/v1/devices/{d.id}/mlo/evidence?interface=wifi-b")).json()
    assert len(calls) == count and any("multiple station interfaces" in limit for limit in shared["limits"])
    measured = await experiments.measurement(st, d, "wifi-b", "192.0.2.1")
    assert len(calls) == count and not measured["per_link"]


def test_per_link_deltas_require_same_association_and_peer_lifetime():
    before = {
        "provenance": {"boot_id": "a"},
        "association_epoch": "epoch-a",
        "per_link": [{"link": 1, "wcid": 9, "generation": 3, "rx_pkts": 10}],
    }
    after = {
        "provenance": {"boot_id": "a"},
        "association_epoch": "epoch-a",
        "per_link": [{"link": 1, "wcid": 9, "generation": 4, "rx_pkts": 100}],
    }
    assert experiments.per_link_delta(before, after)["link=1 wcid=9"]["rx_pkts"] is None
    after["per_link"][0]["generation"] = 3
    assert experiments.per_link_delta(before, after)["link=1 wcid=9"]["rx_pkts"] == 90
    del before["association_epoch"]
    assert experiments.per_link_delta(before, after)["link=1 wcid=9"]["rx_pkts"] is None


async def test_comparison_rechecks_legacy_deltas_and_measurement_settings(ctx):
    c, st = ctx
    for count in (3, 10):
        cid = await make_capture(ctx)
        run = {
            "capture_id": cid,
            "status": "completed",
            "request": {
                "device_id": "d",
                "interface": "w",
                "target": "192.0.2.1",
                "tool": "ping",
                "count": count,
                "comparison_group": "legacy",
            },
            "before": {"provenance": {"boot_id": "a"}, "per_link": [{"link": 1, "wcid": 9, "rx_pkts": 10}]},
            "after": {"provenance": {"boot_id": "a"}, "per_link": [{"link": 1, "wcid": 9, "rx_pkts": 100}]},
            "per_link_deltas": {"link=1 wcid=9": {"rx_pkts": 90}},
        }
        st.store.capture_put_artifact(cid, "experiment.json", "application/json", json.dumps(run).encode())
    result = (await c.get("/api/v1/mlo/comparisons?group=legacy")).json()
    assert result["runs"][0]["per_link_deltas"]["link=1 wcid=9"]["rx_pkts"] is None
    assert result["comparable"] is False


def test_enum_unknown_expression_invalidates_following_implicit_values():
    path = Path(__file__).resolve().parents[2] / "tools/gen_mcu_tables.py"
    spec = importlib.util.spec_from_file_location("gen_mcu_tables", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    assert module.parse_enum("enum { A=1, B=BIT(4), C, D=9, E };", "A") == {"A": 1, "D": 9, "E": 10}


async def test_missing_trace_helper_returns_failed_run_not_http_500(ctx, monkeypatch):
    c, st = ctx
    dev = st.inventory.snapshot.devices[0]
    from whd.helper.protocol import HelperError

    class Broken:
        def call(self, *args, **kwargs):
            raise HelperError("missing", "tracefs unavailable")

    st.helper = Broken()
    original = st.host.root

    class LiveView:
        is_live = True

        def __getattr__(self, name):
            return getattr(original, name)

    monkeypatch.setattr(st.host, "root", LiveView())
    monkeypatch.setattr(experiments, "verify_live_adapter", lambda *args: {})

    async def measurement(*args):
        return {"counters": {}, "provenance": {}}

    monkeypatch.setattr(experiments, "measurement", measurement)
    result = await experiments.run(
        st,
        experiments.ExperimentRequest(
            device_id=dev.id, interface=dev.netdevs[0], target="192.0.2.1", trace_events=["net/net_dev_queue"]
        ),
    )
    assert result.status == "error"
    assert "tracefs" in result.error
    assert not result.command
