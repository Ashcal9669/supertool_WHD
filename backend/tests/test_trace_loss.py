"""Owned-instance loss observations; all tracefs and streams here are fake."""

import asyncio
import io
import json
import threading
import zipfile
from pathlib import Path

import pytest

from whd.events.sources import TraceSource
from whd.helper import server
from whd.helper.server import Helper, Roots, TraceSession

pytest_plugins = ["test_capture"]


def fake_helper(tmp_path):
    roots = Roots(sys=tmp_path / "sys", tracefs=tmp_path / "tracing", debugfs=tmp_path / "debug")
    roots.tracefs.mkdir()
    h = Helper(roots, set(), set())
    h.trace = TraceSession(events=["mt76/mlo_rx"], clock="boot")
    return h


def cpu_stats(h, cpu, body):
    p = h.roots.tracefs / "instances/whd/per_cpu" / cpu / "stats"
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(body)
    return p


def test_owned_per_cpu_loss_counters_are_separate_not_added_together(tmp_path):
    h = fake_helper(tmp_path)
    cpu_stats(h, "cpu0", "entries: 100\noverrun: 7\ncommit overrun: 2\ndropped events: 3\n")
    cpu_stats(h, "cpu2", "overrun: 0\ncommit overrun: 1\ndropped events: 4\n")
    loss = h.tracefs_status()["whd_session"]["loss"]["kernel"]
    assert loss["totals"] == {"overrun": 7, "commit_overrun": 3, "dropped_events": 7}
    assert loss["cpus"]["cpu0"]["overrun"] == 7
    assert loss["coverage"]["cpus"] == ["cpu0", "cpu2"]
    assert all(c["complete"] for c in loss["coverage"]["metrics"].values())


def test_missing_malformed_and_duplicate_stats_are_unknown(tmp_path):
    h = fake_helper(tmp_path)
    cpu_stats(h, "cpu0", "overrun: 5\ncommit overrun: junk\ndropped events: -1\n")
    cpu_stats(h, "cpu1", "overrun: 0\noverrun: 1\ncommit overrun: 0\n").unlink()
    loss = h.tracefs_status()["whd_session"]["loss"]["kernel"]
    assert loss["totals"] == {"overrun": None, "commit_overrun": None, "dropped_events": None}
    assert loss["cpus"]["cpu0"] == {"overrun": 5, "commit_overrun": None, "dropped_events": None}
    assert loss["coverage"]["metrics"]["overrun"]["missing_cpus"] == ["cpu1"]
    cpu_stats(h, "cpu1", "overrun: 0\noverrun: 1\ncommit overrun: 0\ndropped events: 0\n")
    assert h.tracefs_status()["whd_session"]["loss"]["kernel"]["cpus"]["cpu1"]["overrun"] is None


def test_inactive_or_escaped_cpu_stats_are_never_read(tmp_path, monkeypatch):
    h = fake_helper(tmp_path)
    outside = h.roots.tracefs / "instances/other/per_cpu/cpu0/stats"
    outside.parent.mkdir(parents=True)
    outside.write_text("overrun: 999\n")
    p = cpu_stats(h, "cpu0", "overrun: 1\n")
    p.unlink()
    p.symlink_to(outside)
    read = server._read
    touched = []

    def record(path, limit):
        touched.append(path)
        return read(path, limit)

    monkeypatch.setattr(server, "_read", record)
    assert h.tracefs_status()["whd_session"]["loss"]["kernel"]["totals"]["overrun"] is None
    assert not touched
    h.trace = None
    assert h.tracefs_status()["whd_session"] is None
    assert not touched


def test_rate_limit_loss_is_not_queue_loss(tmp_path, monkeypatch):
    h = fake_helper(tmp_path)
    pipe = tmp_path / "trace_pipe"
    pipe.write_bytes(b"one\ntwo\nthree\n")
    session = TraceSession(events=[], clock="boot")
    monkeypatch.setattr(server, "MAX_LINES_PER_SEC", 1)

    def emit(lines, dropped):
        assert lines == ["one"]
        session.stop.set()

    h._pump(pipe, session, emit)
    assert session.rate_limit_dropped == 2 and session.queue_dropped == 0


async def test_stream_retains_queue_loss_and_final_cpu_stats_before_teardown(tmp_path, monkeypatch):
    h = fake_helper(tmp_path)
    session = h.trace
    cpu_stats(h, "cpu0", "overrun: 4\ncommit overrun: 0\ndropped events: 1\n")
    monkeypatch.setattr(h, "_trace_setup", lambda *args: session)
    finished = threading.Event()

    def pump(path, active, emit):
        for _ in range(300):
            emit(["line"], 0)
        finished.set()

    monkeypatch.setattr(h, "_pump", pump)
    monkeypatch.setattr(h, "_trace_teardown", lambda: cpu_stats(h, "cpu0", "").unlink())
    messages = []

    async def send(msg):
        messages.append(msg)
        if "stream" in msg:
            await asyncio.sleep(0.005)

    result = await h.trace_stream(send, 1, ["mt76/mlo_rx"], max_seconds=1)
    assert finished.is_set() and h.trace is None
    assert result["loss"]["helper"]["queue_dropped"] > 0
    assert result["loss"]["helper"]["rate_limit_dropped"] == 0
    assert result["loss"]["kernel"]["totals"]["overrun"] == 4
    assert result["dropped"] == result["loss"]["helper"]["queue_dropped"]


class StreamHelper:
    available = True

    def __init__(self, messages):
        self.messages = messages

    async def stream(self, *args, **kwargs):
        for msg in self.messages:
            yield msg


async def test_source_retains_cumulative_drop_counters_including_final_result(ctx):
    _, st = ctx
    st.host.helper = StreamHelper(
        [
            {"stream_start": {"events": [], "clock": "boot", "instance": "instances/whd"}},
            {
                "stream": [],
                "dropped": 3,
                "loss": {"helper": {"rate_limit_dropped": 2, "queue_dropped": 1, "total_dropped": 3}},
            },
            {
                "stream": [],
                "dropped": 3,
                "loss": {"helper": {"rate_limit_dropped": 2, "queue_dropped": 1, "total_dropped": 3}},
            },
            {
                "result": {
                    "dropped": 5,
                    "loss": {"helper": {"rate_limit_dropped": 2, "queue_dropped": 3, "total_dropped": 5}},
                }
            },
        ]
    )
    src = TraceSource(st.events.ctx, [], 64, 1)
    await src.run()
    assert src.loss["helper"] == {"rate_limit_dropped": 2, "queue_dropped": 3, "total_dropped": 5}
    assert src.loss["kernel"] is None
    st.events.trace = src
    st.events.tasks["trace"] = asyncio.create_task(asyncio.sleep(0))
    await st.events.tasks["trace"]
    await st.events.stop_trace()
    assert st.events.trace_status()["result"]["dropped"] == 5
    assert st.events.trace_status()["loss"]["helper"]["queue_dropped"] == 3


async def test_legacy_helper_keeps_split_and_kernel_loss_unknown(ctx):
    _, st = ctx
    st.host.helper = StreamHelper([{"stream": [], "dropped": 4}, {"result": {"dropped": 6}}])
    src = TraceSource(st.events.ctx, [], 64, 1)
    await src.run()
    assert src.loss["helper"] == {"rate_limit_dropped": None, "queue_dropped": None, "total_dropped": 6}
    assert src.loss["kernel"] is None


async def test_capture_retains_final_trace_result_and_import_does_not_refresh_it(ctx, monkeypatch):
    c, st = ctx
    loss = {"helper": {"rate_limit_dropped": 2, "queue_dropped": 3, "total_dropped": 5}, "kernel": None}
    before = {"active": True, "loss": loss, "result": None}
    final = {"active": False, "loss": loss, "result": {"ended": "max_seconds", "loss": loss}}
    status = [before]
    monkeypatch.setattr(st.events, "trace_status", lambda: status[0])

    async def start(*args):
        return {"started": {"instance": "instances/whd"}}

    async def stop():
        status[0] = final
        return {"stopped": True, **final}

    monkeypatch.setattr(st.events, "start_trace", start)
    monkeypatch.setattr(st.events, "stop_trace", stop)
    st.helper = None
    cid = (await c.post("/api/v1/captures", json={"trace_events": ["mt76/mlo_rx"]})).json()["id"]
    from test_capture import ev

    st.bus.publish(ev(1))
    await c.post(f"/api/v1/captures/{cid}/stop")
    provenance = await st.captures.artifact_json(cid, "provenance_end.json")
    assert provenance["trace_status"]["result"] == final["result"]
    artifact = await st.captures.artifact_json(cid, "trace-status-end.json")
    assert artifact["before_stop"]["active"] is True and artifact["after_stop"]["active"] is False
    assert provenance["lost_trace_events"] is None
    bundle = await st.captures.bundle(cid, redact=False)
    from whd.capture.importer import parse_upload

    imp = await st.captures.import_capture(parse_upload(bundle, "loss.zip"), "historical")
    monkeypatch.setattr(
        st.events, "trace_status", lambda: pytest.fail("must not refresh imported trace status")
    )
    exported = await st.captures.bundle(imp.id, redact=False)
    with zipfile.ZipFile(io.BytesIO(exported)) as z:
        assert json.loads(z.read("provenance_end.json"))["trace_status"] == final
        assert json.loads(z.read("trace-status-end.json")) == artifact


async def test_bundle_exports_current_decoder_hashes_and_preserves_imported_sources(ctx):
    c, st = ctx
    cid = (await c.post("/api/v1/captures", json={})).json()["id"]
    from test_capture import ev
    from whd.capture.importer import parse_upload

    st.bus.publish(ev(1))
    await c.post(f"/api/v1/captures/{cid}/stop")
    bundle = await st.captures.bundle(cid, redact=False)
    import hashlib

    source_root = Path(__file__).parents[1] / "src/whd/mlo"
    with zipfile.ZipFile(io.BytesIO(bundle)) as z:
        manifest = json.loads(z.read("analysis/decoder-manifest.json"))
        for module in ("transport", "rx_layout", "rx", "mcu", "fwid", "tx_observation", "state", "report"):
            source = source_root / f"{module}.py"
            if source.exists():
                name = f"analysis/decoders/{module}.py"
                assert z.read(name) == source.read_bytes()
                assert manifest["files"][name] == hashlib.sha256(z.read(name)).hexdigest()
        original_evidence = z.read("mlo/evidence.json")
        original_identity = z.read("mlo/identity-tlv-decoder.py")
    imp = await st.captures.import_capture(parse_upload(bundle, "source.zip"), "original sources")
    marker = b"# imported decoder revision\n"
    await asyncio.to_thread(
        st.store.capture_put_artifact, imp.id, "analysis/decoders/transport.py", "text/plain", marker
    )
    exported = await st.captures.bundle(imp.id, redact=False)
    with zipfile.ZipFile(io.BytesIO(exported)) as z:
        assert z.read("imported-analysis/decoders/transport.py") == marker
        assert z.read("mlo/evidence.json") == original_evidence
        assert z.read("mlo/identity-tlv-decoder.py") == original_identity


async def test_cancelled_stream_retains_pre_cleanup_sample_but_not_a_fake_final(ctx, monkeypatch):
    _, st = ctx
    session_start = {"instance": "instances/whd", "started": 123.0}
    counters = {"helper": {"rate_limit_dropped": 2, "queue_dropped": 1, "total_dropped": 3}, "kernel": None}
    calls = []

    class HelperStatus:
        def call(self, verb, timeout):
            calls.append(verb)
            return {"whd_session": {"started": 123.0, "loss": counters}}

    st.host.helper = HelperStatus()
    src = TraceSource(st.events.ctx, [], 64, 1)
    src.started = session_start
    st.events.trace = src
    st.events.tasks["trace"] = asyncio.create_task(asyncio.sleep(60))
    result = await st.events.stop_trace()
    assert calls == ["tracefs_status"]
    assert result["loss"] == counters
    assert result["result"] is None and result["final_result_available"] is False
    assert st.events.trace_status()["loss"] == counters
