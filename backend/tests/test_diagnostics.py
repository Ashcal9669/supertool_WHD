from __future__ import annotations

import asyncio
import json
from collections.abc import AsyncIterator
from pathlib import Path

import httpx
import pytest

from conftest import fixture_host
from whd.app import build_state, create_app
from whd.config import Settings
from whd.diagnostics import engine
from whd.diagnostics.ollama import OllamaClient, check_summary, report_for_prompt
from whd.discovery import Discovery
from whd.events.sources import make_event
from whd.model.events import Event

SR = Path(__file__).parent / "fixtures" / "sysroots"
DEV = "pci:0000:07:00.0:14c3:7927"


def load(name: str) -> list[Event]:
    return [
        Event.model_validate_json(x)
        for x in (SR / name / "events.jsonl").read_text().splitlines()
        if x.strip()
    ]


def ev(t: float, kind: str, sev: str, cat: str, summary: str = "", **data):  # type: ignore[no-untyped-def]
    e = make_event(
        ts=int(t * 1e9),
        ts_source="receive_boottime",
        source="test",
        device_id=DEV,
        severity=sev,  # type: ignore[arg-type]
        category=cat,
        kind=kind,
        summary=summary or kind,
        explanation="x",
        raw="r",
        data=data,
    )
    e.id = int(t * 1000)
    return e


def devices(name: str = "mt7927-pcie-host"):  # type: ignore[no-untyped-def]
    return Discovery(fixture_host(name)).run().devices


def test_scripted_incident_is_found_and_hypothesis_is_unconfirmed() -> None:
    rep = engine.analyze(
        load("mt7927-pcie-host"), devices(), coverage={"mcu_lifecycle": "partial"}, helper_ok=True, demo=True
    )
    assert rep.cause_confirmed is False and "does not assert a root cause" in rep.disclaimer
    assert len(rep.incidents) >= 1
    inc = max(rep.incidents, key=lambda i: i.event_count)
    layers = [s.layer for s in inc.sequence]
    assert set(layers) >= {"firmware", "mac80211", "netdev"} and inc.severity in ("error", "critical")
    assert [s.rel_s for s in inc.sequence] == sorted(s.rel_s for s in inc.sequence)
    h = {x.id: x for x in rep.hypotheses}
    fw = h["H-fw-unresponsive"]
    assert fw.status == "unconfirmed" and fw.confidence in ("low", "moderate")
    assert fw.supporting and fw.unknowns and fw.follow_up_ids
    assert "root cause" not in fw.statement.lower()
    oids = {o.id for o in rep.observations}
    assert set(fw.supporting) <= oids and set(fw.contradicting) <= oids
    assert {m.id for m in rep.missing_instrumentation} >= {"M-reset-stages", "M-cov-mcu_lifecycle"}
    assert {f.id for f in rep.follow_ups} >= {"F-aer", "F-repeat"}
    assert any(
        c.a_kind == "firmware.mcu_retry" or c.a_kind == "firmware.mcu_timeout" for c in rep.correlations
    )
    assert any("polling" in lim for lim in rep.limits)


def test_baseline_without_errors_has_no_incidents_or_hypotheses() -> None:
    evs = [
        ev(1, "assoc.associated", "notice", "association"),
        ev(2, "netdev.state", "notice", "netdev"),
        ev(3, "trace.mt76.mlo_rx", "debug", "mlo"),
    ]
    rep = engine.analyze(evs, devices(), helper_ok=True)
    assert rep.incidents == [] and rep.hypotheses == [] and rep.patterns == []
    assert rep.scope.event_count == 3 and rep.scope.significant_event_count == 2


def test_bus_fault_first_contradicts_firmware_only_story() -> None:
    evs = [
        ev(10.0, "pci.aer.received", "error", "pci_error", "AER: Uncorrectable (Non-Fatal) error"),
        ev(10.4, "pci.link.changed", "warning", "pci_link"),
        ev(11.0, "firmware.mcu_timeout", "error", "firmware", cmd="00020027", seq="3"),
        ev(11.2, "reset.chip_reset", "warning", "reset"),
        ev(11.5, "assoc.deauth_local", "notice", "association"),
    ]
    rep = engine.analyze(evs, devices(), helper_ok=True)
    h = {x.id: x for x in rep.hypotheses}
    assert "H-bus-precedes" in h and h["H-bus-precedes"].confidence == "low"
    fw = h["H-fw-unresponsive"]
    assert fw.contradicting, "bus events before the MCU timeout must be recorded as contradicting evidence"
    assert fw.confidence == "low"
    inc = rep.incidents[0]
    assert inc.earliest_layers[0] == "bus" and inc.sequence[0].layer == "bus"


def test_recurring_pattern_detection() -> None:
    evs = [ev(5.0 * i, "firmware.mcu_timeout", "error", "firmware") for i in range(1, 6)]
    rep = engine.analyze(evs, devices(), helper_ok=False)
    (p,) = rep.patterns
    assert p.count == 5 and p.median_interval_s == 5.0 and p.regularity == "periodic"
    assert any(
        m.id == "M-helper" for m in rep.missing_instrumentation
    )  # helper missing is reported, not hidden
    # five separate single-event clusters of 5 s spacing merge into one incident (gap 8 s)
    assert len(rep.incidents) == 1


def test_usb_hypothesis_and_missing_usbmon() -> None:
    evs = [
        ev(1, "usb.reset", "warning", "reset"),
        ev(2, "usb.reset", "warning", "reset"),
        ev(3, "usb.disconnect", "warning", "hotplug"),
    ]
    rep = engine.analyze(evs, devices("mt7921u-usb"), helper_ok=True)
    assert any(h.id == "H-usb-instability" for h in rep.hypotheses)
    assert any(m.id == "M-usbmon" for m in rep.missing_instrumentation)
    assert "F-usbmon" in {f.id for f in rep.follow_ups}


def test_demo_usb_story_yields_usb_hypothesis() -> None:
    rep = engine.analyze(load("mt7921u-usb"), devices("mt7921u-usb"), helper_ok=True, demo=True)
    assert rep.scope.demo and any(h.id == "H-usb-instability" for h in rep.hypotheses)
    assert all(h.status == "unconfirmed" for h in rep.hypotheses)


def test_unattributed_events_flagged() -> None:
    e = ev(1, "driver.kv_trace", "warning", "mlo")
    e.device_id = None
    rep = engine.analyze([e], devices(), helper_ok=True)
    assert rep.scope.unattributed_events == 1 and any(
        m.id == "M-attribution" for m in rep.missing_instrumentation
    )


# ------------------------------------------------------------------------------------------- ollama


def test_prompt_contains_report_only_and_masks_macs() -> None:
    evs = load("mt7927-pcie-host")
    rep = engine.analyze(evs, devices(), helper_ok=True)
    rep.observations[0].text += " peer 8c:ed:e1:98:cc:18"
    p = report_for_prompt(rep, redact=True)
    assert "8c:ed:e1:98:cc:18" not in p and "8c:ed:e1:xx:xx:01" in p
    assert '"raw"' not in p and "ts_wall" not in p  # no raw event payloads
    assert "8c:ed:e1:98:cc:18" in report_for_prompt(rep, redact=False)


def test_summary_checks_flag_ungrounded_output() -> None:
    rep = engine.analyze(load("mt7927-pcie-host"), devices(), helper_ok=True)
    good = "Observed\n[O1] things. Hypotheses (unconfirmed)\n[H-fw-unresponsive]. Next tests\n[F-repeat]."
    assert check_summary(good, rep) == []
    bad = "The root cause is the firmware [H-made-up]."
    w = check_summary(bad, rep)
    assert any("H-made-up" in x for x in w) and any("may assert a cause" in x for x in w)
    assert any("no report ids" in x for x in check_summary("plain text without citations", rep))


@pytest.fixture
def ollama_mock() -> httpx.MockTransport:
    calls: list[dict[str, object]] = []

    def handler(req: httpx.Request) -> httpx.Response:
        if req.url.path == "/api/tags":
            return httpx.Response(
                200, json={"models": [{"name": "tiny:1b", "size": 1, "details": {"parameter_size": "1B"}}]}
            )
        if req.url.path == "/api/generate":
            body = json.loads(req.content)
            calls.append(body)
            return httpx.Response(
                200,
                json={
                    "response": "Observed\n[O1] x\nHypotheses (unconfirmed)\n[H-fw-unresponsive]\n"
                    "Next tests\n[F-repeat]",
                    "eval_count": 42,
                },
            )
        return httpx.Response(404)

    t = httpx.MockTransport(handler)
    t.calls = calls  # type: ignore[attr-defined]
    return t


async def test_ollama_client_with_mock(
    monkeypatch: pytest.MonkeyPatch, ollama_mock: httpx.MockTransport
) -> None:
    real = httpx.AsyncClient

    def patched(*a, **kw):  # type: ignore[no-untyped-def]
        kw["transport"] = ollama_mock
        return real(*a, **kw)

    monkeypatch.setattr("whd.diagnostics.ollama.httpx.AsyncClient", patched)
    rep = engine.analyze(load("mt7927-pcie-host"), devices(), helper_ok=True)
    c = OllamaClient("http://127.0.0.1:11434")
    st = await c.status()
    assert st.reachable and st.loopback and st.models[0]["name"] == "tiny:1b"
    s = await c.summarize(rep, "tiny:1b")
    assert s.generated_by == "ollama:tiny:1b" and s.not_evidence and s.warnings == []
    sent = ollama_mock.calls[0]  # type: ignore[attr-defined]
    assert (
        sent["stream"] is False and "UNCONFIRMED" in sent["system"] and sent["options"]["temperature"] <= 0.2
    )
    with pytest.raises(ValueError, match="not installed"):
        await c.summarize(rep, "other:7b")
    with pytest.raises(ValueError):
        await c.summarize(rep, "bad name; rm -rf /")


async def test_ollama_unreachable_does_not_break_platform() -> None:
    c = OllamaClient("http://127.0.0.1:1")  # nothing listens
    st = await c.status()
    assert not st.reachable and st.error


# ------------------------------------------------------------------------------------------- API


@pytest.fixture
async def client(settings: Settings) -> AsyncIterator[httpx.AsyncClient]:
    settings.ollama_url = "http://127.0.0.1:1"
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
        st.store.insert_events(load("mt7927-pcie-host")[:0])  # store starts empty in the isolated test DB
        yield c


async def test_analyze_api_and_llm_optional(client: httpx.AsyncClient) -> None:
    r = await client.post("/api/v1/diagnostics/analyze", json={"window_s": 3600})
    assert r.status_code == 200
    rep = r.json()
    assert rep["cause_confirmed"] is False and rep["scope"]["demo"] is True
    assert (await client.get(f"/api/v1/diagnostics/reports/{rep['report_id']}")).status_code == 200
    assert (await client.get("/api/v1/diagnostics/latest")).json()["report_id"] == rep["report_id"]
    s = await client.get("/api/v1/diagnostics/llm/status")
    assert s.status_code == 200 and s.json()["reachable"] is False  # platform works with Ollama absent
    r = await client.post(
        "/api/v1/diagnostics/llm/summarize", json={"report_id": rep["report_id"], "model": "tiny:1b"}
    )
    assert r.status_code == 503 and "not reachable" in r.text
    assert (
        await client.post("/api/v1/diagnostics/llm/summarize", json={"report_id": "nope"})
    ).status_code == 404
    assert (
        await client.post("/api/v1/diagnostics/analyze", json={"capture_id": "cap-none"})
    ).status_code == 404
    _ = asyncio
