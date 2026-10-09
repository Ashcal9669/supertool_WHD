"""Phase 7 endpoints: evidence-based analysis and optional local-LLM summary."""

from __future__ import annotations

import asyncio
import json
from typing import Any

import httpx
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field

from whd.api.deps import get_state, require_auth
from whd.clock import boottime_ns
from whd.diagnostics import engine
from whd.diagnostics.models import DiagnosticReport
from whd.diagnostics.ollama import OllamaClient, OllamaStatus, Summary
from whd.drivers import mt76
from whd.model.device import Device
from whd.model.events import EventFilter
from whd.state import AppState

router = APIRouter(prefix="/api/v1")
Auth = Depends(require_auth)
State = Depends(get_state)
MAX_REPORTS = 20


class AnalyzeBody(BaseModel):
    device_id: str | None = None
    window_s: int = Field(3600, ge=10, le=7 * 86400)
    capture_id: str | None = None


class SummarizeBody(BaseModel):
    report_id: str
    model: str | None = None
    redact_macs: bool = True


async def _coverage(st: AppState, device_ids: list[str]) -> dict[str, str]:
    snap = st.inventory.snapshot
    out: dict[str, str] = {}
    if snap is None:
        return out
    for d in snap.devices:
        if d.id in device_ids and mt76.is_mt76(d) and d.present:
            try:
                ins = await asyncio.to_thread(mt76.discover_instrumentation, st.host, d, True)
            except Exception:
                continue
            for i in ins.items:
                out.setdefault(i.id, i.status)
                if i.status != "available":
                    out[i.id] = i.status
    return out


@router.post("/diagnostics/analyze", response_model=DiagnosticReport)
async def analyze(body: AnalyzeBody, actor: str = Auth, st: AppState = State) -> DiagnosticReport:
    snap = await st.inventory.get()
    imported = False
    origin: dict[str, Any] = {}
    cap_devices: list[Device] | None = None
    cap_cov: dict[str, str] = {}
    if body.capture_id:
        if st.captures is None:
            raise HTTPException(503, "capture manager not running")
        try:
            info = await st.captures.info(body.capture_id)
        except KeyError:
            raise HTTPException(404, "unknown capture") from None
        events = await st.captures.events(body.capture_id)
        window = None
        imported = info.mode == "imported"
        if imported:
            # An imported capture is analyzed against ITS OWN inventory/coverage, never this host's.
            origin = await st.captures.artifact_json(body.capture_id, "origin.json") or {}
            raw = (await st.captures.artifact_json(body.capture_id, "devices_start.json") or {}).get(
                "devices", []
            )
            cap_devices = []
            for d in raw:
                try:
                    cap_devices.append(Device.model_validate(d))
                except ValueError:
                    continue
            cap_cov = await st.captures.artifact_json(body.capture_id, "coverage.json") or {}
    else:
        flt = EventFilter(since_ns=boottime_ns() - body.window_s * 10**9)
        events = await asyncio.to_thread(st.store.query_events, flt, None, 100000, "asc")
        window = float(body.window_s)
    if body.device_id:
        events = [e for e in events if e.device_id in (body.device_id, None)]
    devices = [
        d
        for d in (cap_devices if cap_devices is not None else snap.devices)
        if body.device_id in (None, d.id)
    ]
    if imported:
        cov, helper_ok = cap_cov, True  # host helper state says nothing about another machine
        demo = bool(origin.get("all_events_demo"))
    else:
        cov = await _coverage(st, [d.id for d in devices])
        helper_ok = bool(st.helper and st.helper.available)
        demo = st.settings.mode == "demo"
    rep = await asyncio.to_thread(
        engine.analyze,
        events,
        devices,
        window_s=window,
        coverage=cov,
        helper_ok=helper_ok,
        demo=demo,
        capture_id=body.capture_id,
        device_filter=body.device_id,
        imported=imported,
    )
    reports: dict[str, DiagnosticReport] = st.extra.setdefault("diag_reports", {})
    reports[rep.report_id] = rep
    while len(reports) > MAX_REPORTS:
        reports.pop(next(iter(reports)))
    st.extra["diagnostics_report_json"] = json.loads(rep.model_dump_json())
    await asyncio.to_thread(st.store.kv_set, "diag.latest", rep.model_dump_json())
    st.store.audit(
        actor,
        "diagnostics_analyze",
        {
            "device": body.device_id,
            "capture": body.capture_id,
            "window_s": body.window_s,
            "report": rep.report_id,
        },
    )
    return rep


@router.get("/diagnostics/latest", response_model=DiagnosticReport)
async def latest(_: str = Auth, st: AppState = State) -> DiagnosticReport:
    reports: dict[str, DiagnosticReport] = st.extra.get("diag_reports", {})
    if reports:
        return list(reports.values())[-1]
    raw = await asyncio.to_thread(st.store.kv_get, "diag.latest")
    if raw:
        return DiagnosticReport.model_validate_json(raw)
    raise HTTPException(404, "no analysis has been run yet")


@router.get("/diagnostics/reports/{report_id}", response_model=DiagnosticReport)
async def get_report(report_id: str, _: str = Auth, st: AppState = State) -> DiagnosticReport:
    rep = st.extra.get("diag_reports", {}).get(report_id)
    if rep is None:
        raise HTTPException(404, "unknown or expired report")
    return rep  # type: ignore[no-any-return]


def _client(st: AppState) -> OllamaClient:
    return OllamaClient(st.settings.ollama_url, st.settings.ollama_model)


@router.get("/diagnostics/llm/status", response_model=OllamaStatus)
async def llm_status(_: str = Auth, st: AppState = State) -> OllamaStatus:
    return await _client(st).status()


@router.post("/diagnostics/llm/summarize", response_model=Summary)
async def llm_summarize(body: SummarizeBody, actor: str = Auth, st: AppState = State) -> Summary:
    rep = st.extra.get("diag_reports", {}).get(body.report_id)
    if rep is None:
        raise HTTPException(404, "unknown or expired report; run the analysis again")
    try:
        summary = await _client(st).summarize(rep, body.model, body.redact_macs)
    except ValueError as e:
        raise HTTPException(422, str(e)) from e
    except ConnectionError as e:
        raise HTTPException(503, str(e)) from e
    except httpx.HTTPError as e:
        raise HTTPException(502, f"Ollama request failed: {type(e).__name__}: {e}") from e
    st.store.audit(
        actor,
        "llm_summarize",
        {"report": body.report_id, "model": summary.model, "elapsed_s": summary.elapsed_s},
    )
    return summary
