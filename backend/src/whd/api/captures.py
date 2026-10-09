"""Phase 6 endpoints: capture sessions, export, diagnostic bundles, replay."""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query, Response
from pydantic import BaseModel, Field

from whd.api.deps import get_state, require_auth
from whd.capture.manager import CaptureConfig, CaptureInfo
from whd.model.events import Event, TelemetrySample
from whd.state import AppState

router = APIRouter(prefix="/api/v1")
Auth = Depends(require_auth)
State = Depends(get_state)


def _mgr(st: AppState):  # type: ignore[no-untyped-def]
    if st.captures is None:
        raise HTTPException(503, "capture manager not running")
    return st.captures


@router.get("/captures", response_model=list[CaptureInfo])
async def list_captures(_: str = Auth, st: AppState = State) -> list[CaptureInfo]:
    return await _mgr(st).list_all()  # type: ignore[no-any-return]


@router.post("/captures", response_model=CaptureInfo)
async def create_capture(cfg: CaptureConfig, _: str = Auth, st: AppState = State) -> CaptureInfo:
    try:
        return await _mgr(st).create(cfg)  # type: ignore[no-any-return]
    except ValueError as e:
        raise HTTPException(409, str(e)) from e


@router.get("/captures/{cid}", response_model=CaptureInfo)
async def get_capture(cid: str, _: str = Auth, st: AppState = State) -> CaptureInfo:
    try:
        return await _mgr(st).info(cid)  # type: ignore[no-any-return]
    except KeyError:
        raise HTTPException(404, "unknown capture") from None


@router.post("/captures/{cid}/stop", response_model=CaptureInfo)
async def stop_capture(cid: str, _: str = Auth, st: AppState = State) -> CaptureInfo:
    try:
        return await _mgr(st).stop_capture(cid)  # type: ignore[no-any-return]
    except KeyError:
        raise HTTPException(404, "unknown capture") from None


@router.delete("/captures/{cid}")
async def delete_capture(cid: str, _: str = Auth, st: AppState = State) -> dict[str, bool]:
    await _mgr(st).delete(cid)
    return {"ok": True}


@router.get("/captures/{cid}/events", response_model=list[Event])
async def capture_events(
    cid: str, offset: int = 0, limit: int = Query(2000, ge=1, le=20000), _: str = Auth, st: AppState = State
) -> list[Event]:
    try:
        await _mgr(st).info(cid)
    except KeyError:
        raise HTTPException(404, "unknown capture") from None
    evs = await _mgr(st).events(cid)
    return evs[offset : offset + limit]  # type: ignore[no-any-return]


@router.get("/captures/{cid}/telemetry", response_model=list[TelemetrySample])
async def capture_telemetry(cid: str, _: str = Auth, st: AppState = State) -> list[TelemetrySample]:
    try:
        await _mgr(st).info(cid)
    except KeyError:
        raise HTTPException(404, "unknown capture") from None
    return await _mgr(st).telemetry(cid)  # type: ignore[no-any-return]


@router.get("/captures/{cid}/export")
async def export_capture(
    cid: str,
    format: str = Query("json", pattern="^(json|jsonl|csv|trace)$"),
    _: str = Auth,
    st: AppState = State,
) -> Response:
    try:
        ctype, data, name = await _mgr(st).export(cid, format)
    except KeyError:
        raise HTTPException(404, "unknown capture") from None
    return Response(
        content=data, media_type=ctype, headers={"Content-Disposition": f'attachment; filename="{name}"'}
    )


@router.get("/captures/{cid}/bundle")
async def bundle(cid: str, redact_macs: bool = True, actor: str = Auth, st: AppState = State) -> Response:
    try:
        data = await _mgr(st).bundle(cid, redact=redact_macs, extra=await _extras(st))
    except KeyError:
        raise HTTPException(404, "unknown capture") from None
    st.store.audit(actor, "bundle_download", {"capture": cid, "redact_macs": redact_macs})
    return Response(
        content=data,
        media_type="application/zip",
        headers={"Content-Disposition": f'attachment; filename="whd-bundle-{cid}.zip"'},
    )


async def _extras(st: AppState) -> dict[str, bytes]:
    """Optional bundle members from other modules (mt76 instrumentation, diagnostics) when available."""
    import json

    out: dict[str, bytes] = {}
    snap = st.inventory.snapshot
    if snap is None:
        return out
    from whd.drivers import mt76

    for d in snap.devices:
        if mt76.is_mt76(d) and d.present:
            try:
                import asyncio

                ins = await asyncio.to_thread(mt76.discover_instrumentation, st.host, d, True)
                out[f"mt76_instrumentation_{d.phys[0] if d.phys else 'x'}.json"] = ins.model_dump_json(
                    indent=1
                ).encode()
            except Exception as e:
                out[f"mt76_instrumentation_error_{d.id[:20]}.txt"] = repr(e).encode()
    diag = st.extra.get("diagnostics_report_json")
    if diag:
        out["diagnostics.json"] = json.dumps(diag, indent=1, default=str).encode()
    return out


class ReplayBody(BaseModel):
    speed: float = Field(1.0, ge=0.1, le=20)


@router.post("/captures/{cid}/replay")
async def start_replay(cid: str, body: ReplayBody, actor: str = Auth, st: AppState = State) -> dict[str, Any]:
    try:
        await _mgr(st).info(cid)
        r = await _mgr(st).replay(cid, body.speed)
    except KeyError:
        raise HTTPException(404, "unknown capture") from None
    except ValueError as e:
        raise HTTPException(409, str(e)) from e
    st.store.audit(actor, "replay_start", {"capture": cid, "speed": body.speed})
    return r  # type: ignore[no-any-return]


@router.post("/replay/stop")
async def stop_replay(_: str = Auth, st: AppState = State) -> dict[str, Any]:
    if st.events is None:
        raise HTTPException(409, "event runtime not running")
    await st.events.stop_replay()
    return st.events.replay_status()


@router.get("/replay/status")
async def replay_status(_: str = Auth, st: AppState = State) -> dict[str, Any]:
    return st.events.replay_status() if st.events else {"active": False}
