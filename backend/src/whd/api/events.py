"""Phase 3/4 endpoints: event history, sources, telemetry, tracing control, WebSocket stream."""

from __future__ import annotations

import asyncio
import contextlib
import json
import time
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query, WebSocket, WebSocketDisconnect
from pydantic import BaseModel, Field

from whd.api.deps import get_state, require_auth
from whd.clock import boottime_ns
from whd.helper.protocol import HelperError
from whd.model.common import Model
from whd.model.events import Event, EventFilter, Severity, TelemetrySample
from whd.state import AppState

router = APIRouter(prefix="/api/v1")
Auth = Depends(require_auth)
State = Depends(get_state)


def _csv(v: str | None) -> list[str] | None:
    return [x for x in v.split(",") if x] if v else None


class EventPage(Model):
    events: list[Event]
    next_after_id: int | None
    server_boottime_ns: int
    server_wall: float


@router.get("/events", response_model=EventPage)
async def list_events(
    _: str = Auth,
    st: AppState = State,
    device_id: str | None = None,
    categories: str | None = None,
    min_severity: Severity | None = None,
    sources: str | None = None,
    kinds: str | None = None,
    text: str | None = None,
    since_ns: int | None = None,
    until_ns: int | None = None,
    after_id: int | None = None,
    limit: int = Query(500, ge=1, le=10000),
    order: str = Query("desc", pattern="^(asc|desc)$"),
) -> EventPage:
    flt = EventFilter(
        device_id=device_id,
        categories=_csv(categories),
        min_severity=min_severity,
        sources=_csv(sources),
        kinds=_csv(kinds),
        text=text,
        since_ns=since_ns,
        until_ns=until_ns,
    )
    evs = await asyncio.to_thread(st.store.query_events, flt, after_id, limit, order)
    nxt = max((e.id or 0 for e in evs), default=None)
    return EventPage(events=evs, next_after_id=nxt, server_boottime_ns=boottime_ns(), server_wall=time.time())


@router.get("/events/{event_id}", response_model=Event)
async def get_event(event_id: int, _: str = Auth, st: AppState = State) -> Event:
    evs = await asyncio.to_thread(st.store.query_events, None, event_id - 1, 1, "asc")
    if not evs or evs[0].id != event_id:
        raise HTTPException(404, "unknown event")
    return evs[0]


@router.get("/sources")
async def sources(_: str = Auth, st: AppState = State) -> dict[str, Any]:
    if st.events is None:
        return {"sources": [], "published": st.bus.published}
    return {
        "sources": st.events.status(),
        "published": st.bus.published,
        "ring": len(st.bus.ring),
        "stored": await asyncio.to_thread(st.store.event_count),
    }


@router.get("/telemetry", response_model=list[TelemetrySample])
async def telemetry(
    _: str = Auth,
    st: AppState = State,
    device_id: str | None = None,
    series_prefix: str | None = None,
    since_ns: int | None = None,
    limit: int = Query(3600, ge=1, le=20000),
) -> list[TelemetrySample]:
    out = [
        s
        for s in st.bus.telemetry
        if (device_id is None or s.device_id == device_id)
        and (series_prefix is None or s.series.startswith(series_prefix))
        and (since_ns is None or s.ts_boottime_ns >= since_ns)
    ]
    return out[-limit:]


# ---------------------------------------------------------------- tracing


class TraceStart(BaseModel):
    events: list[str] = Field(min_length=1, max_length=256, description="'group/event' or 'group/*'")
    buffer_kb: int = Field(4096, ge=64, le=16384)
    max_seconds: int = Field(600, ge=5, le=24 * 3600)


@router.get("/trace/available")
async def trace_available(
    _: str = Auth, st: AppState = State, groups: str | None = None, with_format: bool = False
) -> dict[str, Any]:
    h = st.helper
    if h is None or not h.available:
        raise HTTPException(409, "tracefs requires the whd-helper (not running)")
    try:
        args: dict[str, Any] = {}
        if groups:
            args = {"groups": _csv(groups), "with_format": with_format}
        result: dict[str, Any] = await asyncio.to_thread(h.call, "tracefs_events", 10.0, **args)
        return result
    except HelperError as e:
        raise HTTPException(409, f"helper: {e}") from e


@router.get("/trace/status")
async def trace_status(_: str = Auth, st: AppState = State) -> dict[str, Any]:
    out: dict[str, Any] = st.events.trace_status() if st.events else {"active": False}
    h = st.helper
    if h is not None and h.available:
        with contextlib.suppress(HelperError):
            out["tracefs"] = await asyncio.to_thread(h.call, "tracefs_status", 5.0)
    return out


@router.post("/trace/start")
async def trace_start(body: TraceStart, actor: str = Auth, st: AppState = State) -> dict[str, Any]:
    if st.events is None:
        raise HTTPException(409, "event runtime not running")
    if st.settings.mode == "demo":
        raise HTTPException(409, "tracing is not available in demo mode")
    try:
        r = await st.events.start_trace(body.events, body.buffer_kb, body.max_seconds)
    except RuntimeError as e:
        raise HTTPException(409, str(e)) from e
    st.store.audit(actor, "trace_start", body.model_dump())
    return r


@router.post("/trace/stop")
async def trace_stop(actor: str = Auth, st: AppState = State) -> dict[str, Any]:
    if st.events is None:
        raise HTTPException(409, "event runtime not running")
    r = await st.events.stop_trace()
    st.store.audit(actor, "trace_stop", r)
    return r


# ---------------------------------------------------------------- WebSocket stream


def _filter_from(params: dict[str, Any]) -> EventFilter:
    return EventFilter(
        device_id=params.get("device_id") or None,
        categories=_csv(params.get("categories")),
        min_severity=params.get("min_severity") or None,
        sources=_csv(params.get("sources")),
        kinds=_csv(params.get("kinds")),
        text=params.get("text") or None,
    )


@router.websocket("/stream")
async def stream(ws: WebSocket) -> None:
    st: AppState = ws.app.state.whd
    if not st.auth.check_ws(ws):
        await ws.close(code=4401, reason="authentication required")
        return
    await ws.accept()
    q = ws.query_params
    try:
        flt = _filter_from(dict(q))
    except ValueError:
        await ws.close(code=4400, reason="bad filter")
        return
    want_tel = q.get("telemetry") == "1"
    sub = st.bus.subscribe(flt)
    tel_id, tel_q = st.bus.subscribe_telemetry() if want_tel else (None, None)
    send_lock = asyncio.Lock()

    async def send(obj: dict[str, Any]) -> None:
        async with send_lock:
            await ws.send_text(json.dumps(obj, default=str))

    async def pump_events() -> None:
        while True:
            e = await sub.queue.get()
            await send({"type": "event", "event": e.model_dump(mode="json")})

    async def pump_tel() -> None:
        assert tel_q is not None
        while True:
            s = await tel_q.get()
            await send({"type": "telemetry", "sample": s.model_dump(mode="json")})

    async def status_loop() -> None:
        while True:
            await asyncio.sleep(5)
            await send(
                {
                    "type": "status",
                    "dropped": sub.dropped,
                    "server_boottime_ns": boottime_ns(),
                    "sources": st.events.status() if st.events else [],
                }
            )

    async def recv_loop() -> None:
        nonlocal flt
        while True:
            msg = json.loads(await ws.receive_text())
            if msg.get("type") == "filter":
                flt = _filter_from(msg)
                sub.flt = flt
                await send({"type": "filter_ack", "filter": flt.model_dump()})
            elif msg.get("type") == "ping":
                await send({"type": "pong", "server_boottime_ns": boottime_ns()})

    tasks: list[asyncio.Task[None]] = []
    try:
        await send(
            {
                "type": "hello",
                "mode": st.settings.mode,
                "server_boottime_ns": boottime_ns(),
                "server_wall": time.time(),
                "subscriber": sub.id,
            }
        )
        since_id = q.get("since_id")
        if since_id is not None and since_id.isdigit():
            backlog = await asyncio.to_thread(st.store.query_events, flt, int(since_id), 2000, "asc")
            for e in backlog:
                await send({"type": "event", "event": e.model_dump(mode="json"), "backlog": True})
            await send({"type": "backlog_done", "count": len(backlog), "truncated": len(backlog) >= 2000})
        tasks = [
            asyncio.create_task(pump_events()),
            asyncio.create_task(status_loop()),
            asyncio.create_task(recv_loop()),
        ]
        if want_tel:
            tasks.append(asyncio.create_task(pump_tel()))
        done, _ = await asyncio.wait(tasks, return_when=asyncio.FIRST_EXCEPTION)
        for t in done:
            exc = t.exception()
            if exc and not isinstance(exc, WebSocketDisconnect):
                raise exc
    except (WebSocketDisconnect, RuntimeError, ConnectionError):
        pass
    finally:
        for t in tasks:
            t.cancel()
        st.bus.unsubscribe(sub)
        if tel_id is not None:
            st.bus.unsubscribe_telemetry(tel_id)
        with contextlib.suppress(Exception):
            await ws.close()


# ---------------------------------------------------------------- usbmon (optional, explicit)


class UsbmonStart(BaseModel):
    buses: list[int] | None = Field(
        default=None, description="default: buses of present USB wireless devices"
    )
    max_seconds: int = Field(300, ge=5, le=3600)


@router.get("/usbmon/status")
async def usbmon_status(_: str = Auth, st: AppState = State) -> dict[str, Any]:
    h = st.helper
    ping: dict[str, Any] = {}
    if h is not None and h.available:
        with contextlib.suppress(HelperError):
            ping = await asyncio.to_thread(h.call, "ping", 3.0)
    s = st.bus.sources.get("usbmon")
    return {
        "helper": bool(h and h.available),
        "usbmon_present": bool(ping.get("usbmon")),
        "active": bool(st.events and "usbmon" in st.events.tasks and not st.events.tasks["usbmon"].done()),
        "state": s.state if s else "stopped",
        "detail": s.detail if s else None,
        "buses": st.events.usb_buses() if st.events else [],
        "note": "usbmon must already be loaded (modprobe usbmon); WHD never loads kernel modules.",
    }


@router.post("/usbmon/start")
async def usbmon_start(body: UsbmonStart, actor: str = Auth, st: AppState = State) -> dict[str, Any]:
    if st.events is None or st.settings.mode == "demo":
        raise HTTPException(409, "usbmon capture is not available in demo mode")
    try:
        r = await st.events.start_usbmon(body.buses, body.max_seconds)
    except RuntimeError as e:
        raise HTTPException(409, str(e)) from e
    st.store.audit(actor, "usbmon_start", body.model_dump())
    return r


@router.post("/usbmon/stop")
async def usbmon_stop(actor: str = Auth, st: AppState = State) -> dict[str, Any]:
    if st.events is None:
        raise HTTPException(409, "event runtime not running")
    r = await st.events.stop_usbmon()
    st.store.audit(actor, "usbmon_stop", r)
    return r


# ---------------------------------------------------------------- trace presets (derived from discovery)

WIRELESS_TP_GROUPS = (
    "mt76",
    "mt792x",
    "mt7925",
    "mt7921",
    "iwlwifi",
    "ath11k",
    "ath12k",
    "rtw89",
    "mac80211",
    "cfg80211",
)


@router.get("/trace/presets")
async def trace_presets(_: str = Auth, st: AppState = State) -> list[dict[str, Any]]:
    """Presets built only from tracepoints that exist on this kernel (nothing is assumed)."""
    from whd.helper.protocol import TRACE_GROUPS

    h = st.helper
    if h is None or not h.available:
        return []
    try:
        r = await asyncio.to_thread(h.call, "tracefs_events", 15.0, groups=TRACE_GROUPS, with_format=False)
    except HelperError:
        return []
    groups: dict[str, dict[str, Any]] = r["groups"]
    out: list[dict[str, Any]] = []
    for g in WIRELESS_TP_GROUPS:
        names = sorted(groups.get(g, {}))
        if not names:
            continue
        out.append({"name": f"{g}: all ({len(names)})", "events": [f"{g}/*"]})
        if g == "mac80211":
            ops = [n for n in names if n.startswith("drv_")]
            if ops:
                out.append(
                    {"name": f"mac80211: driver ops ({len(ops)})", "events": [f"{g}/{n}" for n in ops]}
                )
        else:
            sub = [n for n in names if n.startswith("mlo_")]
            if sub:
                out.append({"name": f"{g}: mlo_* ({len(sub)})", "events": [f"{g}/{n}" for n in sub]})
    return out
