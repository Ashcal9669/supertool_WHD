"""Phase 5: mt76-specific diagnostics (instrumentation coverage, debugfs snapshot, trace aggregates)."""

from __future__ import annotations

import asyncio
import time
from pathlib import Path
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi.responses import PlainTextResponse
from pydantic import BaseModel

from whd.api.deps import get_state, require_auth
from whd.drivers import mt76
from whd.helper.protocol import HelperError
from whd.model.device import Device
from whd.model.events import EventFilter
from whd.state import AppState

router = APIRouter(prefix="/api/v1")
Auth = Depends(require_auth)
State = Depends(get_state)

PATCH_DIR = Path(__file__).resolve().parents[4] / "docs" / "patches"
_CACHE_TTL = 30.0


async def _dev(st: AppState, device_id: str) -> Device:
    dev = await st.inventory.device(device_id)
    if dev is None:
        raise HTTPException(404, "unknown device")
    if not mt76.is_mt76(dev):
        raise HTTPException(
            409,
            f"{dev.driver or 'no driver'} is not an mt76 driver; "
            "the mt76 module applies to mt76/mt79xx drivers",
        )
    if not dev.present:
        raise HTTPException(409, "device not present")
    return dev


@router.get("/devices/{device_id}/mt76/instrumentation", response_model=mt76.Instrumentation)
async def instrumentation(
    device_id: str, refresh: bool = False, phy: str | None = None, _: str = Auth, st: AppState = State
) -> mt76.Instrumentation:
    dev = await _dev(st, device_id)
    cache: dict[str, tuple[float, mt76.Instrumentation]] = st.extra.setdefault("mt76_instr", {})
    key = f"{device_id}|{phy or ''}"
    hit = cache.get(key)
    if hit and not refresh and time.monotonic() - hit[0] < _CACHE_TTL:
        return hit[1]
    jr = bool(st.events and st.bus.sources.get("journal") and st.bus.sources["journal"].state == "running")
    if st.settings.mode == "demo":
        jr = True  # demo replays recorded kernel-log events
    try:
        res = await asyncio.to_thread(mt76.discover_instrumentation, st.host, dev, jr, phy)
    except HelperError as e:
        raise HTTPException(422, str(e)) from e
    cache[key] = (time.monotonic(), res)
    return res


@router.get("/devices/{device_id}/mt76/snapshot", response_model=mt76.Mt76Snapshot)
async def snapshot(
    device_id: str, wake: bool = False, phy: str | None = None, actor: str = Auth, st: AppState = State
) -> mt76.Mt76Snapshot:
    dev = await _dev(st, device_id)
    try:
        snap = await asyncio.to_thread(mt76.read_snapshot, st.host, dev, wake, phy)
    except HelperError as e:
        raise HTTPException(422 if e.code == "args" else 409, str(e)) from e
    if wake:
        st.store.audit(
            actor, "mt76_snapshot_wake", {"device": device_id, "paths": [r.path for r in snap.reads]}
        )
    return snap


class RawFile(BaseModel):
    path: str
    tier: str | None
    policy: str | None = None
    mode: str | None = None


class RawListing(BaseModel):
    device_id: str
    phy: str
    truncated: bool
    files: list[RawFile]


class RawRead(BaseModel):
    device_id: str
    phy: str
    path: str
    tier: str | None
    policy: str | None
    bytes: int
    truncated: bool
    elapsed_ms: float
    read_at_boottime_ns: int
    read_at_wall: float
    text: str | None
    binary: bool = False


@router.get("/devices/{device_id}/mt76/raw-files", response_model=RawListing)
async def raw_files(
    device_id: str, phy: str | None = None, _: str = Auth, st: AppState = State
) -> RawListing:
    """Every file the driver exposes for this PHY, with the access tier the helper policy gives it. The list comes from
    the running kernel, so a driver with other files shows those."""
    dev = await _dev(st, device_id)
    h = st.host.helper
    if h is None or not h.available:
        raise HTTPException(409, "whd-helper is not running; mt76 debugfs requires root")
    chosen = mt76.pick_phy(dev, phy) or (dev.phys[0] if dev.phys else None)
    if chosen is None:
        raise HTTPException(409, "device has no registered PHY")
    try:
        res = await asyncio.to_thread(h.call, "debugfs_list", 10.0, phy=chosen)
    except HelperError as e:
        raise HTTPException(422 if e.code == "args" else 409, str(e)) from e
    return RawListing(
        device_id=device_id,
        phy=chosen,
        truncated=bool(res.get("truncated")),
        files=[
            RawFile(path=e["path"], tier=e.get("tier"), policy=e.get("policy"), mode=e.get("mode"))
            for e in res["entries"]
        ],
    )


@router.get("/devices/{device_id}/mt76/raw", response_model=RawRead)
async def raw_read(
    device_id: str,
    path: str,
    phy: str | None = None,
    wake: bool = False,
    actor: str = Auth,
    st: AppState = State,
) -> RawRead:
    """The unmodified text of one debugfs file, with when it was read. Passive files are always readable; files that
    wake the chip need wake=true (and are audited); MMIO/MCU/never-tier files are refused here and by the helper."""
    dev = await _dev(st, device_id)
    h = st.host.helper
    if h is None or not h.available:
        raise HTTPException(409, "whd-helper is not running; mt76 debugfs requires root")
    chosen = mt76.pick_phy(dev, phy) or (dev.phys[0] if dev.phys else None)
    if chosen is None:
        raise HTTPException(409, "device has no registered PHY")
    try:
        listing = await asyncio.to_thread(h.call, "debugfs_list", 10.0, phy=chosen)
        entry = next((e for e in listing["entries"] if e["path"] == path), None)
        if entry is None:
            raise HTTPException(404, "no such file for this PHY")
        tier = entry.get("tier")
        if tier == "wakes_device" and not wake:
            raise HTTPException(
                409, "reading this file wakes the chip from runtime PM; pass wake=true to allow it"
            )
        if tier not in ("passive", "wakes_device"):
            raise HTTPException(
                403, f"{path}: tier {tier} is not readable from the viewer ({entry.get('policy')})"
            )
        r = await asyncio.to_thread(h.call, "debugfs_read", 10.0, phy=chosen, path=path)
    except HelperError as e:
        raise HTTPException(422 if e.code == "args" else 409, str(e)) from e
    if tier == "wakes_device":
        st.store.audit(actor, "mt76_raw_read_wake", {"device": device_id, "phy": chosen, "path": path})
    return RawRead(
        device_id=device_id,
        phy=chosen,
        path=path,
        tier=tier,
        policy=r.get("policy"),
        bytes=int(r["bytes"]),
        truncated=bool(r.get("truncated")),
        elapsed_ms=float(r["elapsed_ms"]),
        read_at_boottime_ns=int(r["read_at_boottime_ns"]),
        read_at_wall=time.time(),
        text=r.get("text"),
        binary=r.get("text") is None,
    )


@router.get("/devices/{device_id}/mt76/trace-aggregate", response_model=mt76.TraceAggregate)
async def trace_aggregate(
    device_id: str, window_s: int = Query(300, ge=5, le=86400), _: str = Auth, st: AppState = State
) -> mt76.TraceAggregate:
    await _dev(st, device_id)
    from whd.clock import boottime_ns

    flt = EventFilter(device_id=device_id, kinds=["trace.mt76."], since_ns=boottime_ns() - window_s * 10**9)
    evs = await asyncio.to_thread(st.store.query_events, flt, None, 20000, "asc")
    ring_ids = {e.id for e in evs}
    evs += [e for e in st.bus.recent(flt, 20000) if e.id not in ring_ids]
    return mt76.aggregate_trace(device_id, evs)


@router.get("/devices/{device_id}/mt76/driver-tags", response_model=list[mt76.TagSummary])
async def driver_tags(
    device_id: str, window_s: int = Query(3600, ge=5, le=7 * 86400), _: str = Auth, st: AppState = State
) -> list[mt76.TagSummary]:
    await _dev(st, device_id)
    from whd.clock import boottime_ns

    flt = EventFilter(
        device_id=device_id, kinds=["driver.kv_trace"], since_ns=boottime_ns() - window_s * 10**9
    )
    evs = await asyncio.to_thread(st.store.query_events, flt, None, 20000, "asc")
    return mt76.summarize_driver_tags(evs)


@router.get("/patches")
async def list_patches(_: str = Auth) -> list[dict[str, Any]]:
    out = []
    for p in mt76.PATCHES:
        f = PATCH_DIR / Path(p["file"]).name
        out.append(p | {"available": f.exists(), "applied_by_whd": False})
    return out


@router.get("/patches/{patch_id}", response_class=PlainTextResponse)
async def get_patch(patch_id: str, _: str = Auth) -> str:
    for p in mt76.PATCHES:
        if p["id"] == patch_id:
            f = PATCH_DIR / Path(p["file"]).name
            if f.exists():
                return await asyncio.to_thread(f.read_text)
    raise HTTPException(404, "unknown patch")
