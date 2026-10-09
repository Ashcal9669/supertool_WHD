"""Phase 1 endpoints: health, auth, system, devices, discovery."""

from __future__ import annotations

import asyncio
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Request, Response
from pydantic import BaseModel

from whd.api.deps import get_state, require_auth
from whd.auth import COOKIE, SESSION_TTL_S
from whd.model.common import Issue, Model
from whd.model.device import Device, DeviceSummary
from whd.model.system import SystemInfo
from whd.services.system import system_info
from whd.state import AppState

router = APIRouter(prefix="/api/v1")
Auth = Depends(require_auth)
State = Depends(get_state)


class LoginBody(BaseModel):
    token: str


class Health(Model):
    status: str
    mode: str


@router.get("/health", response_model=Health)
async def health(st: AppState = State) -> Health:
    return Health(status="ok", mode=st.settings.mode)


@router.post("/auth/login")
async def login(
    body: LoginBody, request: Request, response: Response, st: AppState = State
) -> dict[str, bool]:
    client = request.client.host if request.client else "?"
    if not st.auth.check_token(body.token, client):
        await asyncio.sleep(0.5)
        raise HTTPException(401, "invalid token")
    response.set_cookie(
        COOKIE,
        st.auth.new_session(),
        max_age=SESSION_TTL_S,
        httponly=True,
        samesite="strict",
        secure=st.settings.cookie_secure,
        path="/",
    )
    st.store.audit(client, "login", {})
    return {"ok": True}


@router.post("/auth/logout")
async def logout(request: Request, response: Response, st: AppState = State) -> dict[str, bool]:
    st.auth.revoke(request.cookies.get(COOKIE))
    response.delete_cookie(COOKIE, path="/")
    return {"ok": True}


@router.get("/auth/session")
async def session(_: str = Auth) -> dict[str, bool]:
    return {"authenticated": True}


@router.get("/system", response_model=SystemInfo)
async def get_system(_: str = Auth, st: AppState = State) -> SystemInfo:
    helper_status = (
        await st.helper.status() if st.helper else {"connected": False, "detail": "not configured"}
    )
    return await asyncio.to_thread(system_info, st.host, st.settings.demo_scenario, helper_status)


class Inventory(Model):
    devices: list[DeviceSummary]
    taken_at: float
    duration_ms: float
    issues: list[Issue]
    mode: str


@router.get("/devices", response_model=Inventory)
async def list_devices(_: str = Auth, st: AppState = State) -> Inventory:
    snap = await st.inventory.get()
    return Inventory(
        devices=await st.inventory.summaries(),
        taken_at=snap.taken_at,
        duration_ms=snap.duration_ms,
        issues=snap.issues,
        mode=st.settings.mode,
    )


@router.get("/devices/{device_id}", response_model=Device)
async def get_device(device_id: str, _: str = Auth, st: AppState = State) -> Device:
    d = await st.inventory.device(device_id)
    if d is None:
        raise HTTPException(404, f"unknown device {device_id}")
    return d


@router.get("/devices/{device_id}/evidence")
async def device_evidence(device_id: str, _: str = Auth, st: AppState = State) -> dict[str, Any]:
    d = await st.inventory.device(device_id)
    if d is None:
        raise HTTPException(404, f"unknown device {device_id}")
    return {
        "device_id": d.id,
        "present": d.present,
        "sysfs_attributes": d.evidence,
        "sections": {
            name: getattr(d, name).meta.model_dump() if getattr(d, name) is not None else None
            for name in ("pci", "usb", "driver_info", "firmware", "power", "pci_config")
        },
        "wiphys": [w.model_dump(include={"index", "name", "undecoded_attrs", "meta"}) for w in d.wiphys],
        "netdevs": [n.meta.model_dump() | {"name": n.name} for n in d.netdev_info],
    }


class RescanResult(Model):
    added: list[str]
    removed: list[str]
    changed: dict[str, dict[str, Any]]
    device_count: int
    duration_ms: float


@router.post("/discovery/rescan", response_model=RescanResult)
async def rescan(_: str = Auth, st: AppState = State) -> RescanResult:
    snap, df = await st.inventory.refresh()
    return RescanResult(
        added=df.added,
        removed=df.removed,
        changed=df.changed,
        device_count=len(snap.devices),
        duration_ms=snap.duration_ms,
    )


@router.get("/discovery/runs")
async def discovery_runs(_: str = Auth, st: AppState = State) -> list[dict[str, Any]]:
    return await asyncio.to_thread(st.store.discovery_runs)
