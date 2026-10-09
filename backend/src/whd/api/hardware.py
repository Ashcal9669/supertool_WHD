"""Phase 2 endpoints: topology, privileged helper status, raw config space."""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, HTTPException

from whd.api.deps import get_state, require_auth
from whd.services.topology import Topology, build_topology
from whd.state import AppState

router = APIRouter(prefix="/api/v1")
Auth = Depends(require_auth)
State = Depends(get_state)


@router.get("/topology", response_model=Topology)
async def topology(_: str = Auth, st: AppState = State) -> Topology:
    snap = await st.inventory.get()
    return build_topology(snap.devices, st.settings.mode)


@router.get("/helper/status")
async def helper_status(_: str = Auth, st: AppState = State) -> dict[str, Any]:
    if st.helper is None:
        return {"connected": False, "detail": "no helper configured"}
    return await st.helper.status()


@router.get("/devices/{device_id}/pci-config/hexdump")
async def pci_hexdump(device_id: str, _: str = Auth, st: AppState = State) -> dict[str, Any]:
    d = await st.inventory.device(device_id)
    if d is None:
        raise HTTPException(404, "unknown device")
    if d.pci_config is None or not d.pci_config.raw_hex:
        raise HTTPException(409, "config space not available (helper not running or not a PCI device)")
    raw = bytes.fromhex(d.pci_config.raw_hex)
    lines = []
    for off in range(0, len(raw), 16):
        chunk = raw[off : off + 16]
        lines.append(f"{off:03x}: " + " ".join(f"{b:02x}" for b in chunk))
    return {"device_id": d.id, "length": len(raw), "lines": lines, "read_only": True}
