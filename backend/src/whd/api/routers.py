"""Collects feature routers."""

from __future__ import annotations

from fastapi import APIRouter

from whd.api import captures, diagnostics, events, hardware, mlo, mt76, wireless


def all_routers() -> list[APIRouter]:
    return [
        hardware.router,
        events.router,
        wireless.router,
        mt76.router,
        captures.router,
        diagnostics.router,
        mlo.router,
    ]
