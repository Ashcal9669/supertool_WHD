"""FastAPI application factory."""

from __future__ import annotations

import asyncio
import contextlib
import logging
from collections.abc import AsyncIterator
from pathlib import Path

from fastapi import FastAPI, Request
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles

from whd import __version__
from whd.api import core
from whd.auth import Auth
from whd.config import Settings
from whd.events.bus import EventBus
from whd.platform.host import FixtureHost, Host, LiveHost
from whd.services.inventory import Inventory
from whd.state import AppState
from whd.store.db import Store

log = logging.getLogger("whd.app")


def make_host(settings: Settings) -> Host:
    if settings.demo_scenario:
        d = settings.fixtures_dir / settings.demo_scenario
        if not d.is_dir():
            raise SystemExit(f"unknown demo scenario {settings.demo_scenario!r} (no directory {d})")
        return FixtureHost(d)
    return LiveHost(settings.helper_socket)


def build_state(settings: Settings, host: Host | None = None) -> AppState:
    host = host or make_host(settings)
    store = Store(settings.db_path)
    auth = Auth(settings.config_dir)
    bus = EventBus(
        store=store,
        ring_size=settings.event_ring_size,
        queue_size=settings.ws_queue_size,
        demo=host.mode == "demo",
    )
    from whd.drivers import registry

    inv = Inventory(host, store, bus, ttl_s=settings.cache_ttl_s, extensions=registry.extensions())
    return AppState(
        settings=settings, host=host, store=store, auth=auth, bus=bus, inventory=inv, helper=host.helper
    )


def create_app(settings: Settings | None = None, state: AppState | None = None) -> FastAPI:
    settings = settings or (state.settings if state else Settings.from_env())

    @contextlib.asynccontextmanager
    async def lifespan(app: FastAPI) -> AsyncIterator[None]:
        st = state or build_state(settings)
        app.state.whd = st
        log.info(
            "whd starting",
            extra={"mode": settings.mode, "db": str(settings.db_path), "token_file": str(st.auth.token_path)},
        )
        tasks: list[asyncio.Task[None]] = [asyncio.create_task(st.bus.run_flusher())]
        from whd import runtime

        await runtime.start(st, tasks)
        try:
            await st.inventory.get(force=True)
        except Exception:
            log.exception("initial discovery failed")
        try:
            yield
        finally:
            await runtime.stop(st)
            for t in tasks:
                t.cancel()
            await asyncio.gather(*tasks, return_exceptions=True)
            st.bus.flush()
            st.store.close()

    app = FastAPI(
        title="Wireless Hardware Debugger",
        version=__version__,
        lifespan=lifespan,
        docs_url="/api/docs" if settings.enable_docs else None,
        openapi_url="/api/openapi.json" if settings.enable_docs else None,
        redoc_url=None,
    )
    if state is not None:
        app.state.whd = state

    @app.middleware("http")
    async def security_headers(request: Request, call_next):  # type: ignore[no-untyped-def]
        resp = await call_next(request)
        resp.headers.setdefault("X-Content-Type-Options", "nosniff")
        resp.headers.setdefault("X-Frame-Options", "DENY")
        resp.headers.setdefault("Referrer-Policy", "no-referrer")
        if not request.url.path.startswith("/api/docs"):
            resp.headers.setdefault(
                "Content-Security-Policy",
                "default-src 'self'; connect-src 'self' ws: wss:; img-src 'self' data:; "
                "style-src 'self' 'unsafe-inline'; script-src 'self'; frame-ancestors 'none'",
            )
        return resp

    from whd.api import routers

    app.include_router(core.router)
    for r in routers.all_routers():
        app.include_router(r)

    static = settings.static_dir or Path(__file__).resolve().parents[3] / "frontend" / "dist"
    if (static / "index.html").exists():
        app.mount("/assets", StaticFiles(directory=static / "assets"), name="assets")

        @app.get("/{path:path}", include_in_schema=False, response_model=None)
        async def spa(path: str) -> FileResponse | JSONResponse:
            if path.startswith("api/"):
                return JSONResponse({"detail": "not found"}, status_code=404)
            f = (static / path).resolve()
            if path and f.is_file() and static.resolve() in f.parents:
                return FileResponse(f)
            return FileResponse(static / "index.html")

    return app
