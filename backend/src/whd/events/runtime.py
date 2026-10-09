"""Lifecycle of event sources, device attribution refresh, trace sessions and replays."""

from __future__ import annotations

import asyncio
import contextlib
import logging
from pathlib import Path
from typing import Any

from whd.events.attrib import DeviceIndex
from whd.events.sources import (
    Ctx,
    JournalSource,
    Nl80211Source,
    ReplaySource,
    RtnlSource,
    Source,
    SysfsPoller,
    TelemetryPoller,
    TraceSource,
    UeventSource,
    load_jsonl_events,
)
from whd.model.events import Event, TelemetrySample
from whd.platform.host import FixtureHost
from whd.state import AppState

log = logging.getLogger("whd.runtime")


class EventRuntime:
    def __init__(self, st: AppState) -> None:
        self.st = st
        self.index = DeviceIndex()
        self.ctx = Ctx(
            bus=st.bus,
            index=self.index,
            host=st.host,
            inventory=st.inventory,
            request_rescan=self.request_rescan,
            settings=st.settings,
        )
        self.tasks: dict[str, asyncio.Task[None]] = {}
        self.sources: dict[str, Source] = {}
        self._rescan_handle: asyncio.TimerHandle | None = None
        self._bg: set[asyncio.Future[Any]] = set()
        self.trace: TraceSource | None = None
        self.replay: ReplaySource | None = None

    # -------------------------------------------------------------- lifecycle
    def refresh_index(self) -> None:
        snap = self.st.inventory.snapshot
        if snap is not None:
            self.index.update(snap.devices)

    def _start(self, src: Source, key: str | None = None) -> None:
        k = key or src.name
        self.sources[k] = src
        self.tasks[k] = asyncio.create_task(src.supervise(), name=f"source:{k}")

    async def start(self) -> None:
        self.refresh_index()
        self.st.inventory.on_refresh.append(lambda _snap: self.refresh_index())
        if not self.st.settings.enable_event_sources:
            return
        host = self.st.host
        if isinstance(host, FixtureHost):
            evp = host.dir / "events.jsonl"
            if evp.exists():
                self._start(
                    ReplaySource(
                        self.ctx,
                        load_jsonl_events(evp),
                        speed=self.st.settings.demo_speed,
                        loop=True,
                        session=f"fixture:{host.dir.name}",
                        period_s=float(host.meta.get("demo_loop_seconds") or 0) or None,
                    ),
                    "replay:fixture",
                )
            tp = host.dir / "telemetry.jsonl"
            if tp.exists():
                self.tasks["telemetry:fixture"] = asyncio.create_task(
                    self._replay_telemetry(
                        tp,
                        float(host.meta.get("demo_loop_seconds") or 0) or None,
                        self.st.settings.demo_speed,
                    )
                )
            return
        from whd.drivers.mt76_poller import Mt76Poller

        for src in (
            JournalSource(self.ctx),
            UeventSource(self.ctx),
            Nl80211Source(self.ctx),
            RtnlSource(self.ctx),
            SysfsPoller(self.ctx),
            TelemetryPoller(self.ctx, self.st.settings.telemetry_interval_s),
            Mt76Poller(self.ctx, self.st.settings.telemetry_interval_s),
        ):
            self._start(src)

    async def _replay_telemetry(self, path: Path, period_s: float | None = None, speed: float = 1.0) -> None:
        from whd.clock import boot_to_wall, boottime_ns

        samples = [TelemetrySample.model_validate_json(x) for x in path.read_text().splitlines() if x.strip()]
        if not samples:
            return
        st = self.st.bus.source("telemetry")
        st.state, st.detail = "running", f"replaying {path.name} (demo)"
        while True:
            base = samples[0].ts_boottime_ns
            start = boottime_ns()
            for s in samples:
                delay = (s.ts_boottime_ns - base) / 1e9 / speed - (boottime_ns() - start) / 1e9
                if delay > 0:
                    await asyncio.sleep(min(delay, 5))
                ns = s.model_copy()
                ns.ts_boottime_ns = boottime_ns()
                ns.ts_wall = boot_to_wall(ns.ts_boottime_ns)
                self.st.bus.publish_sample(ns)
                st.events += 1
            await asyncio.sleep(
                max(1.0, period_s / speed - (boottime_ns() - start) / 1e9) if period_s else 1.0
            )

    async def stop(self) -> None:
        for t in self.tasks.values():
            t.cancel()
        await asyncio.gather(*self.tasks.values(), return_exceptions=True)
        self.tasks.clear()

    def request_rescan(self, reason: str) -> None:
        """Debounced inventory refresh after hotplug-like events."""
        loop = asyncio.get_event_loop()
        if self._rescan_handle is not None:
            self._rescan_handle.cancel()

        def fire() -> None:
            self._rescan_handle = None
            t = asyncio.ensure_future(self.st.inventory.refresh())
            self._bg.add(t)
            t.add_done_callback(self._bg.discard)

        self._rescan_handle = loop.call_later(1.0, fire)

    def status(self) -> list[dict[str, Any]]:
        out = []
        for name, s in self.st.bus.sources.items():
            out.append(
                {
                    "name": name,
                    "state": s.state,
                    "detail": s.detail,
                    "events": s.events,
                    "errors": s.errors,
                    "last_event_ns": s.last_event_ns,
                }
            )
        return out

    # -------------------------------------------------------------- tracing
    async def start_trace(self, events: list[str], buffer_kb: int, max_seconds: int) -> dict[str, Any]:
        if self.trace is not None and "trace" in self.tasks and not self.tasks["trace"].done():
            raise RuntimeError("a trace session is already running")
        src = TraceSource(self.ctx, events, buffer_kb, max_seconds)
        self.trace = src
        self._start(src, "trace")
        for _ in range(100):
            await asyncio.sleep(0.05)
            if src.started is not None or self.tasks["trace"].done():
                break
        if self.tasks["trace"].done() and src.started is None:
            st = src.status
            self.trace = None
            raise RuntimeError(st.detail or "trace session failed to start")
        return {"started": src.started}

    async def stop_trace(self) -> dict[str, Any]:
        t = self.tasks.pop("trace", None)
        src = self.trace
        self.trace = None
        if t is None:
            return {"stopped": False}
        t.cancel()
        with contextlib.suppress(BaseException):
            await t
        if src:
            src.status.state = "stopped"
        return {"stopped": True, "lines": src.lines if src else 0}

    def trace_status(self) -> dict[str, Any]:
        t = self.tasks.get("trace")
        src = self.trace
        return {
            "active": bool(t and not t.done()),
            "events": src.events if src else [],
            "started": src.started if src else None,
            "lines": src.lines if src else 0,
            "detail": src.status.detail if src else None,
            "result": src.result if src else None,
        }

    # -------------------------------------------------------------- usbmon
    def usb_buses(self) -> list[int]:
        snap = self.st.inventory.snapshot
        return sorted(
            {d.usb.busnum for d in (snap.devices if snap else []) if d.usb and d.usb.busnum is not None}
        )

    async def start_usbmon(self, buses: list[int] | None, max_seconds: int) -> dict[str, Any]:
        from whd.events.sources import UsbmonSource

        t = self.tasks.get("usbmon")
        if t is not None and not t.done():
            raise RuntimeError("usbmon capture already running")
        use = buses or self.usb_buses()
        if not use:
            raise RuntimeError("no USB wireless devices are present")
        src = UsbmonSource(self.ctx, use, max_seconds)
        self._start(src, "usbmon")
        await asyncio.sleep(0.6)  # give the helper stream time to fail fast (e.g. usbmon not loaded)
        if self.tasks["usbmon"].done() or src.status.state == "unavailable":
            raise RuntimeError(src.status.detail or "usbmon could not start")
        return {"buses": use}

    async def stop_usbmon(self) -> dict[str, Any]:
        t = self.tasks.pop("usbmon", None)
        if t is None:
            return {"stopped": False}
        t.cancel()
        with contextlib.suppress(BaseException):
            await t
        self.st.bus.source("usbmon").state = "stopped"
        return {"stopped": True}

    # -------------------------------------------------------------- replay
    async def start_replay(self, events: list[Event], session: str, speed: float) -> None:
        await self.stop_replay()
        self.replay = ReplaySource(self.ctx, events, speed=speed, loop=False, session=session, max_gap_s=3.0)
        self._start(self.replay, "replay:capture")

    async def stop_replay(self) -> None:
        t = self.tasks.pop("replay:capture", None)
        if t is not None:
            t.cancel()
            with contextlib.suppress(BaseException):
                await t
        self.replay = None

    def replay_status(self) -> dict[str, Any]:
        t = self.tasks.get("replay:capture")
        r = self.replay
        return {
            "active": bool(t and not t.done()),
            "session": r.session if r else None,
            "position": r.position if r else 0,
            "total": len(r.events) if r else 0,
            "speed": r.speed if r else None,
        }
