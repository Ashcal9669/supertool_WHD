"""Start/stop of background runtime components (event sources, helper, captures)."""

from __future__ import annotations

import asyncio

from whd.state import AppState


async def start(st: AppState, tasks: list[asyncio.Task[None]]) -> None:
    from whd.events.runtime import EventRuntime

    st.events = EventRuntime(st)
    await st.inventory.get(force=True)
    await st.events.start()
    try:
        from whd.capture.manager import CaptureManager
    except ImportError:
        return
    st.captures = CaptureManager(st)
    await st.captures.start()


async def stop(st: AppState) -> None:
    if st.captures is not None:
        await st.captures.stop()
    if st.events is not None:
        await st.events.stop()
