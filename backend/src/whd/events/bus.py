"""In-process event bus with a bounded ring, bounded subscriber queues and batched persistence."""

from __future__ import annotations

import asyncio
import logging
from collections import deque
from collections.abc import Callable
from dataclasses import dataclass, field

from whd.model.events import Event, EventFilter, TelemetrySample
from whd.store.db import Store

log = logging.getLogger("whd.events")


@dataclass
class Subscriber:
    flt: EventFilter
    queue: asyncio.Queue[Event]
    dropped: int = 0
    id: int = 0


@dataclass
class SourceStatus:
    name: str
    state: str = "stopped"  # running | stopped | unavailable | error
    detail: str | None = None
    events: int = 0
    errors: int = 0
    last_event_ns: int | None = None


@dataclass
class EventBus:
    store: Store | None
    ring_size: int = 20000
    queue_size: int = 2000
    telemetry_size: int = 7200
    demo: bool = False
    ring: deque[Event] = field(init=False)
    telemetry: deque[TelemetrySample] = field(init=False)
    _subs: dict[int, Subscriber] = field(default_factory=dict)
    _tsubs: dict[int, asyncio.Queue[TelemetrySample]] = field(default_factory=dict)
    _pending: list[Event] = field(default_factory=list)
    _next: int = 1
    _flush_task: asyncio.Task[None] | None = None
    sources: dict[str, SourceStatus] = field(default_factory=dict)
    published: int = 0
    taps: list[Callable[[Event], None]] = field(default_factory=list)
    sample_taps: list[Callable[[TelemetrySample], None]] = field(default_factory=list)
    _mem_id: int = 0
    _ephemeral_id: int = 10**12

    def __post_init__(self) -> None:
        self.ring = deque(maxlen=self.ring_size)
        self.telemetry = deque(maxlen=self.telemetry_size)

    def source(self, name: str) -> SourceStatus:
        return self.sources.setdefault(name, SourceStatus(name))

    def publish(self, e: Event) -> None:
        if self.demo:
            e.demo = True
        if self.store is None:
            self._mem_id += 1
            e.id = self._mem_id
        self.published += 1
        if e.session and e.session.startswith("replay:"):
            # Capture replays are fanned out to live subscribers only: never persisted, never in the ring,
            # so replayed history cannot be mistaken for (or mixed into) live history or aggregates.
            self._ephemeral_id += 1
            e.id = self._ephemeral_id
            self._fanout([e])
            return
        self.ring.append(e)
        self._pending.append(e)
        st = self.sources.get(e.source.split(":", 1)[0])
        if st:
            st.events += 1
            st.last_event_ns = e.ts_boottime_ns
        for tap in list(self.taps):
            try:
                tap(e)
            except Exception:
                log.exception("event tap failed")
        if self.store is None:
            self._fanout([e])

    def _fanout(self, events: list[Event]) -> None:
        for sub in list(self._subs.values()):
            for e in events:
                if not sub.flt.matches(e):
                    continue
                if sub.queue.full():
                    try:
                        sub.queue.get_nowait()
                    except asyncio.QueueEmpty:
                        pass
                    sub.dropped += 1
                sub.queue.put_nowait(e)

    def publish_sample(self, s: TelemetrySample) -> None:
        if self.demo:
            s.demo = True
        self.telemetry.append(s)
        for tap in list(self.sample_taps):
            try:
                tap(s)
            except Exception:
                log.exception("sample tap failed")
        for q in list(self._tsubs.values()):
            if q.full():
                try:
                    q.get_nowait()
                except asyncio.QueueEmpty:
                    pass
            q.put_nowait(s)

    def flush(self) -> None:
        """Persist pending events (assigns ids) and fan out. Called from the flush loop."""
        if not self._pending:
            return
        batch, self._pending = self._pending, []
        if self.store is not None:
            try:
                self.store.insert_events(batch)
            except Exception:
                log.exception("event persistence failed", extra={"count": len(batch)})
            self._fanout(batch)

    async def run_flusher(self, interval: float = 0.2) -> None:
        while True:
            await asyncio.sleep(interval)
            if self._pending:
                await asyncio.to_thread(self.flush)

    def subscribe(self, flt: EventFilter) -> Subscriber:
        sid = self._next
        self._next += 1
        s = Subscriber(flt=flt, queue=asyncio.Queue(self.queue_size), id=sid)
        self._subs[sid] = s
        return s

    def unsubscribe(self, s: Subscriber) -> None:
        self._subs.pop(s.id, None)

    def subscribe_telemetry(self) -> tuple[int, asyncio.Queue[TelemetrySample]]:
        sid = self._next
        self._next += 1
        q: asyncio.Queue[TelemetrySample] = asyncio.Queue(self.queue_size)
        self._tsubs[sid] = q
        return sid, q

    def unsubscribe_telemetry(self, sid: int) -> None:
        self._tsubs.pop(sid, None)

    def recent(self, flt: EventFilter, limit: int = 500) -> list[Event]:
        out = [e for e in self.ring if flt.matches(e)]
        return out[-limit:]
