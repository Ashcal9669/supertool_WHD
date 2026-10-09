"""Bounded diagnostic capture sessions.

A capture subscribes to the event bus (and telemetry) with a device-scoped filter, keeps a circular buffer
(max events / max bytes / max duration, all enforced), persists it to SQLite, and can export, replay and bundle.
Resource limits are hard-capped regardless of what the client requests.
"""

from __future__ import annotations

import asyncio
import contextlib
import csv
import hashlib
import io
import json
import logging
import re
import secrets
import time
import zipfile
from collections import deque
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any, Literal

from pydantic import Field

from whd import __version__
from whd.capture.importer import Imported, finalize
from whd.clock import boottime_ns
from whd.model.common import Model
from whd.model.events import Event, EventFilter, Severity, TelemetrySample

if TYPE_CHECKING:
    from whd.state import AppState

log = logging.getLogger("whd.capture")

HARD_MAX_EVENTS = 500_000
HARD_MAX_BYTES = 256 * 1024 * 1024
HARD_MAX_SECONDS = 24 * 3600
HARD_MAX_TELEMETRY = 100_000
MAX_CONCURRENT = 3
FLUSH_EVERY_S = 1.0

State = Literal["running", "stopped", "expired", "error", "imported"]


class CaptureConfig(Model):
    name: str = Field(default="capture", max_length=80)
    device_id: str | None = None
    categories: list[str] | None = None
    min_severity: Severity | None = None
    sources: list[str] | None = None
    max_events: int = Field(default=50_000, ge=100, le=HARD_MAX_EVENTS)
    max_bytes: int = Field(default=32 * 1024 * 1024, ge=64 * 1024, le=HARD_MAX_BYTES)
    max_seconds: int = Field(default=900, ge=5, le=HARD_MAX_SECONDS)
    include_telemetry: bool = True
    trace_events: list[str] | None = Field(
        default=None, description="start a tracefs session for the capture"
    )

    def event_filter(self) -> EventFilter:
        return EventFilter(
            device_id=self.device_id,
            categories=self.categories,
            min_severity=self.min_severity,
            sources=self.sources,
        )


class CaptureStats(Model):
    events_seen: int = 0
    events_kept: int = 0
    events_dropped_oldest: int = 0
    bytes_kept: int = 0
    telemetry_samples: int = 0
    first_ts_ns: int | None = None
    last_ts_ns: int | None = None
    by_severity: dict[str, int] = Field(default_factory=dict)
    by_category: dict[str, int] = Field(default_factory=dict)
    stop_reason: str | None = None


class CaptureInfo(Model):
    id: str
    name: str
    state: State
    created_at: float
    started_ns: int | None
    stopped_ns: int | None
    mode: str
    config: CaptureConfig
    stats: CaptureStats
    artifacts: list[dict[str, Any]] = Field(default_factory=list)
    seconds_remaining: float | None = None


@dataclass
class _Live:
    id: str
    cfg: CaptureConfig
    flt: EventFilter
    started_ns: int
    deadline: float
    created_at: float = field(default_factory=time.time)
    seq: int = 0
    buf: deque[tuple[int, Event, int]] = field(default_factory=deque)  # (seq, event, size)
    pending: list[tuple[int, Event]] = field(default_factory=list)
    tel: deque[TelemetrySample] = field(default_factory=lambda: deque(maxlen=HARD_MAX_TELEMETRY))
    stats: CaptureStats = field(default_factory=CaptureStats)
    start_snapshot: dict[str, Any] | None = None
    trace_started: bool = False


MAC_RE = re.compile(r"\b([0-9a-fA-F]{2}(?::[0-9a-fA-F]{2}){5})\b")


class Redactor:
    """Consistent MAC masking for bundles (keeps the OUI so vendor correlation survives)."""

    def __init__(self) -> None:
        self.map: dict[str, str] = {}

    def mac(self, m: re.Match[str]) -> str:
        k = m.group(1).lower()
        if k in ("00:00:00:00:00:00", "ff:ff:ff:ff:ff:ff"):
            return k
        if k not in self.map:
            self.map[k] = f"{k[:8]}:xx:xx:{len(self.map) + 1:02x}"
        return self.map[k]

    def text(self, s: str) -> str:
        return MAC_RE.sub(self.mac, s)


CSV_COLUMNS = [
    "id",
    "ts_boottime_ns",
    "ts_wall_iso",
    "ts_source",
    "ts_raw",
    "source",
    "device_id",
    "severity",
    "category",
    "kind",
    "summary",
    "explanation",
    "raw",
    "demo",
    "session",
]


def events_to_csv(events: list[Event]) -> str:
    out = io.StringIO()
    w = csv.writer(out)
    w.writerow(CSV_COLUMNS)
    for e in events:
        w.writerow(
            [
                e.id,
                e.ts_boottime_ns,
                time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime(e.ts_wall))
                + f".{int((e.ts_wall % 1) * 1000):03d}Z",
                e.ts_source,
                e.ts_raw or "",
                e.source,
                e.device_id or "",
                e.severity,
                e.category,
                e.kind,
                e.summary,
                e.explanation,
                e.raw,
                e.demo,
                e.session or "",
            ]
        )
    return out.getvalue()


def events_to_trace_text(events: list[Event]) -> str:
    """ftrace text-format lines recovered from tracepoint events (the original TP_printk lines)."""
    lines = [
        "# tracer: nop",
        "# exported by WHD from captured tracefs events (text format; not trace.dat)",
        "# clock: boot (CLOCK_BOOTTIME seconds)",
    ]
    for e in sorted(events, key=lambda x: x.ts_boottime_ns):
        if e.source.startswith("tracefs:") and e.raw:
            lines.append(e.raw.rstrip())
    return "\n".join(lines) + "\n"


class CaptureManager:
    def __init__(self, st: AppState) -> None:
        self.st = st
        self.live: dict[str, _Live] = {}
        self._task: asyncio.Task[None] | None = None
        self._lock = asyncio.Lock()

    # ----------------------------------------------------------- lifecycle
    async def start(self) -> None:
        # captures left "running" by a previous process cannot continue: mark them stopped
        for c in await asyncio.to_thread(self.st.store.capture_list):
            if c["state"] == "running":
                c["state"] = "stopped"
                st = CaptureStats.model_validate_json(c["stats_json"])
                st.stop_reason = st.stop_reason or "server restarted while capturing"
                c["stats_json"] = st.model_dump_json()
                await asyncio.to_thread(self.st.store.capture_upsert, c)
        self.st.bus.taps.append(self._on_event)
        self.st.bus.sample_taps.append(self._on_sample)
        self._task = asyncio.create_task(self._maintain())

    async def stop(self) -> None:
        if self._task:
            self._task.cancel()
            with contextlib.suppress(BaseException):
                await self._task
        for cid in list(self.live):
            await self.stop_capture(cid, "server shutdown")
        with contextlib.suppress(ValueError):
            self.st.bus.taps.remove(self._on_event)
        with contextlib.suppress(ValueError):
            self.st.bus.sample_taps.remove(self._on_sample)

    async def create(self, cfg: CaptureConfig) -> CaptureInfo:
        async with self._lock:
            if len(self.live) >= MAX_CONCURRENT:
                raise ValueError(f"at most {MAX_CONCURRENT} captures may run at once")
            cid = "cap-" + secrets.token_hex(5)
            lv = _Live(
                id=cid,
                cfg=cfg,
                flt=cfg.event_filter(),
                started_ns=boottime_ns(),
                deadline=time.monotonic() + cfg.max_seconds,
            )
            snap = self.st.inventory.snapshot
            lv.start_snapshot = {
                "taken_at": snap.taken_at if snap else None,
                "devices": [
                    d.model_dump(mode="json")
                    for d in (snap.devices if snap else [])
                    if cfg.device_id in (None, d.id)
                ],
            }
            if cfg.trace_events and self.st.events is not None:
                try:
                    await self.st.events.start_trace(cfg.trace_events, 4096, cfg.max_seconds)
                    lv.trace_started = True
                except RuntimeError as e:
                    raise ValueError(f"trace could not start: {e}") from e
            self.live[cid] = lv
            await self._persist(lv, "running")
        self.st.store.audit("api", "capture_start", {"id": cid, **cfg.model_dump()})
        return await self.info(cid)

    async def stop_capture(self, cid: str, reason: str = "stopped by user") -> CaptureInfo:
        async with self._lock:
            lv = self.live.pop(cid, None)
            if lv is None:
                return await self.info(cid)
            lv.stats.stop_reason = reason
            await self._flush(lv)
            if lv.trace_started and self.st.events is not None:
                with contextlib.suppress(Exception):
                    await self.st.events.stop_trace()
            stopped = boottime_ns()
            snap = self.st.inventory.snapshot
            end_snapshot = {
                "taken_at": snap.taken_at if snap else None,
                "devices": [
                    d.model_dump(mode="json")
                    for d in (snap.devices if snap else [])
                    if lv.cfg.device_id in (None, d.id)
                ],
            }
            store = self.st.store
            await asyncio.to_thread(
                store.capture_put_artifact,
                cid,
                "devices_start.json",
                "application/json",
                json.dumps(lv.start_snapshot, default=str).encode(),
            )
            await asyncio.to_thread(
                store.capture_put_artifact,
                cid,
                "devices_end.json",
                "application/json",
                json.dumps(end_snapshot, default=str).encode(),
            )
            if lv.tel:
                data = "\n".join(s.model_dump_json() for s in lv.tel).encode()
                await asyncio.to_thread(
                    store.capture_put_artifact, cid, "telemetry.jsonl", "application/x-ndjson", data
                )
            await self._persist(
                lv, "expired" if "limit" in reason or "duration" in reason else "stopped", stopped
            )
        self.st.store.audit("api", "capture_stop", {"id": cid, "reason": reason})
        return await self.info(cid)

    # ----------------------------------------------------------- collection
    def _on_event(self, e: Event) -> None:
        for lv in self.live.values():
            if not lv.flt.matches(e):
                continue
            lv.seq += 1
            size = len(e.model_dump_json())
            lv.buf.append((lv.seq, e, size))
            lv.pending.append((lv.seq, e))
            s = lv.stats
            s.events_seen += 1
            s.events_kept += 1
            s.bytes_kept += size
            s.first_ts_ns = (
                e.ts_boottime_ns if s.first_ts_ns is None else min(s.first_ts_ns, e.ts_boottime_ns)
            )
            s.last_ts_ns = e.ts_boottime_ns if s.last_ts_ns is None else max(s.last_ts_ns, e.ts_boottime_ns)
            s.by_severity[e.severity] = s.by_severity.get(e.severity, 0) + 1
            s.by_category[e.category] = s.by_category.get(e.category, 0) + 1
            while lv.buf and (len(lv.buf) > lv.cfg.max_events or s.bytes_kept > lv.cfg.max_bytes):
                _, _, sz = lv.buf.popleft()
                s.events_kept -= 1
                s.bytes_kept -= sz
                s.events_dropped_oldest += 1

    def _on_sample(self, smp: TelemetrySample) -> None:
        for lv in self.live.values():
            if not lv.cfg.include_telemetry:
                continue
            if lv.cfg.device_id and smp.device_id != lv.cfg.device_id:
                continue
            lv.tel.append(smp)
            lv.stats.telemetry_samples += 1

    async def _flush(self, lv: _Live) -> None:
        if not lv.pending:
            return
        # events get their DB ids on bus flush; persist after assigning them
        batch, lv.pending = lv.pending, []
        start_seq = batch[0][0]
        await asyncio.to_thread(self.st.store.capture_add_events, lv.id, start_seq, [e for _, e in batch])
        lo = lv.buf[0][0] if lv.buf else lv.seq + 1
        if lo > 1:
            await asyncio.to_thread(self._trim, lv.id, lo)

    def _trim(self, cid: str, min_seq: int) -> None:
        with self.st.store.lock:
            self.st.store.conn.execute(
                "DELETE FROM capture_events WHERE capture_id=? AND seq<?", (cid, min_seq)
            )

    async def _persist(self, lv: _Live, state: State, stopped_ns: int | None = None) -> None:
        await asyncio.to_thread(
            self.st.store.capture_upsert,
            {
                "id": lv.id,
                "name": lv.cfg.name,
                "state": state,
                "created_at": lv.created_at,
                "started_ns": lv.started_ns,
                "stopped_ns": stopped_ns,
                "config_json": lv.cfg.model_dump_json(),
                "stats_json": lv.stats.model_dump_json(),
                "mode": self.st.settings.mode,
            },
        )

    async def _maintain(self) -> None:
        while True:
            await asyncio.sleep(FLUSH_EVERY_S)
            for cid, lv in list(self.live.items()):
                try:
                    await self._flush(lv)
                    await self._persist(lv, "running")
                except Exception:
                    log.exception("capture flush failed", extra={"capture": cid})
                if time.monotonic() >= lv.deadline:
                    await self.stop_capture(cid, "duration limit reached")

    # ----------------------------------------------------------- queries
    async def info(self, cid: str) -> CaptureInfo:
        row = await asyncio.to_thread(self.st.store.capture_get, cid)
        if row is None:
            raise KeyError(cid)
        return await self._info_from_row(row)

    async def _info_from_row(self, row: dict[str, Any]) -> CaptureInfo:
        lv = self.live.get(row["id"])
        stats = lv.stats if lv else CaptureStats.model_validate_json(row["stats_json"])
        arts = await asyncio.to_thread(self.st.store.capture_artifacts, row["id"])
        return CaptureInfo(
            id=row["id"],
            name=row["name"],
            state="running" if lv else row["state"],
            created_at=row["created_at"],
            started_ns=row["started_ns"],
            stopped_ns=row["stopped_ns"],
            mode=row["mode"],
            config=CaptureConfig.model_validate_json(row["config_json"]),
            stats=stats,
            artifacts=arts,
            seconds_remaining=max(0.0, lv.deadline - time.monotonic()) if lv else None,
        )

    async def list_all(self) -> list[CaptureInfo]:
        rows = await asyncio.to_thread(self.st.store.capture_list)
        return [await self._info_from_row(r) for r in rows]

    async def events(self, cid: str) -> list[Event]:
        lv = self.live.get(cid)
        if lv:
            await self._flush(lv)
        return await asyncio.to_thread(self.st.store.capture_events, cid)

    async def delete(self, cid: str) -> None:
        if cid in self.live:
            await self.stop_capture(cid, "deleted")
        await asyncio.to_thread(self.st.store.capture_delete, cid)
        self.st.store.audit("api", "capture_delete", {"id": cid})

    async def telemetry(self, cid: str) -> list[TelemetrySample]:
        lv = self.live.get(cid)
        if lv:
            return list(lv.tel)
        art = await asyncio.to_thread(self.st.store.capture_artifact, cid, "telemetry.jsonl")
        if not art:
            return []
        return [TelemetrySample.model_validate_json(x) for x in art[1].decode().splitlines() if x.strip()]

    # ----------------------------------------------------------- import
    async def import_capture(self, imp: Imported, name: str) -> CaptureInfo:
        """Store an uploaded capture. It lives only in the capture tables: never in the live event store/ring."""
        cid = "imp-" + secrets.token_hex(5)
        imp = finalize(imp, cid)
        stats = CaptureStats(
            events_seen=len(imp.events),
            events_kept=len(imp.events),
            telemetry_samples=len(imp.telemetry),
            first_ts_ns=imp.events[0].ts_boottime_ns,
            last_ts_ns=imp.events[-1].ts_boottime_ns,
            stop_reason=f"imported from {imp.origin.get('filename', 'upload')} ({imp.format})",
        )
        for e in imp.events:
            stats.bytes_kept += len(e.model_dump_json())
            stats.by_severity[e.severity] = stats.by_severity.get(e.severity, 0) + 1
            stats.by_category[e.category] = stats.by_category.get(e.category, 0) + 1
        store = self.st.store
        cfg = CaptureConfig(name=(name or str(imp.origin.get("capture_name") or "imported"))[:80])
        await asyncio.to_thread(
            store.capture_upsert,
            {
                "id": cid,
                "name": cfg.name,
                "state": "imported",
                "created_at": time.time(),
                "started_ns": stats.first_ts_ns,
                "stopped_ns": stats.last_ts_ns,
                "config_json": cfg.model_dump_json(),
                "stats_json": stats.model_dump_json(),
                "mode": "imported",
            },
        )
        for i in range(0, len(imp.events), 5000):
            await asyncio.to_thread(store.capture_add_events, cid, i + 1, imp.events[i : i + 5000])
        origin = imp.origin | {
            "format": imp.format,
            "warnings": imp.warnings,
            "skipped_lines": imp.skipped_lines,
            "imported_at": time.time(),
            "all_events_demo": all(e.demo for e in imp.events),
        }
        arts: dict[str, tuple[str, bytes]] = {
            "origin.json": ("application/json", json.dumps(origin, default=str, indent=1).encode()),
            "devices_start.json": (
                "application/json",
                json.dumps({"devices": imp.devices}, default=str).encode(),
            ),
            "coverage.json": ("application/json", json.dumps(imp.coverage).encode()),
        }
        if imp.telemetry:
            arts["telemetry.jsonl"] = (
                "application/x-ndjson",
                "\n".join(t.model_dump_json() for t in imp.telemetry).encode(),
            )
        for n, (ct, data) in arts.items():
            await asyncio.to_thread(store.capture_put_artifact, cid, n, ct, data)
        store.audit(
            "api",
            "capture_import",
            {"id": cid, "format": imp.format, "events": len(imp.events), "file": imp.origin.get("filename")},
        )
        return await self.info(cid)

    async def artifact_json(self, cid: str, name: str) -> Any:
        art = await asyncio.to_thread(self.st.store.capture_artifact, cid, name)
        if not art:
            return None
        try:
            return json.loads(art[1])
        except json.JSONDecodeError:
            return None

    # ----------------------------------------------------------- export / bundle
    async def export(self, cid: str, fmt: str) -> tuple[str, bytes, str]:
        """Returns (content_type, data, filename)."""
        info = await self.info(cid)
        evs = await self.events(cid)
        base = f"whd-{info.id}"
        meta = {
            "capture": info.model_dump(mode="json"),
            "mode": info.mode,
            "whd_version": __version__,
            "clock_note": "ts_boottime_ns is CLOCK_BOOTTIME; ts_wall is derived for display. See docs/clock-domains.md",
        }
        if fmt == "json":
            body = json.dumps(meta | {"events": [e.model_dump(mode="json") for e in evs]}, indent=1)
            return "application/json", body.encode(), base + ".json"
        if fmt == "jsonl":
            body = "\n".join(e.model_dump_json() for e in evs) + "\n"
            return "application/x-ndjson", body.encode(), base + ".jsonl"
        if fmt == "csv":
            return "text/csv", events_to_csv(evs).encode(), base + ".csv"
        if fmt == "trace":
            return "text/plain", events_to_trace_text(evs).encode(), base + ".trace.txt"
        raise ValueError("format must be json, jsonl, csv or trace")

    async def bundle(self, cid: str, redact: bool = True, extra: dict[str, bytes] | None = None) -> bytes:
        info = await self.info(cid)
        evs = await self.events(cid)
        tel = await self.telemetry(cid)
        red = Redactor() if redact else None

        def R(s: str) -> str:
            return red.text(s) if red else s

        files: dict[str, bytes] = {}
        events_jsonl = "\n".join(e.model_dump_json() for e in evs) + "\n"
        files["events.jsonl"] = R(events_jsonl).encode()
        files["events.csv"] = R(events_to_csv(evs)).encode()
        files["trace.txt"] = R(events_to_trace_text(evs)).encode()
        files["telemetry.jsonl"] = R("\n".join(s.model_dump_json() for s in tel) + "\n").encode()
        for name in ("devices_start.json", "devices_end.json"):
            art = await asyncio.to_thread(self.st.store.capture_artifact, cid, name)
            if art:
                files[name] = R(art[1].decode()).encode()
        imported = info.mode == "imported"
        snap = None if imported else self.st.inventory.snapshot
        if snap:
            files["inventory_now.json"] = R(
                json.dumps(
                    {
                        "taken_at": snap.taken_at,
                        "issues": [i.model_dump() for i in snap.issues],
                        "devices": [
                            d.model_dump(mode="json")
                            for d in snap.devices
                            if info.config.device_id in (None, d.id)
                        ],
                    },
                    default=str,
                    indent=1,
                )
            ).encode()
        if imported:
            origin = await asyncio.to_thread(self.st.store.capture_artifact, cid, "origin.json")
            if origin:
                files["origin.json"] = R(origin[1].decode()).encode()
        if not imported:  # host-specific facts describe THIS machine, not the capture's origin
            from whd.services.system import system_info

            helper_status: dict[str, Any] = (
                await self.st.helper.status() if self.st.helper else {"connected": False}
            )
            sysinfo = await asyncio.to_thread(
                system_info, self.st.host, self.st.settings.demo_scenario, helper_status
            )
            files["system.json"] = R(sysinfo.model_dump_json(indent=1)).encode()
            files["sources.json"] = json.dumps(
                self.st.events.status() if self.st.events else [], indent=1
            ).encode()
            files["audit.json"] = json.dumps(
                await asyncio.to_thread(self.st.store.audit_log, 100), indent=1, default=str
            ).encode()
        for k, v in (extra or {}).items():
            files[k] = R(v.decode()).encode() if red else v
        demo = info.mode == "demo" or (not imported and self.st.settings.mode == "demo")
        files["README.txt"] = (
            "WHD diagnostic bundle\n=====================\n"
            f"capture: {info.id} ({info.name})  state: {info.state}\n"
            f"generated: {time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())} by WHD {__version__}\n"
            + (
                "*** DEMO MODE: contents come from fixtures / synthetic events, NOT live hardware ***\n"
                if demo
                else ""
            )
            + (
                "*** IMPORTED capture: recorded on another machine or session; see origin.json ***\n"
                if imported
                else ""
            )
            + f"MAC addresses {'were masked consistently (OUI kept)' if redact else 'are NOT masked'}.\n"
            "Timestamps: ts_boottime_ns = CLOCK_BOOTTIME ns (canonical); ts_wall is derived for display.\n"
            "Nothing in this bundle contains the WHD access token, session keys, or wireless key material.\n"
            "Files: events.jsonl/csv (captured events), trace.txt (raw tracefs lines if a trace ran), telemetry.jsonl, "
            "devices_*.json (inventory at start/end), "
            + ("origin.json" if imported else "system.json, sources.json, audit.json")
            + ", manifest.json\n"
        ).encode()
        manifest = {
            "whd_version": __version__,
            "capture": info.model_dump(mode="json"),
            "demo": demo,
            "redacted_macs": redact,
            "mac_map_size": len(red.map) if red else 0,
            "files": {
                k: {"bytes": len(v), "sha256": hashlib.sha256(v).hexdigest()}
                for k, v in sorted(files.items())
            },
        }
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
            for k, v in files.items():
                z.writestr(k, v)
            z.writestr("manifest.json", json.dumps(manifest, indent=1, default=str))
        return buf.getvalue()

    # ----------------------------------------------------------- replay
    async def replay(self, cid: str, speed: float) -> dict[str, Any]:
        if self.st.events is None:
            raise ValueError("event runtime not running")
        evs = await self.events(cid)
        if not evs:
            raise ValueError("capture has no events")
        await self.st.events.start_replay(evs, f"replay:{cid}", speed)
        return self.st.events.replay_status()
