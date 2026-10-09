"""Import captures that did not originate on this host (or are from old sessions).

Accepted inputs (detected from content, not from the file name):
  * WHD diagnostic bundle (.zip)             events + telemetry + device inventory + origin info
  * WHD export: JSON, JSONL, CSV            (CSV has no decoded `data` fields: reported as a warning)
  * ftrace text (trace_pipe / `trace` / WHD trace export)
  * kernel log text: `dmesg`, `dmesg -T`, `journalctl -k -o short-monotonic`
  * journald JSON lines (`journalctl -o json`)

Imported events never touch the live event store or ring. Everything is parsed in memory with hard limits
(upload size, member count/size for zips, event count, per-field length); malformed lines are counted and
reported, never trusted. Timestamps are kept in the *origin* machine's clock domain.
"""

from __future__ import annotations

import csv
import hashlib
import io
import json
import re
import time
import zipfile
from dataclasses import dataclass, field
from typing import Any

from pydantic import ValidationError

from whd.events.classify import classify_kernel
from whd.events.sources import KV, TRACE_LINE, make_event, trace_category
from whd.model.events import Event, TelemetrySample

MAX_UPLOAD_BYTES = 64 * 1024 * 1024
MAX_EVENTS = 200_000
MAX_TELEMETRY = 100_000
MAX_ZIP_MEMBERS = 64
MAX_ZIP_MEMBER_BYTES = 128 * 1024 * 1024
MAX_ZIP_TOTAL_BYTES = 256 * 1024 * 1024
MAX_FIELD = 4096
MAX_DATA_JSON = 16 * 1024

FORMATS = (
    "whd-bundle",
    "whd-json",
    "whd-jsonl",
    "whd-csv",
    "ftrace-text",
    "dmesg",
    "dmesg-wall",
    "journald-json",
    "short-monotonic",
)

BDF = r"[0-9a-f]{4}:[0-9a-f]{2}:[0-9a-f]{2}\.[0-7]"
DMESG_RE = re.compile(r"^(?:<(?P<prio>\d)>)?\[\s*(?P<ts>\d+\.\d+)\]\s?(?P<msg>.*)$")
DMESG_WALL_RE = re.compile(
    r"^\[(?P<wall>[A-Z][a-z]{2} [A-Z][a-z]{2} +\d+ \d\d:\d\d:\d\d \d{4})\]\s?(?P<msg>.*)$"
)
SHORT_MONO_RE = re.compile(r"^\[\s*(?P<ts>\d+\.\d+)\]\s+\S+\s+(?:kernel|[\w.-]+(?:\[\d+\])?):\s(?P<msg>.*)$")


class ImportError_(ValueError):
    """Raised for unusable uploads (reported to the client as HTTP 422)."""


@dataclass
class Imported:
    format: str
    events: list[Event]
    telemetry: list[TelemetrySample] = field(default_factory=list)
    devices: list[dict[str, Any]] = field(default_factory=list)
    coverage: dict[str, str] = field(default_factory=dict)
    origin: dict[str, Any] = field(default_factory=dict)
    warnings: list[str] = field(default_factory=list)
    skipped_lines: int = 0
    trace_inventory: list[str] = field(default_factory=list)


# --------------------------------------------------------------------------------------- detection


def detect_format(data: bytes) -> str:
    if data[:4] == b"PK\x03\x04":
        return "whd-bundle"
    head = data[:65536].decode("utf-8", errors="replace").lstrip("\ufeff")
    first = next((ln for ln in head.splitlines() if ln.strip()), "")
    if first.startswith("{"):
        try:
            j = json.loads(first)
            if isinstance(j, dict) and ("ts_boottime_ns" in j and "kind" in j):
                return "whd-jsonl"
            if isinstance(j, dict) and (
                "MESSAGE" in j
                or "__REALTIME_TIMESTAMP" in j
                or "_SOURCE_MONOTONIC_TIMESTAMP" in j
                or "__MONOTONIC_TIMESTAMP" in j
            ):
                return "journald-json"
        except json.JSONDecodeError:
            pass
        if '"events"' in head[:200000] or head.lstrip().startswith("{\n"):
            return "whd-json"
        return "whd-json"
    if first.startswith("id,ts_boottime_ns"):
        return "whd-csv"
    lines = [ln for ln in head.splitlines() if ln.strip()][:40]
    if any(ln.startswith("# tracer") for ln in lines) or sum(
        1 for ln in lines if TRACE_LINE.match(ln)
    ) >= max(2, len([x for x in lines if not x.startswith("#")]) // 2):
        return "ftrace-text"
    wall = sum(1 for ln in lines if DMESG_WALL_RE.match(ln))
    mono = sum(1 for ln in lines if SHORT_MONO_RE.match(ln))
    plain = sum(1 for ln in lines if DMESG_RE.match(ln))
    if wall and wall >= plain:
        return "dmesg-wall"
    if mono and mono >= plain // 2 and mono > 0 and any(SHORT_MONO_RE.match(ln) for ln in lines[:5]):
        return "short-monotonic"
    if plain:
        return "dmesg"
    raise ImportError_(
        "unrecognized format: expected a WHD bundle/export, ftrace text, dmesg/journalctl output or "
        "journald JSON"
    )


# --------------------------------------------------------------------------------------- helpers


def _clip(s: str, n: int = MAX_FIELD) -> str:
    return s if len(s) <= n else s[: n - 3] + "..."


def _pseudo_device(c_data: dict[str, Any]) -> tuple[str | None, str | None]:
    """Imported logs have no inventory; give lines that name a device a stable pseudo identity."""
    dev = c_data.get("log_device")
    if not isinstance(dev, str):
        return None, None
    if re.fullmatch(BDF, dev):
        return f"log:pci:{dev}", "device prefix in imported log (no inventory snapshot)"
    if re.fullmatch(r"\d+-[\d.]+(?::\d+\.\d+)?", dev):
        return f"log:usb:{dev.split(':')[0]}", "device prefix in imported log (no inventory snapshot)"
    return None, None


def _kernel_event(
    sec: float,
    msg: str,
    prio: int | None,
    tag: str,
    ts_source: str = "kernel_printk",
    ts_raw: str | None = None,
) -> Event:
    c = classify_kernel(msg, prio)
    dev, method = _pseudo_device(c.data)
    data = dict(c.data)
    if method:
        data["attribution"] = method
    ev = make_event(
        ts=int(sec * 1e9),
        ts_source=ts_source,  # type: ignore[arg-type]
        ts_raw=ts_raw or f"{sec:.6f}s (imported {tag})",
        source=f"import:{tag}",
        device_id=dev,
        severity=c.severity,
        category=c.category,
        kind=c.kind,
        summary=_clip(c.summary),
        explanation=c.explanation,
        raw=_clip(msg),
        data=data,
    )
    ev.ts_wall = (
        0.0  # make_event derives wall time from THIS host's boot clock: meaningless for foreign stamps
    )
    return ev


def _no_events(fmt: str) -> ImportError_:
    return ImportError_(f"no events could be parsed from this {fmt} file")


# --------------------------------------------------------------------------------------- parsers


def parse_whd_jsonl(text: str) -> tuple[list[Event], int]:
    out: list[Event] = []
    bad = 0
    for ln in text.splitlines():
        if not ln.strip():
            continue
        try:
            out.append(Event.model_validate_json(ln))
        except (ValidationError, ValueError):
            bad += 1
    return out, bad


def parse_whd_json(text: str) -> tuple[list[Event], dict[str, Any], int]:
    try:
        j = json.loads(text)
    except json.JSONDecodeError as e:
        raise ImportError_(f"invalid JSON: {e}") from e
    if not isinstance(j, dict) or not isinstance(j.get("events"), list):
        raise ImportError_("JSON file has no 'events' array (is this a WHD export?)")
    out: list[Event] = []
    bad = 0
    for item in j["events"]:
        try:
            out.append(Event.model_validate(item))
        except (ValidationError, ValueError):
            bad += 1
    return out, {k: v for k, v in j.items() if k != "events"}, bad


def parse_whd_csv(text: str) -> tuple[list[Event], int]:
    out: list[Event] = []
    bad = 0
    for row in csv.DictReader(io.StringIO(text)):
        try:
            wall = 0.0
            iso = row.get("ts_wall_iso") or ""
            if iso:
                wall = time.mktime(time.strptime(iso[:19], "%Y-%m-%dT%H:%M:%S")) - time.timezone
            out.append(
                Event(
                    ts_boottime_ns=int(row["ts_boottime_ns"]),
                    ts_source=row.get("ts_source") or "recorded",  # type: ignore[arg-type]
                    ts_raw=row.get("ts_raw") or None,
                    ts_wall=wall,
                    source=row.get("source") or "import:csv",
                    device_id=row.get("device_id") or None,
                    severity=row.get("severity") or "info",  # type: ignore[arg-type]
                    category=row.get("category") or "system",  # type: ignore[arg-type]
                    kind=row.get("kind") or "imported",
                    summary=row.get("summary") or "",
                    explanation=row.get("explanation") or "",
                    raw=row.get("raw") or "",
                    demo=(row.get("demo") or "").lower() == "true",
                )
            )
        except (ValueError, KeyError, ValidationError):
            bad += 1
    return out, bad


def parse_ftrace_text(text: str, group_hint: str | None) -> tuple[list[Event], int, int]:
    """Lines in trace_pipe/`trace` format. Without a hint the tracepoint group is unknown (kind trace.unknown.*)."""
    out: list[Event] = []
    bad = 0
    comments = 0
    for ln in text.splitlines():
        if not ln.strip():
            continue
        if ln.startswith("#"):
            comments += 1
            continue
        m = TRACE_LINE.match(ln)
        if not m:
            bad += 1
            continue
        ev = m.group("event")
        group = group_hint or (ev.split(":")[0] if ":" in ev else "unknown")
        name = ev.split(":")[-1]
        sec, frac = m.group("ts").split(".")
        ns = int(sec) * 10**9 + int(frac.ljust(9, "0")[:9])
        body = m.group("body")
        fields = dict(KV.findall(body))
        first = body.split(None, 1)[0] if body.strip() else ""
        if first and "=" not in first and ":" not in first:
            fields.setdefault("wiphy", first)
        cat, sev = trace_category(group, name)
        ev_obj = make_event(
            ts=ns,
            ts_source="tracefs_boot",
            ts_raw=f"{m.group('ts')} (imported ftrace text; clock assumed boot)",
            source=f"import:tracefs:{group}",
            severity=sev,
            category=cat,
            kind=f"trace.{group}.{name}",
            summary=_clip(f"{name}: {body[:160]}"),
            explanation=f"Tracepoint {group}:{name} from an imported ftrace text file (fields as printed by TP_printk; "
            "clock domain of the origin machine).",
            raw=_clip(ln),
            data={
                "task": m.group("task").strip(),
                "pid": int(m.group("pid")),
                "cpu": int(m.group("cpu")),
                "event": name,
                "group": group,
                "ts_ns": ns,
                "clock": "unknown",
                "fields": fields,
            },
        )
        ev_obj.ts_wall = 0.0
        out.append(ev_obj)
    return out, bad, comments


def parse_dmesg(text: str) -> tuple[list[Event], int]:
    out: list[Event] = []
    bad = 0
    for ln in text.splitlines():
        if not ln.strip():
            continue
        m = DMESG_RE.match(ln)
        if not m:
            if out:  # continuation line of the previous message
                bad += 1
            continue
        prio = int(m.group("prio")) if m.group("prio") else None
        out.append(_kernel_event(float(m.group("ts")), m.group("msg"), prio, "dmesg"))
    return out, bad


def parse_short_monotonic(text: str) -> tuple[list[Event], int]:
    out: list[Event] = []
    bad = 0
    for ln in text.splitlines():
        if not ln.strip() or ln.startswith("-- "):
            continue
        m = SHORT_MONO_RE.match(ln)
        if not m:
            bad += 1
            continue
        out.append(_kernel_event(float(m.group("ts")), m.group("msg"), None, "journal"))
    return out, bad


def parse_dmesg_wall(text: str) -> tuple[list[Event], int]:
    out: list[Event] = []
    bad = 0
    for ln in text.splitlines():
        if not ln.strip():
            continue
        m = DMESG_WALL_RE.match(ln)
        if not m:
            bad += 1
            continue
        try:
            wall = time.mktime(time.strptime(m.group("wall").replace("  ", " "), "%a %b %d %H:%M:%S %Y"))
        except ValueError:
            bad += 1
            continue
        e = _kernel_event(
            wall,
            m.group("msg"),
            None,
            "dmesg -T",
            ts_source="imported_wall_clock",
            ts_raw=f"{m.group('wall')} (wall clock, local time of the origin machine)",
        )
        e.ts_wall = wall
        out.append(e)
    return out, bad


def parse_journald_json(text: str) -> tuple[list[Event], int]:
    out: list[Event] = []
    bad = 0
    for ln in text.splitlines():
        if not ln.strip():
            continue
        try:
            j = json.loads(ln)
        except json.JSONDecodeError:
            bad += 1
            continue
        if not isinstance(j, dict):
            bad += 1
            continue
        msg = j.get("MESSAGE")
        if isinstance(msg, list):
            msg = bytes(x & 255 for x in msg if isinstance(x, int)).decode(errors="replace")
        if not isinstance(msg, str) or not msg:
            continue
        us = j.get("_SOURCE_MONOTONIC_TIMESTAMP") or j.get("__MONOTONIC_TIMESTAMP")
        try:
            sec = int(us or "x") / 1e6
            ts_source = "kernel_printk" if j.get("_SOURCE_MONOTONIC_TIMESTAMP") else "journal_monotonic"
            raw = f"{sec:.6f}s (imported journald, boot {str(j.get('_BOOT_ID', '?'))[:8]})"
        except (TypeError, ValueError):
            try:
                sec, ts_source, raw = (
                    int(j["__REALTIME_TIMESTAMP"]) / 1e6,
                    "imported_wall_clock",
                    "realtime (µs)",
                )
            except (KeyError, TypeError, ValueError):
                bad += 1
                continue
        try:
            prio = int(j.get("PRIORITY", 6))
        except (TypeError, ValueError):
            prio = 6
        e = _kernel_event(sec, msg, prio, "journald", ts_source=ts_source, ts_raw=raw)
        try:
            e.ts_wall = int(j["__REALTIME_TIMESTAMP"]) / 1e6 if "__REALTIME_TIMESTAMP" in j else 0.0
        except (TypeError, ValueError):
            e.ts_wall = 0.0
        kd = j.get("_KERNEL_DEVICE")
        if isinstance(kd, str) and e.device_id is None and kd.startswith("+pci:"):
            e.device_id, e.data["attribution"] = f"log:pci:{kd[5:]}", "journald _KERNEL_DEVICE (no inventory)"
        out.append(e)
    return out, bad


# --------------------------------------------------------------------------------------- zip bundle


def _read_zip(data: bytes, warnings: list[str]) -> dict[str, bytes]:
    try:
        z = zipfile.ZipFile(io.BytesIO(data))
    except zipfile.BadZipFile as e:
        raise ImportError_(f"not a valid zip file: {e}") from e
    infos = z.infolist()
    if len(infos) > MAX_ZIP_MEMBERS:
        raise ImportError_(f"zip has {len(infos)} members (limit {MAX_ZIP_MEMBERS})")
    total = sum(i.file_size for i in infos)
    if total > MAX_ZIP_TOTAL_BYTES or any(i.file_size > MAX_ZIP_MEMBER_BYTES for i in infos):
        raise ImportError_("zip expands beyond the allowed size (possible zip bomb)")
    out: dict[str, bytes] = {}
    for i in infos:
        n = i.filename
        if i.is_dir() or n.startswith("/") or ".." in n.split("/") or "\\" in n:
            warnings.append(f"ignored suspicious zip member name {n!r}")
            continue
        with z.open(i) as f:  # read with a hard cap even if the header lied about the size
            buf = f.read(MAX_ZIP_MEMBER_BYTES + 1)
        if len(buf) > MAX_ZIP_MEMBER_BYTES:
            raise ImportError_(f"member {n!r} is larger than allowed")
        out[n] = buf
    return out


def parse_bundle(data: bytes, group_hint: str | None) -> Imported:
    warnings: list[str] = []
    files = _read_zip(data, warnings)
    manifest: dict[str, Any] = {}
    if "manifest.json" in files:
        try:
            manifest = json.loads(files["manifest.json"])
        except json.JSONDecodeError:
            warnings.append("manifest.json is not valid JSON")
        for name, meta in (manifest.get("files") or {}).items():
            if name in files and isinstance(meta, dict) and meta.get("sha256"):
                if hashlib.sha256(files[name]).hexdigest() != meta["sha256"]:
                    warnings.append(f"integrity: {name} does not match the SHA-256 in the manifest")
    else:
        warnings.append("no manifest.json: file integrity could not be checked")
    events: list[Event] = []
    skipped = 0
    if "events.jsonl" in files:
        events, skipped = parse_whd_jsonl(files["events.jsonl"].decode("utf-8", errors="replace"))
    elif "events.csv" in files:
        events, skipped = parse_whd_csv(files["events.csv"].decode("utf-8", errors="replace"))
        warnings.append("events.jsonl missing; used events.csv (no decoded data fields)")
    elif "trace.txt" in files:
        events, skipped, _ = parse_ftrace_text(
            files["trace.txt"].decode("utf-8", errors="replace"), group_hint
        )
        warnings.append("events.jsonl missing; reconstructed events from trace.txt only")
    if not events:
        raise _no_events("bundle")
    tel: list[TelemetrySample] = []
    bad_tel = 0
    if "telemetry.jsonl" in files:
        for ln in files["telemetry.jsonl"].decode("utf-8", errors="replace").splitlines():
            if not ln.strip():
                continue
            try:
                tel.append(TelemetrySample.model_validate_json(ln))
            except (ValidationError, ValueError):
                bad_tel += 1
    if bad_tel:
        warnings.append(f"{bad_tel} unreadable telemetry sample(s) skipped")
    devices: list[dict[str, Any]] = []
    for name in ("devices_start.json", "inventory_now.json", "devices_end.json"):
        if name in files:
            try:
                devices = list(json.loads(files[name]).get("devices", []))
            except (json.JSONDecodeError, AttributeError, TypeError):
                warnings.append(f"{name} unreadable")
                continue
            if devices:
                break
    coverage: dict[str, str] = {}
    trace_inv: list[str] = []
    for name, blob in files.items():
        if name.startswith("mt76_instrumentation_") and name.endswith(".json"):
            try:
                ins = json.loads(blob)
                for it in ins.get("items", []):
                    coverage[it["id"]] = (
                        it["status"]
                        if it["id"] not in coverage or it["status"] != "available"
                        else coverage[it["id"]]
                    )
                trace_inv += [f"{t['group']}/{t['name']}" for t in ins.get("tracepoints", [])]
            except (json.JSONDecodeError, KeyError, TypeError):
                warnings.append(f"{name} unreadable")
    origin: dict[str, Any] = {
        "whd_version": manifest.get("whd_version"),
        "demo": manifest.get("demo"),
        "redacted_macs": manifest.get("redacted_macs"),
    }
    if "system.json" in files:
        try:
            s = json.loads(files["system.json"])
            origin |= {
                k: s.get(k)
                for k in ("hostname", "kernel_release", "arch", "distro", "mode", "demo_scenario")
                if s.get(k) is not None
            }
        except json.JSONDecodeError:
            warnings.append("system.json unreadable")
    cap = manifest.get("capture") or {}
    if cap.get("name"):
        origin["capture_name"] = cap["name"]
    return Imported(
        format="whd-bundle",
        events=events,
        telemetry=tel,
        devices=devices,
        coverage=coverage,
        origin=origin,
        warnings=warnings,
        skipped_lines=skipped,
        trace_inventory=trace_inv,
    )


# --------------------------------------------------------------------------------------- entry point


def parse_upload(data: bytes, filename: str, group_hint: str | None = None) -> Imported:
    if not data:
        raise ImportError_("empty file")
    if len(data) > MAX_UPLOAD_BYTES:
        raise ImportError_(f"file is larger than the {MAX_UPLOAD_BYTES // (1024 * 1024)} MiB limit")
    fmt = detect_format(data)
    warnings: list[str] = []
    if fmt == "whd-bundle":
        imp = parse_bundle(data, group_hint)
    else:
        text = data.decode("utf-8", errors="replace").lstrip("\ufeff")
        origin: dict[str, Any] = {}
        tel: list[TelemetrySample] = []
        skipped = 0
        if fmt == "whd-jsonl":
            evs, skipped = parse_whd_jsonl(text)
        elif fmt == "whd-json":
            evs, origin, skipped = parse_whd_json(text)
            cap = origin.get("capture") or {}
            origin = {
                "whd_version": origin.get("whd_version"),
                "capture_name": cap.get("name"),
                "demo": cap.get("mode") == "demo",
            }
        elif fmt == "whd-csv":
            evs, skipped = parse_whd_csv(text)
            warnings.append(
                "CSV export carries no decoded event fields: TID/link aggregation and the firmware "
                "sequence need JSON, JSONL or a bundle"
            )
        elif fmt == "ftrace-text":
            evs, skipped, _ = parse_ftrace_text(text, group_hint)
            if not group_hint and any(e.kind.startswith("trace.unknown.") for e in evs):
                warnings.append(
                    "tracepoint groups are unknown for this file (names are printed without a group); "
                    "pass a group hint such as mt76 to enable driver-specific views"
                )
        elif fmt == "dmesg":
            evs, skipped = parse_dmesg(text)
        elif fmt == "dmesg-wall":
            evs, skipped = parse_dmesg_wall(text)
            warnings.append(
                "`dmesg -T` has wall-clock stamps only; ordering uses them (second resolution, DST/clock "
                "steps can reorder)"
            )
        elif fmt == "short-monotonic":
            evs, skipped = parse_short_monotonic(text)
        else:  # journald-json
            evs, skipped = parse_journald_json(text)
        if not evs:
            raise _no_events(fmt)
        imp = Imported(
            format=fmt, events=evs, telemetry=tel, origin=origin, warnings=warnings, skipped_lines=skipped
        )
    if imp.skipped_lines:
        imp.warnings.append(f"{imp.skipped_lines} line(s)/record(s) could not be parsed and were skipped")
    imp.origin["filename"] = _clip(filename.rsplit("/", 1)[-1], 200)
    return imp


def finalize(imp: Imported, cid: str, max_events: int = MAX_EVENTS) -> Imported:
    """Sort, cap, sanitize and re-tag events so imported data can never masquerade as live data."""
    evs = sorted(imp.events, key=lambda e: (e.ts_boottime_ns, e.id or 0))
    if len(evs) > max_events:
        imp.warnings.append(f"capture has {len(evs)} events; kept the last {max_events}")
        evs = evs[-max_events:]
    last = evs[-1]
    anchor = time.time()
    for e in evs:
        e.id = None
        e.session = f"import:{cid}"
        e.summary, e.explanation, e.raw = _clip(e.summary), _clip(e.explanation), _clip(e.raw)
        if e.ts_raw is None:
            e.ts_raw = f"{e.ts_boottime_ns / 1e9:.6f}s (origin clock)"
        if not e.ts_wall or e.ts_wall < 86400:
            e.ts_wall = anchor - (last.ts_boottime_ns - e.ts_boottime_ns) / 1e9
            e.data = dict(e.data) | {"wall_time_anchored_to_import": True}
        if len(json.dumps(e.data, default=str)) > MAX_DATA_JSON:
            e.data = {"dropped": "decoded data exceeded the size limit on import"}
            imp.warnings.append("some events had oversized decoded data; it was dropped")
    imp.events = evs
    if len(imp.telemetry) > MAX_TELEMETRY:
        imp.warnings.append(f"telemetry truncated to the last {MAX_TELEMETRY} samples")
        imp.telemetry = imp.telemetry[-MAX_TELEMETRY:]
    imp.warnings = list(dict.fromkeys(imp.warnings))
    return imp
