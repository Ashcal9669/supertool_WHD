"""Typed access to the driver's key=value debug lines (driver.kv_trace events) and to tracepoint events.

The driver prints `TAG: key=value ...` lines. WHD already splits them into data["tag"] and data["fields"]; this module
adds the numeric/hex conversions the MLO analysis needs and never raises on a malformed field.
"""

from __future__ import annotations

from typing import Any

from whd.model.events import Event


def tag_of(e: Event) -> str | None:
    if e.kind != "driver.kv_trace":
        return None
    t = (e.data or {}).get("tag")
    return str(t) if t else None


def fields_of(e: Event) -> dict[str, str]:
    f = (e.data or {}).get("fields")
    return {str(k): str(v) for k, v in f.items()} if isinstance(f, dict) else {}


def to_int(v: str | None) -> int | None:
    """Parse a decimal or 0x-hex field; None for missing, pointers-as-text and anything else non-numeric."""
    if v is None:
        return None
    try:
        return int(v, 0)
    except ValueError:
        return None


def num(f: dict[str, str], key: str) -> int | None:
    return to_int(f.get(key))


def trace_name(e: Event) -> str | None:
    """`mlo_rx` for kind trace.mt76.mlo_rx; the group is returned by trace_group."""
    if not e.kind.startswith("trace."):
        return None
    parts = e.kind.split(".", 2)
    return parts[2] if len(parts) == 3 else None


def trace_group(e: Event) -> str | None:
    if not e.kind.startswith("trace."):
        return None
    parts = e.kind.split(".", 2)
    return parts[1] if len(parts) == 3 else None


def trace_fields(e: Event) -> dict[str, str]:
    return fields_of(e)


def mac_of(v: str | None) -> str | None:
    if v and len(v) == 17 and v.count(":") == 5:
        return v.lower()
    return None


def ev_ref(e: Event) -> dict[str, Any]:
    return {"event_id": e.id, "ts_boottime_ns": e.ts_boottime_ns, "kind": e.kind}
