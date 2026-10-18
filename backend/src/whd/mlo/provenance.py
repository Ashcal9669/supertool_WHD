"""Capture-time provenance; a source checkout is never assumed to match a loaded module."""

from __future__ import annotations

import copy
import hashlib
import os
import struct
import subprocess
import time
from pathlib import Path
from typing import Any

from whd import __version__
from whd.clock import boottime_ns, monotonic_ns
from whd.mlo.definitions import mcu_ids
from whd.platform.host import Host
from whd.platform.sysfs import SysfsError


def build_id(note: bytes) -> str | None:
    at = 0
    while at + 12 <= len(note):
        names, desc, typ = struct.unpack_from("<III", note, at)
        at += 12
        if names > len(note) or desc > len(note):
            return None
        name = note[at : at + names].rstrip(b"\0")
        at += (names + 3) & ~3
        body = note[at : at + desc]
        at += (desc + 3) & ~3
        if name == b"GNU" and typ == 3 and len(body) == desc:
            return body.hex()
    return None


def _git(path: Path, *args: str) -> bytes | None:
    try:
        r = subprocess.run(["git", "-C", str(path), *args], capture_output=True, timeout=5, check=False)
        return r.stdout if r.returncode == 0 else None
    except (OSError, subprocess.TimeoutExpired):
        return None


def snapshot(
    host: Host,
    devices: list[Any],
    sources: list[dict[str, Any]] | None = None,
    *,
    trace_status: dict[str, Any] | None = None,
) -> dict[str, Any]:
    def read(path: str) -> bytes | None:
        try:
            return host.root.read_bytes(path)
        except (SysfsError, OSError):
            return None

    clock_before = boottime_ns()
    wall, mono = time.time_ns(), monotonic_ns()
    clock_after = boottime_ns()
    modules: dict[str, Any] = {}
    for dev in devices:
        for name in [dev.module, *dev.driver_info.module_dependencies]:
            if not name or name in modules:
                continue
            note = read(f"/sys/module/{name}/notes/.note.gnu.build-id")
            param_dir = host.root.path(f"/sys/module/{name}/parameters")
            params = {}
            try:
                for p in param_dir.iterdir():
                    b = read(f"/sys/module/{name}/parameters/{p.name}")
                    params[p.name] = b.decode(errors="replace").strip() if b else None
            except OSError:
                pass
            modules[name] = {
                "loaded_build_id": build_id(note) if note else None,
                "parameters": params,
                "loaded_build_note_hex": note.hex() if note else None,
                "modinfo": host.modinfo(name),
            }
    boot = read("/proc/sys/kernel/random/boot_id")
    repo = Path(__file__).resolve().parents[4]
    revision, diff = _git(repo, "rev-parse", "HEAD"), _git(repo, "diff", "--binary", "HEAD")
    source_path = os.environ.get("WHD_DRIVER_SOURCE") if host.root.is_live else None
    source: dict[str, Any] = {
        "path": source_path,
        "revision": None,
        "dirty_diff_sha256": None,
        "matches_loaded_build": None,
    }
    if source_path:
        rev, dirty = (
            _git(Path(source_path), "rev-parse", "HEAD"),
            _git(Path(source_path), "diff", "--binary", "HEAD"),
        )
        source.update(
            revision=rev.decode().strip() if rev else None,
            dirty_diff_sha256=hashlib.sha256(dirty).hexdigest() if dirty is not None else None,
        )
    return {
        "mode": "live" if host.root.is_live else "fixture",
        "boot_id": boot.decode().strip() if boot else None,
        "kernel": host.uname(),
        "modules": modules,
        "firmware": {d.id: d.firmware.model_dump(mode="json") for d in devices},
        "devices": [d.model_dump(mode="json") for d in devices],
        "driver_source": source,
        "decoder_source": mcu_ids().get("source"),
        "decoder_matches_loaded_build": None,
        "collector": {
            "whd_version": __version__,
            "revision": revision.decode().strip() if revision else None,
            "dirty_diff_sha256": hashlib.sha256(diff).hexdigest() if diff is not None else None,
            "source_sha256": {
                str(p.relative_to(repo)): hashlib.sha256(p.read_bytes()).hexdigest()
                for p in (repo / "backend/src/whd").rglob("*.py")
            },
        },
        "clock": {
            "boottime_before_ns": clock_before,
            "boottime_after_ns": clock_after,
            "wall_ns": wall,
            "monotonic_ns": mono,
            "uncertainty_ns": clock_after - clock_before,
            "air_clock_offset_ns": None,
        },
        "sources": sources or [],
        "lost_trace_events": None,
        "trace_status": copy.deepcopy(trace_status),
        "trace_loss": copy.deepcopy(trace_status.get("loss")) if trace_status else None,
        "limits": [
            "source/build equivalence unverified unless independently established",
            "trace loss unknown unless collector exports it",
            "trace loss counters are cumulative for their owned session, not capture deltas; kernel metrics must not be summed together",
            "firmware build text is not a firmware hash",
        ],
    }
