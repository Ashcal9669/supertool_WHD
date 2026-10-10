"""whd-helper: narrowly scoped privileged helper (runs as root).

Security model
--------------
* Listens on a Unix stream socket (default /run/whd/helper.sock), mode 0660.
* Every connection is checked with SO_PEERCRED: only uids in --allow-uid (and/or gids in
  --allow-gid) may talk to it. Root peers are not implicitly trusted beyond that list.
* Fixed verb set (protocol.VERBS); arguments are validated with strict regexes and every
  filesystem path is built from validated components and re-checked with realpath.
* No shell, no subprocess, no arbitrary paths, no writes to devices/drivers/config space.
* The only writes it ever performs are inside its own tracefs instance directory
  (instances/whd): create instance, set trace_clock/buffer size, enable/disable events,
  tracing_on, remove instance. The global trace buffer and other instances are never touched.
* debugfs reads go through helper/policy.py (allowlist with side-effect tiers).

Run (development): sudo .venv/bin/python -m whd.helper.server --allow-uid $(id -u)
Run (production):  see deploy/systemd/whd-helper.{socket,service}
"""

from __future__ import annotations

import argparse
import asyncio
import base64
import contextlib
import grp
import json
import logging
import os
import signal
import socket
import stat
import struct
import sys
import threading
import time
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from whd.helper import policy
from whd.helper.protocol import (
    BDF_RE,
    MAX_REQUEST,
    NAME_RE,
    PHY_RE,
    PROTOCOL_VERSION,
    RELPATH_RE,
    USB_BUS_RE,
    VERBS,
    HelperError,
)

log = logging.getLogger("whd.helper")

INSTANCE = "whd"
MAX_BUFFER_KB = 16384
MAX_EVENTS = 256
MAX_LINES_PER_SEC = 50_000
CONFIG_MAX = 4096


@dataclass
class Roots:
    """Filesystem roots (overridable for tests)."""

    sys: Path = Path("/sys")
    tracefs: Path = Path("/sys/kernel/tracing")
    debugfs: Path = Path("/sys/kernel/debug")

    @property
    def ieee80211(self) -> Path:
        return self.debugfs / "ieee80211"

    @property
    def usbmon(self) -> Path:
        return self.debugfs / "usb" / "usbmon"


def _within(p: Path, base: Path) -> Path:
    rp = Path(os.path.realpath(p))
    rb = Path(os.path.realpath(base))
    if rp != rb and rb not in rp.parents:
        raise HelperError("path", f"path escapes {base}")
    return rp


def _read(p: Path, limit: int) -> bytes:
    fd = os.open(p, os.O_RDONLY | os.O_CLOEXEC | os.O_NONBLOCK)
    try:
        out = b""
        while len(out) < limit:
            b = os.read(fd, min(65536, limit - len(out)))
            if not b:
                break
            out += b
        return out
    finally:
        os.close(fd)


def _write_own(p: Path, value: str, roots: Roots) -> None:
    """Write only inside our own tracefs instance."""
    inst = roots.tracefs / "instances" / INSTANCE
    _within(p, inst)
    fd = os.open(p, os.O_WRONLY | os.O_CLOEXEC | os.O_TRUNC)
    try:
        os.write(fd, value.encode())
    finally:
        os.close(fd)


@dataclass
class TraceSession:
    events: list[str]
    clock: str
    started: float = field(default_factory=time.time)
    stop: threading.Event = field(default_factory=threading.Event)
    dropped: int = 0
    lines: int = 0


class Helper:
    def __init__(self, roots: Roots, allow_uids: set[int], allow_gids: set[int]) -> None:
        self.roots = roots
        self.allow_uids = allow_uids
        self.allow_gids = allow_gids
        self.trace: TraceSession | None = None
        self.trace_lock = threading.Lock()
        self.handlers: dict[str, Callable[..., Any]] = {
            "ping": self.ping,
            "pci_config_read": self.pci_config_read,
            "debugfs_list": self.debugfs_list,
            "debugfs_read": self.debugfs_read,
            "tracefs_events": self.tracefs_events,
            "tracefs_status": self.tracefs_status,
        }
        assert set(self.handlers) | {"trace_stream", "usbmon_stream"} == set(VERBS)

    # ------------------------------------------------------------------ verbs
    def ping(self) -> dict[str, Any]:
        tr = self.roots.tracefs
        return {
            "protocol": PROTOCOL_VERSION,
            "euid": os.geteuid(),
            "pid": os.getpid(),
            "tracefs": tr.is_dir() and (tr / "events").is_dir(),
            "debugfs": self.roots.ieee80211.is_dir(),
            "usbmon": self.roots.usbmon.is_dir(),
            "trace_active": self.trace is not None,
            "verbs": list(VERBS),
        }

    def pci_config_read(self, bdf: str) -> dict[str, Any]:
        if not isinstance(bdf, str) or not BDF_RE.match(bdf):
            raise HelperError("args", "invalid BDF")
        base = self.roots.sys / "bus" / "pci" / "devices"
        dev = _within(base / bdf, self.roots.sys / "devices")
        data = _read(dev / "config", CONFIG_MAX)
        return {"bdf": bdf, "length": len(data), "data": base64.b64encode(data).decode()}

    def _phy_dir(self, phy: str) -> Path:
        if not isinstance(phy, str) or not PHY_RE.match(phy):
            raise HelperError("args", "invalid phy")
        d = self.roots.ieee80211 / phy
        if not d.is_dir():
            raise HelperError("missing", f"no debugfs directory for {phy}")
        return d

    def _phy_bus(self, phy: str) -> str | None:
        try:
            return os.path.basename(
                os.readlink(self.roots.sys / "class/ieee80211" / phy / "device/subsystem")
            )
        except OSError:
            return None

    def debugfs_list(self, phy: str, max_entries: int = 2000) -> dict[str, Any]:
        base = self._phy_dir(phy)
        bus = self._phy_bus(phy)
        out: list[dict[str, Any]] = []
        for dirpath, dirnames, filenames in os.walk(base):
            rel_dir = os.path.relpath(dirpath, base)
            depth = 0 if rel_dir == "." else rel_dir.count("/") + 1
            if depth >= 5:
                dirnames[:] = []
            for fn in sorted(filenames):
                rel = fn if rel_dir == "." else f"{rel_dir}/{fn}"
                try:
                    st = os.lstat(os.path.join(dirpath, fn))
                except OSError:
                    continue
                tier, desc = policy.classify(rel, bus)
                out.append(
                    {
                        "path": rel,
                        "mode": stat.filemode(st.st_mode),
                        "readable_by_owner": bool(st.st_mode & stat.S_IRUSR),
                        "writable_by_owner": bool(st.st_mode & stat.S_IWUSR),
                        "tier": tier,
                        "policy": desc,
                    }
                )
                if len(out) >= max_entries:
                    return {"phy": phy, "entries": out, "truncated": True}
        return {"phy": phy, "entries": out, "truncated": False}

    def debugfs_read(self, phy: str, path: str, allow: list[str] | None = None) -> dict[str, Any]:
        base = self._phy_dir(phy)
        if not isinstance(path, str) or not RELPATH_RE.match(path) or ".." in path.split("/"):
            raise HelperError("args", "invalid debugfs path")
        tier, desc = policy.classify(path, self._phy_bus(phy))
        if tier is None or tier == "never":
            raise HelperError("policy", f"{path}: {desc}")
        if tier in ("mmio", "mcu") and tier not in (allow or []):
            raise HelperError("confirm", f"{path} performs a {tier} access ({desc}); explicit allow required")
        p = _within(base / path, base)
        st = os.stat(p)
        if not stat.S_ISREG(st.st_mode) or not st.st_mode & stat.S_IRUSR:
            raise HelperError("policy", f"{path} is not a readable file")
        t0 = time.monotonic()
        data = _read(p, policy.MAX_READ)
        return {
            "phy": phy,
            "path": path,
            "tier": tier,
            "policy": desc,
            "bytes": len(data),
            "truncated": len(data) >= policy.MAX_READ,
            "elapsed_ms": (time.monotonic() - t0) * 1000,
            "text": data.decode("utf-8", errors="replace") if b"\0" not in data[:4096] else None,
            "b64": base64.b64encode(data).decode() if b"\0" in data[:4096] else None,
            "read_at_boottime_ns": time.clock_gettime_ns(time.CLOCK_BOOTTIME),
        }

    def tracefs_events(self, groups: list[str] | None = None, with_format: bool = False) -> dict[str, Any]:
        ev = self.roots.tracefs / "events"
        if not ev.is_dir():
            raise HelperError("missing", "tracefs events directory not available")
        out: dict[str, dict[str, Any]] = {}
        for g in sorted(os.listdir(ev)):
            gp = ev / g
            if not gp.is_dir() or (groups and g not in groups):
                continue
            if groups is None and not with_format:
                out[g] = {}
                continue
            items: dict[str, Any] = {}
            for e in sorted(os.listdir(gp)):
                if not (gp / e).is_dir():
                    continue
                items[e] = _read(gp / e / "format", 16384).decode(errors="replace") if with_format else True
            out[g] = items
        return {"groups": out}

    def tracefs_status(self) -> dict[str, Any]:
        tr = self.roots.tracefs
        if not tr.is_dir():
            raise HelperError("missing", "tracefs not mounted")
        inst = sorted(os.listdir(tr / "instances")) if (tr / "instances").is_dir() else []
        clocks = _read(tr / "trace_clock", 4096).decode().split() if (tr / "trace_clock").exists() else []
        cur = _read(tr / "current_tracer", 256).decode().strip() if (tr / "current_tracer").exists() else None
        s = self.trace
        return {
            "instances": inst,
            "trace_clocks": [c.strip("[]") for c in clocks],
            "global_current_tracer": cur,
            "whd_session": None
            if s is None
            else {
                "events": s.events,
                "clock": s.clock,
                "started": s.started,
                "lines": s.lines,
                "dropped": s.dropped,
            },
        }

    # ------------------------------------------------------------- tracing
    def _trace_setup(self, events: list[str], buffer_kb: int) -> TraceSession:
        tr = self.roots.tracefs
        if not (tr / "instances").is_dir():
            raise HelperError("missing", "tracefs instances not supported")
        if not isinstance(events, list) or not events or len(events) > MAX_EVENTS:
            raise HelperError("args", f"events must be a list of 1..{MAX_EVENTS} 'group/event' or 'group/*'")
        resolved: list[str] = []
        for spec in events:
            if not isinstance(spec, str) or spec.count("/") != 1:
                raise HelperError("args", f"bad event spec {spec!r}")
            g, e = spec.split("/")
            if not NAME_RE.match(g) or not (e == "*" or NAME_RE.match(e)):
                raise HelperError("args", f"bad event spec {spec!r}")
            gp = tr / "events" / g
            if not gp.is_dir():
                raise HelperError("missing", f"tracepoint group {g} not available on this kernel")
            if e == "*":
                resolved += [f"{g}/{x}" for x in sorted(os.listdir(gp)) if (gp / x).is_dir()]
            elif (gp / e).is_dir():
                resolved.append(spec)
            else:
                raise HelperError("missing", f"tracepoint {spec} not available on this kernel")
        inst = tr / "instances" / INSTANCE
        if inst.exists():
            self._trace_teardown()
        os.mkdir(inst)  # creates a new, independent ring buffer instance
        clocks = [c.strip("[]") for c in _read(inst / "trace_clock", 4096).decode().split()]
        clock = "boot" if "boot" in clocks else "mono" if "mono" in clocks else "local"
        _write_own(inst / "trace_clock", clock, self.roots)
        _write_own(inst / "buffer_size_kb", str(max(64, min(int(buffer_kb), MAX_BUFFER_KB))), self.roots)
        for spec in resolved:
            g, e = spec.split("/")
            _write_own(inst / "events" / g / e / "enable", "1", self.roots)
        _write_own(inst / "tracing_on", "1", self.roots)
        return TraceSession(events=resolved, clock=clock)

    def _trace_teardown(self) -> None:
        inst = self.roots.tracefs / "instances" / INSTANCE
        if not inst.exists():
            return
        with contextlib.suppress(OSError):
            _write_own(inst / "tracing_on", "0", self.roots)
        with contextlib.suppress(OSError):
            _write_own(inst / "events" / "enable", "0", self.roots)
        for _ in range(20):
            try:
                os.rmdir(inst)
                return
            except OSError:
                time.sleep(0.05)

    def _pump(self, path: Path, session: TraceSession, emit: Callable[[list[str], int], None]) -> None:
        """Blocking reader for trace_pipe / usbmon text; batches lines, enforces a rate limit."""
        fd = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NONBLOCK)
        buf = b""
        window_start, window_lines = time.monotonic(), 0
        try:
            while not session.stop.is_set():
                try:
                    chunk = os.read(fd, 65536)
                except BlockingIOError:
                    chunk = b""
                if not chunk:
                    time.sleep(0.05)
                    continue
                buf += chunk
                *lines, buf = buf.split(b"\n")
                now = time.monotonic()
                if now - window_start >= 1.0:
                    window_start, window_lines = now, 0
                keep: list[str] = []
                for ln in lines:
                    if window_lines >= MAX_LINES_PER_SEC:
                        session.dropped += 1
                        continue
                    window_lines += 1
                    keep.append(ln.decode(errors="replace"))
                session.lines += len(keep)
                if keep:
                    emit(keep, session.dropped)
        finally:
            os.close(fd)

    async def trace_stream(
        self,
        send: Callable[[dict[str, Any]], Awaitable[None]],
        rid: int,
        events: list[str],
        buffer_kb: int = 4096,
        max_seconds: int = 3600,
    ) -> dict[str, Any]:
        if not self.trace_lock.acquire(blocking=False):
            raise HelperError("busy", "a WHD trace session is already active")
        try:
            session = await asyncio.to_thread(self._trace_setup, events, buffer_kb)
            self.trace = session
            await send(
                {
                    "id": rid,
                    "stream_start": {
                        "events": session.events,
                        "clock": session.clock,
                        "instance": f"instances/{INSTANCE}",
                    },
                }
            )
            loop = asyncio.get_running_loop()
            q: asyncio.Queue[tuple[list[str], int]] = asyncio.Queue(256)

            def emit(lines: list[str], dropped: int) -> None:
                def put() -> None:
                    if q.full():
                        session.dropped += len(lines)
                        return
                    q.put_nowait((lines, dropped))

                loop.call_soon_threadsafe(put)

            inst = self.roots.tracefs / "instances" / INSTANCE
            th = threading.Thread(target=self._pump, args=(inst / "trace_pipe", session, emit), daemon=True)
            th.start()
            deadline = time.monotonic() + max(1, min(int(max_seconds), 24 * 3600))
            try:
                while time.monotonic() < deadline:
                    try:
                        lines, dropped = await asyncio.wait_for(q.get(), timeout=1.0)
                    except TimeoutError:
                        continue
                    await send({"id": rid, "stream": lines, "dropped": dropped})
            finally:
                session.stop.set()
                await asyncio.to_thread(th.join, 2.0)
            return {"ended": "max_seconds", "lines": session.lines, "dropped": session.dropped}
        finally:
            self.trace = None
            await asyncio.to_thread(self._trace_teardown)
            self.trace_lock.release()

    async def usbmon_stream(
        self, send: Callable[[dict[str, Any]], Awaitable[None]], rid: int, bus: str, max_seconds: int = 600
    ) -> dict[str, Any]:
        if not isinstance(bus, str) or not USB_BUS_RE.match(bus):
            raise HelperError("args", "invalid bus number")
        p = self.roots.usbmon / f"{bus}u"
        if not p.exists():
            raise HelperError(
                "missing",
                "usbmon text interface not available (usbmon module not loaded; "
                "WHD does not load kernel modules)",
            )
        session = TraceSession(events=[f"usbmon/{bus}u"], clock="usbmon")
        loop = asyncio.get_running_loop()
        q: asyncio.Queue[tuple[list[str], int]] = asyncio.Queue(256)

        def emit(lines: list[str], dropped: int) -> None:
            loop.call_soon_threadsafe(lambda: None if q.full() else q.put_nowait((lines, dropped)))

        await send({"id": rid, "stream_start": {"source": str(p), "clock": "usbmon_us"}})
        th = threading.Thread(target=self._pump, args=(p, session, emit), daemon=True)
        th.start()
        deadline = time.monotonic() + max(1, min(int(max_seconds), 3600))
        try:
            while time.monotonic() < deadline:
                try:
                    lines, dropped = await asyncio.wait_for(q.get(), timeout=1.0)
                except TimeoutError:
                    continue
                await send({"id": rid, "stream": lines, "dropped": dropped})
        finally:
            session.stop.set()
            await asyncio.to_thread(th.join, 2.0)
        return {"ended": "max_seconds", "lines": session.lines, "dropped": session.dropped}

    # ------------------------------------------------------------ transport
    def peer_ok(self, sock: socket.socket) -> tuple[bool, int, int, int]:
        creds = sock.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, struct.calcsize("3i"))
        pid, uid, gid = struct.unpack("3i", creds)
        ok = uid in self.allow_uids or gid in self.allow_gids
        return ok, pid, uid, gid

    async def handle(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        sock = writer.get_extra_info("socket")
        ok, pid, uid, gid = self.peer_ok(sock)
        if not ok:
            log.warning("rejected peer", extra={"pid": pid, "uid": uid, "gid": gid})
            writer.write(
                json.dumps({"id": 0, "ok": False, "code": "denied", "error": "peer not allowed"}).encode()
                + b"\n"
            )
            await writer.drain()
            writer.close()
            return
        lock = asyncio.Lock()

        async def send(obj: dict[str, Any]) -> None:
            async with lock:
                writer.write(json.dumps(obj).encode() + b"\n")
                await writer.drain()

        tasks: set[asyncio.Task[None]] = set()
        try:
            while True:
                line = await reader.readline()
                if not line:
                    break
                if len(line) > MAX_REQUEST:
                    await send({"id": 0, "ok": False, "code": "args", "error": "request too large"})
                    break
                t = asyncio.create_task(self._dispatch(line, send, uid, pid))
                tasks.add(t)
                t.add_done_callback(tasks.discard)
        except (ConnectionError, asyncio.LimitOverrunError, ValueError):
            pass
        finally:
            for t in tasks:
                t.cancel()
            await asyncio.gather(*tasks, return_exceptions=True)
            writer.close()

    async def _dispatch(
        self, line: bytes, send: Callable[[dict[str, Any]], Awaitable[None]], uid: int, pid: int
    ) -> None:
        rid = 0
        try:
            req = json.loads(line)
            rid = int(req.get("id", 0))
            verb = req.get("verb")
            args = req.get("args") or {}
            if verb not in VERBS or not isinstance(args, dict):
                raise HelperError("verb", f"unknown verb {verb!r}")
            log.info(
                "request",
                extra={
                    "verb": verb,
                    "uid": uid,
                    "pid": pid,
                    "call_args": {k: v for k, v in args.items() if k != "data"},
                },
            )
            if verb == "trace_stream":
                result = await self.trace_stream(send, rid, **args)
            elif verb == "usbmon_stream":
                result = await self.usbmon_stream(send, rid, **args)
            else:
                result = await asyncio.to_thread(self.handlers[verb], **args)
            await send({"id": rid, "ok": True, "result": result})
        except HelperError as e:
            await send({"id": rid, "ok": False, "code": e.code, "error": str(e)})
        except TypeError as e:
            await send({"id": rid, "ok": False, "code": "args", "error": f"bad arguments: {e}"})
        except OSError as e:
            await send({"id": rid, "ok": False, "code": "os", "error": f"{e.strerror or e} ({e.errno})"})
        except asyncio.CancelledError:
            raise
        except Exception as e:
            log.exception("verb failed")
            await send({"id": rid, "ok": False, "code": "internal", "error": repr(e)})


async def serve(helper: Helper, path: Path, group: str | None) -> None:
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o750)
    if path.exists() or path.is_symlink():
        path.unlink()
    server = await asyncio.start_unix_server(helper.handle, path=str(path), limit=MAX_REQUEST)
    os.chmod(path, 0o660)
    if group:
        gid = grp.getgrnam(group).gr_gid
        os.chown(path, 0, gid)
        os.chown(path.parent, 0, gid)
    elif helper.allow_uids and os.geteuid() == 0:
        # Hand the socket (and its directory) to the first allowed uid so that account can connect without
        # being root or in group root; peers are still checked with SO_PEERCRED on every connection.
        owner = min(helper.allow_uids)
        os.chown(path, owner, -1)
        os.chown(path.parent, owner, -1)
    log.info(
        "whd-helper listening",
        extra={"socket": str(path), "uids": sorted(helper.allow_uids), "gids": sorted(helper.allow_gids)},
    )
    try:
        await server.serve_forever()
    finally:
        server.close()
        if hasattr(server, "close_clients"):
            server.close_clients()
        with contextlib.suppress(OSError):
            helper._trace_teardown()
        with contextlib.suppress(OSError):
            path.unlink()  # a stale socket file would make the helper look available after it exited


async def _serve_until_signalled(helper: Helper, path: Path, group: str | None) -> None:
    task = asyncio.ensure_future(serve(helper, path, group))
    loop = asyncio.get_running_loop()
    for sig in (signal.SIGTERM, signal.SIGINT):
        loop.add_signal_handler(sig, task.cancel)
    with contextlib.suppress(asyncio.CancelledError):
        await task


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="whd-helper")
    ap.add_argument("--socket", default="/run/whd/helper.sock")
    ap.add_argument("--allow-uid", type=int, action="append", default=[])
    ap.add_argument("--allow-gid", type=int, action="append", default=[])
    ap.add_argument("--group", help="chown the socket to this group (e.g. whd)")
    ap.add_argument("--allow-non-root", action="store_true", help="testing only: run without root")
    a = ap.parse_args(argv)
    from whd.logging_setup import setup_logging

    setup_logging()
    if os.geteuid() != 0 and not a.allow_non_root:
        print("whd-helper must run as root (it reads root-only kernel interfaces)", file=sys.stderr)
        return 2
    gids = set(a.allow_gid)
    if a.group:
        gids.add(grp.getgrnam(a.group).gr_gid)
    if not a.allow_uid and not gids:
        print("refusing to start without --allow-uid/--allow-gid/--group", file=sys.stderr)
        return 2
    helper = Helper(Roots(), set(a.allow_uid), gids)
    with contextlib.suppress(KeyboardInterrupt):
        asyncio.run(_serve_until_signalled(helper, Path(a.socket), a.group))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
