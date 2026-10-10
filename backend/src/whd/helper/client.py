"""Client side of the whd-helper protocol (used by the unprivileged server).

HelperClient   - talks to a live helper socket.
RecordedHelper - replays helper responses stored in a fixture (helper.json) for demo mode/tests.
Both expose the same `call()` / `stream()` / `status()` surface.
"""

from __future__ import annotations

import asyncio
import base64
import contextlib
import itertools
import json
import socket
import time
from collections.abc import AsyncIterator
from pathlib import Path
from typing import Any, Protocol

from whd.helper.protocol import MAX_REQUEST, HelperError


class HelperLike(Protocol):
    def call(self, verb: str, timeout: float = 5.0, **args: Any) -> Any: ...

    def stream(self, verb: str, **args: Any) -> AsyncIterator[dict[str, Any]]: ...

    async def status(self) -> dict[str, Any]: ...

    @property
    def available(self) -> bool: ...


class HelperUnavailable(HelperError):
    def __init__(self, msg: str) -> None:
        super().__init__("unavailable", msg)


class HelperClient:
    def __init__(self, socket_path: Path) -> None:
        self.path = Path(socket_path)
        self._ids = itertools.count(1)
        self._status: dict[str, Any] | None = None
        self._status_at = 0.0

    @property
    def available(self) -> bool:
        return self.path.exists()

    def call(self, verb: str, timeout: float = 5.0, **args: Any) -> Any:
        """Blocking request/response (safe to use from worker threads)."""
        rid = next(self._ids)
        try:
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as s:
                s.settimeout(timeout)
                s.connect(str(self.path))
                s.sendall(json.dumps({"id": rid, "verb": verb, "args": args}).encode() + b"\n")
                with s.makefile("rb") as f:
                    return self._read_reply(f, rid)
        except (FileNotFoundError, ConnectionRefusedError) as e:
            raise HelperUnavailable(f"helper socket {self.path} not available: {e}") from e
        except PermissionError as e:
            raise HelperUnavailable(f"no permission to connect to {self.path}") from e
        except TimeoutError as e:
            raise HelperUnavailable(f"helper timed out on {verb}") from e

    @staticmethod
    def _read_reply(f: Any, rid: int) -> Any:
        while True:
            line = f.readline(MAX_REQUEST * 64)
            if not line:
                raise HelperUnavailable("helper closed the connection")
            msg = json.loads(line)
            if msg.get("id") not in (rid, 0) or "stream" in msg:
                continue
            if msg.get("ok"):
                return msg.get("result")
            raise HelperError(str(msg.get("code", "error")), str(msg.get("error")))

    async def stream(self, verb: str, **args: Any) -> AsyncIterator[dict[str, Any]]:
        """Yield stream messages ({"stream_start"}/{"stream"}) then a final {"result"} message."""
        rid = next(self._ids)
        try:
            reader, writer = await asyncio.open_unix_connection(str(self.path), limit=MAX_REQUEST * 64)
        except (FileNotFoundError, ConnectionRefusedError, PermissionError) as e:
            raise HelperUnavailable(f"helper socket {self.path} not available: {e}") from e
        try:
            writer.write(json.dumps({"id": rid, "verb": verb, "args": args}).encode() + b"\n")
            await writer.drain()
            while True:
                line = await reader.readline()
                if not line:
                    raise HelperUnavailable("helper closed the stream")
                msg = json.loads(line)
                if msg.get("id") not in (rid, 0):
                    continue
                if "ok" in msg:
                    if not msg["ok"]:
                        raise HelperError(str(msg.get("code", "error")), str(msg.get("error")))
                    yield {"result": msg.get("result")}
                    return
                yield msg
        finally:
            writer.close()
            with contextlib.suppress(Exception):
                await writer.wait_closed()

    async def status(self) -> dict[str, Any]:
        if self._status is not None and time.monotonic() - self._status_at < 5:
            return self._status
        try:
            info = await asyncio.to_thread(self.call, "ping", 2.0)
            st: dict[str, Any] = {"connected": True, "socket": str(self.path), **info}
        except HelperError as e:
            st = {"connected": False, "socket": str(self.path), "detail": str(e)}
        self._status, self._status_at = st, time.monotonic()
        return st


class RecordedHelper:
    """Replays a fixture's helper.json: {"ping": {...}, "calls": {"<verb>:<json args>": result|{"error":..}},
    "streams": {"<verb>:<json args>": [messages]}}."""

    def __init__(self, path: Path) -> None:
        self.path = path
        self.data: dict[str, Any] = json.loads(path.read_text()) if path.exists() else {}

    @staticmethod
    def key(verb: str, args: dict[str, Any]) -> str:
        return f"{verb}:{json.dumps(args, sort_keys=True)}"

    @property
    def available(self) -> bool:
        return bool(self.data)

    def call(self, verb: str, timeout: float = 5.0, **args: Any) -> Any:
        if not self.data:
            raise HelperUnavailable("fixture has no recorded helper data")
        if verb == "ping":
            return self.data.get("ping", {})
        k = self.key(verb, args)
        calls = self.data.get("calls", {})
        if k not in calls and verb == "tracefs_events":
            sup = self._tracefs_subset(args)
            if sup is not None:
                return sup
        if k not in calls:
            raise HelperError("missing", f"no recording for {k}")
        v = calls[k]
        if isinstance(v, dict) and "error" in v and "code" in v:
            raise HelperError(v["code"], v["error"])
        return v

    def _tracefs_subset(self, args: dict[str, Any]) -> dict[str, Any] | None:
        """Callers choose groups from what the system has, so replay answers any group list from a recording
        that covered at least those groups (with formats), instead of requiring an identical argument list."""
        want = args.get("groups")
        fmt = bool(args.get("with_format"))
        for key, v in self.data.get("calls", {}).items():
            if not key.startswith("tracefs_events:") or not isinstance(v, dict) or "groups" not in v:
                continue
            groups: dict[str, Any] = v["groups"]
            if want is None:
                return {"groups": {g: {} for g in groups}} if not fmt else None
            if not any(groups.get(g) for g in want):
                continue
            has_fmt = any(isinstance(x, str) for evs in groups.values() for x in evs.values())
            if fmt and not has_fmt:
                continue
            out = {g: (groups[g] if fmt else {n: True for n in groups[g]}) for g in want if g in groups}
            return {"groups": out}
        return None

    async def stream(self, verb: str, **args: Any) -> AsyncIterator[dict[str, Any]]:
        msgs = self.data.get("streams", {}).get(self.key(verb, args))
        if msgs is None:
            raise HelperError("missing", f"no recorded stream for {verb}")
        for m in msgs:
            await asyncio.sleep(0)
            yield m

    async def status(self) -> dict[str, Any]:
        if not self.data:
            return {"connected": False, "detail": "fixture has no recorded helper data"}
        return {"connected": True, "recorded": True, **self.data.get("ping", {})}


class RecordingHelper:
    """Wraps a live client and records call results (used by `whd capture-fixture`)."""

    def __init__(self, inner: HelperClient) -> None:
        self.inner = inner
        self.calls: dict[str, Any] = {}
        self.ping: dict[str, Any] = {}

    @property
    def available(self) -> bool:
        return self.inner.available

    def call(self, verb: str, timeout: float = 5.0, **args: Any) -> Any:
        try:
            r = self.inner.call(verb, timeout, **args)
        except HelperError as e:
            self.calls[RecordedHelper.key(verb, args)] = {"code": e.code, "error": str(e)}
            raise
        if verb == "ping":
            self.ping = r
        else:
            self.calls[RecordedHelper.key(verb, args)] = r
        return r

    def stream(self, verb: str, **args: Any) -> AsyncIterator[dict[str, Any]]:
        return self.inner.stream(verb, **args)

    async def status(self) -> dict[str, Any]:
        return await self.inner.status()

    def dump(self) -> dict[str, Any]:
        return {"ping": self.ping, "calls": self.calls, "streams": {}}


def config_bytes(result: dict[str, Any]) -> bytes:
    return base64.b64decode(result["data"])
