"""nl80211 transport sources.

`Nl80211Source.request()` returns raw genl payloads (genl header + attributes).
Live: real generic netlink socket. Recorded: payloads replayed from a fixture
JSON file (used by tests and demo mode). Recording: wraps live and keeps a copy.

Only GET commands are permitted; the allowlist is enforced here so no caller can
issue a state-changing nl80211 command through WHD.
"""

from __future__ import annotations

import base64
import json
import threading
from pathlib import Path
from typing import Protocol

from whd.platform.kconsts import nl80211 as C
from whd.platform.netlink import GenlSocket, NetlinkError

ALLOWED_CMDS = frozenset(
    {
        C.NL80211_CMD_GET_WIPHY,
        C.NL80211_CMD_GET_INTERFACE,
        C.NL80211_CMD_GET_STATION,
        C.NL80211_CMD_GET_REG,
        C.NL80211_CMD_GET_SURVEY,
        C.NL80211_CMD_GET_SCAN,
        C.NL80211_CMD_GET_POWER_SAVE,
        C.NL80211_CMD_GET_PROTOCOL_FEATURES,
    }
)

CMD_NAMES: dict[int, str] = {v: k for k, v in C.ENUMS["nl80211_commands"].items()}


def request_key(cmd: int, attrs: bytes, dump: bool) -> str:
    return f"{CMD_NAMES.get(cmd, str(cmd))}:{attrs.hex()}:{'dump' if dump else 'get'}"


class Nl80211Unavailable(Exception):
    pass


class Nl80211Source(Protocol):
    def request(self, cmd: int, attrs: bytes = b"", dump: bool = False) -> list[bytes]: ...

    def multicast_groups(self) -> dict[str, int]: ...

    @property
    def family_id(self) -> int: ...


def _check(cmd: int) -> None:
    if cmd not in ALLOWED_CMDS:
        raise PermissionError(
            f"nl80211 command {CMD_NAMES.get(cmd, cmd)} is not on the WHD read-only allowlist"
        )


class LiveNl80211:
    def __init__(self, timeout: float = 3.0) -> None:
        self._lock = threading.Lock()
        try:
            self._sock = GenlSocket(timeout=timeout)
            self._family, self._groups = self._sock.resolve_family(C.NL80211_GENL_NAME)
        except (OSError, NetlinkError) as e:
            raise Nl80211Unavailable(str(e)) from e

    @property
    def family_id(self) -> int:
        return self._family

    def multicast_groups(self) -> dict[str, int]:
        return dict(self._groups)

    def request(self, cmd: int, attrs: bytes = b"", dump: bool = False) -> list[bytes]:
        _check(cmd)
        with self._lock:
            return self._sock.request(self._family, cmd, attrs, dump=dump)

    def close(self) -> None:
        self._sock.close()


class RecordedNl80211:
    """Replays payloads recorded by RecordingNl80211 / `whd capture-fixture`."""

    def __init__(self, path: Path) -> None:
        if not path.exists():
            raise Nl80211Unavailable(f"no recorded nl80211 data at {path}")
        data = json.loads(path.read_text())
        self._family = int(data.get("family_id", 0))
        self._groups = {str(k): int(v) for k, v in data.get("multicast_groups", {}).items()}
        self._replies: dict[str, list[bytes]] = {
            k: [base64.b64decode(p) for p in v] for k, v in data.get("requests", {}).items()
        }
        self._errors: dict[str, int] = {k: int(v) for k, v in data.get("errors", {}).items()}

    @property
    def family_id(self) -> int:
        return self._family

    def multicast_groups(self) -> dict[str, int]:
        return dict(self._groups)

    def request(self, cmd: int, attrs: bytes = b"", dump: bool = False) -> list[bytes]:
        _check(cmd)
        key = request_key(cmd, attrs, dump)
        if key in self._errors:
            raise NetlinkError(self._errors[key], f"recorded error for {key}")
        if key not in self._replies:
            raise NetlinkError(95, f"no recording for {key}")  # EOPNOTSUPP
        return list(self._replies[key])


class RecordingNl80211:
    def __init__(self, inner: LiveNl80211) -> None:
        self.inner = inner
        self.requests: dict[str, list[str]] = {}
        self.errors: dict[str, int] = {}

    @property
    def family_id(self) -> int:
        return self.inner.family_id

    def multicast_groups(self) -> dict[str, int]:
        return self.inner.multicast_groups()

    def request(self, cmd: int, attrs: bytes = b"", dump: bool = False) -> list[bytes]:
        key = request_key(cmd, attrs, dump)
        try:
            out = self.inner.request(cmd, attrs, dump)
        except NetlinkError as e:
            self.errors[key] = e.errno
            raise
        self.requests[key] = [base64.b64encode(p).decode() for p in out]
        return out

    def dump_json(self) -> dict[str, object]:
        return {
            "family_id": self.family_id,
            "multicast_groups": self.multicast_groups(),
            "requests": self.requests,
            "errors": self.errors,
        }
