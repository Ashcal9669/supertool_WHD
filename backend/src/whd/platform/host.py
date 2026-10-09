"""Host abstraction: the single place where WHD touches the machine.

LiveHost talks to the running kernel. FixtureHost replays a recorded or
synthetic fixture directory (tests, demo mode). Everything above this layer is
identical in both modes, so demo mode exercises the real code paths.

Fixture layout (<dir>/):
    fixture.json      {"kind": "recorded"|"synthetic", "description": ..., "uname": {...}}
    root/             sysroot (sys/, run/udev/data, lib/modules/<rel>/modules.*, usr/share/misc/*.ids)
    nl80211.json      recorded nl80211 replies (see nl80211/source.py)
    ethtool.json      {ifname: drvinfo dict | {"errno": n}}
    modinfo.json      {module: {key: [values]}}
    helper.json       recorded privileged-helper replies (optional)
    events.jsonl      recorded/synthetic event stream for demo mode (optional)
"""

from __future__ import annotations

import errno
import json
import os
import platform
import shutil
import subprocess
from pathlib import Path
from typing import Any, Literal

from whd.helper.client import HelperClient, HelperLike, RecordedHelper
from whd.platform.kmod import parse_modinfo0
from whd.platform.nl80211.client import Nl80211
from whd.platform.nl80211.source import LiveNl80211, Nl80211Source, Nl80211Unavailable, RecordedNl80211
from whd.platform.sysfs import SysRoot

Mode = Literal["live", "demo"]


class Host:
    mode: Mode = "live"
    fixture_kind: str | None = None
    description: str | None = None

    def __init__(self, root: SysRoot) -> None:
        self.root = root
        self.helper: HelperLike | None = None
        self._nl: Nl80211 | None = None
        self._nl_error: str | None = None

    # -- identity --------------------------------------------------------------
    def uname(self) -> dict[str, str]:
        raise NotImplementedError

    def os_release(self) -> dict[str, str]:
        out: dict[str, str] = {}
        for p in ("/etc/os-release", "/usr/lib/os-release"):
            v = self.root.attr(p)
            if v:
                for line in v.splitlines():
                    if "=" in line:
                        k, val = line.split("=", 1)
                        out[k] = val.strip().strip('"')
                break
        return out

    # -- nl80211 ---------------------------------------------------------------
    def _open_nl80211(self) -> Nl80211Source:
        raise NotImplementedError

    def nl80211(self) -> Nl80211 | None:
        if self._nl is None and self._nl_error is None:
            try:
                self._nl = Nl80211(self._open_nl80211())
            except Nl80211Unavailable as e:
                self._nl_error = str(e)
        return self._nl

    @property
    def nl80211_error(self) -> str | None:
        self.nl80211()
        return self._nl_error

    # -- other sources -----------------------------------------------------------
    def ethtool_drvinfo(self, ifname: str) -> dict[str, Any]:
        """Raises OSError when unavailable."""
        raise NotImplementedError

    def modinfo(self, module: str) -> dict[str, list[str]] | None:
        raise NotImplementedError

    def tool_path(self, name: str) -> str | None:
        raise NotImplementedError


class LiveHost(Host):
    mode: Mode = "live"

    def __init__(self, helper_socket: Path | None = None) -> None:
        super().__init__(SysRoot("/"))
        if helper_socket is not None:
            self.helper = HelperClient(helper_socket)
        self._modinfo_cache: dict[str, dict[str, list[str]] | None] = {}

    def uname(self) -> dict[str, str]:
        u = os.uname()
        return {
            "sysname": u.sysname,
            "nodename": u.nodename,
            "release": u.release,
            "version": u.version,
            "machine": u.machine,
            "python": platform.python_version(),
        }

    def _open_nl80211(self) -> Nl80211Source:
        return LiveNl80211()

    def ethtool_drvinfo(self, ifname: str) -> dict[str, Any]:
        from whd.platform.ethtool import get_drvinfo

        return get_drvinfo(ifname)

    def modinfo(self, module: str) -> dict[str, list[str]] | None:
        if module in self._modinfo_cache:
            return self._modinfo_cache[module]
        exe = shutil.which("modinfo") or "/usr/sbin/modinfo"
        res: dict[str, list[str]] | None = None
        try:
            p = subprocess.run([exe, "-0", module], capture_output=True, timeout=5, check=False)
            if p.returncode == 0:
                res = parse_modinfo0(p.stdout)
        except (OSError, subprocess.TimeoutExpired):
            res = None
        self._modinfo_cache[module] = res
        return res

    def tool_path(self, name: str) -> str | None:
        return shutil.which(name, path=os.environ.get("PATH", "") + ":/usr/sbin:/sbin")


class FixtureHost(Host):
    mode: Mode = "demo"

    def __init__(self, fixture_dir: Path) -> None:
        self.dir = Path(fixture_dir)
        meta_p = self.dir / "fixture.json"
        self.meta: dict[str, Any] = json.loads(meta_p.read_text()) if meta_p.exists() else {}
        super().__init__(SysRoot(self.dir / "root"))
        self.fixture_kind = str(self.meta.get("kind", "synthetic"))
        self.description = self.meta.get("description")
        self._eth: dict[str, Any] = self._json("ethtool.json")
        if (self.dir / "helper.json").exists():
            self.helper = RecordedHelper(self.dir / "helper.json")
        self._modinfo: dict[str, Any] = self._json("modinfo.json")

    def _json(self, name: str) -> dict[str, Any]:
        p = self.dir / name
        return json.loads(p.read_text()) if p.exists() else {}

    def uname(self) -> dict[str, str]:
        u = dict(self.meta.get("uname", {}))
        u.setdefault("release", "unknown")
        u.setdefault("machine", "unknown")
        u.setdefault("nodename", "fixture")
        return u

    def _open_nl80211(self) -> Nl80211Source:
        return RecordedNl80211(self.dir / "nl80211.json")

    def ethtool_drvinfo(self, ifname: str) -> dict[str, Any]:
        v = self._eth.get(ifname)
        if v is None:
            raise OSError(errno.ENODEV, "no recorded ethtool data")
        if "errno" in v:
            raise OSError(int(v["errno"]), os.strerror(int(v["errno"])))
        return dict(v)

    def modinfo(self, module: str) -> dict[str, list[str]] | None:
        v = self._modinfo.get(module)
        return {k: list(x) for k, x in v.items()} if v else None

    def tool_path(self, name: str) -> str | None:
        tools = self.meta.get("tools", {})
        v = tools.get(name)
        return str(v) if v else None
