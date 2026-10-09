"""Kernel module metadata: modules.alias / modules.dep matching and modinfo.

Used to (a) find which modules *could* drive a device by modalias, and (b)
decide whether such a module is a wireless driver (its dependency closure
contains cfg80211). Works for in-tree, out-of-tree and DKMS modules alike.
"""

from __future__ import annotations

import fnmatch
import re
from dataclasses import dataclass, field

from whd.platform.sysfs import SysfsError, SysRoot

_KO_RE = re.compile(r"\.ko(\.(xz|zst|gz))?$")


def mod_name_from_path(path: str) -> str:
    return _KO_RE.sub("", path.rsplit("/", 1)[-1]).replace("-", "_")


@dataclass
class ModuleIndex:
    release: str
    aliases: list[tuple[str, str]] = field(default_factory=list)  # (pattern, module)
    deps: dict[str, list[str]] = field(default_factory=dict)  # module -> direct deps (names)
    paths: dict[str, str] = field(default_factory=dict)  # module -> relative .ko path
    errors: list[str] = field(default_factory=list)
    _by_prefix: dict[str, list[tuple[str, str]]] = field(default_factory=dict)
    _generic: list[tuple[str, str]] = field(default_factory=list)

    _KEY = 13  # e.g. "pci:v000014C3" / "usb:v0E8Dp7961"

    def _index(self) -> None:
        for pat, mod in self.aliases:
            lit = re.split(r"[*?\[]", pat, maxsplit=1)[0]
            if len(lit) >= self._KEY:
                self._by_prefix.setdefault(lit[: self._KEY], []).append((pat, mod))
            else:
                self._generic.append((pat, mod))

    @classmethod
    def load(cls, root: SysRoot, release: str) -> ModuleIndex:
        idx = cls(release=release)
        base = f"/lib/modules/{release}"
        try:
            for line in root.read_text(f"{base}/modules.alias", limit=32 << 20).splitlines():
                parts = line.split()
                if len(parts) == 3 and parts[0] == "alias":
                    idx.aliases.append((parts[1], parts[2].replace("-", "_")))
        except SysfsError as e:
            idx.errors.append(f"modules.alias: {e.issue.kind} {e.issue.detail}")
        try:
            for line in root.read_text(f"{base}/modules.dep", limit=32 << 20).splitlines():
                if ":" not in line:
                    continue
                path, rest = line.split(":", 1)
                name = mod_name_from_path(path)
                idx.paths[name] = path
                idx.deps[name] = [mod_name_from_path(d) for d in rest.split()]
        except SysfsError as e:
            idx.errors.append(f"modules.dep: {e.issue.kind} {e.issue.detail}")
        idx._index()
        return idx

    @property
    def available(self) -> bool:
        return bool(self.aliases)

    def match(self, modalias: str) -> list[str]:
        """Modules whose alias pattern matches the device modalias (kmod semantics: fnmatch)."""
        seen: list[str] = []
        if not self._by_prefix and not self._generic and self.aliases:
            self._index()
        cands = self._by_prefix.get(modalias[: self._KEY], []) + self._generic
        for pat, mod in cands:
            if mod not in seen and fnmatch.fnmatchcase(modalias, pat):
                seen.append(mod)
        return seen

    def closure(self, module: str) -> set[str]:
        out: set[str] = set()
        stack = [module]
        while stack:
            m = stack.pop()
            for d in self.deps.get(m, []):
                if d not in out:
                    out.add(d)
                    stack.append(d)
        return out

    def is_wireless(self, module: str) -> bool:
        return module == "cfg80211" or "cfg80211" in self.closure(module)


def parse_modinfo0(out: bytes) -> dict[str, list[str]]:
    """Parse `modinfo -0` output (NUL separated, 'filename:<ws>path' then 'key=value')."""
    info: dict[str, list[str]] = {}
    for rec in out.split(b"\0"):
        s = rec.decode(errors="replace").strip("\n")
        if not s:
            continue
        if s.startswith("filename:"):
            info.setdefault("filename", []).append(s[len("filename:") :].strip())
            continue
        if "=" in s:
            k, v = s.split("=", 1)
            info.setdefault(k.strip(), []).append(v)
    return info
