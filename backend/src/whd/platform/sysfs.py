"""Read-only sysfs access rooted at a configurable sysroot.

All filesystem reads of kernel pseudo-files go through `SysRoot`. It enforces:
  * read-only opens (O_RDONLY), never write/append/create,
  * a per-read size cap,
  * a denylist of attribute names that must never be opened even for reading
    (side-effecting or mmap-only attributes),
  * typed failure classification (not_exposed / requires_privilege / device_error / error).

The sysroot is "/" on a live host or a fixture directory in tests and demo mode.
"""

from __future__ import annotations

import errno
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Literal

IssueKind = Literal["not_exposed", "requires_privilege", "device_error", "unsupported", "error"]

MAX_READ = 64 * 1024

# Never opened by WHD, even read-only.
DENIED_NAMES = frozenset(
    {
        "reset",
        "remove",
        "rescan",
        "rom",
        "driver_override",
        "new_id",
        "remove_id",
        "bind",
        "unbind",
        "uevent_trigger",
        "authorized_default",
    }
)


def _denied(name: str) -> bool:
    if name in DENIED_NAMES:
        return True
    # resource0, resource2_wc ... are mmap BARs. The plain "resource" text table is fine.
    return name.startswith("resource") and name != "resource"


@dataclass(frozen=True)
class ReadIssue:
    path: str
    kind: IssueKind
    detail: str


class SysfsError(Exception):
    def __init__(self, issue: ReadIssue) -> None:
        super().__init__(f"{issue.kind}: {issue.path}: {issue.detail}")
        self.issue = issue


def classify_oserror(e: OSError) -> IssueKind:
    if e.errno in (errno.ENOENT, errno.ENOTDIR):
        return "not_exposed"
    if e.errno in (errno.EACCES, errno.EPERM):
        return "requires_privilege"
    if e.errno in (errno.EIO, errno.ENODEV, errno.ENXIO, errno.ETIMEDOUT):
        return "device_error"
    if e.errno in (errno.EOPNOTSUPP, errno.EINVAL):
        return "unsupported"
    return "error"


@dataclass
class ReadLog:
    """Records every source read for a section: provenance for the UI."""

    sources: list[str] = field(default_factory=list)
    issues: list[ReadIssue] = field(default_factory=list)
    raw: dict[str, str] = field(default_factory=dict)


class SysRoot:
    def __init__(self, root: str | Path = "/") -> None:
        self.root = Path(root).resolve()

    @property
    def is_live(self) -> bool:
        return str(self.root) == "/"

    def path(self, abs_path: str | Path) -> Path:
        p = str(abs_path)
        if not p.startswith("/"):
            raise ValueError(f"absolute path required: {p}")
        return self.root / p.lstrip("/")

    def to_abs(self, real: Path) -> str:
        """Map a real filesystem path back to its host-absolute form."""
        try:
            rel = real.relative_to(self.root)
        except ValueError:
            return str(real)
        return "/" + str(rel)

    # ---- reads -------------------------------------------------------------

    def read_bytes(self, abs_path: str, limit: int = MAX_READ) -> bytes:
        name = abs_path.rstrip("/").rsplit("/", 1)[-1]
        if _denied(name):
            raise SysfsError(ReadIssue(abs_path, "error", "attribute is on the WHD never-open list"))
        real = self.path(abs_path)
        try:
            fd = os.open(real, os.O_RDONLY | os.O_CLOEXEC | os.O_NONBLOCK)
        except OSError as e:
            raise SysfsError(ReadIssue(abs_path, classify_oserror(e), e.strerror or str(e))) from e
        try:
            chunks: list[bytes] = []
            total = 0
            while total < limit:
                try:
                    b = os.read(fd, min(65536, limit - total))
                except OSError as e:
                    raise SysfsError(ReadIssue(abs_path, classify_oserror(e), e.strerror or str(e))) from e
                if not b:
                    break
                chunks.append(b)
                total += len(b)
            return b"".join(chunks)
        finally:
            os.close(fd)

    def read_text(self, abs_path: str, limit: int = MAX_READ) -> str:
        return self.read_bytes(abs_path, limit).decode("utf-8", errors="replace").strip()

    def attr(self, abs_path: str, log: ReadLog | None = None) -> str | None:
        """Read a text attribute; returns None and records an issue on failure."""
        try:
            v = self.read_text(abs_path)
        except SysfsError as e:
            if log is not None:
                log.issues.append(e.issue)
            return None
        if log is not None:
            log.sources.append(abs_path)
            log.raw[abs_path] = v
        return v

    def attr_int(self, abs_path: str, log: ReadLog | None = None, base: int = 0) -> int | None:
        v = self.attr(abs_path, log)
        if v is None or v == "":
            return None
        try:
            return int(v, base)
        except ValueError:
            if log is not None:
                log.issues.append(ReadIssue(abs_path, "error", f"unparseable integer {v!r}"))
            return None

    # ---- directory helpers ----------------------------------------------------

    def exists(self, abs_path: str) -> bool:
        return os.path.lexists(self.path(abs_path))

    def isdir(self, abs_path: str) -> bool:
        return self.path(abs_path).is_dir()

    def listdir(self, abs_path: str) -> list[str]:
        try:
            return sorted(os.listdir(self.path(abs_path)))
        except OSError:
            return []

    def readlink_name(self, abs_path: str) -> str | None:
        """Basename of a symlink target (e.g. driver -> .../drivers/mt7925e)."""
        try:
            return os.path.basename(os.readlink(self.path(abs_path)))
        except OSError:
            return None

    def realpath(self, abs_path: str) -> str | None:
        """Resolve symlinks within the sysroot, returning a host-absolute path."""
        real = self.path(abs_path)
        if not os.path.lexists(real):
            return None
        resolved = Path(os.path.realpath(real))
        return self.to_abs(resolved)
