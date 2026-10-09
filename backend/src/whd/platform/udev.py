"""Read the udev database (/run/udev/data) for hwdb-derived device names.

The file format is line oriented: 'E:KEY=VALUE' entries are properties. This is
the same data `udevadm info` prints, read directly without spawning a process.
"""

from __future__ import annotations

from whd.platform.sysfs import ReadLog, SysfsError, SysRoot


def udev_db_id(root: SysRoot, sysfs_path: str, subsystem: str) -> str | None:
    """udev database id for a device: c<maj>:<min> / b<maj>:<min> or +<subsystem>:<sysname>."""
    dev = root.attr(f"{sysfs_path}/dev")
    if dev:
        return f"c{dev}"
    return f"+{subsystem}:{sysfs_path.rstrip('/').rsplit('/', 1)[-1]}"


def udev_props(root: SysRoot, sysfs_path: str, subsystem: str, log: ReadLog | None = None) -> dict[str, str]:
    did = udev_db_id(root, sysfs_path, subsystem)
    if did is None:
        return {}
    p = f"/run/udev/data/{did}"
    try:
        text = root.read_text(p)
    except SysfsError as e:
        if log is not None and e.issue.kind != "not_exposed":
            log.issues.append(e.issue)
        return {}
    if log is not None:
        log.sources.append(p)
    props: dict[str, str] = {}
    for line in text.splitlines():
        if line.startswith("E:") and "=" in line:
            k, v = line[2:].split("=", 1)
            props[k] = v
    return props
