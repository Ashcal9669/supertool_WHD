"""Stable device identities (spec section 4.4).

Identity never includes netdev names, phy indexes or ifindexes: those are
mutable attributes tracked separately in the store.
"""

from __future__ import annotations

import re


def _hex4(v: int | None) -> str:
    return f"{v:04x}" if v is not None else "????"


def pci_identity(bdf: str, vendor: int | None, device: int | None) -> str:
    return f"pci:{bdf}:{_hex4(vendor)}:{_hex4(device)}"


_SAFE = re.compile(r"[^A-Za-z0-9._-]")


def usb_identity(
    serial: str | None,
    busnum: int | None,
    devpath: str | None,
    port_path: str | None,
    vid: int | None,
    pid: int | None,
) -> str:
    if serial and serial.strip():
        return f"usb:{_SAFE.sub('_', serial.strip())}:{_hex4(vid)}:{_hex4(pid)}"
    loc = port_path or f"{busnum}-{devpath}"
    return f"usb:{loc}:{_hex4(vid)}:{_hex4(pid)}"
