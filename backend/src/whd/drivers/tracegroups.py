"""Which tracefs event groups matter for the adapters on *this* system.

Nothing here names a chip or vendor. Kernel subsystems that every wireless/bus stack uses are fixed; driver groups
are derived from the loaded driver modules of the discovered devices (the driver and its dependency closure), by
matching module names against the group names tracefs actually has.
"""

from __future__ import annotations

from collections.abc import Iterable
from typing import Any

from whd.helper.protocol import HelperError
from whd.model.device import Device

# kernel subsystems, not drivers
CORE_WIRELESS_GROUPS = ("mac80211", "mac80211_msg", "cfg80211")
CORE_BUS_GROUPS = ("pci", "xhci-hcd", "usbcore")
CORE_GROUPS = (*CORE_WIRELESS_GROUPS, *CORE_BUS_GROUPS)
_MIN_PREFIX = 4  # avoid matching a 2-3 letter module against unrelated groups


def _norm(name: str) -> str:
    return name.replace("-", "_")


def driver_trace_groups(devices: Iterable[Device], available: Iterable[str]) -> list[str]:
    """Core groups present on the kernel plus groups matching the devices' driver modules, in a stable order."""
    have = sorted(available)
    mods: set[str] = set()
    for d in devices:
        for m in (d.module or d.driver_info.module, d.driver, *d.driver_info.module_dependencies):
            if m and len(_norm(m)) >= _MIN_PREFIX:
                mods.add(_norm(m))
    driver = [
        g
        for g in have
        if g not in CORE_GROUPS
        and len(g) >= _MIN_PREFIX
        and any(_norm(m).startswith(_norm(g)) or _norm(g).startswith(_norm(m)) for m in mods)
    ]
    return driver + [g for g in CORE_GROUPS if g in have]


def resolve_trace_groups(helper: Any, devices: Iterable[Device]) -> list[str]:
    """Ask the helper which groups exist (names only), then derive the interesting ones. May raise HelperError."""
    r = helper.call("tracefs_events", 15.0)
    names = list(r["groups"])
    if not names:
        raise HelperError("missing", "no tracefs event groups found")
    return driver_trace_groups(devices, names)
