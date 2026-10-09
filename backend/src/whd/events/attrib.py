"""Attribute events to stable device identities using only explicit identifiers."""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from whd.model.device import Device

BDF_IN_TEXT = re.compile(r"\b([0-9a-f]{4}:[0-9a-f]{2}:[0-9a-f]{2}\.[0-7])\b")
MODULE_IN_BRACKETS = re.compile(r"\[(\w+)\]")
GENERIC_MODULES = {"cfg80211", "mac80211", "rfkill", "libarc4", "usbcore", "bluetooth", "btusb"}


@dataclass
class DeviceIndex:
    bdf: dict[str, str] = field(default_factory=dict)
    usb_port: dict[str, str] = field(default_factory=dict)
    netdev: dict[str, str] = field(default_factory=dict)
    phy: dict[str, str] = field(default_factory=dict)
    ifindex: dict[int, str] = field(default_factory=dict)
    wiphy_idx: dict[int, str] = field(default_factory=dict)
    usb_busdev: dict[tuple[int, int], str] = field(default_factory=dict)
    paths: list[tuple[str, str]] = field(default_factory=list)  # (sysfs path prefix, id), longest first
    modules: dict[str, set[str]] = field(default_factory=dict)
    _word: re.Pattern[str] | None = None

    def update(self, devices: list[Device]) -> None:
        for mp in (
            self.bdf,
            self.usb_port,
            self.netdev,
            self.phy,
            self.ifindex,
            self.wiphy_idx,
            self.modules,
        ):
            mp.clear()
        paths = []
        for d in devices:
            if not d.present:
                continue
            paths.append((d.sysfs_path, d.id))
            if d.pci:
                self.bdf[d.pci.bdf] = d.id
            if d.usb and d.usb.port_path:
                self.usb_port[d.usb.port_path] = d.id
            if d.usb and d.usb.busnum is not None and d.usb.devnum is not None:
                self.usb_busdev[(d.usb.busnum, d.usb.devnum)] = d.id
            for n in d.netdev_info:
                self.netdev[n.name] = d.id
                if n.ifindex is not None:
                    self.ifindex[n.ifindex] = d.id
            for p in d.phys:
                self.phy[p] = d.id
            for w in d.wiphys:
                self.wiphy_idx[w.index] = d.id
            mods = {m for m in [d.module, *d.driver_info.module_dependencies] if m} - GENERIC_MODULES
            for m in mods:
                self.modules.setdefault(m, set()).add(d.id)
        self.paths = sorted(paths, key=lambda x: -len(x[0]))
        names = list(self.netdev) + list(self.phy)
        self._word = re.compile(r"\b(" + "|".join(re.escape(n) for n in names) + r")\b") if names else None

    def by_kernel_device(self, kdev: str | None) -> str | None:
        """journald _KERNEL_DEVICE: '+pci:0000:07:00.0', '+usb:3-3:1.0', 'n12', '+ieee80211:phy1', 'c189:2'."""
        if not kdev:
            return None
        if kdev.startswith("n") and kdev[1:].isdigit():
            return self.ifindex.get(int(kdev[1:]))
        if kdev.startswith("+"):
            sub, _, name = kdev[1:].partition(":")
            if sub == "pci":
                return self.bdf.get(name)
            if sub == "usb":
                return self.usb_port.get(name.split(":")[0])
            if sub == "ieee80211":
                return self.phy.get(name)
            if sub == "net":
                return self.netdev.get(name)
        return None

    def by_path(self, path: str | None) -> str | None:
        if not path:
            return None
        if not path.startswith("/sys"):
            path = "/sys" + path
        for prefix, did in self.paths:
            if path == prefix or path.startswith(prefix + "/"):
                return did
        return None

    def by_text(self, text: str) -> tuple[str | None, str | None]:
        """Returns (device_id, method)."""
        for m in BDF_IN_TEXT.finditer(text):
            if m.group(1) in self.bdf:
                return self.bdf[m.group(1)], "bdf_in_message"
        if self._word is not None:
            m2 = self._word.search(text)
            if m2:
                n = m2.group(1)
                return (self.netdev.get(n) or self.phy.get(n)), "interface_name_in_message"
        for m in MODULE_IN_BRACKETS.finditer(text):
            ids = self.modules.get(m.group(1))
            if ids and len(ids) == 1:
                return next(iter(ids)), "driver_module_in_message"
        return None, None

    def by_ancestor_bdf(self, bdf: str) -> str | None:
        """A message about a PCI bridge/controller is attributed to a tracked device only if exactly one tracked
        device sits below it in the sysfs hierarchy (topology, not guesswork)."""
        hits = {did for prefix, did in self.paths if f"/{bdf}/" in prefix + "/"}
        return next(iter(hits)) if len(hits) == 1 else None
