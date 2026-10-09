"""Wireless device discovery.

Detection (spec section 4.2):
  1. bound_phy     - device is the parent of /sys/class/ieee80211/<phy>/device (authoritative)
  2. driver_match  - modalias matches a module whose dependency closure contains cfg80211
  3. class_hint    - PCI class 0x0280xx with no bound driver (weak)
"""

from __future__ import annotations

import logging
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import cast

from whd.collectors.driver import collect_driver
from whd.collectors.netdev import collect_netdev, collect_rfkill, netdevs_of, phys_of
from whd.collectors.pci import BDF_RE, collect_pci
from whd.collectors.power import collect_power
from whd.collectors.usb import collect_usb
from whd.identity import pci_identity, usb_identity
from whd.model.common import Issue
from whd.model.device import Bus, BusKind, BusNode, DetectionReason, Device
from whd.model.wireless import WifiInterface, Wiphy
from whd.platform.host import Host
from whd.platform.ids_db import PCI_IDS, USB_IDS, IdsDb
from whd.platform.kmod import ModuleIndex
from whd.platform.netlink import NetlinkError
from whd.platform.udev import udev_props

log = logging.getLogger("whd.discovery")

PCI_CLASS_NETWORK_OTHER = 0x0280

# Driver-specific extension hook: (host, device) -> None, mutates device.extensions.
Extension = Callable[[Host, Device], None]


@dataclass
class DiscoveryResult:
    devices: list[Device]
    started_at: float
    duration_ms: float
    issues: list[Issue] = field(default_factory=list)


@dataclass
class _Cand:
    path: str
    bus: str
    reasons: list[DetectionReason] = field(default_factory=list)
    iface_paths: list[str] = field(default_factory=list)


class Discovery:
    def __init__(self, host: Host, extensions: list[Extension] | None = None) -> None:
        self.host = host
        self.extensions = extensions or []
        root = host.root
        self.pci_ids = IdsDb.load(root, PCI_IDS)
        self.usb_ids = IdsDb.load(root, USB_IDS)
        self.kidx = ModuleIndex.load(root, host.uname()["release"])

    # ------------------------------------------------------------------ helpers
    def _usb_device_of(self, path: str) -> tuple[str, str | None]:
        """If path is a USB interface (contains ':'), return (device path, interface path)."""
        name = path.rstrip("/").rsplit("/", 1)[-1]
        if ":" in name and not BDF_RE.match(name):
            return path.rsplit("/", 1)[0], path
        return path, None

    def _bus_of(self, path: str) -> str:
        sub = self.host.root.readlink_name(f"{path}/subsystem")
        if sub in ("pci", "usb", "sdio", "platform"):
            return sub
        return "other"

    def candidates(self) -> list[_Cand]:
        root = self.host.root
        found: dict[str, _Cand] = {}
        # 1. bound phys
        for phy in root.listdir("/sys/class/ieee80211"):
            rp = root.realpath(f"/sys/class/ieee80211/{phy}/device")
            if rp is None:
                continue
            dev, iface = self._usb_device_of(rp)
            c = found.setdefault(dev, _Cand(dev, self._bus_of(dev)))
            if iface and iface not in c.iface_paths:
                c.iface_paths.append(iface)
            c.reasons.append(
                DetectionReason(
                    kind="bound_phy",
                    strength="authoritative",
                    detail=f"/sys/class/ieee80211/{phy}/device -> {rp}",
                )
            )
        # 2/3. PCI
        for name in root.listdir("/sys/bus/pci/devices"):
            rp = root.realpath(f"/sys/bus/pci/devices/{name}")
            if rp is None:
                continue
            ma = root.attr(f"{rp}/modalias")
            mods = [m for m in self.kidx.match(ma) if self.kidx.is_wireless(m)] if ma else []
            cls = root.attr_int(f"{rp}/class")
            bound = root.readlink_name(f"{rp}/driver")
            reasons = []
            if mods:
                reasons.append(
                    DetectionReason(
                        kind="driver_match",
                        strength="strong",
                        detail=f"modalias matches wireless module(s): {', '.join(mods)}",
                    )
                )
            elif cls is not None and (cls >> 8) == PCI_CLASS_NETWORK_OTHER and bound is None:
                reasons.append(
                    DetectionReason(
                        kind="class_hint",
                        strength="weak",
                        detail=f"PCI class 0x{cls:06x} (network controller, other), no driver bound",
                    )
                )
            if reasons:
                c = found.setdefault(rp, _Cand(rp, "pci"))
                c.reasons += reasons
        # 2. USB (per-interface modalias)
        for name in root.listdir("/sys/bus/usb/devices"):
            if ":" in name or name.startswith("usb"):
                continue
            rp = root.realpath(f"/sys/bus/usb/devices/{name}")
            if rp is None:
                continue
            for child in root.listdir(rp):
                if not child.startswith(name + ":"):
                    continue
                ma = root.attr(f"{rp}/{child}/modalias")
                mods = [m for m in self.kidx.match(ma) if self.kidx.is_wireless(m)] if ma else []
                if mods:
                    c = found.setdefault(rp, _Cand(rp, "usb"))
                    if f"{rp}/{child}" not in c.iface_paths:
                        c.iface_paths.append(f"{rp}/{child}")
                    c.reasons.append(
                        DetectionReason(
                            kind="driver_match",
                            strength="strong",
                            detail=f"interface {child} modalias matches wireless module(s): {', '.join(mods)}",
                        )
                    )
        # 2. SDIO
        for name in root.listdir("/sys/bus/sdio/devices"):
            rp = root.realpath(f"/sys/bus/sdio/devices/{name}")
            ma = root.attr(f"{rp}/modalias") if rp else None
            mods = [m for m in self.kidx.match(ma) if self.kidx.is_wireless(m)] if ma else []
            if rp and mods:
                c = found.setdefault(rp, _Cand(rp, "sdio"))
                c.reasons.append(
                    DetectionReason(
                        kind="driver_match",
                        strength="strong",
                        detail=f"modalias matches wireless module(s): {', '.join(mods)}",
                    )
                )
        return list(found.values())

    def bus_path(self, path: str) -> list[BusNode]:
        root = self.host.root
        parts = path.strip("/").split("/")
        nodes: list[BusNode] = []
        for i in range(3, len(parts) + 1):  # skip /sys/devices
            p = "/" + "/".join(parts[:i])
            name = parts[i - 1]
            drv = root.readlink_name(f"{p}/driver")
            sub = root.readlink_name(f"{p}/subsystem")
            attrs: dict[str, str | int | None] = {}
            if name.startswith("pci") and ":" in name and sub is None:
                nodes.append(BusNode(kind="pci_root", sysfs_path=p, name=name, label=f"PCI root {name[3:]}"))
                continue
            if sub == "pci":
                cls = root.attr_int(f"{p}/class")
                is_bridge = cls is not None and (cls >> 8) == 0x0604
                for a in ("current_link_speed", "current_link_width", "max_link_speed", "max_link_width"):
                    attrs[a] = root.attr(f"{p}/{a}")
                attrs["vendor"] = root.attr(f"{p}/vendor")
                attrs["device"] = root.attr(f"{p}/device")
                attrs["class"] = f"0x{cls:06x}" if cls is not None else None
                model = udev_props(root, p, "pci").get("ID_MODEL_FROM_DATABASE")
                if model:
                    attrs["model"] = model
                nodes.append(
                    BusNode(
                        kind="pci_bridge" if is_bridge else "pci_device",
                        sysfs_path=p,
                        name=name,
                        label=("Bridge " if is_bridge else "") + name,
                        driver=drv,
                        attrs=attrs,
                    )
                )
            elif sub == "usb":
                if ":" in name:
                    nodes.append(
                        BusNode(kind="usb_interface", sysfs_path=p, name=name, label=f"If {name}", driver=drv)
                    )
                    continue
                dclass = root.attr(f"{p}/bDeviceClass")
                attrs["speed"] = root.attr(f"{p}/speed")
                attrs["version"] = root.attr(f"{p}/version")
                attrs["idVendor"] = root.attr(f"{p}/idVendor")
                attrs["idProduct"] = root.attr(f"{p}/idProduct")
                kind: BusKind
                if name.startswith("usb"):
                    kind = "usb_host"
                    label = f"USB bus {name[3:]} root hub"
                elif dclass == "09":
                    kind, label = "usb_hub", f"Hub {name}"
                else:
                    kind, label = "usb_device", f"USB {name}"
                nodes.append(
                    BusNode(
                        kind=kind,
                        sysfs_path=p,
                        name=name,
                        label=label,
                        driver=drv,
                        attrs=attrs,
                    )
                )
            elif sub in ("platform", "sdio", "mmc_host", "mmc"):
                nodes.append(BusNode(kind="platform", sysfs_path=p, name=name, label=name, driver=drv))
        return nodes

    # ------------------------------------------------------------------ build
    def _build(
        self, c: _Cand, wiphys: dict[str, Wiphy], ifaces: dict[int, WifiInterface], ps: dict[int, str | None]
    ) -> Device:
        root = self.host.root
        dev = Device(
            id="",
            bus=cast(Bus, c.bus),
            sysfs_path=c.path,
            title="",
            detection=c.reasons,
            demo=self.host.mode == "demo",
        )
        modalias = None
        if c.bus == "pci":
            dev.pci, plog = collect_pci(root, c.path, self.pci_ids)
            dev.evidence.update(plog.raw)
            p = dev.pci
            dev.id = pci_identity(p.bdf, p.vendor_id, p.device_id)
            dev.vendor_id, dev.product_id = p.vendor_id, p.device_id
            dev.vendor_name, dev.product_name = p.vendor_name, p.device_name
            modalias = p.modalias
        elif c.bus == "usb":
            dev.usb, ulog = collect_usb(root, c.path, self.usb_ids)
            dev.evidence.update(ulog.raw)
            u = dev.usb
            dev.id = usb_identity(u.serial, u.busnum, u.devpath, u.port_path, u.vendor_id, u.product_id)
            dev.vendor_id, dev.product_id = u.vendor_id, u.product_id
            dev.vendor_name = u.vendor_name or u.manufacturer
            dev.product_name = u.product_name or u.product
            for iface in u.interfaces:
                if iface.modalias:
                    iface.candidate_modules = self.kidx.match(iface.modalias)
                    iface.wireless_candidate = any(self.kidx.is_wireless(m) for m in iface.candidate_modules)
            wl = [i for i in u.interfaces if i.wireless_candidate]
            modalias = wl[0].modalias if wl else (u.interfaces[0].modalias if u.interfaces else None)
            if not c.iface_paths:
                c.iface_paths = [f"{c.path}/{i.name}" for i in u.interfaces]
        else:
            name = c.path.rsplit("/", 1)[-1]
            dev.id = f"{c.bus}:{name}"
            modalias = root.attr(f"{c.path}/modalias")
        dev.bus_path = self.bus_path(c.path)
        nds = netdevs_of(root, c.path)
        dev.phys = phys_of(root, c.path)
        dev.netdevs = nds
        dev.driver_info, dev.firmware = collect_driver(
            self.host, c.path, modalias, self.kidx, nds, c.iface_paths
        )
        dev.driver = dev.driver_info.driver
        dev.module = dev.driver_info.module
        dev.firmware_version = dev.firmware.version
        dev.power = collect_power(root, c.path, c.bus)
        if dev.pci is not None:
            self._pci_config(dev)
        for phy in dev.phys:
            if phy in wiphys:
                dev.wiphys.append(wiphys[phy])
            dev.rfkill += collect_rfkill(root, phy)
        for nd in nds:
            n = collect_netdev(root, nd)
            if n.ifindex is not None and n.ifindex in ifaces:
                n.wifi = ifaces[n.ifindex]
                n.wifi.power_save = ps.get(n.ifindex)
                dev.power.wifi_power_save[nd] = ps.get(n.ifindex)
            dev.netdev_info.append(n)
        dev.operstate = next((n.operstate for n in dev.netdev_info if n.operstate), None)
        dev.title = dev.product_name or (
            f"{dev.vendor_id:04x}:{dev.product_id:04x}"
            if dev.vendor_id is not None and dev.product_id is not None
            else dev.id
        )
        for ext in self.extensions:
            try:
                ext(self.host, dev)
            except Exception as e:
                log.warning("extension failed", extra={"device_id": dev.id, "error": repr(e)})
        return dev

    def _pci_config(self, dev: Device) -> None:
        """Full config space via the privileged helper (read-only); fills ASPM from Link Control."""
        helper = self.host.helper
        if helper is None or dev.pci is None or not helper.available:
            return
        from whd.collectors.pciconfig import decode_config
        from whd.helper.client import config_bytes
        from whd.helper.protocol import HelperError

        try:
            res = helper.call("pci_config_read", bdf=dev.pci.bdf)
        except HelperError as e:
            dev.power.aspm_meta.note = f"helper: {e}"
            return
        cfg = decode_config(config_bytes(res))
        cfg.meta.sources = [f"whd-helper pci_config_read {dev.pci.bdf} ({cfg.length} bytes)"]
        dev.pci_config = cfg
        aspm = dict(cfg.aspm)
        if cfg.l1ss:
            aspm.update({k: v for k, v in cfg.l1ss.items() if k.endswith("_enabled")})
        sources = list(cfg.meta.sources)
        upstream = next(
            (n for n in reversed(dev.bus_path[:-1]) if n.kind in ("pci_bridge", "pci_device")), None
        )
        if upstream is not None:
            try:
                up = decode_config(config_bytes(helper.call("pci_config_read", bdf=upstream.name)))
                aspm["upstream_port"] = upstream.name
                aspm["upstream_l0s_enabled"] = up.aspm.get("l0s_enabled")
                aspm["upstream_l1_enabled"] = up.aspm.get("l1_enabled")
                if "l1_enabled" in cfg.aspm and "l1_enabled" in up.aspm:
                    aspm["l1_effective"] = bool(cfg.aspm["l1_enabled"] and up.aspm["l1_enabled"])
                sources.append(f"whd-helper pci_config_read {upstream.name}")
            except HelperError:
                pass
        if not dev.power.aspm:
            dev.power.aspm = aspm
            dev.power.aspm_meta.availability = "ok" if cfg.length > 64 else "partial"
            dev.power.aspm_meta.sources = sources
            dev.power.aspm_meta.note = "Decoded from PCIe Link Control / L1 PM Substates Control (read-only)"

    def run(self) -> DiscoveryResult:
        t0 = time.time()
        m0 = time.monotonic()
        issues: list[Issue] = []
        wiphys: dict[str, Wiphy] = {}
        ifaces: dict[int, WifiInterface] = {}
        ps: dict[int, str | None] = {}
        nl = self.host.nl80211()
        if nl is None:
            issues.append(
                Issue(
                    source="nl80211",
                    kind="unsupported",
                    detail=self.host.nl80211_error or "nl80211 unavailable",
                )
            )
        else:
            try:
                wiphys = {w.name: w for w in nl.wiphys() if w.name}
            except (NetlinkError, OSError) as e:
                issues.append(Issue(source="nl80211 GET_WIPHY", kind="error", detail=str(e)))
            try:
                for i in nl.interfaces():
                    ifaces[i.ifindex] = i
                    try:
                        ps[i.ifindex] = nl.power_save(i.ifindex)
                    except (NetlinkError, OSError):
                        ps[i.ifindex] = None
            except (NetlinkError, OSError) as e:
                issues.append(Issue(source="nl80211 GET_INTERFACE", kind="error", detail=str(e)))
        if not self.kidx.available:
            issues.extend(
                Issue(source="modules.alias", kind="not_exposed", detail=e) for e in self.kidx.errors
            )
        devices = []
        for c in self.candidates():
            try:
                devices.append(self._build(c, wiphys, ifaces, ps))
            except Exception as e:
                log.exception("device build failed", extra={"sysfs_path": c.path})
                issues.append(Issue(source=c.path, kind="error", detail=f"discovery failed: {e!r}"))
        if nl is not None and wiphys:
            for w in wiphys.values():
                w.meta.availability = "ok"
        devices.sort(key=lambda d: d.id)
        return DiscoveryResult(
            devices=devices, started_at=t0, duration_ms=(time.monotonic() - m0) * 1000, issues=issues
        )
