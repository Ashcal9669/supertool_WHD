"""PCI device data from sysfs (unprivileged)."""

from __future__ import annotations

import re

from whd.collectors.base import meta_from_log
from whd.model.device import PciBar, PciInfo, PciLink
from whd.platform.ids_db import IdsDb
from whd.platform.kconsts import ioport as IO
from whd.platform.sysfs import ReadLog, SysRoot
from whd.platform.udev import udev_props

BDF_RE = re.compile(r"^[0-9a-f]{4}:[0-9a-f]{2}:[0-9a-f]{2}\.[0-7]$")

# PCIe base spec: data rate per generation.
_GT_TO_GEN = {
    "2.5": 1,
    "5.0": 2,
    "5": 2,
    "8.0": 3,
    "8": 3,
    "16.0": 4,
    "16": 4,
    "32.0": 5,
    "32": 5,
    "64.0": 6,
    "64": 6,
}


def speed_to_gen(s: str | None) -> int | None:
    if not s:
        return None
    m = re.match(r"([\d.]+)\s*GT/s", s)
    return _GT_TO_GEN.get(m.group(1)) if m else None


def parse_aer(text: str) -> dict[str, int]:
    out: dict[str, int] = {}
    for line in text.splitlines():
        parts = line.split()
        if len(parts) == 2:
            try:
                out[parts[0]] = int(parts[1])
            except ValueError:
                continue
    return out


def parse_resource(text: str) -> list[PciBar]:
    bars = []
    for i, line in enumerate(text.splitlines()[:6]):
        parts = line.split()
        if len(parts) != 3:
            continue
        start, end, flags = (int(x, 16) for x in parts)
        if start == 0 and end == 0:
            continue
        kind = "io" if flags & IO.IORESOURCE_IO else "mem" if flags & IO.IORESOURCE_MEM else "unknown"
        bars.append(
            PciBar(
                index=i,
                start=f"0x{start:x}",
                end=f"0x{end:x}",
                size=end - start + 1,
                flags_hex=f"0x{flags:x}",
                kind=kind,  # type: ignore[arg-type]
                prefetchable=bool(flags & IO.IORESOURCE_PREFETCH),
                mem64=bool(flags & IO.IORESOURCE_MEM_64),
            )
        )
    return bars


def collect_pci(root: SysRoot, path: str, ids: IdsDb) -> tuple[PciInfo, ReadLog]:
    log = ReadLog()
    bdf = path.rstrip("/").rsplit("/", 1)[-1]

    def a(n: str) -> str | None:
        return root.attr(f"{path}/{n}", log)

    def ai(n: str) -> int | None:
        return root.attr_int(f"{path}/{n}", log)

    info = PciInfo(bdf=bdf)
    info.vendor_id = ai("vendor")
    info.device_id = ai("device")
    info.subsystem_vendor_id = ai("subsystem_vendor")
    info.subsystem_device_id = ai("subsystem_device")
    info.class_code = ai("class")
    info.revision = ai("revision")
    info.modalias = a("modalias")
    props = udev_props(root, path, "pci", log)
    info.vendor_name = props.get("ID_VENDOR_FROM_DATABASE") or ids.vendor(info.vendor_id)
    info.device_name = props.get("ID_MODEL_FROM_DATABASE") or ids.device(info.vendor_id, info.device_id)
    info.subsystem_name = ids.subsystem(
        info.vendor_id, info.device_id, info.subsystem_vendor_id, info.subsystem_device_id
    )
    info.class_name = props.get("ID_PCI_SUBCLASS_FROM_DATABASE") or props.get("ID_PCI_CLASS_FROM_DATABASE")
    if "ID_MODEL_FROM_DATABASE" in props:
        info.names_source = "udev hwdb (/run/udev/data)"
    elif ids.path:
        info.names_source = ids.path
    cur_s, max_s = a("current_link_speed"), a("max_link_speed")
    cur_w, max_w = ai("current_link_width"), ai("max_link_width")
    if any(v is not None for v in (cur_s, max_s, cur_w, max_w)):
        link = PciLink(
            current_speed=cur_s,
            max_speed=max_s,
            current_width=cur_w,
            max_width=max_w,
            current_gen=speed_to_gen(cur_s),
            max_gen=speed_to_gen(max_s),
        )
        if link.current_gen and link.max_gen and cur_w is not None and max_w is not None:
            link.degraded = link.current_gen < link.max_gen or cur_w < max_w
        info.link = link
    info.irq = ai("irq")
    info.msi_irqs = sorted(int(x) for x in root.listdir(f"{path}/msi_irqs") if x.isdigit())
    if info.msi_irqs:
        log.sources.append(f"{path}/msi_irqs/")
    info.numa_node = ai("numa_node")
    grp = root.readlink_name(f"{path}/iommu_group")
    info.iommu_group = grp
    en = ai("enable")
    info.enabled = bool(en) if en is not None else None
    d3 = ai("d3cold_allowed")
    info.d3cold_allowed = bool(d3) if d3 is not None else None
    info.power_state = a("power_state")
    rm = a("reset_method")
    info.reset_methods = rm.split() if rm else []
    for kind in ("correctable", "fatal", "nonfatal"):
        t = a(f"aer_dev_{kind}")
        if t is not None:
            info.aer[kind] = parse_aer(t)
    for kind in ("rootport_total_err_cor", "rootport_total_err_fatal", "rootport_total_err_nonfatal"):
        v = ai(f"aer_stats/{kind}") if root.isdir(f"{path}/aer_stats") else None
        if v is not None:
            info.aer.setdefault("rootport", {})[kind] = v
    res = a("resource")
    if res:
        info.bars = parse_resource(res)
    try:
        info.config_bytes_readable = len(root.read_bytes(f"{path}/config", limit=4096))
        log.sources.append(f"{path}/config (length only)")
    except Exception:
        pass
    info.meta = meta_from_log(log)
    return info, log
