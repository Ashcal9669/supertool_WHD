"""Resolve a discovered PHY from current interface metadata without defaulting to another PHY."""

from typing import Any


def verify_live_adapter(host: Any, interface: str) -> dict[str, Any]:
    """Recheck the actual netdev owner immediately before any live measurement."""
    root = host.root
    path = f"/sys/class/net/{interface}/device"
    vendor = root.attr_int(f"{path}/vendor")
    product = root.attr_int(f"{path}/device")
    driver = root.readlink_name(f"{path}/driver")
    if (vendor, product) != (0x14C3, 0x0616) or driver not in ("mt7921e", "mt7921e_git"):
        raise ValueError("live testing requires verified MT7922 PCI 14c3:0616 and mt7921e driver")
    return {"vendor_id": vendor, "device_id": product, "driver": driver, "interface": interface}


def interface_phy(dev: Any, iface: Any) -> str | None:
    index = getattr(iface, "wiphy", None)
    if index is not None:
        names = [w.name for w in dev.wiphys if w.index == index and w.name in dev.phys]
        if len(names) == 1:
            return str(names[0])
        canonical = f"phy{index}"
        return canonical if canonical in dev.phys else None
    names = [n.phy for n in dev.netdev_info if n.name == iface.name and n.phy in dev.phys]
    return str(names[0]) if len(names) == 1 else None
