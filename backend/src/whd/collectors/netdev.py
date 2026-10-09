"""Network interfaces and rfkill switches attached to a device (sysfs)."""

from __future__ import annotations

from whd.collectors.base import meta_from_log
from whd.model.device import Netdev, NetdevStats, Rfkill
from whd.platform.sysfs import ReadLog, SysRoot

IFF_UP = 0x1  # include/uapi/linux/if.h net_device_flags


def netdevs_of(root: SysRoot, dev_path: str) -> list[str]:
    names = set(root.listdir(f"{dev_path}/net"))
    # USB: netdevs hang off an interface child, e.g. 3-3:1.0/net/wlan0
    for child in root.listdir(dev_path):
        if ":" in child and root.isdir(f"{dev_path}/{child}/net"):
            names.update(root.listdir(f"{dev_path}/{child}/net"))
    return sorted(names)


def phys_of(root: SysRoot, dev_path: str) -> list[str]:
    phys = set(root.listdir(f"{dev_path}/ieee80211"))
    for child in root.listdir(dev_path):
        if ":" in child and root.isdir(f"{dev_path}/{child}/ieee80211"):
            phys.update(root.listdir(f"{dev_path}/{child}/ieee80211"))
    return sorted(phys)


def collect_netdev(root: SysRoot, name: str) -> Netdev:
    log = ReadLog()
    p = f"/sys/class/net/{name}"

    def ai(n: str, b: int = 10) -> int | None:
        return root.attr_int(f"{p}/{n}", log, base=b)

    nd = Netdev(name=name)
    nd.ifindex = ai("ifindex")
    nd.mac = root.attr(f"{p}/address", log)
    nd.operstate = root.attr(f"{p}/operstate", log)
    car = ai("carrier")  # EINVAL when interface is down -> issue recorded as unsupported
    nd.carrier = bool(car) if car is not None else None
    flags = ai("flags", 16)
    if flags is not None:
        nd.flags_hex = f"0x{flags:x}"
        nd.up = bool(flags & IFF_UP)
    nd.mtu = ai("mtu")
    nd.arp_type = ai("type")
    nd.phy = root.readlink_name(f"{p}/phy80211")
    st = NetdevStats()
    for f in NetdevStats.model_fields:
        v = root.attr_int(f"{p}/statistics/{f}", log)
        setattr(st, f, v)
    nd.stats = st
    nd.meta = meta_from_log(log)
    # carrier read fails with EINVAL when down: expected, do not mark partial
    nd.meta.issues = [i for i in nd.meta.issues if not i.source.endswith("/carrier")]
    if nd.meta.availability == "partial" and not [i for i in nd.meta.issues if i.kind != "not_exposed"]:
        nd.meta.availability = "ok"
    return nd


def collect_rfkill(root: SysRoot, phy: str) -> list[Rfkill]:
    out = []
    base = f"/sys/class/ieee80211/{phy}"
    for rk in root.listdir(base):
        if not rk.startswith("rfkill"):
            continue
        p = f"{base}/{rk}"
        soft, hard = root.attr_int(f"{p}/soft"), root.attr_int(f"{p}/hard")
        out.append(
            Rfkill(
                name=root.attr(f"{p}/name") or rk,
                type=root.attr(f"{p}/type"),
                soft=bool(soft) if soft is not None else None,
                hard=bool(hard) if hard is not None else None,
                state=root.attr_int(f"{p}/state"),
            )
        )
    return out
