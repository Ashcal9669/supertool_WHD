"""Hardware topology graph built strictly from discovered relationships.

PCIe: root complex -> bridge(s) -> function -> driver -> firmware -> phy -> netdev
USB:  (PCI chain to xHCI) -> root hub -> hub(s) -> device -> interface -> endpoints;
      interface -> driver -> firmware -> phy -> netdev
Every node/edge comes from sysfs paths, driver symlinks, ETHTOOL_GDRVINFO or nl80211.
Nothing is inferred from model names; absent links are simply not drawn.
"""

from __future__ import annotations

import time
from typing import Any, Literal

from pydantic import Field

from whd.model.common import Model
from whd.model.device import Device

NodeKind = Literal[
    "pci_root",
    "pci_bridge",
    "pci_device",
    "usb_host",
    "usb_hub",
    "usb_device",
    "usb_interface",
    "usb_endpoint",
    "platform",
    "other",
    "driver",
    "driver_candidate",
    "firmware",
    "phy",
    "netdev",
]


class TopoNode(Model):
    id: str
    kind: NodeKind
    label: str
    sublabel: str | None = None
    device_id: str | None = None
    sysfs_path: str | None = None
    state: dict[str, Any] = Field(default_factory=dict)
    attrs: dict[str, Any] = Field(default_factory=dict)
    evidence: str


EdgeKind = Literal["bus", "binds", "loads", "registers", "exposes", "has", "candidate"]


class TopoEdge(Model):
    id: str
    source: str
    target: str
    kind: EdgeKind
    label: str | None = None
    state: dict[str, Any] = Field(default_factory=dict)


class Topology(Model):
    nodes: list[TopoNode]
    edges: list[TopoEdge]
    generated_at: float
    mode: str


class _G:
    def __init__(self) -> None:
        self.nodes: dict[str, TopoNode] = {}
        self.edges: dict[str, TopoEdge] = {}

    def node(self, n: TopoNode) -> str:
        if n.id in self.nodes:
            ex = self.nodes[n.id]
            if n.device_id and not ex.device_id:
                ex.device_id = n.device_id
            ex.state.update(n.state)
        else:
            self.nodes[n.id] = n
        return n.id

    def edge(
        self,
        src: str,
        dst: str,
        kind: EdgeKind,
        label: str | None = None,
        state: dict[str, Any] | None = None,
    ) -> None:
        eid = f"{src}->{dst}"
        if eid not in self.edges:
            self.edges[eid] = TopoEdge(
                id=eid,
                source=src,
                target=dst,
                kind=kind,
                label=label,
                state=state or {},
            )


def build_topology(devices: list[Device], mode: str) -> Topology:
    g = _G()
    for d in devices:
        if not d.present:
            continue
        prev: str | None = None
        for i, bn in enumerate(d.bus_path):
            is_dev = i == len(d.bus_path) - 1 and bn.sysfs_path == d.sysfs_path
            state: dict[str, Any] = {}
            sub = None
            if bn.kind in ("pci_bridge", "pci_device"):
                cs, cw = bn.attrs.get("current_link_speed"), bn.attrs.get("current_link_width")
                if cs:
                    state["link"] = f"{cs} x{cw}"
                    sub = state["link"]
            if bn.kind in ("usb_host", "usb_hub", "usb_device"):
                sp = bn.attrs.get("speed")
                if sp:
                    state["speed_mbps"] = sp
                    sub = f"{sp} Mb/s"
            if is_dev:
                if d.pci and d.pci.link:
                    lk = d.pci.link
                    state.update(
                        {
                            "link": f"{lk.current_speed} x{lk.current_width}",
                            "max_link": f"{lk.max_speed} x{lk.max_width}",
                            "degraded": lk.degraded,
                        }
                    )
                    sub = f"Gen{lk.current_gen} x{lk.current_width}"
                state["runtime_pm"] = d.power.runtime_status
                if d.power.aspm:
                    state["aspm_l1"] = d.power.aspm.get("l1_enabled")
                    state["aspm_l0s"] = d.power.aspm.get("l0s_enabled")
                if d.pci and d.pci.aer:
                    state["aer_total"] = sum(
                        v.get("TOTAL_ERR_COR", 0)
                        + v.get("TOTAL_ERR_FATAL", 0)
                        + v.get("TOTAL_ERR_NONFATAL", 0)
                        for v in d.pci.aer.values()
                    )
            label = (
                d.title
                if is_dev
                else (f"{bn.label} · {bn.attrs['model']}" if bn.attrs.get("model") else bn.label)
            )
            nid = g.node(
                TopoNode(
                    id=bn.sysfs_path,
                    kind=bn.kind,
                    label=label,
                    sublabel=sub if not is_dev else f"{bn.name} · {sub or ''}",
                    device_id=d.id if is_dev else None,
                    sysfs_path=bn.sysfs_path,
                    state=state,
                    attrs={k: v for k, v in bn.attrs.items() if v is not None}
                    | ({"driver": bn.driver} if bn.driver else {}),
                    evidence=f"sysfs path component {bn.sysfs_path}",
                )
            )
            if prev is not None:
                edge_state = (
                    {"link": state.get("link")}
                    if bn.kind.startswith("pci")
                    else {"speed_mbps": state.get("speed_mbps")}
                )
                g.edge(prev, nid, "bus", label=sub, state=edge_state)
            prev = nid
        dev_node = d.sysfs_path
        if dev_node not in g.nodes:
            continue
        anchor = dev_node
        # USB: interfaces and endpoints
        if d.usb:
            for itf in d.usb.interfaces:
                ip = f"{d.sysfs_path}/{itf.name}"
                g.node(
                    TopoNode(
                        id=ip,
                        kind="usb_interface",
                        label=f"if {itf.number}.{itf.alt_setting}",
                        sublabel=itf.class_name
                        or (f"class {itf.class_code:02x}" if itf.class_code is not None else None),
                        device_id=d.id,
                        sysfs_path=ip,
                        attrs={"driver": itf.driver, "modalias": itf.modalias},
                        state={"wireless": itf.wireless_candidate},
                        evidence=f"{ip} (bInterfaceNumber/bAlternateSetting)",
                    )
                )
                g.edge(dev_node, ip, "has")
                for ep in itf.endpoints:
                    eid = f"{ip}/ep_{ep.address:02x}"
                    g.node(
                        TopoNode(
                            id=eid,
                            kind="usb_endpoint",
                            label=f"EP 0x{ep.address:02x} {ep.direction}",
                            sublabel=f"{ep.type} {ep.max_packet_size}B",
                            device_id=d.id,
                            attrs={"type": ep.type, "direction": ep.direction, "interval": ep.interval},
                            evidence=f"{ip}/ep_{ep.address:02x}",
                        )
                    )
                    g.edge(ip, eid, "has")
                if itf.driver and itf.driver == d.driver:
                    anchor = ip
        di = d.driver_info
        if d.driver:
            drv = g.node(
                TopoNode(
                    id=f"driver:{d.id}",
                    kind="driver",
                    label=d.driver,
                    sublabel=f"module {d.module}" if d.module else None,
                    device_id=d.id,
                    attrs={
                        "module": d.module,
                        "taint": di.module_sysfs.get("taint"),
                        "srcversion": di.module_sysfs.get("srcversion"),
                    },
                    state={"bound": True},
                    evidence=f"{anchor}/driver symlink",
                )
            )
            g.edge(anchor, drv, "binds", label="bound")
        else:
            cands = [m.module for m in di.candidate_modules if m.wireless]
            if not cands:
                continue
            drv = g.node(
                TopoNode(
                    id=f"driver:{d.id}",
                    kind="driver_candidate",
                    label="no driver bound",
                    sublabel="candidates: " + ", ".join(cands),
                    device_id=d.id,
                    attrs={"candidates": [m.model_dump() for m in di.candidate_modules]},
                    state={"bound": False},
                    evidence="modules.alias match (not bound)",
                )
            )
            g.edge(anchor, drv, "candidate", label="modalias match")
            continue
        up = drv
        if d.firmware.version:
            fw = g.node(
                TopoNode(
                    id=f"fw:{d.id}",
                    kind="firmware",
                    label="firmware",
                    sublabel=d.firmware.version,
                    device_id=d.id,
                    attrs={"declared_files": d.firmware.declared_files},
                    evidence="ETHTOOL_GDRVINFO fw_version",
                )
            )
            g.edge(drv, fw, "loads")
            up = fw
        wmap = {w.name: w for w in d.wiphys}
        for phy in d.phys:
            w = wmap.get(phy)
            pid = g.node(
                TopoNode(
                    id=f"phy:{d.id}:{phy}",
                    kind="phy",
                    label=phy,
                    sublabel=" ".join(b.name for b in w.bands) if w else None,
                    device_id=d.id,
                    attrs={"bands": [b.name for b in w.bands], "mlo_support": w.mlo_support} if w else {},
                    evidence=f"{d.sysfs_path}/ieee80211/{phy}" + (" + nl80211 GET_WIPHY" if w else ""),
                )
            )
            g.edge(up, pid, "registers")
            for n in d.netdev_info:
                if n.phy != phy:
                    continue
                nid = g.node(
                    TopoNode(
                        id=f"netdev:{d.id}:{n.name}",
                        kind="netdev",
                        label=n.name,
                        sublabel=(n.wifi.iftype if n.wifi else None),
                        device_id=d.id,
                        state={
                            "operstate": n.operstate,
                            "carrier": n.carrier,
                            "freq_mhz": n.wifi.freq_mhz if n.wifi else None,
                            "mlo_links": len(n.wifi.mlo_links) if n.wifi else 0,
                        },
                        attrs={"ifindex": n.ifindex, "ssid": n.wifi.ssid if n.wifi else None},
                        evidence=f"/sys/class/net/{n.name}/phy80211 -> {phy}",
                    )
                )
                g.edge(pid, nid, "exposes", label=n.operstate)
    return Topology(
        nodes=list(g.nodes.values()), edges=list(g.edges.values()), generated_at=time.time(), mode=mode
    )
