from __future__ import annotations

from typing import Any, Literal

from pydantic import Field

from whd.model.common import Model, Section, SectionMeta
from whd.model.wireless import WifiInterface, Wiphy

Bus = Literal["pci", "usb", "sdio", "platform", "other"]


class DetectionReason(Model):
    kind: Literal["bound_phy", "driver_match", "class_hint"]
    strength: Literal["authoritative", "strong", "weak"]
    detail: str


BusKind = Literal[
    "pci_root",
    "pci_bridge",
    "pci_device",
    "usb_host",
    "usb_hub",
    "usb_device",
    "usb_interface",
    "platform",
    "other",
]


class BusNode(Model):
    kind: BusKind
    sysfs_path: str
    name: str
    label: str
    driver: str | None = None
    attrs: dict[str, str | int | None] = Field(default_factory=dict)


# ---------------------------------------------------------------------------
# PCI
# ---------------------------------------------------------------------------


class PciBar(Model):
    index: int
    start: str
    end: str
    size: int
    flags_hex: str
    kind: Literal["mem", "io", "unknown"]
    prefetchable: bool = False
    mem64: bool = False


class PciLink(Model):
    current_speed: str | None = None
    current_width: int | None = None
    max_speed: str | None = None
    max_width: int | None = None
    current_gen: int | None = None
    max_gen: int | None = None
    degraded: bool | None = Field(default=None, description="current < max speed or width (sysfs values)")


class PciInfo(Section):
    bdf: str
    vendor_id: int | None = None
    device_id: int | None = None
    subsystem_vendor_id: int | None = None
    subsystem_device_id: int | None = None
    class_code: int | None = None
    revision: int | None = None
    vendor_name: str | None = None
    device_name: str | None = None
    subsystem_name: str | None = None
    class_name: str | None = None
    names_source: str | None = None
    modalias: str | None = None
    link: PciLink | None = None
    irq: int | None = None
    msi_irqs: list[int] = Field(default_factory=list)
    numa_node: int | None = None
    iommu_group: str | None = None
    enabled: bool | None = None
    d3cold_allowed: bool | None = None
    power_state: str | None = None
    reset_methods: list[str] = Field(default_factory=list)
    aer: dict[str, dict[str, int]] = Field(default_factory=dict)
    bars: list[PciBar] = Field(default_factory=list)
    config_bytes_readable: int | None = None


class PciCapability(Model):
    id: int
    name: str
    offset: int
    extended: bool = False
    version: int | None = None


class DecodedRegister(Model):
    name: str
    offset: int
    raw_hex: str
    fields: dict[str, str | int | bool] = Field(default_factory=dict)


class PciConfig(Section):
    """Decoded PCI configuration space (read via the privileged helper; read-only)."""

    length: int = 0
    capabilities: list[PciCapability] = Field(default_factory=list)
    registers: list[DecodedRegister] = Field(default_factory=list)
    aspm: dict[str, Any] = Field(default_factory=dict)
    aer: dict[str, Any] = Field(default_factory=dict)
    msi: dict[str, Any] = Field(default_factory=dict)
    msix: dict[str, Any] = Field(default_factory=dict)
    pm: dict[str, Any] = Field(default_factory=dict)
    l1ss: dict[str, Any] = Field(default_factory=dict)
    link: dict[str, Any] = Field(default_factory=dict)
    raw_hex: str | None = None


# ---------------------------------------------------------------------------
# USB
# ---------------------------------------------------------------------------


class UsbEndpoint(Model):
    address: int
    number: int
    direction: Literal["in", "out"]
    type: Literal["control", "isochronous", "bulk", "interrupt"]
    max_packet_size: int | None = None
    interval: str | None = None
    b_interval: int | None = None
    attributes_hex: str | None = None
    ss_max_burst: int | None = None


class UsbInterface(Model):
    name: str
    number: int
    alt_setting: int
    num_endpoints: int | None = None
    class_code: int | None = None
    subclass: int | None = None
    protocol: int | None = None
    class_name: str | None = None
    driver: str | None = None
    modalias: str | None = None
    endpoints: list[UsbEndpoint] = Field(default_factory=list)
    candidate_modules: list[str] = Field(default_factory=list)
    wireless_candidate: bool = False


class UsbDescriptorNode(Model):
    type: int
    type_name: str
    length: int
    offset: int
    fields: dict[str, str | int] = Field(default_factory=dict)
    raw_hex: str


class UsbInfo(Section):
    busnum: int | None = None
    devnum: int | None = None
    devpath: str | None = None
    port_path: str | None = None
    vendor_id: int | None = None
    product_id: int | None = None
    bcd_device: str | None = None
    usb_version: str | None = None
    speed_mbps: float | None = None
    speed_name: str | None = None
    rx_lanes: int | None = None
    tx_lanes: int | None = None
    manufacturer: str | None = None
    product: str | None = None
    serial: str | None = None
    vendor_name: str | None = None
    product_name: str | None = None
    names_source: str | None = None
    device_class: int | None = None
    max_power: str | None = None
    num_configurations: int | None = None
    active_config: int | None = None
    removable: str | None = None
    authorized: bool | None = None
    quirks: str | None = None
    ltm_capable: str | None = None
    power: dict[str, str | int | None] = Field(default_factory=dict)
    port_state: dict[str, str | int | None] = Field(default_factory=dict)
    interfaces: list[UsbInterface] = Field(default_factory=list)
    descriptors: list[UsbDescriptorNode] = Field(default_factory=list)
    descriptors_hex: str | None = None


# ---------------------------------------------------------------------------
# Driver / firmware / netdev / power
# ---------------------------------------------------------------------------


class CandidateModule(Model):
    module: str
    wireless: bool
    loaded: bool
    path: str | None = None


class DriverInfo(Section):
    driver: str | None = None
    module: str | None = None
    bound: bool = False
    candidate_modules: list[CandidateModule] = Field(default_factory=list)
    module_info: dict[str, list[str]] = Field(default_factory=dict)
    module_sysfs: dict[str, str] = Field(default_factory=dict)
    module_params: dict[str, str] = Field(default_factory=dict)
    module_dependencies: list[str] = Field(default_factory=list)
    ethtool: dict[str, Any] = Field(default_factory=dict)


class FirmwareInfo(Section):
    version: str | None = None
    declared_files: list[str] = Field(default_factory=list)


class NetdevStats(Model):
    rx_bytes: int | None = None
    tx_bytes: int | None = None
    rx_packets: int | None = None
    tx_packets: int | None = None
    rx_errors: int | None = None
    tx_errors: int | None = None
    rx_dropped: int | None = None
    tx_dropped: int | None = None


class Rfkill(Model):
    name: str
    type: str | None = None
    soft: bool | None = None
    hard: bool | None = None
    state: int | None = None


class Netdev(Section):
    name: str
    ifindex: int | None = None
    mac: str | None = None
    operstate: str | None = None
    carrier: bool | None = None
    flags_hex: str | None = None
    up: bool | None = None
    mtu: int | None = None
    arp_type: int | None = None
    phy: str | None = None
    stats: NetdevStats = Field(default_factory=NetdevStats)
    wifi: WifiInterface | None = None
    name_history: list[str] = Field(default_factory=list)


class PowerInfo(Section):
    runtime_control: str | None = None
    runtime_status: str | None = None
    runtime_active_ms: int | None = None
    runtime_suspended_ms: int | None = None
    autosuspend_delay_ms: int | None = None
    wakeup: str | None = None
    pci_power_state: str | None = None
    d3cold_allowed: bool | None = None
    aspm: dict[str, Any] = Field(default_factory=dict)
    aspm_meta: SectionMeta = Field(default_factory=SectionMeta)
    wifi_power_save: dict[str, str | None] = Field(default_factory=dict)


# ---------------------------------------------------------------------------
# Device
# ---------------------------------------------------------------------------


class DeviceSummary(Model):
    id: str
    bus: Bus
    sysfs_path: str
    title: str
    vendor_id: int | None = None
    product_id: int | None = None
    vendor_name: str | None = None
    product_name: str | None = None
    driver: str | None = None
    module: str | None = None
    firmware_version: str | None = None
    phys: list[str] = Field(default_factory=list)
    netdevs: list[str] = Field(default_factory=list)
    operstate: str | None = None
    detection: list[DetectionReason] = Field(default_factory=list)
    first_seen: float | None = None
    last_seen: float | None = None
    present: bool = True
    demo: bool = False


class Device(DeviceSummary):
    bus_path: list[BusNode] = Field(default_factory=list)
    pci: PciInfo | None = None
    pci_config: PciConfig | None = None
    usb: UsbInfo | None = None
    driver_info: DriverInfo = Field(default_factory=DriverInfo)
    firmware: FirmwareInfo = Field(default_factory=FirmwareInfo)
    wiphys: list[Wiphy] = Field(default_factory=list)
    netdev_info: list[Netdev] = Field(default_factory=list)
    power: PowerInfo = Field(default_factory=PowerInfo)
    rfkill: list[Rfkill] = Field(default_factory=list)
    extensions: dict[str, Any] = Field(default_factory=dict)
    evidence: dict[str, str] = Field(default_factory=dict, exclude=True)
