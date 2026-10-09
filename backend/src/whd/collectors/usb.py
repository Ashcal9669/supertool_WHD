"""USB device data from sysfs (unprivileged): device, interfaces, endpoints, raw descriptors."""

from __future__ import annotations

import struct

from whd.collectors.base import meta_from_log
from whd.model.device import UsbDescriptorNode, UsbEndpoint, UsbInfo, UsbInterface
from whd.platform.ids_db import IdsDb
from whd.platform.kconsts import usb_ch9 as U
from whd.platform.sysfs import ReadLog, SysRoot
from whd.platform.udev import udev_props

DT_NAMES = {
    v: k.removeprefix("USB_DT_")
    for k, v in U.DEFINES.items()
    if k.startswith("USB_DT_") and not k.endswith(("_SIZE", "_AUDIO_SIZE")) and v < 256
}
XFER = {
    U.USB_ENDPOINT_XFER_CONTROL: "control",
    U.USB_ENDPOINT_XFER_ISOC: "isochronous",
    U.USB_ENDPOINT_XFER_BULK: "bulk",
    U.USB_ENDPOINT_XFER_INT: "interrupt",
}
CLASS_NAMES = {v: k.removeprefix("USB_CLASS_") for k, v in U.DEFINES.items() if k.startswith("USB_CLASS_")}

# Speed strings from drivers/usb/core/sysfs.c speed_show() -> marketing names (usb.org).
SPEED_NAMES = {
    "1.5": "Low Speed",
    "12": "Full Speed",
    "480": "High Speed",
    "5000": "SuperSpeed",
    "10000": "SuperSpeed+ 10Gbps",
    "20000": "SuperSpeed+ 20Gbps",
}


def parse_descriptors(blob: bytes) -> list[UsbDescriptorNode]:
    """Walk raw descriptors from sysfs `descriptors` (device descriptor + config descriptors)."""
    out = []
    off = 0
    while off + 2 <= len(blob):
        ln, typ = blob[off], blob[off + 1]
        if ln < 2 or off + ln > len(blob):
            break
        d = blob[off : off + ln]
        f: dict[str, str | int] = {}
        try:
            if typ == U.USB_DT_DEVICE and ln >= 18:
                (bcd_usb, cls, sub, proto, mps0, vid, pid, bcd_dev, _m, _p, _s, ncfg) = struct.unpack_from(
                    "<HBBBBHHHBBBB", d, 2
                )
                f = {
                    "bcdUSB": f"{bcd_usb >> 8:x}.{bcd_usb & 0xFF:02x}",
                    "bDeviceClass": cls,
                    "bDeviceSubClass": sub,
                    "bDeviceProtocol": proto,
                    "bMaxPacketSize0": mps0,
                    "idVendor": f"{vid:04x}",
                    "idProduct": f"{pid:04x}",
                    "bcdDevice": f"{bcd_dev:04x}",
                    "bNumConfigurations": ncfg,
                }
            elif typ == U.USB_DT_CONFIG and ln >= 9:
                total, nif, val, _i, attr, maxp = struct.unpack_from("<HBBBBB", d, 2)
                f = {
                    "wTotalLength": total,
                    "bNumInterfaces": nif,
                    "bConfigurationValue": val,
                    "bmAttributes": f"0x{attr:02x}",
                    "bMaxPower": maxp,
                }
            elif typ == U.USB_DT_INTERFACE and ln >= 9:
                num, alt, neps, cls, sub, proto = struct.unpack_from("<BBBBBB", d, 2)
                f = {
                    "bInterfaceNumber": num,
                    "bAlternateSetting": alt,
                    "bNumEndpoints": neps,
                    "bInterfaceClass": cls,
                    "bInterfaceSubClass": sub,
                    "bInterfaceProtocol": proto,
                }
            elif typ == U.USB_DT_ENDPOINT and ln >= 7:
                addr, attr, mps, interval = struct.unpack_from("<BBHB", d, 2)
                f = {
                    "bEndpointAddress": f"0x{addr:02x}",
                    "direction": "in" if addr & U.USB_DIR_IN else "out",
                    "type": XFER.get(attr & U.USB_ENDPOINT_XFERTYPE_MASK, "?"),
                    "wMaxPacketSize": mps,
                    "bInterval": interval,
                }
            elif typ == U.USB_DT_SS_ENDPOINT_COMP and ln >= 6:
                burst, attr, bpi = struct.unpack_from("<BBH", d, 2)
                f = {"bMaxBurst": burst, "bmAttributes": f"0x{attr:02x}", "wBytesPerInterval": bpi}
            elif typ == U.USB_DT_INTERFACE_ASSOCIATION and ln >= 8:
                first, cnt, cls, sub, proto = struct.unpack_from("<BBBBB", d, 2)
                f = {
                    "bFirstInterface": first,
                    "bInterfaceCount": cnt,
                    "bFunctionClass": cls,
                    "bFunctionSubClass": sub,
                    "bFunctionProtocol": proto,
                }
        except struct.error:
            f = {}
        out.append(
            UsbDescriptorNode(
                type=typ,
                type_name=DT_NAMES.get(typ, f"0x{typ:02x}"),
                length=ln,
                offset=off,
                fields=f,
                raw_hex=d.hex(),
            )
        )
        off += ln
    return out


def collect_usb(root: SysRoot, path: str, ids: IdsDb) -> tuple[UsbInfo, ReadLog]:
    log = ReadLog()

    def a(n: str) -> str | None:
        return root.attr(f"{path}/{n}", log)

    def ai(n: str, b: int = 10) -> int | None:
        return root.attr_int(f"{path}/{n}", log, base=b)

    u = UsbInfo()
    u.busnum, u.devnum = ai("busnum"), ai("devnum")
    u.devpath = a("devpath")
    u.port_path = path.rstrip("/").rsplit("/", 1)[-1]
    u.vendor_id, u.product_id = ai("idVendor", 16), ai("idProduct", 16)
    u.bcd_device = a("bcdDevice")
    u.usb_version = a("version")
    sp = a("speed")
    if sp is not None:
        try:
            u.speed_mbps = float(sp)
        except ValueError:
            pass
        u.speed_name = SPEED_NAMES.get(sp)
    u.rx_lanes, u.tx_lanes = ai("rx_lanes"), ai("tx_lanes")
    u.manufacturer, u.product, u.serial = a("manufacturer"), a("product"), a("serial")
    u.device_class = ai("bDeviceClass", 16)
    u.max_power = a("bMaxPower")
    u.num_configurations = ai("bNumConfigurations")
    u.active_config = ai("bConfigurationValue")
    u.removable = a("removable")
    au = ai("authorized")
    u.authorized = bool(au) if au is not None else None
    u.quirks = a("quirks")
    u.ltm_capable = a("ltm_capable")
    props = udev_props(root, path, "usb", log)
    u.vendor_name = props.get("ID_VENDOR_FROM_DATABASE") or ids.vendor(u.vendor_id)
    u.product_name = props.get("ID_MODEL_FROM_DATABASE") or ids.device(u.vendor_id, u.product_id)
    u.names_source = "udev hwdb (/run/udev/data)" if "ID_VENDOR_FROM_DATABASE" in props else ids.path
    for n in (
        "control",
        "runtime_status",
        "autosuspend_delay_ms",
        "runtime_active_time",
        "runtime_suspended_time",
        "level",
        "persist",
        "connected_duration",
        "active_duration",
        "wakeup",
        "usb2_hardware_lpm",
        "usb3_hardware_lpm_u1",
        "usb3_hardware_lpm_u2",
    ):
        v = root.attr(f"{path}/power/{n}", log)
        if v is not None:
            u.power[n] = v
    # Port state lives on the parent hub's port device (portN/), if exposed.
    port = root.realpath(f"{path}/port")
    if port:
        for n in (
            "connect_type",
            "state",
            "over_current_count",
            "quirks",
            "usb3_lpm_permit",
            "location",
            "early_stop",
            "disable",
        ):
            if n in ("disable",):
                continue  # writable control; do not read
            v = root.attr(f"{port}/{n}", log)
            if v is not None:
                u.port_state[n] = v
    try:
        blob = root.read_bytes(f"{path}/descriptors", limit=65536)
        u.descriptors_hex = blob.hex()
        u.descriptors = parse_descriptors(blob)
        log.sources.append(f"{path}/descriptors")
    except Exception as e:
        from whd.platform.sysfs import SysfsError

        if isinstance(e, SysfsError):
            log.issues.append(e.issue)
    # Interfaces: children named "<port>:<cfg>.<if>"
    prefix = u.port_path + ":"
    for child in root.listdir(path):
        if not child.startswith(prefix):
            continue
        ip = f"{path}/{child}"

        def ia(n: str, b: int = 16, ip: str = ip) -> int | None:
            return root.attr_int(f"{ip}/{n}", log, base=b)

        iface = UsbInterface(
            name=child,
            number=ia("bInterfaceNumber") or 0,
            alt_setting=ia("bAlternateSetting", 10) or 0,
            num_endpoints=ia("bNumEndpoints"),
            class_code=ia("bInterfaceClass"),
            subclass=ia("bInterfaceSubClass"),
            protocol=ia("bInterfaceProtocol"),
            driver=root.readlink_name(f"{ip}/driver"),
            modalias=root.attr(f"{ip}/modalias", log),
        )
        iface.class_name = CLASS_NAMES.get(iface.class_code or -1)
        for ep in root.listdir(ip):
            if not ep.startswith("ep_"):
                continue
            ep_p = f"{ip}/{ep}"
            addr = root.attr_int(f"{ep_p}/bEndpointAddress", log, base=16)
            attr = root.attr_int(f"{ep_p}/bmAttributes", log, base=16)
            if addr is None or attr is None:
                continue
            mps = root.attr_int(f"{ep_p}/wMaxPacketSize", log, base=16)
            binterval = root.attr_int(f"{ep_p}/bInterval", log, base=16)
            iface.endpoints.append(
                UsbEndpoint(
                    address=addr,
                    number=addr & U.USB_ENDPOINT_NUMBER_MASK,
                    direction="in" if addr & U.USB_DIR_IN else "out",
                    type=XFER.get(attr & U.USB_ENDPOINT_XFERTYPE_MASK, "control"),  # type: ignore[arg-type]
                    max_packet_size=mps,
                    interval=root.attr(f"{ep_p}/interval", log),
                    b_interval=binterval,
                    attributes_hex=f"0x{attr:02x}",
                )
            )
        u.interfaces.append(iface)
    u.meta = meta_from_log(log)
    return u, log
