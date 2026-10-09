#!/usr/bin/env python3
"""Build derived and synthetic fixture scenarios.

Derived (from the recorded `mt7927-pcie-host` capture):
  renamed-netdev  - same device, netdev wlp7s0 -> wlx_renamed, phy1 -> phy3
  pci-no-driver   - same PCI device with no driver bound, no phy, no netdev
  no-nl80211      - recorded sysfs, nl80211 family unavailable
  empty           - no wireless devices at all

Synthetic (marked kind=synthetic; values are illustrative, not measured):
  mt7921u-usb     - USB 3 MT7921AU-style adapter (0e8d:7961) on an xHCI root hub,
                    associated in station mode, used to exercise USB code paths
                    because the development host has no USB Wi-Fi adapter.

Usage: uv run python tests/fixtures/build_fixtures.py
"""

from __future__ import annotations

import base64
import json
import os
import shutil
import struct
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
SR = HERE / "sysroots"
BASE = SR / "mt7927-pcie-host"
sys.path.insert(0, str(HERE.parents[1] / "src"))

from whd.platform.kconsts import netlink as N  # noqa: E402
from whd.platform.kconsts import nl80211 as C  # noqa: E402
from whd.platform.netlink import GENL_HDR, nla, nla_flag, nla_str, nla_u32, nla_u64  # noqa: E402
from whd.platform.nl80211.source import request_key  # noqa: E402


def _w(p: Path, text: str | bytes) -> None:
    p.parent.mkdir(parents=True, exist_ok=True)
    if isinstance(text, bytes):
        p.write_bytes(text)
    else:
        p.write_text(text if text.endswith("\n") or text == "" else text + "\n")


def _ln(p: Path, target: str) -> None:
    p.parent.mkdir(parents=True, exist_ok=True)
    if p.is_symlink() or p.exists():
        p.unlink()
    os.symlink(target, p)


def _meta(d: Path, **kw: object) -> None:
    m = json.loads((d / "fixture.json").read_text())
    m.update(kw)
    (d / "fixture.json").write_text(json.dumps(m, indent=1))


def fresh(name: str) -> Path:
    d = SR / name
    if d.exists():
        shutil.rmtree(d)
    shutil.copytree(BASE, d, symlinks=True, ignore=shutil.ignore_patterns("events.jsonl", "telemetry.jsonl"))
    return d


def find_dev(root: Path) -> Path:
    for p in (root / "sys/devices").rglob("*"):
        if p.name == "ieee80211" and p.is_dir():
            return p.parent
    raise SystemExit("no device with ieee80211 in base fixture")


# ---------------------------------------------------------------- derived


def build_renamed() -> None:
    d = fresh("renamed-netdev")
    root = d / "root"
    dev = find_dev(root)
    old_nd = next((dev / "net").iterdir()).name
    old_phy = next((dev / "ieee80211").iterdir()).name
    (dev / "net" / old_nd).rename(dev / "net" / "wlx_renamed")
    (dev / "ieee80211" / old_phy).rename(dev / "ieee80211" / "phy3")
    (root / "sys/class/net" / old_nd).unlink()
    (root / "sys/class/ieee80211" / old_phy).unlink()
    rel = os.path.relpath(dev, root / "sys/class/net")
    _ln(root / "sys/class/net/wlx_renamed", f"{rel}/net/wlx_renamed")
    _ln(
        root / "sys/class/ieee80211/phy3",
        f"{os.path.relpath(dev, root / 'sys/class/ieee80211')}/ieee80211/phy3",
    )
    phy_link = dev / "net/wlx_renamed/phy80211"
    if phy_link.is_symlink():
        phy_link.unlink()
        _ln(phy_link, "../../ieee80211/phy3")
    # nl80211: rewrite names inside recorded payloads (same-length not required: rebuild NLA strings)
    nlj = json.loads((d / "nl80211.json").read_text())
    for k, v in nlj["requests"].items():
        out = []
        for p in v:
            b = base64.b64decode(p)
            b = _replace_str_attr(b, old_nd, "wlx_renamed")
            b = _replace_str_attr(b, old_phy, "phy3")
            out.append(base64.b64encode(b).decode())
        nlj["requests"][k] = out
    (d / "nl80211.json").write_text(json.dumps(nlj, indent=1))
    eth = json.loads((d / "ethtool.json").read_text())
    eth["wlx_renamed"] = eth.pop(old_nd)
    (d / "ethtool.json").write_text(json.dumps(eth, indent=1))
    _meta(
        d,
        kind="derived",
        description=f"Derived from mt7927-pcie-host: netdev {old_nd} renamed to wlx_renamed "
        f"and {old_phy} renumbered to phy3 (identity must stay stable).",
    )


def _replace_str_attr(payload: bytes, old: str, new: str) -> bytes:
    """Rewrite top-level string attributes equal to `old` (IFNAME / WIPHY_NAME)."""
    hdr, body = payload[: GENL_HDR.size], payload[GENL_HDR.size :]
    out = b""
    off = 0
    while off + 4 <= len(body):
        ln, at = struct.unpack_from("=HH", body, off)
        if ln < 4:
            break
        val = body[off + 4 : off + ln]
        t = at & 0x3FFF
        if t in (C.NL80211_ATTR_IFNAME, C.NL80211_ATTR_WIPHY_NAME) and val.rstrip(b"\0") == old.encode():
            out += nla_str(t, new)
        else:
            out += body[off : off + ((ln + 3) & ~3)]
        off += (ln + 3) & ~3
    return hdr + out


def build_no_driver() -> None:
    d = fresh("pci-no-driver")
    root = d / "root"
    dev = find_dev(root)
    for n in ("driver", "ieee80211", "net"):
        p = dev / n
        if p.is_symlink():
            p.unlink()
        elif p.is_dir():
            shutil.rmtree(p)
    for p in list((root / "sys/class/ieee80211").iterdir()) + list((root / "sys/class/net").iterdir()):
        p.unlink()
    shutil.rmtree(root / "sys/module", ignore_errors=True)
    (d / "nl80211.json").write_text(
        json.dumps(
            {
                "family_id": 0x1F,
                "multicast_groups": {},
                "requests": {
                    request_key(C.NL80211_CMD_GET_WIPHY, nla_flag(C.NL80211_ATTR_SPLIT_WIPHY_DUMP), True): [],
                    request_key(C.NL80211_CMD_GET_INTERFACE, b"", True): [],
                },
            },
            indent=1,
        )
    )
    (d / "ethtool.json").write_text("{}")
    _meta(
        d,
        kind="derived",
        description="Derived from mt7927-pcie-host: same PCI function with no driver bound "
        "(e.g. probe failure or module not loaded). Detection relies on modules.alias.",
    )


def build_no_nl80211() -> None:
    d = fresh("no-nl80211")
    (d / "nl80211.json").unlink()
    _meta(
        d,
        kind="derived",
        description="Derived from mt7927-pcie-host: nl80211 generic netlink family "
        "unavailable (cfg80211 not loaded / netlink blocked). sysfs data only.",
    )


def build_empty() -> None:
    d = SR / "empty"
    if d.exists():
        shutil.rmtree(d)
    root = d / "root"
    for p in (
        "sys/class/ieee80211",
        "sys/class/net",
        "sys/bus/pci/devices",
        "sys/bus/usb/devices",
        "sys/devices",
    ):
        (root / p).mkdir(parents=True, exist_ok=True)
    base_meta = json.loads((BASE / "fixture.json").read_text())
    rel = base_meta["uname"]["release"]
    mods = root / "lib/modules" / rel
    mods.mkdir(parents=True)
    shutil.copy(BASE / "root/lib/modules" / rel / "modules.alias", mods / "modules.alias")
    shutil.copy(BASE / "root/lib/modules" / rel / "modules.dep", mods / "modules.dep")
    _w(root / "etc/os-release", 'PRETTY_NAME="Fixture Linux"\nID=fixture')
    (d / "nl80211.json").write_text(
        json.dumps(
            {
                "family_id": 0x1F,
                "multicast_groups": {},
                "requests": {
                    request_key(C.NL80211_CMD_GET_WIPHY, nla_flag(C.NL80211_ATTR_SPLIT_WIPHY_DUMP), True): [],
                    request_key(C.NL80211_CMD_GET_INTERFACE, b"", True): [],
                },
            },
            indent=1,
        )
    )
    (d / "fixture.json").write_text(
        json.dumps(
            {
                "kind": "synthetic",
                "description": "Host with no wireless devices.",
                "uname": base_meta["uname"],
            },
            indent=1,
        )
    )


# ---------------------------------------------------------------- synthetic USB


def genl(cmd: int, *attrs: bytes) -> str:
    return base64.b64encode(GENL_HDR.pack(cmd, 1, 0) + b"".join(attrs)).decode()


def nest(t: int, *parts: bytes) -> bytes:
    return nla(t | N.NLA_F_NESTED, b"".join(parts))


def u8(t: int, v: int) -> bytes:
    return nla(t, bytes([v]))


def u16(t: int, v: int) -> bytes:
    return nla(t, struct.pack("=H", v))


def s8(t: int, v: int) -> bytes:
    return nla(t, struct.pack("=b", v))


def freq(i: int, mhz: int, *flags: int, power_mbm: int = 2000) -> bytes:
    return nest(
        i,
        nla_u32(C.NL80211_FREQUENCY_ATTR_FREQ, mhz),
        nla_u32(C.NL80211_FREQUENCY_ATTR_MAX_TX_POWER, power_mbm),
        *[nla_flag(f) for f in flags],
    )


def build_usb() -> None:
    d = SR / "mt7921u-usb"
    if d.exists():
        shutil.rmtree(d)
    root = d / "root"
    rel = "6.12.0-synthetic"
    xhci = root / "sys/devices/pci0000:00/0000:00:14.0"
    usb2 = xhci / "usb2"
    dev = usb2 / "2-1"
    iface = dev / "2-1:1.0"
    # PCI root + xHCI controller
    for k, v in {
        "vendor": "0x8086",
        "device": "0x7ae0",
        "class": "0x0c0330",
        "subsystem_vendor": "0x8086",
        "subsystem_device": "0x7270",
        "revision": "0x11",
        "irq": "128",
        "enable": "1",
        "power_state": "D0",
        "numa_node": "-1",
        "modalias": "pci:v00008086d00007AE0sv00008086sd00007270bc0Csc03i30",
    }.items():
        _w(xhci / k, v)
    _ln(xhci / "subsystem", "../../../bus/pci")
    _ln(xhci / "driver", "../../../bus/pci/drivers/xhci_hcd")
    (root / "sys/bus/pci/drivers/xhci_hcd").mkdir(parents=True, exist_ok=True)
    _ln(root / "sys/bus/pci/devices/0000:00:14.0", "../../../devices/pci0000:00/0000:00:14.0")
    # root hub
    for k, v in {
        "idVendor": "1d6b",
        "idProduct": "0003",
        "bDeviceClass": "09",
        "speed": "10000",
        "version": " 3.20",
        "busnum": "2",
        "devnum": "1",
        "devpath": "0",
        "manufacturer": "Linux xhci-hcd",
        "product": "xHCI Host Controller",
        "serial": "0000:00:14.0",
        "bNumConfigurations": "1",
        "bConfigurationValue": "1",
        "maxchild": "4",
        "authorized": "1",
        "removable": "unknown",
    }.items():
        _w(usb2 / k, v)
    _ln(usb2 / "subsystem", "../../../../bus/usb")
    _ln(usb2 / "driver", "../../../../bus/usb/drivers/usb")
    # hub port
    port = usb2 / "2-0:1.0" / "usb2-port1"
    for k, v in {
        "connect_type": "hotplug",
        "state": "configured",
        "over_current_count": "0",
        "usb3_lpm_permit": "u1_u2",
        "quirks": "00000000",
    }.items():
        _w(port / k, v)
    # device
    devdesc = struct.pack("<BBHBBBBHHHBBBB", 18, 1, 0x0320, 0, 0, 0, 9, 0x0E8D, 0x7961, 0x0100, 1, 2, 3, 1)
    eps = [(0x84, 2), (0x85, 2), (0x08, 2), (0x04, 2), (0x05, 2), (0x06, 2), (0x07, 2), (0x09, 2)]
    ifdesc = struct.pack("<BBBBBBBBB", 9, 4, 0, 0, len(eps), 0xFF, 0xFF, 0xFF, 0)
    epdescs = b""
    for addr, typ in eps:
        epdescs += struct.pack("<BBBBHB", 7, 5, addr, typ, 1024, 0) + struct.pack("<BBBBH", 6, 48, 3, 0, 0)
    cfg_body = ifdesc + epdescs
    cfgdesc = struct.pack("<BBHBBBBB", 9, 2, 9 + len(cfg_body), 1, 1, 0, 0xA0, 112)
    _w(dev / "descriptors", devdesc + cfgdesc + cfg_body)
    for k, v in {
        "idVendor": "0e8d",
        "idProduct": "7961",
        "bcdDevice": "0100",
        "bDeviceClass": "00",
        "speed": "5000",
        "version": " 3.20",
        "busnum": "2",
        "devnum": "3",
        "devpath": "1",
        "manufacturer": "MediaTek Inc.",
        "product": "Wireless_Device",
        "serial": "000000000",
        "bNumConfigurations": "1",
        "bConfigurationValue": "1",
        "bMaxPower": "896mA",
        "removable": "removable",
        "authorized": "1",
        "quirks": "0x0",
        "ltm_capable": "no",
        "rx_lanes": "1",
        "tx_lanes": "1",
        "dev": "189:130",
    }.items():
        _w(dev / k, v)
    for k, v in {
        "control": "auto",
        "runtime_status": "active",
        "autosuspend_delay_ms": "2000",
        "runtime_active_time": "5123456",
        "runtime_suspended_time": "0",
        "level": "auto",
        "persist": "1",
        "connected_duration": "5123456",
        "active_duration": "5123456",
        "usb3_hardware_lpm_u1": "disabled",
        "usb3_hardware_lpm_u2": "disabled",
    }.items():
        _w(dev / "power" / k, v)
    _ln(dev / "subsystem", "../../../../../bus/usb")
    _ln(dev / "driver", "../../../../../bus/usb/drivers/usb")
    _ln(dev / "port", "../2-0:1.0/usb2-port1")
    # interface
    for k, v in {
        "bInterfaceNumber": "00",
        "bAlternateSetting": " 0",
        "bNumEndpoints": f"{len(eps):02x}",
        "bInterfaceClass": "ff",
        "bInterfaceSubClass": "ff",
        "bInterfaceProtocol": "ff",
        "modalias": "usb:v0E8Dp7961d0100dc00dsc00dp00icFFiscFFipFFin00",
        "supports_autosuspend": "1",
    }.items():
        _w(iface / k, v)
    for addr, typ in eps:
        ep = iface / f"ep_{addr:02x}"
        _w(ep / "bEndpointAddress", f"{addr:02x}")
        _w(ep / "bmAttributes", f"{typ:02x}")
        _w(ep / "wMaxPacketSize", "0400")
        _w(ep / "bInterval", "00")
        _w(ep / "interval", "0ms")
        _w(ep / "direction", "in" if addr & 0x80 else "out")
        _w(ep / "type", "Bulk")
    _ln(iface / "subsystem", "../../../../../../bus/usb")
    _ln(iface / "driver", "../../../../../../bus/usb/drivers/mt7921u")
    drv = root / "sys/bus/usb/drivers/mt7921u"
    drv.mkdir(parents=True, exist_ok=True)
    _ln(drv / "module", "../../../../module/mt7921u")
    (root / "sys/bus/usb/drivers/usb").mkdir(parents=True, exist_ok=True)
    # phy + netdev under the interface
    phy = iface / "ieee80211/phy0"
    _w(phy / "index", "0")
    _w(phy / "name", "phy0")
    _w(phy / "macaddress", "02:00:5e:20:00:01")
    _ln(phy / "device", "../../../2-1:1.0")
    rk = phy / "rfkill0"
    for k, v in {"name": "phy0", "type": "wlan", "soft": "0", "hard": "0", "state": "1"}.items():
        _w(rk / k, v)
    nd = iface / "net/wlan0"
    for k, v in {
        "ifindex": "5",
        "address": "02:00:5e:20:00:01",
        "operstate": "up",
        "carrier": "1",
        "flags": "0x1003",
        "mtu": "1500",
        "type": "1",
    }.items():
        _w(nd / k, v)
    for k, v in {
        "rx_bytes": "48211933",
        "tx_bytes": "3920114",
        "rx_packets": "40122",
        "tx_packets": "18233",
        "rx_errors": "0",
        "tx_errors": "0",
        "rx_dropped": "3",
        "tx_dropped": "0",
    }.items():
        _w(nd / "statistics" / k, v)
    _ln(nd / "phy80211", "../../ieee80211/phy0")
    _ln(
        root / "sys/class/ieee80211/phy0",
        "../../devices/pci0000:00/0000:00:14.0/usb2/2-1/2-1:1.0/ieee80211/phy0",
    )
    _ln(root / "sys/class/net/wlan0", "../../devices/pci0000:00/0000:00:14.0/usb2/2-1/2-1:1.0/net/wlan0")
    for n in ("2-1", "2-1:1.0", "usb2"):
        p = {"2-1": "2-1", "2-1:1.0": "2-1/2-1:1.0", "usb2": ""}[n]
        _ln(
            root / f"sys/bus/usb/devices/{n}",
            f"../../../devices/pci0000:00/0000:00:14.0/usb2{'/' + p if p else ''}",
        )
    (root / "sys/bus/pci/devices").mkdir(parents=True, exist_ok=True)
    for k, v in {
        "srcversion": "SYNTHETIC0000000000000",
        "refcnt": "0",
        "initstate": "live",
        "coresize": "28672",
        "taint": "",
    }.items():
        _w(root / "sys/module/mt7921u" / k, v)
    _w(
        root / "run/udev/data/c189:130",
        "E:ID_VENDOR_FROM_DATABASE=MediaTek Inc.\nE:ID_MODEL_FROM_DATABASE="
        "Wireless_Device (synthetic fixture)\n",
    )
    mods = root / "lib/modules" / rel
    _w(
        mods / "modules.alias",
        "alias usb:v0E8Dp7961d*dc*dsc*dp*icFFiscFFipFFin* mt7921u\n"
        "alias usb:v0E8Dp7961d*dc*dsc*dp*ic*isc*ip*in* btusb\n",
    )
    _w(
        mods / "modules.dep",
        "kernel/drivers/net/wireless/mediatek/mt76/mt7921/mt7921u.ko.xz: "
        "kernel/drivers/net/wireless/mediatek/mt76/mt7921/mt7921-common.ko.xz "
        "kernel/drivers/net/wireless/mediatek/mt76/mt76-usb.ko.xz kernel/net/mac80211/mac80211.ko.xz "
        "kernel/net/wireless/cfg80211.ko.xz\n"
        "kernel/drivers/net/wireless/mediatek/mt76/mt7921/mt7921-common.ko.xz: kernel/net/wireless/cfg80211.ko.xz\n"
        "kernel/drivers/net/wireless/mediatek/mt76/mt76-usb.ko.xz:\n"
        "kernel/net/mac80211/mac80211.ko.xz: kernel/net/wireless/cfg80211.ko.xz\n"
        "kernel/net/wireless/cfg80211.ko.xz:\n"
        "kernel/drivers/bluetooth/btusb.ko.xz: kernel/net/bluetooth/bluetooth.ko.xz\n"
        "kernel/net/bluetooth/bluetooth.ko.xz:\n",
    )
    _w(
        root / "usr/share/misc/usb.ids",
        "0e8d  MediaTek Inc.\n\t7961  Wireless_Device\n1d6b  Linux Foundation\n\t0003  3.0 root hub\n",
    )
    _w(
        root / "usr/share/misc/pci.ids",
        "8086  Intel Corporation\n\t7ae0  Alder Lake-S PCH USB 3.2 Gen 2x2 XHCI Controller\n",
    )
    _w(root / "etc/os-release", 'PRETTY_NAME="Synthetic Debian (fixture)"\nID=debian')

    # nl80211 replies
    WIPHY = 0
    ht_capa = 0x01EF  # synthetic: LDPC, 40 MHz, SM PS disabled, GF, SGI20/40, TX STBC, RX STBC1
    vht_capa = 0x339071B2
    he_mac = bytes.fromhex("08011a000040")
    he_phy_5g = bytes.fromhex("0c704e090fbd8c00000000")
    he_phy_2g = bytes.fromhex("02704e090fbd8c00000000")
    he_mcs = struct.pack("<HHHH", 0xFFFA, 0xFFFA, 0xFFFF, 0xFFFF)
    iftd = lambda phy: nest(
        1,
        nest(C.NL80211_BAND_IFTYPE_ATTR_IFTYPES, nla_flag(C.NL80211_IFTYPE_STATION)),
        nla(C.NL80211_BAND_IFTYPE_ATTR_HE_CAP_MAC, he_mac),
        nla(C.NL80211_BAND_IFTYPE_ATTR_HE_CAP_PHY, phy),
        nla(C.NL80211_BAND_IFTYPE_ATTR_HE_CAP_MCS_SET, he_mcs),
    )
    b24 = nest(
        C.NL80211_BAND_2GHZ,
        nest(
            C.NL80211_BAND_ATTR_FREQS,
            *[freq(i, 2412 + 5 * i) for i in range(11)],
            freq(11, 2467, C.NL80211_FREQUENCY_ATTR_NO_IR),
            freq(12, 2472, C.NL80211_FREQUENCY_ATTR_NO_IR),
            freq(13, 2484, C.NL80211_FREQUENCY_ATTR_DISABLED),
        ),
        u16(C.NL80211_BAND_ATTR_HT_CAPA, ht_capa),
        nla(C.NL80211_BAND_ATTR_HT_MCS_SET, bytes([0xFF, 0xFF]) + bytes(14)),
        nest(C.NL80211_BAND_ATTR_IFTYPE_DATA, iftd(he_phy_2g)),
    )
    ch5 = [
        5180,
        5200,
        5220,
        5240,
        5260,
        5280,
        5300,
        5320,
        5500,
        5520,
        5540,
        5560,
        5580,
        5600,
        5620,
        5640,
        5660,
        5680,
        5700,
        5720,
        5745,
        5765,
        5785,
        5805,
        5825,
    ]
    f5 = [
        freq(
            i,
            m,
            *((C.NL80211_FREQUENCY_ATTR_RADAR, C.NL80211_FREQUENCY_ATTR_NO_IR) if 5260 <= m <= 5720 else ()),
        )
        for i, m in enumerate(ch5)
    ]
    b5 = nest(
        C.NL80211_BAND_5GHZ,
        nest(C.NL80211_BAND_ATTR_FREQS, *f5),
        u16(C.NL80211_BAND_ATTR_HT_CAPA, ht_capa),
        nla(C.NL80211_BAND_ATTR_HT_MCS_SET, bytes([0xFF, 0xFF]) + bytes(14)),
        nla_u32(C.NL80211_BAND_ATTR_VHT_CAPA, vht_capa),
        nla(C.NL80211_BAND_ATTR_VHT_MCS_SET, struct.pack("<HHHH", 0xFFFA, 0, 0xFFFA, 0)),
        nest(C.NL80211_BAND_ATTR_IFTYPE_DATA, iftd(he_phy_5g)),
    )
    wiphy = [
        genl(
            C.NL80211_CMD_NEW_WIPHY,
            nla_u32(C.NL80211_ATTR_WIPHY, WIPHY),
            nla_str(C.NL80211_ATTR_WIPHY_NAME, "phy0"),
            nla(C.NL80211_ATTR_MAC, bytes.fromhex("02005e200001")),
            nest(
                C.NL80211_ATTR_SUPPORTED_IFTYPES,
                nla_flag(C.NL80211_IFTYPE_STATION),
                nla_flag(C.NL80211_IFTYPE_AP),
                nla_flag(C.NL80211_IFTYPE_MONITOR),
            ),
            nla(
                C.NL80211_ATTR_CIPHER_SUITES,
                struct.pack("<4I", 0x000FAC01, 0x000FAC02, 0x000FAC04, 0x000FAC06),
            ),
            u8(C.NL80211_ATTR_MAX_NUM_SCAN_SSIDS, 4),
            nla_u32(C.NL80211_ATTR_WIPHY_ANTENNA_AVAIL_TX, 3),
            nla_u32(C.NL80211_ATTR_WIPHY_ANTENNA_AVAIL_RX, 3),
        ),
        genl(
            C.NL80211_CMD_NEW_WIPHY,
            nla_u32(C.NL80211_ATTR_WIPHY, WIPHY),
            nest(C.NL80211_ATTR_WIPHY_BANDS, b24),
        ),
        genl(
            C.NL80211_CMD_NEW_WIPHY,
            nla_u32(C.NL80211_ATTR_WIPHY, WIPHY),
            nest(C.NL80211_ATTR_WIPHY_BANDS, b5),
        ),
    ]
    ifidx = nla_u32(C.NL80211_ATTR_IFINDEX, 5)
    iface_msg = genl(
        C.NL80211_CMD_NEW_INTERFACE,
        ifidx,
        nla_str(C.NL80211_ATTR_IFNAME, "wlan0"),
        nla_u32(C.NL80211_ATTR_WIPHY, WIPHY),
        nla_u32(C.NL80211_ATTR_IFTYPE, C.NL80211_IFTYPE_STATION),
        nla_u64(C.NL80211_ATTR_WDEV, 1),
        nla(C.NL80211_ATTR_MAC, bytes.fromhex("02005e200001")),
        nla(C.NL80211_ATTR_SSID, b"ssid1-synthetic"),
        nla_u32(C.NL80211_ATTR_WIPHY_FREQ, 5180),
        nla_u32(C.NL80211_ATTR_CHANNEL_WIDTH, C.NL80211_CHAN_WIDTH_80),
        nla_u32(C.NL80211_ATTR_CENTER_FREQ1, 5210),
        nla(C.NL80211_ATTR_WIPHY_TX_POWER_LEVEL, struct.pack("=i", 2000)),
        u8(C.NL80211_ATTR_4ADDR, 0),
    )
    rate = lambda br, mcs, nss: nest(
        C.NL80211_STA_INFO_TX_BITRATE,
        nla_u32(C.NL80211_RATE_INFO_BITRATE32, br),
        u8(C.NL80211_RATE_INFO_HE_MCS, mcs),
        u8(C.NL80211_RATE_INFO_HE_NSS, nss),
        u8(C.NL80211_RATE_INFO_HE_GI, 0),
        nla_flag(C.NL80211_RATE_INFO_80_MHZ_WIDTH),
    )
    rrate = nest(
        C.NL80211_STA_INFO_RX_BITRATE,
        nla_u32(C.NL80211_RATE_INFO_BITRATE32, 9607),
        u8(C.NL80211_RATE_INFO_HE_MCS, 11),
        u8(C.NL80211_RATE_INFO_HE_NSS, 2),
        u8(C.NL80211_RATE_INFO_HE_GI, 0),
        nla_flag(C.NL80211_RATE_INFO_80_MHZ_WIDTH),
    )
    sta = genl(
        C.NL80211_CMD_NEW_STATION,
        ifidx,
        nla(C.NL80211_ATTR_MAC, bytes.fromhex("02005e200002")),
        nest(
            C.NL80211_ATTR_STA_INFO,
            nla_u32(C.NL80211_STA_INFO_INACTIVE_TIME, 12),
            nla_u32(C.NL80211_STA_INFO_CONNECTED_TIME, 5120),
            nla_u64(C.NL80211_STA_INFO_RX_BYTES64, 48211933),
            nla_u64(C.NL80211_STA_INFO_TX_BYTES64, 3920114),
            nla_u32(C.NL80211_STA_INFO_RX_PACKETS, 40122),
            nla_u32(C.NL80211_STA_INFO_TX_PACKETS, 18233),
            nla_u32(C.NL80211_STA_INFO_TX_RETRIES, 811),
            nla_u32(C.NL80211_STA_INFO_TX_FAILED, 4),
            s8(C.NL80211_STA_INFO_SIGNAL, -52),
            s8(C.NL80211_STA_INFO_SIGNAL_AVG, -53),
            nest(C.NL80211_STA_INFO_CHAIN_SIGNAL, s8(0, -54), s8(1, -55)),
            rate(8647, 9, 2),
            rrate,
            nla_u64(C.NL80211_STA_INFO_BEACON_RX, 51003),
            s8(C.NL80211_STA_INFO_BEACON_SIGNAL_AVG, -51),
            nla_u32(C.NL80211_STA_INFO_BEACON_LOSS, 0),
            nla(C.NL80211_STA_INFO_STA_FLAGS, struct.pack("=II", 0x7E, 0x6A)),
        ),
    )
    reg = genl(
        C.NL80211_CMD_GET_REG,
        nla_str(C.NL80211_ATTR_REG_ALPHA2, "US"),
        u8(C.NL80211_ATTR_DFS_REGION, 1),
        nest(
            C.NL80211_ATTR_REG_RULES,
            nest(
                0,
                nla_u32(C.NL80211_ATTR_REG_RULE_FLAGS, 0),
                nla_u32(C.NL80211_ATTR_FREQ_RANGE_START, 2402000),
                nla_u32(C.NL80211_ATTR_FREQ_RANGE_END, 2472000),
                nla_u32(C.NL80211_ATTR_FREQ_RANGE_MAX_BW, 40000),
                nla_u32(C.NL80211_ATTR_POWER_RULE_MAX_EIRP, 3000),
            ),
            nest(
                1,
                nla_u32(C.NL80211_ATTR_REG_RULE_FLAGS, 0),
                nla_u32(C.NL80211_ATTR_FREQ_RANGE_START, 5170000),
                nla_u32(C.NL80211_ATTR_FREQ_RANGE_END, 5250000),
                nla_u32(C.NL80211_ATTR_FREQ_RANGE_MAX_BW, 80000),
                nla_u32(C.NL80211_ATTR_POWER_RULE_MAX_EIRP, 2300),
            ),
        ),
    )
    survey = [
        genl(
            C.NL80211_CMD_NEW_SURVEY_RESULTS,
            ifidx,
            nest(
                C.NL80211_ATTR_SURVEY_INFO,
                nla_u32(C.NL80211_SURVEY_INFO_FREQUENCY, 5180),
                s8(C.NL80211_SURVEY_INFO_NOISE, -92),
                nla_flag(C.NL80211_SURVEY_INFO_IN_USE),
                nla_u64(C.NL80211_SURVEY_INFO_TIME, 600000),
                nla_u64(C.NL80211_SURVEY_INFO_TIME_BUSY, 91000),
                nla_u64(C.NL80211_SURVEY_INFO_TIME_RX, 52000),
                nla_u64(C.NL80211_SURVEY_INFO_TIME_TX, 9000),
            ),
        )
    ]
    scan = [
        genl(
            C.NL80211_CMD_NEW_SCAN_RESULTS,
            ifidx,
            nest(
                C.NL80211_ATTR_BSS,
                nla(C.NL80211_BSS_BSSID, bytes.fromhex("02005e200002")),
                nla_u32(C.NL80211_BSS_FREQUENCY, 5180),
                nla(C.NL80211_BSS_SIGNAL_MBM, struct.pack("=i", -5200)),
                nla_u32(C.NL80211_BSS_STATUS, C.NL80211_BSS_STATUS_ASSOCIATED),
                u16(C.NL80211_BSS_BEACON_INTERVAL, 100),
                u16(C.NL80211_BSS_CAPABILITY, 0x1511),
                nla_u32(C.NL80211_BSS_SEEN_MS_AGO, 840),
                nla(C.NL80211_BSS_INFORMATION_ELEMENTS, bytes([0, 15]) + b"ssid1-synthetic"),
            ),
        )
    ]
    ps = genl(C.NL80211_CMD_GET_POWER_SAVE, nla_u32(C.NL80211_ATTR_PS_STATE, C.NL80211_PS_ENABLED))
    req = {
        request_key(C.NL80211_CMD_GET_WIPHY, nla_flag(C.NL80211_ATTR_SPLIT_WIPHY_DUMP), True): wiphy,
        request_key(C.NL80211_CMD_GET_INTERFACE, b"", True): [iface_msg],
        request_key(C.NL80211_CMD_GET_POWER_SAVE, ifidx, False): [ps],
        request_key(C.NL80211_CMD_GET_STATION, ifidx, True): [sta],
        request_key(C.NL80211_CMD_GET_REG, b"", True): [reg],
        request_key(C.NL80211_CMD_GET_SURVEY, ifidx, True): survey,
        request_key(C.NL80211_CMD_GET_SCAN, ifidx, True): scan,
    }
    (d / "nl80211.json").write_text(
        json.dumps(
            {
                "family_id": 0x1F,
                "multicast_groups": {"config": 4, "scan": 5, "regulatory": 6, "mlme": 7, "vendor": 8},
                "requests": req,
            },
            indent=1,
        )
    )
    (d / "ethtool.json").write_text(
        json.dumps(
            {
                "wlan0": {
                    "driver": "mt7921u",
                    "version": rel,
                    "fw_version": "____010000-SYNTHETIC",
                    "bus_info": "2-1:1.0",
                    "erom_version": "",
                    "n_stats": 0,
                    "n_priv_flags": 0,
                    "regdump_len": 0,
                    "eedump_len": 0,
                    "testinfo_len": 0,
                }
            },
            indent=1,
        )
    )
    (d / "modinfo.json").write_text(
        json.dumps(
            {
                "mt7921u": {
                    "filename": [
                        f"/lib/modules/{rel}/kernel/drivers/net/wireless/mediatek/mt76/mt7921/mt7921u.ko.xz"
                    ],
                    "description": ["MediaTek MT7921U (USB) wireless driver"],
                    "license": ["Dual BSD/GPL"],
                    "firmware": [
                        "mediatek/WIFI_MT7961_patch_mcu_1_2_hdr.bin",
                        "mediatek/WIFI_RAM_CODE_MT7961_1.bin",
                    ],
                    "alias": ["usb:v0E8Dp7961d*dc*dsc*dp*icFFiscFFipFFin*"],
                    "vermagic": [f"{rel} SMP preempt mod_unload"],
                }
            },
            indent=1,
        )
    )
    (d / "fixture.json").write_text(
        json.dumps(
            {
                "kind": "synthetic",
                "description": "SYNTHETIC USB 3 MT7921U-style adapter (0e8d:7961) on xHCI root hub port 1, associated on "
                "5180 MHz / 80 MHz. Values are illustrative and were not measured on hardware.",
                "uname": {
                    "release": rel,
                    "machine": "x86_64",
                    "nodename": "synthetic-host",
                    "version": "#1 SMP",
                },
                "devices": ["usb:000000000:0e8d:7961"],
                "tools": {},
            },
            indent=1,
        )
    )


def main() -> int:
    if not BASE.is_dir():
        print(f"missing base fixture {BASE}; run `whd capture-fixture` first", file=sys.stderr)
        return 1
    build_renamed()
    build_no_driver()
    build_no_nl80211()
    build_empty()
    build_usb()
    print("fixtures built:", ", ".join(sorted(p.name for p in SR.iterdir() if p.is_dir())))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
