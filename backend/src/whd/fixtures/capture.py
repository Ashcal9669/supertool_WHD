"""`whd capture-fixture`: record this host's wireless devices into a fixture directory.

Read-only. Copies readable sysfs attributes of the wireless devices and their bus
ancestors (skipping the WHD never-open list and side-effecting attributes),
relevant class/bus symlinks, module metadata, udev database entries, and the
nl80211 / ethtool / modinfo responses. MAC addresses and SSIDs are replaced by
same-length placeholders unless --keep-mac is given.
"""

from __future__ import annotations

import base64
import json
import os
import re
import shutil
import sys
import time
from collections.abc import Callable, Sequence
from pathlib import Path
from typing import Any

from whd.discovery import Discovery
from whd.platform.host import LiveHost
from whd.platform.nl80211.client import Nl80211
from whd.platform.nl80211.source import LiveNl80211, RecordingNl80211
from whd.platform.sysfs import DENIED_NAMES

SKIP_NAMES = DENIED_NAMES | {
    "vpd",
    "firmware_node",
    "of_node",
    "iommu",
    "subsystem",
    "driver",
    "physfn",
    "consumer",
    "supplier",
    "wakeup",
    "peer",
    "phy80211",
    "aer_inject",
    "label",
    "index_ext",
}
SKIP_DIRS = {
    "iommu",
    "iommu_group",
    "firmware_node",
    "of_node",
    "wakeup",
    "msi_bus",
    "power_supply",
    "subsystem",
    "driver",
    "hidraw",
    "input",
    "sound",
    "bluetooth",
    "hci0",
    "rfkill_dummy",
    "holders",
    "sections",
    "notes",
    "drivers",
    "queues",
    "ptp",
    "mdio_bus",
}
MAX_FILE = 65536
MAC_RE = re.compile(rb"(?<![0-9a-fA-F:])([0-9a-f]{2}(?::[0-9a-f]{2}){5})(?![0-9a-fA-F:])")


class Scrubber:
    def __init__(self, keep: bool) -> None:
        self.keep = keep
        self.macs: dict[bytes, bytes] = {}
        self.ssids: dict[bytes, bytes] = {}

    def add_mac(self, mac: str | None) -> None:
        if self.keep or not mac or mac in ("00:00:00:00:00:00", "ff:ff:ff:ff:ff:ff"):
            return
        raw = bytes(int(x, 16) for x in mac.split(":"))
        if raw not in self.macs:
            n = len(self.macs) + 1
            self.macs[raw] = bytes([0x02, 0x00, 0x5E, 0x10, (n >> 8) & 0xFF, n & 0xFF])

    def add_ssid(self, ssid: str | None) -> None:
        if self.keep or not ssid:
            return
        raw = ssid.encode()
        if raw not in self.ssids:
            rep = f"ssid{len(self.ssids) + 1}".encode()
            rep = (rep + b"-" * len(raw))[: len(raw)]
            self.ssids[raw] = rep

    def bin(self, b: bytes) -> bytes:
        for k, v in self.macs.items():
            b = b.replace(k, v)
        for k, v in self.ssids.items():
            if len(k) >= 3:
                b = b.replace(k, v)
        return b

    def text(self, b: bytes) -> bytes:
        if self.keep:
            return b
        for k, v in self.macs.items():
            ks = ":".join(f"{x:02x}" for x in k).encode()
            vs = ":".join(f"{x:02x}" for x in v).encode()
            b = b.replace(ks, vs).replace(ks.upper(), vs)
            # variants that differ only in the first octet (e.g. the per-interface addresses a driver derives from
            # the permanent address) are just as identifying: mask them too, keeping their first octet
            tail = re.escape(":".join(f"{x:02x}" for x in k[1:]).encode())
            repl = vs.split(b":", 1)[1]
            b = re.sub(rb"(?i)\b([0-9a-f]{2}):" + tail, rb"\1:" + repl, b)
        return self.bin(b)


def _copy_file(src: str, dst_root: Path, scrub: Scrubber, limit: int = MAX_FILE) -> bool:
    try:
        st = os.stat(src)
        if not (st.st_mode & 0o444):
            return False
        fd = os.open(src, os.O_RDONLY | os.O_NONBLOCK)
        try:
            data = os.read(fd, limit)
        finally:
            os.close(fd)
    except OSError:
        return False
    dst = dst_root / src.lstrip("/")
    dst.parent.mkdir(parents=True, exist_ok=True)
    dst.write_bytes(scrub.text(data))
    return True


def _link(src: str, dst_root: Path) -> None:
    """Recreate a symlink with its original (relative) target."""
    try:
        target = os.readlink(src)
    except OSError:
        return
    dst = dst_root / src.lstrip("/")
    dst.parent.mkdir(parents=True, exist_ok=True)
    if dst.is_symlink() or dst.exists():
        return
    if target.startswith("/"):
        target = os.path.relpath(target, os.path.dirname(src))
    os.symlink(target, dst)


def _copy_dir_attrs(path: str, dst: Path, scrub: Scrubber, recurse: bool, depth: int = 0) -> None:
    try:
        entries = os.listdir(path)
    except OSError:
        return
    (dst / path.lstrip("/")).mkdir(parents=True, exist_ok=True)
    for name in entries:
        p = f"{path}/{name}"
        if name in ("subsystem", "driver", "module", "phy80211", "device", "port", "iommu_group", "peer"):
            if os.path.islink(p):
                _link(p, dst)
                continue
        if os.path.islink(p):
            continue
        if os.path.isdir(p):
            if name in SKIP_DIRS:
                continue
            if name in ("power", "msi_irqs", "aer_stats", "link", "statistics", "queues_skip") or recurse:
                if depth < 6:
                    _copy_dir_attrs(p, dst, scrub, recurse, depth + 1)
            continue
        if name in SKIP_NAMES or (name.startswith("resource") and name != "resource"):
            continue
        if name == "config":
            _copy_file(p, dst, scrub, limit=64)
            continue
        _copy_file(p, dst, scrub)


def _record_helper(socket_path: Path, devices: list[Any], scrub: Scrubber) -> dict[str, Any] | None:
    """Record read-only helper responses (config space, debugfs listing + passive/wakes_device reads, tracefs
    event formats) so demo mode can replay Phase 2/5 views."""
    from whd.drivers.tracegroups import resolve_trace_groups
    from whd.helper.client import HelperClient, RecordingHelper
    from whd.helper.protocol import HelperError

    rec = RecordingHelper(HelperClient(socket_path))
    try:
        rec.call("ping")
    except HelperError:
        return None
    for d in devices:
        if d.pci is not None:
            for bdf in [d.pci.bdf] + [n.name for n in d.bus_path if n.kind in ("pci_bridge", "pci_device")]:
                try:
                    rec.call("pci_config_read", bdf=bdf)
                except HelperError:
                    pass
        for phy in d.phys:
            try:
                listing = rec.call("debugfs_list", phy=phy)
            except HelperError:
                continue
            for e in listing["entries"]:
                if e["tier"] in ("passive", "wakes_device") and e["readable_by_owner"]:
                    try:
                        rec.call("debugfs_read", phy=phy, path=e["path"])
                    except HelperError:
                        pass
    try:
        groups = resolve_trace_groups(rec, devices)
    except HelperError:
        groups = []
    calls: list[dict[str, Any]] = [{}, {"groups": groups, "with_format": True}]
    for args in calls:
        try:
            rec.call("tracefs_events", 10.0, **args)
        except HelperError:
            pass
    try:
        rec.call("tracefs_status")
    except HelperError:
        pass
    data = rec.dump()
    if not scrub.keep:
        for v in data["calls"].values():
            if isinstance(v, dict) and isinstance(v.get("text"), str):
                v["text"] = scrub.text(v["text"].encode()).decode(errors="replace")
        data["ping"]["pid"] = 0
    return data


def capture_fixture(
    out: Path,
    device_ids: list[str] | None,
    keep_mac: bool = False,
    description: str = "",
    helper_socket: Path | None = None,
) -> int:
    host = LiveHost()
    disc = Discovery(host)
    res = disc.run()
    devices = [d for d in res.devices if not device_ids or d.id in device_ids]
    if not devices:
        print("no matching wireless devices", file=sys.stderr)
        return 1
    if out.exists() and any(out.iterdir()):
        print(f"{out} exists and is not empty", file=sys.stderr)
        return 1
    root = out / "root"
    root.mkdir(parents=True, exist_ok=True)
    scrub = Scrubber(keep_mac)
    rec = RecordingNl80211(LiveNl80211())
    nl = Nl80211(rec)
    wiphys = nl.wiphys()
    ifaces = nl.interfaces()
    for w in wiphys:
        scrub.add_mac(w.perm_addr)
    for i in ifaces:
        scrub.add_mac(i.mac)
        scrub.add_ssid(i.ssid)
        for link in i.mlo_links:
            scrub.add_mac(link.mac)
        try:
            nl.power_save(i.ifindex)
        except Exception:
            pass
        calls: tuple[Callable[[int], Sequence[object]], ...] = (nl.stations, nl.survey, nl.scan)
        for call in calls:
            try:
                for item in call(i.ifindex):
                    for attr in ("mac", "bssid", "mld_addr"):
                        scrub.add_mac(getattr(item, attr, None))
                    scrub.add_ssid(getattr(item, "ssid", None))
                    for link in getattr(item, "links", []):
                        scrub.add_mac(link.mac)
            except Exception:
                pass
    try:
        nl.regdomains()
    except Exception:
        pass
    for d in devices:
        for n in d.netdev_info:
            scrub.add_mac(n.mac)

    modules: set[str] = set()
    for d in devices:
        # device dir: recursive (interfaces, endpoints, net/, ieee80211/)
        _copy_dir_attrs(d.sysfs_path, root, scrub, recurse=True)
        for node in d.bus_path:
            _copy_dir_attrs(node.sysfs_path, root, scrub, recurse=False)
            for ln in ("subsystem", "driver"):
                _link(f"{node.sysfs_path}/{ln}", root)
        # bus/class symlinks
        name = d.sysfs_path.rsplit("/", 1)[-1]
        bus = d.bus
        if bus in ("pci", "usb", "sdio"):
            _link(f"/sys/bus/{bus}/devices/{name}", root)
            for node in d.bus_path:
                _link(f"/sys/bus/{bus}/devices/{node.name}", root)
        for phy in d.phys:
            _link(f"/sys/class/ieee80211/{phy}", root)
        for nd in d.netdevs:
            _link(f"/sys/class/net/{nd}", root)
        for node in d.bus_path:
            drv = node.driver
            if drv:
                (root / "sys/bus" / (bus if bus != "other" else "platform") / "drivers" / drv).mkdir(
                    parents=True, exist_ok=True
                )
                _link(f"/sys/bus/{bus}/drivers/{drv}/module", root)
        for p in [d.sysfs_path] + [n.sysfs_path for n in d.bus_path]:
            for sub in ("pci", "usb", "net", "ieee80211", "sdio"):
                did = None
                try:
                    dev_attr = Path(p, "dev").read_text().strip()
                    did = f"c{dev_attr}"
                except OSError:
                    did = f"+{sub}:{p.rsplit('/', 1)[-1]}"
                _copy_file(f"/run/udev/data/{did}", root, scrub)
        if d.module:
            modules.add(d.module)
        modules.update(m.module for m in d.driver_info.candidate_modules)
        modules.update(d.driver_info.module_dependencies)
    for bus in ("pci", "usb", "sdio"):
        (root / f"sys/bus/{bus}/devices").mkdir(parents=True, exist_ok=True)
    (root / "sys/class/ieee80211").mkdir(parents=True, exist_ok=True)
    (root / "sys/class/net").mkdir(parents=True, exist_ok=True)
    for m in sorted(modules):
        mp = f"/sys/module/{m}"
        if os.path.isdir(mp):
            for a in ("version", "srcversion", "taint", "refcnt", "coresize", "initstate"):
                _copy_file(f"{mp}/{a}", root, scrub)
            if os.path.isdir(f"{mp}/parameters"):
                for prm in os.listdir(f"{mp}/parameters"):
                    _copy_file(f"{mp}/parameters/{prm}", root, scrub)
    rel = host.uname()["release"]
    mdir = root / "lib/modules" / rel
    mdir.mkdir(parents=True, exist_ok=True)
    wireless_mods = {m for m in disc.kidx.deps if disc.kidx.is_wireless(m)} | {"cfg80211"}
    keep_mods = wireless_mods | modules
    with open(f"/lib/modules/{rel}/modules.alias") as f:
        lines = [ln for ln in f if ln.split()[-1:] and ln.split()[-1].replace("-", "_") in keep_mods]
    (mdir / "modules.alias").write_text("".join(lines))
    with open(f"/lib/modules/{rel}/modules.dep") as f:
        deps = []
        for ln in f:
            if ":" not in ln:
                continue
            from whd.platform.kmod import mod_name_from_path

            if mod_name_from_path(ln.split(":", 1)[0]) in keep_mods | {
                x for m in keep_mods for x in disc.kidx.closure(m)
            }:
                deps.append(ln)
    (mdir / "modules.dep").write_text("".join(deps))
    vendors = {f"{d.vendor_id:04x}" for d in devices if d.vendor_id is not None}
    for ids_path in ("/usr/share/misc/pci.ids", "/usr/share/misc/usb.ids"):
        if not os.path.exists(ids_path):
            continue
        out_lines: list[str] = []
        keep = False
        with open(ids_path, errors="replace") as f:
            for ln in f:
                if ln.startswith("C "):
                    break
                if ln and not ln.startswith(("\t", "#")) and len(ln) > 4:
                    keep = ln[:4].lower() in vendors
                if keep:
                    out_lines.append(ln)
        dst = root / ids_path.lstrip("/")
        dst.parent.mkdir(parents=True, exist_ok=True)
        dst.write_text("".join(out_lines))
    _copy_file("/etc/os-release", root, scrub) or _copy_file("/usr/lib/os-release", root, scrub)

    nl_json = rec.dump_json()
    nl_json["requests"] = {
        k: [base64.b64encode(scrub.bin(base64.b64decode(p))).decode() for p in v]
        for k, v in rec.requests.items()
    }
    (out / "nl80211.json").write_text(json.dumps(nl_json, indent=1))
    eth: dict[str, Any] = {}
    for d in devices:
        for nd in d.netdevs:
            try:
                eth[nd] = host.ethtool_drvinfo(nd)
            except OSError as e:
                eth[nd] = {"errno": e.errno}
    (out / "ethtool.json").write_text(json.dumps(eth, indent=1))
    if helper_socket is not None:
        hdata = _record_helper(helper_socket, devices, scrub)
        if hdata is not None:
            (out / "helper.json").write_text(json.dumps(hdata, indent=1))
            print(f"recorded {len(hdata['calls'])} helper responses")
        else:
            print("helper not reachable; fixture has no privileged data", file=sys.stderr)
    if helper_socket is not None:
        hdata = _record_helper(helper_socket, devices, scrub)
        if hdata is not None:
            (out / "helper.json").write_text(json.dumps(hdata, indent=1))
            print(f"recorded {len(hdata['calls'])} helper responses")
        else:
            print("helper not reachable; fixture has no privileged data", file=sys.stderr)
    mi = {m: host.modinfo(m) for m in sorted(modules)}
    (out / "modinfo.json").write_text(json.dumps({k: v for k, v in mi.items() if v}, indent=1))
    u = host.uname()
    (out / "fixture.json").write_text(
        json.dumps(
            {
                "kind": "recorded",
                "description": description or f"Recorded from {u['nodename']} ({u['release']})",
                "recorded_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                "uname": {k: u[k] for k in ("release", "machine", "version")} | {"nodename": "recorded-host"},
                "macs_scrubbed": not keep_mac,
                "devices": [d.id for d in devices],
                "tools": {},
            },
            indent=1,
        )
    )
    shutil.rmtree(root / "proc", ignore_errors=True)
    print(f"fixture written to {out} ({len(devices)} device(s))")
    return 0
