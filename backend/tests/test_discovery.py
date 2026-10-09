from __future__ import annotations

import os
from pathlib import Path

import pytest

from conftest import fixture_host
from whd.discovery import Discovery
from whd.platform.host import FixtureHost


def run(name: str):  # type: ignore[no-untyped-def]
    return Discovery(fixture_host(name)).run()


def test_mt7927_recorded() -> None:
    r = run("mt7927-pcie-host")
    assert not r.issues
    (d,) = r.devices
    assert d.id == "pci:0000:07:00.0:14c3:7927"
    assert d.bus == "pci" and d.demo
    assert d.driver == "mt7925e_git" and d.module == "mt7925e_git"
    assert d.firmware_version == "____000000-20260414134255"
    assert d.phys == ["phy1"] and d.netdevs == ["wlp7s0"]
    assert [r.kind for r in d.detection] == ["bound_phy", "driver_match"]
    assert d.pci and d.pci.link and d.pci.link.current_gen == 3 and d.pci.link.current_width == 1
    assert d.pci.vendor_id == 0x14C3 and d.pci.subsystem_vendor_id == 0x105B
    assert d.pci.bars and d.pci.bars[0].mem64
    assert [n.kind for n in d.bus_path] == ["pci_root", "pci_bridge", "pci_device"]
    # two modules alias this device: in-tree mt7925e and the DKMS mt7925e_git build
    mods = {m.module: m for m in d.driver_info.candidate_modules}
    assert mods["mt7925e_git"].loaded and not mods["mt7925e"].loaded
    assert "cfg80211" in d.driver_info.module_dependencies
    assert d.wiphys and d.wiphys[0].name == "phy1"
    assert d.netdev_info[0].wifi and d.netdev_info[0].wifi.iftype == "STATION"
    assert d.power.pci_power_state == "D0"
    # recorded privileged-helper data: ASPM decoded from config space (all disabled on this host)
    assert d.power.aspm_meta.availability == "ok"
    assert d.power.aspm["l1_enabled"] is False and d.power.aspm["upstream_port"] == "0000:00:02.2"
    assert d.pci_config is not None and d.pci_config.length == 4096
    assert d.firmware.meta.availability == "ok"


def test_without_helper_aspm_requires_privilege(copied_fixture: Path) -> None:
    (copied_fixture / "helper.json").unlink()
    (d,) = Discovery(FixtureHost(copied_fixture)).run().devices
    assert d.power.aspm_meta.availability == "requires_privilege" and d.pci_config is None


def test_identity_stable_across_rename() -> None:
    a = run("mt7927-pcie-host").devices[0]
    b = run("renamed-netdev").devices[0]
    assert a.id == b.id
    assert b.netdevs == ["wlx_renamed"] and b.phys == ["phy3"]
    assert b.wiphys and b.wiphys[0].name == "phy3"
    assert b.netdev_info[0].wifi and b.netdev_info[0].wifi.name == "wlx_renamed"


def test_unbound_device_found_by_modalias() -> None:
    (d,) = run("pci-no-driver").devices
    assert [r.kind for r in d.detection] == ["driver_match"]
    assert d.driver is None and not d.driver_info.bound
    assert {m.module for m in d.driver_info.candidate_modules} == {"mt7925e", "mt7925e_git"}
    assert not any(m.loaded for m in d.driver_info.candidate_modules)
    assert d.firmware.version is None and d.firmware.meta.availability == "unavailable"


def test_no_nl80211_degrades_gracefully() -> None:
    r = run("no-nl80211")
    assert any(i.source == "nl80211" for i in r.issues)
    (d,) = r.devices
    assert d.wiphys == [] and d.phys == ["phy1"]  # sysfs still maps the phy
    assert d.netdev_info[0].wifi is None


def test_empty_host() -> None:
    r = run("empty")
    assert r.devices == [] and not r.issues


def test_usb_synthetic() -> None:
    (d,) = run("mt7921u-usb").devices
    assert d.id == "usb:000000000:0e8d:7961"
    assert d.bus == "usb" and d.driver == "mt7921u"
    assert d.usb and d.usb.usb_version == "3.20" and d.usb.speed_mbps == 5000
    (iface,) = d.usb.interfaces
    assert iface.driver == "mt7921u" and iface.wireless_candidate
    assert len(iface.endpoints) == 8 and {e.type for e in iface.endpoints} == {"bulk"}
    assert {e.direction for e in iface.endpoints} == {"in", "out"}
    types = [n.type_name for n in d.usb.descriptors]
    assert types[:3] == ["DEVICE", "CONFIG", "INTERFACE"] and "SS_ENDPOINT_COMP" in types
    assert [n.kind for n in d.bus_path] == ["pci_root", "pci_device", "usb_host", "usb_device"]
    assert d.usb.port_state.get("connect_type") == "hotplug"
    assert d.power.autosuspend_delay_ms == 2000
    assert d.netdev_info[0].wifi and d.netdev_info[0].wifi.freq_mhz == 5180


@pytest.mark.skipif(os.geteuid() == 0, reason="root ignores file permissions")
def test_permission_denied_is_reported(copied_fixture: Path) -> None:
    dev = copied_fixture / "root/sys/devices/pci0000:00/0000:00:02.2/0000:07:00.0"
    (dev / "aer_dev_correctable").chmod(0)
    (dev / "power" / "runtime_status").chmod(0)
    (d,) = Discovery(FixtureHost(copied_fixture)).run().devices
    kinds = {(i.source.rsplit("/", 1)[-1], i.kind) for i in d.pci.meta.issues}  # type: ignore[union-attr]
    assert ("aer_dev_correctable", "requires_privilege") in kinds
    assert d.pci.meta.availability == "partial"  # type: ignore[union-attr]
    assert d.power.runtime_status is None and d.power.meta.availability == "partial"


def test_discovery_never_opens_for_write(monkeypatch: pytest.MonkeyPatch) -> None:
    real_open = os.open
    write_flags = os.O_WRONLY | os.O_RDWR | os.O_APPEND | os.O_CREAT | os.O_TRUNC

    def guarded(path, flags, *a, **kw):  # type: ignore[no-untyped-def]
        if flags & write_flags:
            raise AssertionError(f"write open attempted: {path}")
        return real_open(path, flags, *a, **kw)

    monkeypatch.setattr(os, "open", guarded)
    import builtins

    real_bopen = builtins.open

    def guarded_b(file, mode="r", *a, **kw):  # type: ignore[no-untyped-def]
        if any(c in mode for c in "wax+"):
            raise AssertionError(f"write open attempted: {file}")
        return real_bopen(file, mode, *a, **kw)

    monkeypatch.setattr(builtins, "open", guarded_b)
    for s in ("mt7927-pcie-host", "mt7921u-usb", "pci-no-driver"):
        assert run(s).devices


def test_denied_attributes_never_opened() -> None:
    from whd.platform.sysfs import SysfsError, SysRoot

    r = SysRoot("/")
    for name in ("reset", "remove", "rescan", "rom", "resource0", "driver_override"):
        with pytest.raises(SysfsError):
            r.read_bytes(f"/sys/bus/pci/devices/0000:00:00.0/{name}")
