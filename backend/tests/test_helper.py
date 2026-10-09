"""whd-helper: argument validation, debugfs policy, peer credentials, path containment, transport."""

from __future__ import annotations

import asyncio
import os
from pathlib import Path

import pytest

from whd.collectors.pciconfig import decode_config
from whd.helper import policy
from whd.helper.client import HelperClient, RecordedHelper, config_bytes
from whd.helper.protocol import HelperError
from whd.helper.server import Helper, Roots, serve

SYSROOTS = Path(__file__).parent / "fixtures" / "sysroots"


@pytest.fixture
def roots(tmp_path: Path) -> Roots:
    r = Roots(sys=tmp_path / "sys", tracefs=tmp_path / "tracing", debugfs=tmp_path / "debug")
    dev = r.sys / "devices/pci0000:00/0000:07:00.0"
    dev.mkdir(parents=True)
    rec = RecordedHelper(SYSROOTS / "mt7927-pcie-host" / "helper.json")
    (dev / "config").write_bytes(config_bytes(rec.call("pci_config_read", bdf="0000:07:00.0")))
    (r.sys / "bus/pci/devices").mkdir(parents=True)
    os.symlink("../../../devices/pci0000:00/0000:07:00.0", r.sys / "bus/pci/devices/0000:07:00.0")
    phy = r.debugfs / "ieee80211/phy0/mt76"
    phy.mkdir(parents=True)
    for name, body in {
        "xmit-queues": "WFDMA0: queued=0\n",
        "chip_reset": "",
        "regval": "0x1\n",
        "fw_region00": "secret",
        "unknown_custom": "x",
    }.items():
        (phy / name).write_text(body)
    (r.debugfs / "ieee80211/phy0/../../../outside").write_text("outside")
    (r.tracefs / "events/mt76/mac_txdone").mkdir(parents=True)
    (r.tracefs / "events/mt76/mac_txdone/format").write_text("name: mac_txdone\n")
    (r.tracefs / "instances").mkdir()
    return r


def helper(roots: Roots) -> Helper:
    return Helper(roots, {os.getuid()}, set())


def test_ping(roots: Roots) -> None:
    p = helper(roots).ping()
    assert p["protocol"] == 1 and p["debugfs"] and "pci_config_read" in p["verbs"]


def test_pci_config_read_and_decode(roots: Roots) -> None:
    h = helper(roots)
    r = h.pci_config_read(bdf="0000:07:00.0")
    cfg = decode_config(config_bytes(r))
    assert cfg.length == 4096
    names = [c.name for c in cfg.capabilities]
    assert names[:3] == ["EXP", "MSI", "PM"] and "L1SS" in names and "ERR" in names
    assert cfg.link["sta_speed"] == "8.0 GT/s" and cfg.link["sta_width"] == 1
    assert cfg.aspm["l1_supported"] is True and cfg.aspm["l1_enabled"] is False
    assert cfg.msi["enabled"] is True and cfg.pm["power_state"] == "D0"
    for bad in ("../../etc", "0000:07:00.0/../x", "07:00.0", "", 5):
        with pytest.raises(HelperError):
            h.pci_config_read(bdf=bad)  # type: ignore[arg-type]


def test_debugfs_policy(roots: Roots) -> None:
    h = helper(roots)
    lst = {e["path"]: e["tier"] for e in h.debugfs_list(phy="phy0")["entries"]}
    assert lst["mt76/xmit-queues"] == "passive"
    assert lst["mt76/chip_reset"] == "never" and lst["mt76/unknown_custom"] is None
    assert "WFDMA0" in h.debugfs_read(phy="phy0", path="mt76/xmit-queues")["text"]
    for path, code in (
        ("mt76/chip_reset", "policy"),
        ("mt76/fw_region00", "policy"),
        ("mt76/unknown_custom", "policy"),
        ("mt76/regval", "confirm"),
        ("../../../outside", "args"),
        ("/etc/passwd", "args"),
    ):
        with pytest.raises(HelperError) as ei:
            h.debugfs_read(phy="phy0", path=path)
        assert ei.value.code == code, path
    # explicit allow for the mmio tier (UI requires user confirmation before sending this)
    assert h.debugfs_read(phy="phy0", path="mt76/regval", allow=["mmio"])["tier"] == "mmio"
    with pytest.raises(HelperError):
        h.debugfs_read(phy="../phy0", path="mt76/xmit-queues")


def test_policy_never_tier_cannot_be_allowed(roots: Roots) -> None:
    with pytest.raises(HelperError):
        helper(roots).debugfs_read(phy="phy0", path="mt76/chip_reset", allow=["mmio", "mcu", "never"])
    assert policy.classify("netdev:wlan0/tsf")[0] is None  # drv_get_tsf touches hardware: not allowlisted


def test_trace_setup_validation(roots: Roots) -> None:
    h = helper(roots)
    for bad in ([], ["mt76"], ["../x/y"], ["nosuch/*"], ["mt76/nosuch"], ["a/b/c"]):
        with pytest.raises(HelperError):
            h._trace_setup(bad, 1024)


async def test_transport_and_peer_check(roots: Roots, tmp_path: Path) -> None:
    sock = tmp_path / "h.sock"
    ok = Helper(roots, {os.getuid()}, set())
    task = asyncio.create_task(serve(ok, sock, None))
    for _ in range(50):
        if sock.exists():
            break
        await asyncio.sleep(0.02)
    c = HelperClient(sock)
    assert (await asyncio.to_thread(c.call, "ping"))["protocol"] == 1
    with pytest.raises(HelperError) as ei:
        await asyncio.to_thread(c.call, "write_config", bdf="0000:07:00.0")
    assert ei.value.code == "verb"
    with pytest.raises(HelperError):
        await asyncio.to_thread(c.call, "pci_config_read", bdf="0000:07:00.0", extra=1)
    task.cancel()
    await asyncio.gather(task, return_exceptions=True)
    # a helper that does not allow our uid rejects the connection
    sock2 = tmp_path / "h2.sock"
    deny = Helper(roots, {os.getuid() + 12345}, set())
    task2 = asyncio.create_task(serve(deny, sock2, None))
    for _ in range(50):
        if sock2.exists():
            break
        await asyncio.sleep(0.02)
    with pytest.raises(HelperError) as ei:
        await asyncio.to_thread(HelperClient(sock2).call, "ping")
    assert ei.value.code == "denied"
    task2.cancel()
    await asyncio.gather(task2, return_exceptions=True)
    assert (sock.stat().st_mode & 0o777) == 0o660 if sock.exists() else True
