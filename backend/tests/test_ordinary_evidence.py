from conftest import fixture_host
from test_mlo_safety import event
from whd.mlo import report


def test_mt7922_is_ordinary_even_if_shared_driver_reports_mlo_fields():
    dev = fixture_host("mt7927-pcie-host")
    from whd.discovery import Discovery

    device = Discovery(dev).run().devices[0]
    device.vendor_id, device.product_id, device.driver = 0x14C3, 0x0616, "mt7921e_git"
    for phy in device.wiphys:
        phy.mlo_support = True
    e = event(1, kind="packet.stack_rx", link="7", skb="0x123")
    e.device_id = device.id
    result = report.analyze([e], device.id, "fixture", device=device)
    assert result.protocol == "ordinary"
    assert result.current_state is None and not result.snapshot_states
    assert all(not w.state.links for w in result.windows)
    assert all(p.scope.link_id is None and p.scope.link_lifetime is None for p in result.packets)
    assert all("links_activated" not in epoch.missing for epoch in result.epochs)
    assert result.packets[0].delivered is True
    assert result.packets[0].authenticated_delivery is not True


def test_mt7927_recorded_device_keeps_mlo_evidence():
    from whd.discovery import Discovery

    device = Discovery(fixture_host("mt7927-pcie-host")).run().devices[0]
    e = event(1, kind="packet.stack_rx", link="7", skb="0x123")
    e.device_id = device.id
    result = report.analyze([e], device.id, "fixture", device=device)
    assert result.protocol == "mlo"
    assert result.packets[0].scope.link_id == 7


def test_live_identity_guard_rechecks_sysfs_instead_of_cached_interface(tmp_path):
    from whd.mlo.selection import verify_live_adapter
    from whd.platform.host import Host
    from whd.platform.sysfs import SysRoot

    path = tmp_path / "sys/class/net/renamed/device"
    path.mkdir(parents=True)
    (path / "vendor").write_text("0x14c3")
    (path / "device").write_text("0x7927")
    (path / "driver").symlink_to("/sys/bus/pci/drivers/mt7925e_git")
    host = Host(SysRoot(tmp_path))
    import pytest

    with pytest.raises(ValueError, match="MT7922"):
        verify_live_adapter(host, "renamed")
    (path / "device").write_text("0x0616")
    (path / "driver").unlink()
    (path / "driver").symlink_to("/sys/bus/pci/drivers/mt7921e_git")
    assert verify_live_adapter(host, "renamed")["driver"] == "mt7921e_git"


def test_scoped_nl80211_refuses_foreign_ifindex_before_query():
    import pytest

    from whd.platform.nl80211.client import Nl80211

    class Transport:
        def request(self, *args, **kwargs):
            raise AssertionError("protected interface must not reach netlink")

    nl = Nl80211(Transport(), allowed_interface=lambda name: False)
    with pytest.raises(PermissionError):
        nl.stations(12345)


def test_mt7922_poller_does_not_read_or_emit_mlo_link_masks():
    from types import SimpleNamespace

    from whd.drivers.mt76_poller import Mt76Poller
    from whd.model.device import Device

    device = Device(
        id="ordinary",
        bus="pci",
        sysfs_path="/sys/device",
        title="MT7922",
        vendor_id=0x14C3,
        product_id=0x0616,
        driver="mt7921e_git",
        module="mt7921e_git",
        phys=["phy22"],
    )
    ctx = SimpleNamespace(
        bus=SimpleNamespace(source=lambda name: SimpleNamespace()),
        inventory=SimpleNamespace(snapshot=SimpleNamespace(devices=[device])),
    )
    poller = Mt76Poller(ctx)
    reads = []

    def read(phy, path):
        reads.append(path)
        return None

    poller._read = read
    poller.sample_once()
    assert "mt76/mlo_active_links" not in reads


def test_recorded_mt7922_key_callback_is_request_not_firmware_completion():
    import json
    from pathlib import Path

    from whd.mlo.timeline import Collectors, build_epochs
    from whd.model.events import Event

    saved = json.loads((Path(__file__).parent / "fixtures/wifi/mt7922-20261012/association.json").read_text())
    events = [Event.model_validate(e) for e in saved["events"]]
    epochs = build_epochs(events, events[0].device_id, Collectors())
    installs = [stage for epoch in epochs for stage in epoch.stages if stage.stage == "key_install_request"]
    assert installs and all(s.stage_class == "queued_request" for s in installs)
    assert not any(s.stage == "key_install_fw" for epoch in epochs for s in epoch.stages)
    assert not any(s.stage == "port_authorized" for epoch in epochs for s in epoch.stages)
