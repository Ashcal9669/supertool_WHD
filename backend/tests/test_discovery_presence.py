from conftest import fixture_host
from whd.discovery import Discovery
from whd.platform.host import LiveHost


def live_fixture(name):
    fixture = fixture_host(name)
    host = LiveHost()
    host.root = fixture.root
    host.uname = fixture.uname
    host.modinfo = fixture.modinfo
    host.ethtool_drvinfo = fixture.ethtool_drvinfo
    host._open_nl80211 = fixture._open_nl80211
    return host


def test_live_inventory_and_nl80211_include_present_mt7927():
    host = live_fixture("mt7927-pcie-host")
    devices = Discovery(host).run().devices
    assert len(devices) == 1
    device = devices[0]
    assert device.present and device.vendor_id == 0x14C3 and device.product_id == 0x7927
    assert device.driver and device.phys and device.netdevs
    assert device.wiphys and device.netdev_info[0].wifi
    assert not device.active_test_eligible


def test_down_and_unbound_are_present_but_not_active_test_eligible():
    for name in ("no-nl80211", "pci-no-driver"):
        devices = Discovery(live_fixture(name)).run().devices
        assert devices and devices[0].present
        assert not devices[0].active_test_eligible


def test_mt7922_policy_does_not_require_an_up_interface():
    from whd.model.device import DeviceSummary

    device = DeviceSummary(
        id="d",
        bus="pci",
        sysfs_path="/sys/device",
        title="MT7922",
        vendor_id=0x14C3,
        product_id=0x0616,
        driver="mt7921e_git",
        operstate="down",
    )
    device.refresh_test_eligibility()
    assert device.present and device.active_test_eligible
    device.present = False
    device.refresh_test_eligibility()
    assert not device.active_test_eligible
