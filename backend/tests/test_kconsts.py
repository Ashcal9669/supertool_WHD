"""Generated constants must match the kernel UAPI values WHD depends on."""

from whd.platform.kconsts import genetlink as G
from whd.platform.kconsts import ieee80211 as IE
from whd.platform.kconsts import nl80211 as C
from whd.platform.kconsts import pci_regs as P


def test_nl80211_core_values() -> None:
    assert C.NL80211_CMD_GET_WIPHY == 1
    assert C.NL80211_CMD_GET_STATION == 17
    assert C.NL80211_ATTR_IFINDEX == 3
    assert C.NL80211_ATTR_WIPHY_BANDS == 22
    assert C.NL80211_ATTR_MLO_LINKS == 312
    assert C.NL80211_GENL_NAME == "nl80211"


def test_genetlink_and_pci() -> None:
    assert G.GENL_ID_CTRL == 0x10
    assert G.CTRL_CMD_GETFAMILY == 3
    assert P.PCI_CAP_ID_EXP == 0x10
    assert P.PCI_EXT_CAP_ID_ERR == 1
    assert P.PCI_EXP_LNKSTA == 0x12


def test_ieee80211_caps() -> None:
    assert IE.IEEE80211_HT_CAP_SUP_WIDTH_20_40 == 0x0002
    assert IE.IEEE80211_EHT_PHY_CAP0_320MHZ_IN_6GHZ == 0x02
    assert IE.WLAN_CIPHER_SUITE_CCMP == 0x000FAC04
