"""High-level read-only nl80211 queries over an Nl80211Source."""

from __future__ import annotations

from whd.model.wireless import RegDomain, ScanBss, Station, SurveyEntry, WifiInterface, Wiphy
from whd.platform.kconsts import nl80211 as C
from whd.platform.netlink import nla_flag, nla_u32
from whd.platform.nl80211 import decode as D
from whd.platform.nl80211.source import Nl80211Source


class Nl80211:
    def __init__(self, src: Nl80211Source) -> None:
        self.src = src

    def wiphys(self) -> list[Wiphy]:
        return D.decode_wiphys(
            self.src.request(C.NL80211_CMD_GET_WIPHY, nla_flag(C.NL80211_ATTR_SPLIT_WIPHY_DUMP), dump=True)
        )

    def interfaces(self) -> list[WifiInterface]:
        return D.decode_interfaces(self.src.request(C.NL80211_CMD_GET_INTERFACE, dump=True))

    def power_save(self, ifindex: int) -> str | None:
        return D.decode_power_save(
            self.src.request(C.NL80211_CMD_GET_POWER_SAVE, nla_u32(C.NL80211_ATTR_IFINDEX, ifindex))
        )

    def stations(self, ifindex: int) -> list[Station]:
        return D.decode_stations(
            self.src.request(C.NL80211_CMD_GET_STATION, nla_u32(C.NL80211_ATTR_IFINDEX, ifindex), dump=True)
        )

    def regdomains(self) -> list[RegDomain]:
        return D.decode_regdomains(self.src.request(C.NL80211_CMD_GET_REG, dump=True))

    def survey(self, ifindex: int) -> list[SurveyEntry]:
        return D.decode_survey(
            self.src.request(C.NL80211_CMD_GET_SURVEY, nla_u32(C.NL80211_ATTR_IFINDEX, ifindex), dump=True)
        )

    def scan(self, ifindex: int) -> list[ScanBss]:
        return D.decode_scan(
            self.src.request(C.NL80211_CMD_GET_SCAN, nla_u32(C.NL80211_ATTR_IFINDEX, ifindex), dump=True)
        )
