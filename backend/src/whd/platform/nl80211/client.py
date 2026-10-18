"""High-level read-only nl80211 queries over an Nl80211Source."""

from __future__ import annotations

import socket
from collections.abc import Callable

from whd.model.wireless import RegDomain, ScanBss, Station, SurveyEntry, WifiInterface, Wiphy
from whd.platform.kconsts import nl80211 as C
from whd.platform.netlink import nla_flag, nla_u32
from whd.platform.nl80211 import decode as D
from whd.platform.nl80211.source import Nl80211Source


class Nl80211:
    def __init__(
        self,
        src: Nl80211Source,
        *,
        allowed_interface: Callable[[str], bool] | None = None,
        allowed_phy: Callable[[str], bool] | None = None,
    ) -> None:
        self.src = src
        self.allowed_interface = allowed_interface
        self.allowed_phy = allowed_phy

    def _check_interface(self, ifindex: int) -> None:
        if self.allowed_interface is not None:
            try:
                name = socket.if_indextoname(ifindex)
            except OSError as exc:
                raise PermissionError("interface identity unavailable; live query refused") from exc
            if not self.allowed_interface(name):
                raise PermissionError("interface excluded by MT7922-only live testing policy")

    def wiphys(self) -> list[Wiphy]:
        rows = D.decode_wiphys(
            self.src.request(C.NL80211_CMD_GET_WIPHY, nla_flag(C.NL80211_ATTR_SPLIT_WIPHY_DUMP), dump=True)
        )
        return [
            w for w in rows if self.allowed_phy is None or (w.name is not None and self.allowed_phy(w.name))
        ]

    def interfaces(self) -> list[WifiInterface]:
        rows = D.decode_interfaces(self.src.request(C.NL80211_CMD_GET_INTERFACE, dump=True))
        return [
            i
            for i in rows
            if self.allowed_interface is None or (i.name is not None and self.allowed_interface(i.name))
        ]

    def power_save(self, ifindex: int) -> str | None:
        self._check_interface(ifindex)
        return D.decode_power_save(
            self.src.request(C.NL80211_CMD_GET_POWER_SAVE, nla_u32(C.NL80211_ATTR_IFINDEX, ifindex))
        )

    def stations(self, ifindex: int) -> list[Station]:
        self._check_interface(ifindex)
        return D.decode_stations(
            self.src.request(C.NL80211_CMD_GET_STATION, nla_u32(C.NL80211_ATTR_IFINDEX, ifindex), dump=True)
        )

    def regdomains(self) -> list[RegDomain]:
        return D.decode_regdomains(self.src.request(C.NL80211_CMD_GET_REG, dump=True))

    def survey(self, ifindex: int) -> list[SurveyEntry]:
        self._check_interface(ifindex)
        return D.decode_survey(
            self.src.request(C.NL80211_CMD_GET_SURVEY, nla_u32(C.NL80211_ATTR_IFINDEX, ifindex), dump=True)
        )

    def scan(self, ifindex: int) -> list[ScanBss]:
        self._check_interface(ifindex)
        return D.decode_scan(
            self.src.request(C.NL80211_CMD_GET_SCAN, nla_u32(C.NL80211_ATTR_IFINDEX, ifindex), dump=True)
        )
