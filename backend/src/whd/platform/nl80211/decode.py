"""Decode nl80211 genl payloads into WHD models.

Every attribute ID and capability bit name comes from kconsts (generated from
kernel headers). Attributes WHD does not decode are listed by name in
`undecoded_attrs` so nothing is silently dropped.
"""

from __future__ import annotations

import struct
from collections.abc import Iterable
from dataclasses import dataclass, field

from whd.model.wireless import (
    Band,
    CapabilityFlags,
    Channel,
    EhtCaps,
    HeCaps,
    HtCaps,
    MldCapability,
    MloLink,
    RateInfo,
    RegDomain,
    RegRule,
    ScanBss,
    Station,
    StationLink,
    SurveyEntry,
    VhtCaps,
    WidthSupport,
    WifiInterface,
    Wiphy,
)
from whd.platform.kconsts import ieee80211 as IE
from whd.platform.kconsts import nl80211 as C
from whd.platform.netlink import Attrs, GenlMsg

IE_SRC = "include/linux/ieee80211-{ht,vht,he,eht}.h"


def _rev(enum: str, prefix: str = "") -> dict[int, str]:
    return {v: k.removeprefix(prefix) for k, v in C.ENUMS.get(enum, {}).items() if not k.startswith("__")}


ATTR_NAMES = _rev("nl80211_attrs", "NL80211_ATTR_")
IFTYPE_NAMES = _rev("nl80211_iftype", "NL80211_IFTYPE_")
BAND_NAMES = _rev("nl80211_band", "NL80211_BAND_")
WIDTH_NAMES = _rev("nl80211_chan_width", "NL80211_CHAN_WIDTH_")
EXT_FEATURE_NAMES = _rev("nl80211_ext_feature_index", "NL80211_EXT_FEATURE_")
DFS_REGION_NAMES = _rev("nl80211_dfs_regions", "NL80211_DFS_")
DFS_STATE_NAMES = _rev("nl80211_dfs_state", "NL80211_DFS_")
BSS_STATUS_NAMES = _rev("nl80211_bss_status", "NL80211_BSS_STATUS_")
PS_NAMES = _rev("nl80211_ps_state", "NL80211_PS_")
STA_FLAG_NAMES = _rev("nl80211_sta_flags", "NL80211_STA_FLAG_")
CIPHER_NAMES = {
    v: k.removeprefix("WLAN_CIPHER_SUITE_")
    for k, v in IE.DEFINES.items()
    if k.startswith("WLAN_CIPHER_SUITE_")
}

WIDTH_MHZ = {
    "20_NOHT": 20,
    "20": 20,
    "40": 40,
    "80": 80,
    "80P80": 160,
    "160": 160,
    "320": 320,
    "5": 5,
    "10": 10,
    "1": 1,
    "2": 2,
    "4": 4,
    "8": 8,
    "16": 16,
}


def mac_str(b: bytes | None) -> str | None:
    if b is None or len(b) < 6:
        return None
    return ":".join(f"{x:02x}" for x in b[:6])


def _bitmask_names(value: int, enum: str, prefix: str) -> list[str]:
    out = []
    for k, v in C.ENUMS.get(enum, {}).items():
        if k.startswith("__") or v == 0 or (v & (v - 1)) != 0:
            continue
        if value & v:
            out.append(k.removeprefix(prefix))
    return out


def freq_to_channel(freq_mhz: int, band: str | None = None) -> int | None:
    """Port of ieee80211_freq_khz_to_channel() (net/wireless/util.c)."""
    f = freq_mhz
    if f == 2484:
        return 14
    if f < 2484 and f >= 2407:
        return (f - 2407) // 5
    if 4910 <= f <= 4980:
        return (f - 4000) // 5
    if f == 5935:
        return 2
    if 5950 < f <= 7115 or band == "6GHZ":
        return (f - 5950) // 5
    if f <= 45000:
        return (f - 5000) // 5
    if 58320 <= f <= 70200:
        return (f - 56160) // 2160
    return None


# ---------------------------------------------------------------------------
# IEEE 802.11 capability decoding (names from kernel headers only)
# ---------------------------------------------------------------------------


def _cap_defs(prefix: str) -> list[tuple[str, int, int | None]]:
    """Defines for a capability word: (name, value, mask or None for single-bit)."""
    defs = {k: v for k, v in IE.DEFINES.items() if k.startswith(prefix)}
    masks = {k[: -len("_MASK")]: v for k, v in defs.items() if k.endswith("_MASK")}
    out: list[tuple[str, int, int | None]] = []
    for k, v in defs.items():
        if k.endswith(("_MASK", "_SHIFT", "_MASK_ALL")) or v == 0:
            continue
        if (v & (v - 1)) == 0:
            out.append((k, v, None))
            continue
        best: tuple[str, int] | None = None
        for mk, mv in masks.items():
            if k.startswith(mk + "_") and (best is None or len(mk) > len(best[0])):
                best = (mk, mv)
        if best is not None:
            out.append((k, v, best[1]))
    return out


_CAP_CACHE: dict[str, list[tuple[str, int, int | None]]] = {}


def decode_cap_word(value: int, prefix: str) -> list[str]:
    defs = _CAP_CACHE.setdefault(prefix, _cap_defs(prefix))
    flags = []
    for name, v, mask in defs:
        hit = (value & v) == v if mask is None else (value & mask) == v
        if hit:
            flags.append(name.removeprefix(prefix))
    return flags


def decode_cap_bytes(data: bytes, prefix: str) -> list[str]:
    """For byte-array caps (HE/EHT): defines are named <prefix><n>_..., applied to byte n."""
    flags: list[str] = []
    for i, b in enumerate(data):
        flags += [f"{i}_{f}" for f in decode_cap_word(b, f"{prefix}{i}_")]
    return flags


def _mcs_map_nss(m: int) -> int:
    """Count spatial streams in a VHT/HE 16-bit MCS map (2 bits/NSS, 3 = unsupported)."""
    n = 0
    for i in range(8):
        if ((m >> (2 * i)) & 3) != 3:
            n = i + 1
    return n


def _derive_widths(
    band: str,
    ht: HtCaps | None,
    vht: VhtCaps | None,
    he: list[HeCaps],
    eht: list[EhtCaps],
    ht_raw: int | None,
    vht_raw: int | None,
    he_phy0: int | None,
    eht_phy0: int | None,
) -> list[WidthSupport]:
    w: list[WidthSupport] = [WidthSupport(width="20", rule="band advertises channels")]
    has40 = has80 = has160 = has8080 = has320 = None
    if ht_raw is not None and ht_raw & IE.IEEE80211_HT_CAP_SUP_WIDTH_20_40:
        has40 = "HT cap IEEE80211_HT_CAP_SUP_WIDTH_20_40"
    if he_phy0 is not None:
        if band == "2GHZ" and he_phy0 & IE.IEEE80211_HE_PHY_CAP0_CHANNEL_WIDTH_SET_40MHZ_IN_2G:
            has40 = has40 or "HE PHY cap0 CHANNEL_WIDTH_SET_40MHZ_IN_2G"
        if band != "2GHZ" and he_phy0 & IE.IEEE80211_HE_PHY_CAP0_CHANNEL_WIDTH_SET_40MHZ_80MHZ_IN_5G:
            has40 = has40 or "HE PHY cap0 CHANNEL_WIDTH_SET_40MHZ_80MHZ_IN_5G"
            has80 = "HE PHY cap0 CHANNEL_WIDTH_SET_40MHZ_80MHZ_IN_5G"
        if band != "2GHZ" and he_phy0 & IE.IEEE80211_HE_PHY_CAP0_CHANNEL_WIDTH_SET_160MHZ_IN_5G:
            has160 = "HE PHY cap0 CHANNEL_WIDTH_SET_160MHZ_IN_5G"
        if band != "2GHZ" and he_phy0 & IE.IEEE80211_HE_PHY_CAP0_CHANNEL_WIDTH_SET_80PLUS80_MHZ_IN_5G:
            has8080 = "HE PHY cap0 CHANNEL_WIDTH_SET_80PLUS80_MHZ_IN_5G"
    if vht_raw is not None:
        has80 = has80 or "VHT capability present (80 MHz mandatory for VHT)"
        cw = vht_raw & IE.IEEE80211_VHT_CAP_SUPP_CHAN_WIDTH_MASK
        if cw in (
            IE.IEEE80211_VHT_CAP_SUPP_CHAN_WIDTH_160MHZ,
            IE.IEEE80211_VHT_CAP_SUPP_CHAN_WIDTH_160_80PLUS80MHZ,
        ):
            has160 = has160 or "VHT cap SUPP_CHAN_WIDTH_160MHZ"
        if cw == IE.IEEE80211_VHT_CAP_SUPP_CHAN_WIDTH_160_80PLUS80MHZ:
            has8080 = has8080 or "VHT cap SUPP_CHAN_WIDTH_160_80PLUS80MHZ"
        if cw == 0 and vht_raw & IE.IEEE80211_VHT_CAP_EXT_NSS_BW_MASK:
            has160 = has160 or "VHT EXT_NSS_BW set (160 MHz at reduced NSS)"
    if band == "6GHZ" and eht_phy0 is not None and eht_phy0 & IE.IEEE80211_EHT_PHY_CAP0_320MHZ_IN_6GHZ:
        has320 = "EHT PHY cap0 320MHZ_IN_6GHZ"
    for width, rule in (("40", has40), ("80", has80), ("160", has160), ("80+80", has8080), ("320", has320)):
        if rule:
            w.append(WidthSupport(width=width, rule=rule))
    return w


# ---------------------------------------------------------------------------
# Wiphy
# ---------------------------------------------------------------------------

DECODED_WIPHY_ATTRS = {
    C.NL80211_ATTR_WIPHY,
    C.NL80211_ATTR_WIPHY_NAME,
    C.NL80211_ATTR_WIPHY_BANDS,
    C.NL80211_ATTR_SUPPORTED_IFTYPES,
    C.NL80211_ATTR_SOFTWARE_IFTYPES,
    C.NL80211_ATTR_CIPHER_SUITES,
    C.NL80211_ATTR_EXT_FEATURES,
    C.NL80211_ATTR_FEATURE_FLAGS,
    C.NL80211_ATTR_WIPHY_ANTENNA_AVAIL_TX,
    C.NL80211_ATTR_WIPHY_ANTENNA_AVAIL_RX,
    C.NL80211_ATTR_WIPHY_ANTENNA_TX,
    C.NL80211_ATTR_WIPHY_ANTENNA_RX,
    C.NL80211_ATTR_MAX_NUM_SCAN_SSIDS,
    C.NL80211_ATTR_WIPHY_RETRY_SHORT,
    C.NL80211_ATTR_WIPHY_RETRY_LONG,
    C.NL80211_ATTR_WIPHY_RTS_THRESHOLD,
    C.NL80211_ATTR_WIPHY_FRAG_THRESHOLD,
    C.NL80211_ATTR_IFTYPE_EXT_CAPA,
    C.NL80211_ATTR_WIPHY_SELF_MANAGED_REG,
    C.NL80211_ATTR_GENERATION,
    C.NL80211_ATTR_SPLIT_WIPHY_DUMP,
    C.NL80211_ATTR_MLO_SUPPORT,
    C.NL80211_ATTR_MAC,
    C.NL80211_ATTR_SUPPORTED_COMMANDS,
}
CMD_NAMES = _rev("nl80211_commands", "NL80211_CMD_")


class _BandAcc:
    def __init__(self, idx: int) -> None:
        self.idx = idx
        self.freqs: list[Attrs] = []
        self.rates: list[Attrs] = []
        self.ht_capa: int | None = None
        self.ht_mcs: bytes | None = None
        self.ampdu_factor: int | None = None
        self.ampdu_density: int | None = None
        self.vht_capa: int | None = None
        self.vht_mcs: bytes | None = None
        self.iftype_data: list[Attrs] = []

    def merge(self, a: Attrs) -> None:
        self.freqs += [f for _, f in a.nested_list(C.NL80211_BAND_ATTR_FREQS)]
        self.rates += [r for _, r in a.nested_list(C.NL80211_BAND_ATTR_RATES)]
        self.ht_capa = (
            a.u16(C.NL80211_BAND_ATTR_HT_CAPA) if a.has(C.NL80211_BAND_ATTR_HT_CAPA) else self.ht_capa
        )
        self.ht_mcs = a.get(C.NL80211_BAND_ATTR_HT_MCS_SET) or self.ht_mcs
        if a.has(C.NL80211_BAND_ATTR_HT_AMPDU_FACTOR):
            self.ampdu_factor = a.u8(C.NL80211_BAND_ATTR_HT_AMPDU_FACTOR)
        if a.has(C.NL80211_BAND_ATTR_HT_AMPDU_DENSITY):
            self.ampdu_density = a.u8(C.NL80211_BAND_ATTR_HT_AMPDU_DENSITY)
        if a.has(C.NL80211_BAND_ATTR_VHT_CAPA):
            self.vht_capa = a.u32(C.NL80211_BAND_ATTR_VHT_CAPA)
        self.vht_mcs = a.get(C.NL80211_BAND_ATTR_VHT_MCS_SET) or self.vht_mcs
        self.iftype_data += [d for _, d in a.nested_list(C.NL80211_BAND_ATTR_IFTYPE_DATA)]

    def build(self) -> Band:
        name = BAND_NAMES.get(self.idx, str(self.idx))
        chans = [decode_freq(f, name) for f in self.freqs]
        ht = vht = None
        if self.ht_capa is not None:
            nss = None
            if self.ht_mcs is not None and len(self.ht_mcs) >= 4:
                nss = sum(1 for b in self.ht_mcs[:4] if b)
            ht = HtCaps(
                cap=CapabilityFlags(
                    raw_hex=f"0x{self.ht_capa:04x}",
                    flags=decode_cap_word(self.ht_capa, "IEEE80211_HT_CAP_"),
                    definitions="include/linux/ieee80211-ht.h",
                ),
                ampdu_factor=self.ampdu_factor,
                ampdu_density=self.ampdu_density,
                mcs_set_hex=self.ht_mcs.hex() if self.ht_mcs else None,
                max_rx_nss=nss,
            )
        if self.vht_capa is not None:
            rxn = txn = None
            if self.vht_mcs is not None and len(self.vht_mcs) >= 8:
                rx_map, _, tx_map, _ = struct.unpack_from("=HHHH", self.vht_mcs)
                rxn, txn = _mcs_map_nss(rx_map), _mcs_map_nss(tx_map)
            vht = VhtCaps(
                cap=CapabilityFlags(
                    raw_hex=f"0x{self.vht_capa:08x}",
                    flags=decode_cap_word(self.vht_capa, "IEEE80211_VHT_CAP_"),
                    definitions="include/linux/ieee80211-vht.h",
                ),
                mcs_set_hex=self.vht_mcs.hex() if self.vht_mcs else None,
                max_rx_nss=rxn,
                max_tx_nss=txn,
            )
        he: list[HeCaps] = []
        eht: list[EhtCaps] = []
        he_phy0 = eht_phy0 = None
        for d in self.iftype_data:
            ift_nest = d.nested(C.NL80211_BAND_IFTYPE_ATTR_IFTYPES)
            iftypes = [IFTYPE_NAMES.get(t, str(t)) for t in ift_nest.types()] if ift_nest else []
            hmac, hphy = (
                d.get(C.NL80211_BAND_IFTYPE_ATTR_HE_CAP_MAC),
                d.get(C.NL80211_BAND_IFTYPE_ATTR_HE_CAP_PHY),
            )
            if hmac is not None and hphy is not None:
                mcs = d.get(C.NL80211_BAND_IFTYPE_ATTR_HE_CAP_MCS_SET)
                he6 = d.get(C.NL80211_BAND_IFTYPE_ATTR_HE_6GHZ_CAPA)
                he_phy0 = (he_phy0 or 0) | (hphy[0] if hphy else 0)
                he.append(
                    HeCaps(
                        iftypes=iftypes,
                        mac=CapabilityFlags(
                            raw_hex=hmac.hex(),
                            flags=decode_cap_bytes(hmac, "IEEE80211_HE_MAC_CAP"),
                            definitions="include/linux/ieee80211-he.h",
                        ),
                        phy=CapabilityFlags(
                            raw_hex=hphy.hex(),
                            flags=decode_cap_bytes(hphy, "IEEE80211_HE_PHY_CAP"),
                            definitions="include/linux/ieee80211-he.h",
                        ),
                        mcs_set_hex=mcs.hex() if mcs else None,
                        ppe_hex=(d.get(C.NL80211_BAND_IFTYPE_ATTR_HE_CAP_PPE) or b"").hex() or None,
                        he_6ghz_capa_hex=he6.hex() if he6 else None,
                        max_rx_nss_80=_mcs_map_nss(struct.unpack_from("=H", mcs)[0])
                        if mcs and len(mcs) >= 2
                        else None,
                    )
                )
            emac, ephy = (
                d.get(C.NL80211_BAND_IFTYPE_ATTR_EHT_CAP_MAC),
                d.get(C.NL80211_BAND_IFTYPE_ATTR_EHT_CAP_PHY),
            )
            if emac is not None and ephy is not None:
                emcs = d.get(C.NL80211_BAND_IFTYPE_ATTR_EHT_CAP_MCS_SET)
                eht_phy0 = (eht_phy0 or 0) | (ephy[0] if ephy else 0)
                eht.append(
                    EhtCaps(
                        iftypes=iftypes,
                        mac=CapabilityFlags(
                            raw_hex=emac.hex(),
                            flags=decode_cap_bytes(emac, "IEEE80211_EHT_MAC_CAP"),
                            definitions="include/linux/ieee80211-eht.h",
                        ),
                        phy=CapabilityFlags(
                            raw_hex=ephy.hex(),
                            flags=decode_cap_bytes(ephy, "IEEE80211_EHT_PHY_CAP"),
                            definitions="include/linux/ieee80211-eht.h",
                        ),
                        mcs_set_hex=emcs.hex() if emcs else None,
                        ppe_hex=(d.get(C.NL80211_BAND_IFTYPE_ATTR_EHT_CAP_PPE) or b"").hex() or None,
                    )
                )
        rates = []
        for r in self.rates:
            br = r.u32(C.NL80211_BITRATE_ATTR_RATE)
            if br is not None:
                rates.append(br / 10.0)
        return Band(
            index=self.idx,
            name=name,
            channels=chans,
            bitrates_mbps=rates,
            ht=ht,
            vht=vht,
            he=he,
            eht=eht,
            widths=_derive_widths(name, ht, vht, he, eht, self.ht_capa, self.vht_capa, he_phy0, eht_phy0),
        )


FREQ_FLAG_ATTRS = {
    v: k.removeprefix("NL80211_FREQUENCY_ATTR_")
    for k, v in C.ENUMS.get("nl80211_frequency_attr", {}).items()
    if k.startswith("NL80211_FREQUENCY_ATTR_")
    and (
        k.endswith(("_NO_IR", "DISABLED", "RADAR"))
        or "_NO_" in k
        or k.endswith(("_INDOOR_ONLY", "_IR_CONCURRENT", "_PSD", "_CAN_MONITOR", "_ALLOW_6GHZ_VLP_AP"))
    )
}


def decode_freq(f: Attrs, band: str | None) -> Channel:
    mhz = f.u32(C.NL80211_FREQUENCY_ATTR_FREQ) or 0
    flags = [name for t, name in FREQ_FLAG_ATTRS.items() if f.has(t)]
    pw = f.u32(C.NL80211_FREQUENCY_ATTR_MAX_TX_POWER)
    dfs = f.u32(C.NL80211_FREQUENCY_ATTR_DFS_STATE)
    return Channel(
        freq_mhz=mhz,
        freq_offset_khz=f.u32(C.NL80211_FREQUENCY_ATTR_OFFSET) or 0,
        channel=freq_to_channel(mhz, band),
        disabled=f.has(C.NL80211_FREQUENCY_ATTR_DISABLED),
        no_ir=f.has(C.NL80211_FREQUENCY_ATTR_NO_IR),
        radar=f.has(C.NL80211_FREQUENCY_ATTR_RADAR),
        max_tx_power_dbm=pw / 100.0 if pw is not None else None,
        dfs_state=DFS_STATE_NAMES.get(dfs)
        if dfs is not None and f.has(C.NL80211_FREQUENCY_ATTR_RADAR)
        else None,
        flags=flags,
    )


def _iftype_list(a: Attrs | None) -> list[str]:
    return [IFTYPE_NAMES.get(t, str(t)) for t in a.types()] if a else []


@dataclass
class _WiphyAcc:
    w: Wiphy
    bands: dict[int, _BandAcc] = field(default_factory=dict)
    undecoded: set[str] = field(default_factory=set)


def decode_wiphys(payloads: Iterable[bytes]) -> list[Wiphy]:
    """Merge a split GET_WIPHY dump into one Wiphy per wiphy index."""
    acc: dict[int, _WiphyAcc] = {}
    for p in payloads:
        m = GenlMsg.from_payload(p)
        a = m.attrs
        idx = a.u32(C.NL80211_ATTR_WIPHY)
        if idx is None:
            continue
        st = acc.setdefault(idx, _WiphyAcc(Wiphy(index=idx)))
        w, bands, und = st.w, st.bands, st.undecoded
        if (name := a.str(C.NL80211_ATTR_WIPHY_NAME)) is not None:
            w.name = name
        for bidx, b in a.nested_list(C.NL80211_ATTR_WIPHY_BANDS):
            bands.setdefault(bidx, _BandAcc(bidx)).merge(b)
        if a.has(C.NL80211_ATTR_SUPPORTED_IFTYPES):
            w.supported_iftypes = _iftype_list(a.nested(C.NL80211_ATTR_SUPPORTED_IFTYPES))
        if a.has(C.NL80211_ATTR_SOFTWARE_IFTYPES):
            w.software_iftypes = _iftype_list(a.nested(C.NL80211_ATTR_SOFTWARE_IFTYPES))
        if (cs := a.get(C.NL80211_ATTR_CIPHER_SUITES)) is not None:
            n = len(cs) // 4
            w.cipher_suites = [CIPHER_NAMES.get(s, f"0x{s:08x}") for s in struct.unpack_from(f"={n}I", cs)]
        if (ef := a.get(C.NL80211_ATTR_EXT_FEATURES)) is not None:
            w.ext_features = [
                EXT_FEATURE_NAMES.get(i, f"bit{i}") for i in range(len(ef) * 8) if ef[i // 8] & (1 << (i % 8))
            ]
        if (ff := a.u32(C.NL80211_ATTR_FEATURE_FLAGS)) is not None:
            w.feature_flags = _bitmask_names(ff, "nl80211_feature_flags", "NL80211_FEATURE_")
        for attr, fld in (
            (C.NL80211_ATTR_WIPHY_ANTENNA_AVAIL_TX, "antenna_avail_tx"),
            (C.NL80211_ATTR_WIPHY_ANTENNA_AVAIL_RX, "antenna_avail_rx"),
            (C.NL80211_ATTR_WIPHY_ANTENNA_TX, "antenna_tx"),
            (C.NL80211_ATTR_WIPHY_ANTENNA_RX, "antenna_rx"),
            (C.NL80211_ATTR_WIPHY_RTS_THRESHOLD, "rts_threshold"),
            (C.NL80211_ATTR_WIPHY_FRAG_THRESHOLD, "frag_threshold"),
        ):
            if (v := a.u32(attr)) is not None:
                setattr(w, fld, v)
        for attr, fld in (
            (C.NL80211_ATTR_MAX_NUM_SCAN_SSIDS, "max_scan_ssids"),
            (C.NL80211_ATTR_WIPHY_RETRY_SHORT, "retry_short"),
            (C.NL80211_ATTR_WIPHY_RETRY_LONG, "retry_long"),
        ):
            if (v := a.u8(attr)) is not None:
                setattr(w, fld, v)
        if a.has(C.NL80211_ATTR_WIPHY_SELF_MANAGED_REG):
            w.self_managed_reg = True
        if a.has(C.NL80211_ATTR_MLO_SUPPORT):
            w.mlo_support = True
        if (pm := mac_str(a.get(C.NL80211_ATTR_MAC))) is not None:
            w.perm_addr = pm
        if a.has(C.NL80211_ATTR_SUPPORTED_COMMANDS):
            sc = a.nested(C.NL80211_ATTR_SUPPORTED_COMMANDS)
            if sc is not None:
                w.supported_commands = [
                    CMD_NAMES.get(struct.unpack_from("=I", p)[0], "?") for _, p in sc.items if len(p) >= 4
                ]
        for _, e in a.nested_list(C.NL80211_ATTR_IFTYPE_EXT_CAPA):
            ift = e.u32(C.NL80211_ATTR_IFTYPE)
            eml = e.u16(C.NL80211_ATTR_EML_CAPABILITY)
            mld = e.u16(C.NL80211_ATTR_MLD_CAPA_AND_OPS)
            ext = e.get(C.NL80211_ATTR_EXT_CAPA)
            w.mld.append(
                MldCapability(
                    iftype=IFTYPE_NAMES.get(ift, str(ift)) if ift is not None else "?",
                    eml_capability_hex=f"0x{eml:04x}" if eml is not None else None,
                    mld_capa_and_ops_hex=f"0x{mld:04x}" if mld is not None else None,
                    ext_capa_hex=ext.hex() if ext else None,
                )
            )
        for t in a.types():
            if t not in DECODED_WIPHY_ATTRS:
                und.add(ATTR_NAMES.get(t, str(t)))
    out = []
    for idx in sorted(acc):
        st = acc[idx]
        st.w.bands = [b.build() for _, b in sorted(st.bands.items())]
        st.w.undecoded_attrs = sorted(st.undecoded)
        st.w.meta.sources = ["nl80211 NL80211_CMD_GET_WIPHY (split dump)"]
        out.append(st.w)
    return out


# ---------------------------------------------------------------------------
# Interfaces
# ---------------------------------------------------------------------------


def _width_name(v: int | None) -> str | None:
    return WIDTH_NAMES.get(v) if v is not None else None


def decode_interfaces(payloads: Iterable[bytes]) -> list[WifiInterface]:
    out = []
    for p in payloads:
        a = GenlMsg.from_payload(p).attrs
        ifi = a.u32(C.NL80211_ATTR_IFINDEX)
        if ifi is None:
            continue
        ift = a.u32(C.NL80211_ATTR_IFTYPE)
        freq = a.u32(C.NL80211_ATTR_WIPHY_FREQ)
        tx = a.s32(C.NL80211_ATTR_WIPHY_TX_POWER_LEVEL)
        ssid = a.get(C.NL80211_ATTR_SSID)
        links = []
        for _, la in a.nested_list(C.NL80211_ATTR_MLO_LINKS):
            lf = la.u32(C.NL80211_ATTR_WIPHY_FREQ)
            ltx = la.s32(C.NL80211_ATTR_WIPHY_TX_POWER_LEVEL)
            links.append(
                MloLink(
                    link_id=la.u8(C.NL80211_ATTR_MLO_LINK_ID) or 0,
                    mac=mac_str(la.get(C.NL80211_ATTR_MAC)),
                    freq_mhz=lf,
                    channel=freq_to_channel(lf) if lf else None,
                    width=_width_name(la.u32(C.NL80211_ATTR_CHANNEL_WIDTH)),
                    center_freq1=la.u32(C.NL80211_ATTR_CENTER_FREQ1),
                    center_freq2=la.u32(C.NL80211_ATTR_CENTER_FREQ2),
                    txpower_dbm=ltx / 100.0 if ltx is not None else None,
                )
            )
        out.append(
            WifiInterface(
                ifindex=ifi,
                name=a.str(C.NL80211_ATTR_IFNAME),
                iftype=IFTYPE_NAMES.get(ift) if ift is not None else None,
                wiphy=a.u32(C.NL80211_ATTR_WIPHY),
                wdev=a.u64(C.NL80211_ATTR_WDEV),
                mac=mac_str(a.get(C.NL80211_ATTR_MAC)),
                ssid=ssid.decode(errors="replace") if ssid else None,
                freq_mhz=freq,
                channel=freq_to_channel(freq) if freq else None,
                width=_width_name(a.u32(C.NL80211_ATTR_CHANNEL_WIDTH)),
                center_freq1=a.u32(C.NL80211_ATTR_CENTER_FREQ1),
                center_freq2=a.u32(C.NL80211_ATTR_CENTER_FREQ2),
                txpower_dbm=tx / 100.0 if tx is not None else None,
                use_4addr=bool(a.u8(C.NL80211_ATTR_4ADDR)) if a.has(C.NL80211_ATTR_4ADDR) else None,
                mlo_links=links,
            )
        )
    return out


def decode_power_save(payloads: list[bytes]) -> str | None:
    for p in payloads:
        v = GenlMsg.from_payload(p).attrs.u32(C.NL80211_ATTR_PS_STATE)
        if v is not None:
            return PS_NAMES.get(v, str(v))
    return None


# ---------------------------------------------------------------------------
# Stations
# ---------------------------------------------------------------------------


def decode_rate(a: Attrs | None) -> RateInfo | None:
    if a is None:
        return None
    br32 = a.u32(C.NL80211_RATE_INFO_BITRATE32)
    br16 = a.u16(C.NL80211_RATE_INFO_BITRATE)
    br = br32 if br32 is not None else br16
    r = RateInfo(bitrate_mbps=br / 10.0 if br is not None else None)
    if a.has(C.NL80211_RATE_INFO_EHT_MCS):
        r.mode, r.mcs, r.nss = "EHT", a.u8(C.NL80211_RATE_INFO_EHT_MCS), a.u8(C.NL80211_RATE_INFO_EHT_NSS)
        gi = a.u8(C.NL80211_RATE_INFO_EHT_GI)
        r.gi = {0: "0.8us", 1: "1.6us", 2: "3.2us"}.get(gi) if gi is not None else None
    elif a.has(C.NL80211_RATE_INFO_HE_MCS):
        r.mode, r.mcs, r.nss = "HE", a.u8(C.NL80211_RATE_INFO_HE_MCS), a.u8(C.NL80211_RATE_INFO_HE_NSS)
        gi = a.u8(C.NL80211_RATE_INFO_HE_GI)
        r.gi = {0: "0.8us", 1: "1.6us", 2: "3.2us"}.get(gi) if gi is not None else None
    elif a.has(C.NL80211_RATE_INFO_VHT_MCS):
        r.mode, r.mcs, r.nss = "VHT", a.u8(C.NL80211_RATE_INFO_VHT_MCS), a.u8(C.NL80211_RATE_INFO_VHT_NSS)
    elif a.has(C.NL80211_RATE_INFO_MCS):
        r.mode, r.mcs = "HT", a.u8(C.NL80211_RATE_INFO_MCS)
    for attr, mhz in (
        (C.NL80211_RATE_INFO_40_MHZ_WIDTH, 40),
        (C.NL80211_RATE_INFO_80_MHZ_WIDTH, 80),
        (C.NL80211_RATE_INFO_80P80_MHZ_WIDTH, 160),
        (C.NL80211_RATE_INFO_160_MHZ_WIDTH, 160),
        (C.NL80211_RATE_INFO_320_MHZ_WIDTH, 320),
    ):
        if a.has(attr):
            r.width_mhz = mhz
    if r.width_mhz is None and r.mode != "legacy":
        r.width_mhz = 20
    if a.has(C.NL80211_RATE_INFO_SHORT_GI):
        r.flags.append("SHORT_GI")
        r.gi = r.gi or "short"
    if a.has(C.NL80211_RATE_INFO_80P80_MHZ_WIDTH):
        r.flags.append("80P80")
    return r


def _sta_info(si: Attrs, s: Station | StationLink) -> None:
    def u(attr: int) -> int | None:
        return si.u32(attr)

    if isinstance(s, Station):
        s.inactive_ms = u(C.NL80211_STA_INFO_INACTIVE_TIME)
        s.connected_s = u(C.NL80211_STA_INFO_CONNECTED_TIME)
        s.rx_packets = u(C.NL80211_STA_INFO_RX_PACKETS)
        s.tx_packets = u(C.NL80211_STA_INFO_TX_PACKETS)
        s.rx_drop_misc = si.u64(C.NL80211_STA_INFO_RX_DROP_MISC)
        s.beacon_loss = u(C.NL80211_STA_INFO_BEACON_LOSS)
        s.beacon_rx = si.u64(C.NL80211_STA_INFO_BEACON_RX)
        s.beacon_signal_avg_dbm = si.s8(C.NL80211_STA_INFO_BEACON_SIGNAL_AVG)
        s.signal_avg_dbm = si.s8(C.NL80211_STA_INFO_SIGNAL_AVG)
        s.ack_signal_dbm = si.s8(C.NL80211_STA_INFO_ACK_SIGNAL)
        s.fcs_errors = u(C.NL80211_STA_INFO_FCS_ERROR_COUNT)
        s.rx_duration_us = si.u64(C.NL80211_STA_INFO_RX_DURATION)
        s.tx_duration_us = si.u64(C.NL80211_STA_INFO_TX_DURATION)
        s.assoc_at_boottime_ns = si.u64(C.NL80211_STA_INFO_ASSOC_AT_BOOTTIME)
        cs = si.nested(C.NL80211_STA_INFO_CHAIN_SIGNAL)
        if cs:
            s.chain_signal_dbm = [struct.unpack("=b", p[:1])[0] for _, p in cs.items]
        csa = si.nested(C.NL80211_STA_INFO_CHAIN_SIGNAL_AVG)
        if csa:
            s.chain_signal_avg_dbm = [struct.unpack("=b", p[:1])[0] for _, p in csa.items]
        fl = si.get(C.NL80211_STA_INFO_STA_FLAGS)
        if fl is not None and len(fl) >= 8:
            mask, setv = struct.unpack_from("=II", fl)
            s.flags = {
                name: bool(setv & (1 << bit))
                for bit, name in STA_FLAG_NAMES.items()
                if 0 < bit < 32 and mask & (1 << bit)
            }
    s.rx_bytes = si.u64(C.NL80211_STA_INFO_RX_BYTES64) or u(C.NL80211_STA_INFO_RX_BYTES)
    s.tx_bytes = si.u64(C.NL80211_STA_INFO_TX_BYTES64) or u(C.NL80211_STA_INFO_TX_BYTES)
    s.tx_retries = u(C.NL80211_STA_INFO_TX_RETRIES)
    s.tx_failed = u(C.NL80211_STA_INFO_TX_FAILED)
    s.signal_dbm = si.s8(C.NL80211_STA_INFO_SIGNAL)
    s.tx_rate = decode_rate(si.nested(C.NL80211_STA_INFO_TX_BITRATE))
    s.rx_rate = decode_rate(si.nested(C.NL80211_STA_INFO_RX_BITRATE))


def decode_stations(payloads: Iterable[bytes]) -> list[Station]:
    out = []
    for p in payloads:
        a = GenlMsg.from_payload(p).attrs
        mac = mac_str(a.get(C.NL80211_ATTR_MAC))
        if mac is None:
            continue
        s = Station(mac=mac, ifindex=a.u32(C.NL80211_ATTR_IFINDEX))
        si = a.nested(C.NL80211_ATTR_STA_INFO)
        if si is not None:
            _sta_info(si, s)
        for _, la in a.nested_list(C.NL80211_ATTR_MLO_LINKS):
            link = StationLink(
                link_id=la.u8(C.NL80211_ATTR_MLO_LINK_ID) or 0, mac=mac_str(la.get(C.NL80211_ATTR_MAC))
            )
            lsi = la.nested(C.NL80211_ATTR_STA_INFO)
            if lsi is not None:
                _sta_info(lsi, link)
            s.links.append(link)
        out.append(s)
    return out


# ---------------------------------------------------------------------------
# Regulatory, survey, scan
# ---------------------------------------------------------------------------


def decode_regdomains(payloads: Iterable[bytes]) -> list[RegDomain]:
    out = []
    for p in payloads:
        a = GenlMsg.from_payload(p).attrs
        rules = []
        for _, r in a.nested_list(C.NL80211_ATTR_REG_RULES):
            fl = r.u32(C.NL80211_ATTR_REG_RULE_FLAGS) or 0
            eirp = r.u32(C.NL80211_ATTR_POWER_RULE_MAX_EIRP)
            gain = r.u32(C.NL80211_ATTR_POWER_RULE_MAX_ANT_GAIN)
            rules.append(
                RegRule(
                    start_khz=r.u32(C.NL80211_ATTR_FREQ_RANGE_START) or 0,
                    end_khz=r.u32(C.NL80211_ATTR_FREQ_RANGE_END) or 0,
                    max_bw_khz=r.u32(C.NL80211_ATTR_FREQ_RANGE_MAX_BW),
                    max_eirp_dbm=eirp / 100.0 if eirp is not None else None,
                    max_ant_gain_dbi=gain / 100.0 if gain is not None else None,
                    cac_ms=r.u32(C.NL80211_ATTR_DFS_CAC_TIME),
                    flags=_bitmask_names(fl, "nl80211_reg_rule_flags", "NL80211_RRF_"),
                )
            )
        dfs = a.u8(C.NL80211_ATTR_DFS_REGION)
        out.append(
            RegDomain(
                alpha2=a.str(C.NL80211_ATTR_REG_ALPHA2),
                dfs_region=DFS_REGION_NAMES.get(dfs) if dfs is not None else None,
                wiphy=a.u32(C.NL80211_ATTR_WIPHY),
                self_managed=a.has(C.NL80211_ATTR_WIPHY_SELF_MANAGED_REG),
                rules=rules,
            )
        )
    return out


def decode_survey(payloads: Iterable[bytes]) -> list[SurveyEntry]:
    out = []
    for p in payloads:
        a = GenlMsg.from_payload(p).attrs
        s = a.nested(C.NL80211_ATTR_SURVEY_INFO)
        if s is None:
            continue
        out.append(
            SurveyEntry(
                freq_mhz=s.u32(C.NL80211_SURVEY_INFO_FREQUENCY) or 0,
                noise_dbm=s.s8(C.NL80211_SURVEY_INFO_NOISE),
                in_use=s.has(C.NL80211_SURVEY_INFO_IN_USE),
                time_ms=s.u64(C.NL80211_SURVEY_INFO_TIME),
                busy_ms=s.u64(C.NL80211_SURVEY_INFO_TIME_BUSY),
                ext_busy_ms=s.u64(C.NL80211_SURVEY_INFO_TIME_EXT_BUSY),
                rx_ms=s.u64(C.NL80211_SURVEY_INFO_TIME_RX),
                tx_ms=s.u64(C.NL80211_SURVEY_INFO_TIME_TX),
                scan_ms=s.u64(C.NL80211_SURVEY_INFO_TIME_SCAN),
                bss_rx_ms=s.u64(C.NL80211_SURVEY_INFO_TIME_BSS_RX),
            )
        )
    return out


def _ssid_from_ies(ies: bytes | None) -> str | None:
    if not ies:
        return None
    off = 0
    while off + 2 <= len(ies):
        eid, ln = ies[off], ies[off + 1]
        if eid == 0:
            return ies[off + 2 : off + 2 + ln].decode(errors="replace")
        off += 2 + ln
    return None


def decode_scan(payloads: Iterable[bytes]) -> list[ScanBss]:
    out = []
    for p in payloads:
        a = GenlMsg.from_payload(p).attrs
        b = a.nested(C.NL80211_ATTR_BSS)
        if b is None:
            continue
        bssid = mac_str(b.get(C.NL80211_BSS_BSSID))
        if bssid is None:
            continue
        freq = b.u32(C.NL80211_BSS_FREQUENCY)
        sig = b.s32(C.NL80211_BSS_SIGNAL_MBM)
        st = b.u32(C.NL80211_BSS_STATUS)
        cap = b.u16(C.NL80211_BSS_CAPABILITY)
        out.append(
            ScanBss(
                bssid=bssid,
                freq_mhz=freq,
                channel=freq_to_channel(freq) if freq else None,
                ssid=_ssid_from_ies(
                    b.get(C.NL80211_BSS_INFORMATION_ELEMENTS) or b.get(C.NL80211_BSS_BEACON_IES)
                ),
                signal_dbm=sig / 100.0 if sig is not None else None,
                seen_ms_ago=b.u32(C.NL80211_BSS_SEEN_MS_AGO),
                status=BSS_STATUS_NAMES.get(st) if st is not None else None,
                beacon_interval=b.u16(C.NL80211_BSS_BEACON_INTERVAL),
                capability_hex=f"0x{cap:04x}" if cap is not None else None,
                last_seen_boottime_ns=b.u64(C.NL80211_BSS_LAST_SEEN_BOOTTIME),
                mlo_link_id=b.u8(C.NL80211_BSS_MLO_LINK_ID),
                mld_addr=mac_str(b.get(C.NL80211_BSS_MLD_ADDR)),
            )
        )
    return out
