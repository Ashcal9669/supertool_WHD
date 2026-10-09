from __future__ import annotations

from pydantic import Field

from whd.model.common import Model, Section


class CapabilityFlags(Model):
    raw_hex: str
    flags: list[str] = Field(default_factory=list)
    definitions: str = Field(description="Header the flag names were decoded with")


class Channel(Model):
    freq_mhz: int
    freq_offset_khz: int = 0
    channel: int | None = None
    disabled: bool = False
    no_ir: bool = False
    radar: bool = False
    max_tx_power_dbm: float | None = None
    dfs_state: str | None = None
    flags: list[str] = Field(default_factory=list)


class WidthSupport(Model):
    width: str
    rule: str


class HtCaps(Model):
    cap: CapabilityFlags
    ampdu_factor: int | None = None
    ampdu_density: int | None = None
    mcs_set_hex: str | None = None
    max_rx_nss: int | None = None


class VhtCaps(Model):
    cap: CapabilityFlags
    mcs_set_hex: str | None = None
    max_rx_nss: int | None = None
    max_tx_nss: int | None = None


class HeCaps(Model):
    iftypes: list[str]
    mac: CapabilityFlags
    phy: CapabilityFlags
    mcs_set_hex: str | None = None
    ppe_hex: str | None = None
    he_6ghz_capa_hex: str | None = None
    max_rx_nss_80: int | None = None


class EhtCaps(Model):
    iftypes: list[str]
    mac: CapabilityFlags
    phy: CapabilityFlags
    mcs_set_hex: str | None = None
    ppe_hex: str | None = None


class Band(Model):
    index: int
    name: str
    channels: list[Channel] = Field(default_factory=list)
    bitrates_mbps: list[float] = Field(default_factory=list)
    ht: HtCaps | None = None
    vht: VhtCaps | None = None
    he: list[HeCaps] = Field(default_factory=list)
    eht: list[EhtCaps] = Field(default_factory=list)
    widths: list[WidthSupport] = Field(default_factory=list)


class MldCapability(Model):
    iftype: str
    eml_capability_hex: str | None = None
    mld_capa_and_ops_hex: str | None = None
    ext_capa_hex: str | None = None


class Wiphy(Section):
    index: int
    name: str | None = None
    bands: list[Band] = Field(default_factory=list)
    supported_iftypes: list[str] = Field(default_factory=list)
    software_iftypes: list[str] = Field(default_factory=list)
    cipher_suites: list[str] = Field(default_factory=list)
    ext_features: list[str] = Field(default_factory=list)
    feature_flags: list[str] = Field(default_factory=list)
    antenna_avail_tx: int | None = None
    antenna_avail_rx: int | None = None
    antenna_tx: int | None = None
    antenna_rx: int | None = None
    max_scan_ssids: int | None = None
    retry_short: int | None = None
    retry_long: int | None = None
    rts_threshold: int | None = None
    frag_threshold: int | None = None
    mld: list[MldCapability] = Field(default_factory=list)
    self_managed_reg: bool = False
    mlo_support: bool = False
    perm_addr: str | None = None
    supported_commands: list[str] = Field(default_factory=list)
    undecoded_attrs: list[str] = Field(default_factory=list)


class MloLink(Model):
    link_id: int
    mac: str | None = None
    freq_mhz: int | None = None
    channel: int | None = None
    width: str | None = None
    center_freq1: int | None = None
    center_freq2: int | None = None
    txpower_dbm: float | None = None


class WifiInterface(Model):
    ifindex: int
    name: str | None = None
    iftype: str | None = None
    wiphy: int | None = None
    wdev: int | None = None
    mac: str | None = None
    ssid: str | None = None
    freq_mhz: int | None = None
    channel: int | None = None
    width: str | None = None
    center_freq1: int | None = None
    center_freq2: int | None = None
    txpower_dbm: float | None = None
    use_4addr: bool | None = None
    mlo_links: list[MloLink] = Field(default_factory=list)
    power_save: str | None = None


class RateInfo(Model):
    bitrate_mbps: float | None = None
    mode: str = "legacy"
    mcs: int | None = None
    nss: int | None = None
    width_mhz: int | None = None
    gi: str | None = None
    flags: list[str] = Field(default_factory=list)


class StationLink(Model):
    link_id: int
    mac: str | None = None
    signal_dbm: int | None = None
    tx_rate: RateInfo | None = None
    rx_rate: RateInfo | None = None
    tx_retries: int | None = None
    tx_failed: int | None = None
    rx_bytes: int | None = None
    tx_bytes: int | None = None


class Station(Model):
    mac: str
    ifindex: int | None = None
    inactive_ms: int | None = None
    connected_s: int | None = None
    rx_bytes: int | None = None
    tx_bytes: int | None = None
    rx_packets: int | None = None
    tx_packets: int | None = None
    tx_retries: int | None = None
    tx_failed: int | None = None
    rx_drop_misc: int | None = None
    beacon_loss: int | None = None
    beacon_rx: int | None = None
    beacon_signal_avg_dbm: int | None = None
    signal_dbm: int | None = None
    signal_avg_dbm: int | None = None
    ack_signal_dbm: int | None = None
    chain_signal_dbm: list[int] = Field(default_factory=list)
    chain_signal_avg_dbm: list[int] = Field(default_factory=list)
    fcs_errors: int | None = None
    rx_duration_us: int | None = None
    tx_duration_us: int | None = None
    tx_rate: RateInfo | None = None
    rx_rate: RateInfo | None = None
    flags: dict[str, bool] = Field(default_factory=dict)
    assoc_at_boottime_ns: int | None = None
    links: list[StationLink] = Field(default_factory=list)


class RegRule(Model):
    start_khz: int
    end_khz: int
    max_bw_khz: int | None = None
    max_eirp_dbm: float | None = None
    max_ant_gain_dbi: float | None = None
    cac_ms: int | None = None
    flags: list[str] = Field(default_factory=list)


class RegDomain(Model):
    alpha2: str | None = None
    dfs_region: str | None = None
    wiphy: int | None = None
    self_managed: bool = False
    rules: list[RegRule] = Field(default_factory=list)


class SurveyEntry(Model):
    freq_mhz: int
    noise_dbm: int | None = None
    in_use: bool = False
    time_ms: int | None = None
    busy_ms: int | None = None
    ext_busy_ms: int | None = None
    rx_ms: int | None = None
    tx_ms: int | None = None
    scan_ms: int | None = None
    bss_rx_ms: int | None = None


class ScanBss(Model):
    bssid: str
    freq_mhz: int | None = None
    channel: int | None = None
    ssid: str | None = None
    signal_dbm: float | None = None
    seen_ms_ago: int | None = None
    status: str | None = None
    beacon_interval: int | None = None
    capability_hex: str | None = None
    last_seen_boottime_ns: int | None = None
    mlo_link_id: int | None = None
    mld_addr: str | None = None
