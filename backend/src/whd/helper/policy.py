"""debugfs read policy enforced by whd-helper (allowlist, never a denylist).

Each entry classifies what *reading* a debugfs file does, determined by reviewing
the read handler in mt76 sources (read-only review; WHD never modifies them):

  passive       - returns driver memory only, no locks that contend with the data path,
                  no device wake (e.g. seq_file over queue structs, debugfs_create_u32 values)
  wakes_device  - takes the mt76 mutex and wakes the chip from runtime power save
                  (mt792x_mutex_acquire -> mt76_connac_pm_wake) before reading driver memory
  mmio          - performs MMIO register reads on the device
  mcu           - sends a firmware (MCU) query command
  never         - write-only/action nodes, or reads that remap/dump firmware memory;
                  the helper refuses these unconditionally

Paths are relative to /sys/kernel/debug/ieee80211/<phy>/. Entries not listed here are
listed by `debugfs_list` but cannot be read. `mmio` and `mcu` reads require the caller to
pass `allow=["mmio"|"mcu"]`, which the WHD UI only does after an explicit user confirmation.

Sources reviewed (2026-10-09):
  ~/mt76/debugfs.c, ~/mt76/mt792x_debugfs.c, ~/mt76/mt7925/debugfs.c (upstream-equivalent)
  ~/.config/superpowers/worktrees/mt76/mt7927-t2lm-emlsr-prototype/mt7925/debugfs.c (custom MLO nodes)
A driver build with different handlers can change these semantics; the classification is
recorded alongside every read so the UI shows what was assumed.
"""

from __future__ import annotations

import fnmatch
from typing import Literal

Tier = Literal["passive", "wakes_device", "mmio", "mcu", "never"]

# (glob relative to ieee80211/<phy>/, tier, description)
MT76_POLICY: list[tuple[str, Tier, str]] = [
    # mt76 core (debugfs.c)
    ("mt76/rx-queues", "passive", "RX queue ring state (mt76_rx_queues_read: memory only)"),
    ("mt76/napi_threaded", "passive", "NAPI threaded flag"),
    ("mt76/led_pin", "passive", "LED pin (u8 memory)"),
    ("mt76/led_active_low", "passive", "LED polarity (bool memory)"),
    ("mt76/regidx", "passive", "register index used by regval (u32 memory)"),
    ("mt76/regval", "mmio", "MMIO read of the register at regidx"),
    ("mt76/eeprom", "passive", "EEPROM blob cached in memory"),
    ("mt76/otp", "passive", "OTP blob cached in memory"),
    # mt792x/mt7925
    ("mt76/xmit-queues", "passive", "TX/MCU queue ring state (mt792x_queues_read: memory only)"),
    ("mt76/runtime_pm_stats", "passive", "runtime PM counters (mt792x_pm_stats: memory only)"),
    ("mt76/tx_stats", "wakes_device", "TX MSDU/aggregation counters (takes mutex, wakes chip)"),
    ("mt76/acq", "mmio", "per-AC PLE queue occupancy (mt76_rr of MT_PLE_AC_QEMPTY)"),
    ("mt76/txpower_sku", "mcu", "TX power tables (mt7925_get_txpwr_info sends MCU query)"),
    ("mt76/fw_debug", "passive", "firmware debug level setting (memory)"),
    ("mt76/runtime-pm", "passive", "runtime PM enable flag (memory)"),
    ("mt76/deep-sleep", "passive", "deep sleep flag (memory)"),
    ("mt76/idle-timeout", "passive", "PM idle timeout (memory)"),
    ("mt76/chip_reset", "never", "write-only action: triggers chip reset"),
    # custom MT7927 MLO instrumentation (present only on patched builds)
    ("mt76/link_stats", "wakes_device", "per-WCID/link TX/RX counters and rate (takes mutex)"),
    ("mt76/mlo_wcid_dump", "wakes_device", "WCID table with link/aggregation state (takes mutex)"),
    ("mt76/mlo_str_cap", "passive", "STR capability per active interface (iterator over memory)"),
    ("mt76/mlo_active_links", "passive", "active link mask (getter returns memory value)"),
    ("mt76/mlo_force_tx_link", "passive", "forced TX link setting (getter returns memory value)"),
    ("mt76/mlo_link2_rssi_override", "passive", "link-2 RSSI override setting (memory)"),
    ("mt76/mlo_diag_trace", "passive", "MLO diagnostic trace flag (bool memory)"),
    ("mt76/mlo_bssadd_skip", "passive", "u8 memory"),
    ("mt76/mlo_bssadd_delay_ms", "passive", "u32 memory"),
    ("mt76/mlo_eml_cap_mask", "never", "write-only action node"),
    ("mt76/mlo_auto_steering", "never", "write-only action node"),
    ("mt76/mlo_ptk_probe", "never", "write-only action node"),
    ("mt76/fw_region*", "never", "dumps firmware RAM through register remap windows"),
    ("mt76/l2_trace", "never", "test-only L2 remap transaction tracer (performs remapped accesses)"),
]

# mac80211 / cfg80211 generic debugfs (net/mac80211/debugfs*.c): memory-only reads.
MAC80211_POLICY: list[tuple[str, Tier, str]] = [
    ("rts_threshold", "passive", "wiphy RTS threshold"),
    ("fragmentation_threshold", "passive", "wiphy fragmentation threshold"),
    ("short_retry_limit", "passive", "retry limit"),
    ("long_retry_limit", "passive", "retry limit"),
    ("ht40allow_map", "passive", "HT40 allowed channel map"),
    ("aqm", "passive", "mac80211 AQM/TXQ statistics"),
    ("airtime_flags", "passive", "airtime fairness flags"),
    ("hw_conf", "passive", "hardware configuration flags"),
    ("queues", "passive", "mac80211 queue stop reasons"),
    ("misc", "passive", "pending packet counts"),
    ("power", "passive", "power save state"),
    ("statistics/*", "passive", "mac80211 dot11 counters"),
]
# Per-vif / per-link / per-station mac80211 files whose read handlers only format memory.
# Deliberately excluded: "tsf" (calls drv_get_tsf -> driver/hardware access), write-only test nodes.
_VIF_FILES = (
    "flags",
    "state",
    "txpower",
    "user_power_level",
    "ap_power_level",
    "hw_queues",
    "bssid",
    "aid",
    "beacon_timeout",
    "smps",
    "uapsd_queues",
    "uapsd_max_sp_len",
    "valid_links",
    "active_links",
    "dormant_links",
    "aqm",
    "addr",
    "num_buffered_multicast",
    "dtim_count",
)
_STA_FILES = (
    "flags",
    "num_ps_buf_frames",
    "last_seq_ctrl",
    "agg_status",
    "ht_capa",
    "vht_capa",
    "he_capa",
    "eht_capa",
    "rx_duplicates",
    "aqm",
    "airtime",
    "aql",
    "link_sta_info",
)
MAC80211_POLICY += [(f"netdev:*/{f}", "passive", "mac80211 per-vif state (memory)") for f in _VIF_FILES]
MAC80211_POLICY += [
    (f"netdev:*/link-*/{f}", "passive", "mac80211 per-link vif state (memory)") for f in _VIF_FILES
]
MAC80211_POLICY += [
    (f"netdev:*/stations/*/{f}", "passive", "mac80211 per-station state (memory)") for f in _STA_FILES
]
MAC80211_POLICY += [
    (f"netdev:*/stations/*/link-*/{f}", "passive", "mac80211 per-link station state (memory)")
    for f in _STA_FILES
]

MAX_READ = 256 * 1024


def classify(relpath: str) -> tuple[Tier | None, str]:
    for pat, tier, desc in MT76_POLICY + MAC80211_POLICY:
        if fnmatch.fnmatchcase(relpath, pat):
            return tier, desc
    return None, "not on the WHD debugfs allowlist"
