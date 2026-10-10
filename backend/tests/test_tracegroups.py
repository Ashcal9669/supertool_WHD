"""Trace groups are derived from the system's own driver modules, not from a fixed list of chips."""

from __future__ import annotations

from types import SimpleNamespace
from typing import Any

from whd.drivers.tracegroups import driver_trace_groups

AVAILABLE = [
    "mac80211", "cfg80211", "pci", "xhci-hcd", "usbcore", "sched", "irq",
    "mt76", "mt7915", "iwlwifi", "iwlwifi_io", "ath12k", "rtw89", "brcmfmac", "mt7925", "ext4",
]  # fmt: skip


def dev(module: str, *deps: str) -> Any:
    return SimpleNamespace(
        module=module,
        driver=module,
        driver_info=SimpleNamespace(module=module, module_dependencies=list(deps)),
    )


def test_groups_follow_the_installed_driver() -> None:
    mt = driver_trace_groups([dev("mt7915e", "mt76_connac_lib", "mt76", "mac80211", "cfg80211")], AVAILABLE)
    assert mt[:2] == ["mt76", "mt7915"] and "mt7925" not in mt and "iwlwifi" not in mt
    assert mt[2:] == ["mac80211", "cfg80211", "pci", "xhci-hcd", "usbcore"]
    iwl = driver_trace_groups([dev("iwlmvm", "iwlwifi", "mac80211")], AVAILABLE)
    assert "iwlwifi" in iwl and "iwlwifi_io" in iwl and "mt76" not in iwl
    assert "rtw89" in driver_trace_groups([dev("rtw89pci", "rtw89_core")], AVAILABLE)


def test_no_driver_means_core_groups_only_and_unrelated_groups_are_never_picked() -> None:
    out = driver_trace_groups([dev("")], AVAILABLE)
    assert out == ["mac80211", "cfg80211", "pci", "xhci-hcd", "usbcore"]
    assert not {"sched", "irq", "ext4"} & set(driver_trace_groups([dev("mt7915e", "mt76")], AVAILABLE))
