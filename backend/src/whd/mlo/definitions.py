"""Decode tables generated from a driver source tree (tools/gen_mcu_tables.py) and the counter-semantics notes."""

from __future__ import annotations

import json
from functools import lru_cache
from pathlib import Path
from typing import Any

DEF_DIR = Path(__file__).parent / "definitions"


@lru_cache(maxsize=1)
def mcu_ids() -> dict[str, Any]:
    p = DEF_DIR / "mcu_ids.json"
    return (
        json.loads(p.read_text()) if p.exists() else {"source": None, "uni_cmd_flag": 0x20000, "tables": {}}
    )


def _rev(table: str) -> dict[int, str]:
    return {v: k for k, v in mcu_ids().get("tables", {}).get(table, {}).items()}


def cmd_name(cmd: int | None) -> str | None:
    """Name of a unified MCU command word as the driver prints it (e.g. 0x20002), or None when unknown."""
    if cmd is None:
        return None
    flag = int(mcu_ids().get("uni_cmd_flag", 0x20000))
    if cmd & flag:
        n = _rev("uni_cmd").get(cmd & 0xFFFF)
        return n.removeprefix("MCU_UNI_CMD_") if n else None
    return None


def tag_name(table: str, tag: int | None) -> str | None:
    return _rev(table).get(tag) if tag is not None else None


# Where per-link counters are incremented, relative to the security checks. Read from the source of the build that
# prints these tags; the file/function are cited, line numbers are not (they move). Used to label counters in the UI.
COUNTER_SEMANTICS: list[dict[str, str]] = [
    {
        "counter": "link_stats rx_pkts / rx_bytes (debugfs)",
        "incremented_in": "mt7925/mac.c: mt7925_mac_fill_rx, 'TEST-ONLY: per-link RX accounting'",
        "after": "the RX descriptor was parsed and the station's wcid was (possibly) remapped to another link by "
        "mt7925_mlo_rx_band_select()",
        "before": "decryption/integrity (ICV, MIC), PN replay checking and delivery to mac80211 and the network stack",
        "means": "frames the hardware handed to the driver and the driver attributed to this link (post-remap); NOT "
        "authenticated or delivered frames",
    },
    {
        "counter": "xmit-queues / rx-queues (debugfs)",
        "incremented_in": "mt76 DMA ring bookkeeping",
        "after": "descriptor placed on / taken from a hardware ring",
        "before": "air transmission, ACK, or any delivery",
        "means": "ring occupancy and index movement; a queued descriptor is not a transmitted frame",
    },
    {
        "counter": "MLO_RX_PN_OK / MLO_RX_DECRYPT_TRACE (driver tags)",
        "incremented_in": "mt7925/mac.c: RX descriptor/decryption observations; mac80211.c: mt76_check_ccmp_pn replay observation",
        "after": "decryption flags and the PN check were evaluated for the frame",
        "before": "the stack's own replay/forwarding decisions",
        "means": "driver security observations; missing checks and adjacent-log joins remain unproven, and network-stack delivery is separate",
    },
    {
        "counter": "mlo_valid_rx_packets (driver readiness counter)",
        "incremented_in": "mt7925/mac.c: mt7925_mlo_account_valid_rx called by mt7925_mac_fill_rx",
        "after": "driver data/unicast, descriptor-error, protected/decrypted and wrong-channel predicates",
        "before": "generic PN/replay checking and accepted network-stack delivery",
        "means": "driver-valid RX readiness, not authenticated delivery; wrong-channel predicate depends on mlo_rx_chan_check; source-to-loaded-build match is unverified",
    },
]
