"""whd-helper wire protocol: newline-delimited JSON over a Unix stream socket.

Request:   {"id": <int>, "verb": <str>, "args": {...}}
Response:  {"id": <int>, "ok": true, "result": ...}
           {"id": <int>, "ok": false, "error": <str>, "code": <str>}
Streaming verbs additionally send {"id": <int>, "stream": [...lines], "dropped": n} until a final
{"id": <int>, "ok": true, "result": {"ended": ...}} response.
"""

from __future__ import annotations

import re

PROTOCOL_VERSION = 1
MAX_REQUEST = 64 * 1024

BDF_RE = re.compile(r"^[0-9a-f]{4}:[0-9a-f]{2}:[0-9a-f]{2}\.[0-7]$")
PHY_RE = re.compile(r"^phy[0-9]{1,3}$")
NAME_RE = re.compile(r"^[A-Za-z0-9_\-]{1,64}$")
USB_BUS_RE = re.compile(r"^[0-9]{1,3}$")
RELPATH_RE = re.compile(r"^[A-Za-z0-9_.:\-]+(/[A-Za-z0-9_.:\-]+){0,5}$")

# Verbs the helper implements. All are read-only with respect to devices and drivers.
# trace_* create/remove WHD's *own* tracefs instance (instances/whd) and never touch the global buffer.
VERBS = (
    "ping",
    "pci_config_read",
    "debugfs_list",
    "debugfs_read",
    "tracefs_events",
    "tracefs_status",
    "trace_stream",
    "usbmon_stream",
)


class HelperError(Exception):
    def __init__(self, code: str, msg: str) -> None:
        super().__init__(msg)
        self.code = code


# Tracepoint groups WHD inspects for wireless/bus diagnostics. Shared by discovery, the mt76 module
# and `whd capture-fixture` so recorded helper data matches live requests exactly.
TRACE_GROUPS = [
    "mt76",
    "mt792x",
    "mt7925",
    "mt7921",
    "mac80211",
    "cfg80211",
    "pci",
    "xhci-hcd",
    "usbcore",
    "iwlwifi",
    "ath11k",
    "ath12k",
    "rtw89",
]
