"""Kernel log classification into WHD event categories with evidence-based explanations.

Message patterns are taken from kernel/driver source format strings (cited per rule).
A rule only names what the message itself states; explanations describe the code path
that emits the message, never a root cause.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any

from whd.model.events import Category, Severity
from whd.platform.kconsts import ieee80211 as IE

PRIO_SEV: dict[int, Severity] = {
    0: "critical",
    1: "critical",
    2: "critical",
    3: "error",
    4: "warning",
    5: "notice",
    6: "info",
    7: "debug",
}

REASON_NAMES = {
    v: k.removeprefix("WLAN_REASON_") for k, v in IE.ENUMS.get("ieee80211_reasoncode", {}).items()
}
STATUS_NAMES = {
    v: k.removeprefix("WLAN_STATUS_") for k, v in IE.ENUMS.get("ieee80211_statuscode", {}).items()
}


@dataclass
class Rule:
    pattern: re.Pattern[str]
    kind: str
    category: Category
    severity: Severity | None
    explanation: str
    source: str  # where the message format comes from


@dataclass
class Classification:
    kind: str
    category: Category
    severity: Severity
    summary: str
    explanation: str
    data: dict[str, Any] = field(default_factory=dict)


MAC = r"([0-9a-f]{2}(?::[0-9a-f]{2}){5})"


def R(p: str, kind: str, cat: Category, sev: Severity | None, expl: str, src: str) -> Rule:
    return Rule(re.compile(p), kind, cat, sev, expl, src)


RULES: list[Rule] = [
    # ---------------------------------------------------------------- PCIe AER (drivers/pci/pcie/aer.c)
    R(
        r"AER: (?P<cls>Corrected|Uncorrectable \(Non-Fatal\)|Uncorrectable \(Fatal\)) error (?:message )?received from (?P<src>\S+)",
        "pci.aer.received",
        "pci_error",
        None,
        "The PCIe Advanced Error Reporting service received an error message for {src}. Corrected errors were "
        "recovered by hardware; uncorrectable errors may lead to recovery (reset) of the link or device.",
        "drivers/pci/pcie/aer.c",
    ),
    R(
        r"PCIe Bus Error: severity=(?P<sev>[\w ()-]+), type=(?P<type>[\w ]+), \((?P<agent>[\w ]+)\)",
        "pci.aer.bus_error",
        "pci_error",
        None,
        "AER decoded a {sev} error of type {type} reported by the {agent}.",
        "drivers/pci/pcie/aer.c aer_print_error",
    ),
    R(
        r"device \[(?P<vid>[0-9a-f]{4}):(?P<did>[0-9a-f]{4})\] error status/mask=(?P<status>[0-9a-f]+)/(?P<mask>[0-9a-f]+)",
        "pci.aer.status",
        "pci_error",
        None,
        "AER status/mask registers for device {vid}:{did} at the time of the error.",
        "drivers/pci/pcie/aer.c",
    ),
    R(
        r"\[\s*(?P<bit>\d+)\] (?P<name>[A-Za-z]+)\s*(?P<first>\(First\))?$",
        "pci.aer.bit",
        "pci_error",
        None,
        "AER error bit {bit} ({name}) was set{first}.",
        "drivers/pci/pcie/aer.c aer_error_string",
    ),
    R(
        r"broken device, retraining non-functional downstream link",
        "pci.link.retrain_broken",
        "pci_link",
        "warning",
        "The PCI core detected a non-functional downstream link and is retraining it.",
        "drivers/pci/quirks.c",
    ),
    R(
        r"(?:[Ll]ink [Dd]own|link is down)",
        "pci.link.down",
        "pci_link",
        "warning",
        "A PCIe port reported the link as down.",
        "drivers/pci/hotplug, pcie port drivers",
    ),
    R(
        r"(?:Unable|Refused) to change power state from (?P<from>D\w+) to (?P<to>D\w+)",
        "power.dstate_failed",
        "power",
        "error",
        "The PCI core could not move the device from {from} to {to}; the device may be "
        "unresponsive on the bus.",
        "drivers/pci/pci.c pci_set_low_power_state",
    ),
    R(
        r"not ready (?P<ms>\d+)ms after (?P<what>\w+); (?:giving up|waiting)",
        "pci.not_ready",
        "pci_error",
        "error",
        "The device did not become ready {ms} ms after {what} (config reads returned CRS/all-ones).",
        "drivers/pci/pci.c pci_dev_wait",
    ),
    # ---------------------------------------------------------------- driver core
    R(
        r"probe of (?P<dev>\S+) failed with error (?P<err>-?\d+)",
        "driver.probe_failed",
        "driver_state",
        "error",
        "The driver's probe() for {dev} returned {err}; the device is left unbound.",
        "drivers/base/dd.c",
    ),
    R(
        r"Direct firmware load for (?P<file>\S+) failed with error (?P<err>-?\d+)",
        "firmware.file_missing",
        "firmware",
        "warning",
        "request_firmware() could not find {file} (error {err}). The driver may try "
        "another file or fail initialization.",
        "drivers/base/firmware_loader/main.c",
    ),
    # ---------------------------------------------------------------- mt76 (formats from mt76 sources)
    R(
        r"Loading (?P<cb>CB )?firmware patch: (?P<file>\S+)",
        "firmware.patch_load",
        "firmware",
        "info",
        "mt76 is loading the ROM patch {file}.",
        "mt76_connac_mcu.c mt76_connac2_load_patch",
    ),
    R(
        r"(?P<which>WM|WA|PHY) Firmware Version: (?P<ver>\S+), Build Time: (?P<build>\S+)",
        "firmware.version",
        "firmware",
        "info",
        "The {which} firmware image reported version {ver} built {build}.",
        "mt76_connac_mcu.c",
    ),
    R(
        r"HW/SW Version: (?P<hwsw>0x[0-9a-f]+), (?:Build|Pack) Time: (?P<build>\S+)",
        "firmware.patch_version",
        "firmware",
        "info",
        "ROM patch header: HW/SW version {hwsw}, built {build}.",
        "mt76_connac_mcu.c",
    ),
    R(
        r"ASIC revision: (?P<rev>[0-9a-f]+)",
        "driver.asic_revision",
        "driver_state",
        "info",
        "The driver read ASIC revision {rev}.",
        "mt792x / mt7925 init",
    ),
    R(
        r"Firmware init done",
        "firmware.init_done",
        "firmware",
        "notice",
        "The driver received the firmware-ready indication after download.",
        "mt7925/mcu.c",
    ),
    R(
        r"Message (?P<cmd>[0-9a-f]{8}) \(seq (?P<seq>\d+)\) timeout",
        "firmware.mcu_timeout",
        "firmware",
        "error",
        "MCU command 0x{cmd} (sequence {seq}) got no response before the driver's timeout. Repeated timeouts "
        "commonly precede a firmware reset/recovery.",
        "mt76 mcu.c mt76_mcu_skb_send_and_get_msg",
    ),
    R(
        r"Retry message (?P<cmd>[0-9a-f]{8}) \(seq (?P<seq>\d+)\)",
        "firmware.mcu_retry",
        "firmware",
        "warning",
        "The driver is resending MCU command 0x{cmd} (sequence {seq}).",
        "mt76 mcu.c",
    ),
    R(
        r"(?P<what>Timeout for initializing firmware|Failed to start (?:WM|WA|PHY) firmware|Failed to send (?:PHY )?firmware|"
        r"Invalid (?:PHY |CBMCU )?firmware|Failed to (?:get|release) (?:cb )?patch semaphore|Failed to send patch|"
        r"Failed to start (?:cb )?patch|Download request failed)",
        "firmware.load_error",
        "firmware",
        "error",
        'Firmware download/start step failed: "{what}".',
        "mt76_connac_mcu.c / mt7925/mcu.c",
    ),
    R(
        r"chip reset failed",
        "reset.chip_reset_failed",
        "reset",
        "critical",
        "The driver's chip reset/recovery sequence failed.",
        "mt792x_mac.c mt792x_reset",
    ),
    R(
        r"chip reset",
        "reset.chip_reset",
        "reset",
        "warning",
        "The driver started a full chip reset (firmware/WFSYS recovery).",
        "mt792x_mac.c",
    ),
    R(
        r"(?P<who>driver|firmware) own failed",
        "power.ownership_failed",
        "power",
        "error",
        "The {who}-own handshake (ownership of the WFDMA between host and firmware power states) did not complete.",
        "mt792x_core.c __mt792xe_mcu_drv_pmctrl / fw_pmctrl",
    ),
    R(
        r"(?P<what>wpdma reset failed|hardware init failed|MLO init failed|register device failed)",
        "driver.init_error",
        "driver_state",
        "error",
        'Driver initialization step failed: "{what}".',
        "mt7925/mt792x",
    ),
    # ---------------------------------------------------------------- mac80211 (net/mac80211/mlme.c)
    R(
        r"(?P<ifname>\S+): authenticate with " + MAC,
        "assoc.authenticate",
        "association",
        "info",
        "{ifname} started 802.11 authentication with the AP.",
        "net/mac80211/mlme.c",
    ),
    R(
        r"(?P<ifname>\S+): send auth to " + MAC + r" \(try (?P<n>\d+)/(?P<max>\d+)\)",
        "assoc.auth_tx",
        "association",
        "info",
        "{ifname} transmitted authentication frame attempt {n}/{max}.",
        "net/mac80211/mlme.c",
    ),
    R(
        r"(?P<ifname>\S+): authenticated",
        "assoc.authenticated",
        "association",
        "info",
        "{ifname} completed 802.11 authentication.",
        "net/mac80211/mlme.c",
    ),
    R(
        r"(?P<ifname>\S+): associate with " + MAC + r" \(try (?P<n>\d+)/(?P<max>\d+)\)",
        "assoc.assoc_tx",
        "association",
        "info",
        "{ifname} transmitted association request attempt {n}/{max}.",
        "net/mac80211/mlme.c",
    ),
    R(
        r"(?P<ifname>\S+): RX (?:Re)?AssocResp from "
        + MAC
        + r" \(capab=(?P<capab>0x[0-9a-f]+) status=(?P<status>\d+) "
        r"aid=(?P<aid>\d+)\)",
        "assoc.assoc_resp",
        "association",
        None,
        "{ifname} received an association response with status {status} ({status_name}), AID {aid}.",
        "net/mac80211/mlme.c",
    ),
    R(
        r"(?P<ifname>\S+): associated$",
        "assoc.associated",
        "association",
        "notice",
        "{ifname} is associated.",
        "net/mac80211/mlme.c",
    ),
    R(
        r"(?P<ifname>\S+): deauthenticating from "
        + MAC
        + r" by local choice \(Reason: (?P<reason>\d+)=(?P<rname>\w+)\)",
        "assoc.deauth_local",
        "association",
        "notice",
        "{ifname} deauthenticated from the AP by local choice, reason {reason} ({rname}).",
        "net/mac80211/mlme.c",
    ),
    R(
        r"(?P<ifname>\S+): deauthenticated from " + MAC + r" \(Reason: (?P<reason>\d+)=(?P<rname>\w+)\)",
        "assoc.deauth_by_ap",
        "association",
        "warning",
        "The AP deauthenticated {ifname}, reason {reason} ({rname}).",
        "net/mac80211/mlme.c",
    ),
    R(
        r"(?P<ifname>\S+): disassociated from " + MAC + r" \(Reason: (?P<reason>\d+)=(?P<rname>\w+)\)",
        "assoc.disassoc_by_ap",
        "association",
        "warning",
        "The AP disassociated {ifname}, reason {reason} ({rname}).",
        "net/mac80211/mlme.c",
    ),
    R(
        r"(?P<ifname>\S+): (?P<what>authentication|association) with " + MAC + r" timed out",
        "assoc.timeout",
        "association",
        "error",
        "{ifname}: {what} with the AP timed out (no response after all retries).",
        "net/mac80211/mlme.c",
    ),
    R(
        r"(?P<ifname>\S+): Connection to AP " + MAC + r" lost",
        "assoc.connection_lost",
        "association",
        "error",
        "{ifname} declared the connection lost (beacon loss / probe failure).",
        "net/mac80211/mlme.c",
    ),
    R(
        r"(?P<ifname>\S+): Limiting TX power to (?P<dbm>-?\d+) (?:dBm|\()",
        "phy.tx_power_limit",
        "phy",
        "info",
        "{ifname} limited TX power to {dbm} dBm (regulatory/AP power constraint).",
        "net/mac80211/mlme.c",
    ),
    # ---------------------------------------------------------------- USB core / xHCI
    R(
        r"(?:usb (?P<port>\S+): )?USB disconnect, device number (?P<num>\d+)",
        "usb.disconnect",
        "hotplug",
        "warning",
        "USB device {port} (#{num}) was disconnected.",
        "drivers/usb/core/hub.c",
    ),
    R(
        r"(?:usb (?P<port>\S+): )?new (?P<speed>[\w+-]+(?: Gen \S+)?) USB device number (?P<num>\d+) using (?P<hcd>\S+)",
        "usb.enumerate",
        "hotplug",
        "notice",
        "A new {speed} USB device was enumerated at {port} via {hcd}.",
        "drivers/usb/core/hub.c",
    ),
    R(
        r"(?:usb (?P<port>\S+): )?reset (?P<speed>[\w+-]+(?: Gen \S+)?) USB device number (?P<num>\d+) using (?P<hcd>\S+)",
        "usb.reset",
        "reset",
        "warning",
        "The USB core reset device {port} ({speed}).",
        "drivers/usb/core/hub.c",
    ),
    R(
        r"(?:usb (?P<port>\S+): )?device descriptor read/(?P<n>\d+), error (?P<err>-?\d+)",
        "usb.descriptor_error",
        "usb_error",
        "error",
        "Reading the device descriptor of {port} failed with {err}.",
        "drivers/usb/core/hub.c",
    ),
    R(
        r"(?:usb (?P<port>\S+): )?device not accepting address (?P<addr>\d+), error (?P<err>-?\d+)",
        "usb.address_error",
        "usb_error",
        "error",
        "SET_ADDRESS to {port} failed with {err}.",
        "drivers/usb/core/hub.c",
    ),
    R(
        r"(?:over-current|Over-current) (?:condition|change)",
        "usb.overcurrent",
        "usb_error",
        "error",
        "A USB port reported an over-current condition.",
        "drivers/usb/core/hub.c",
    ),
    R(
        r"(?P<msg>.*(?:WARN|ERROR|[Ee]rror|timeout|halted|died|dead).*)",
        "usb.xhci_error",
        "usb_error",
        None,
        "The xHCI controller reported: {msg}.",
        "drivers/usb/host/xhci*.c (matched only for messages prefixed by the xhci_hcd driver)",
    ),
    R(
        r"New USB device found, idVendor=(?P<vid>[0-9a-f]{4}), idProduct=(?P<pid>[0-9a-f]{4})",
        "usb.device_found",
        "hotplug",
        "info",
        "The USB core read the descriptor of a new device {vid}:{pid}.",
        "drivers/usb/core/hub.c",
    ),
    # ---------------------------------------------------------------- generic kernel
    R(
        r"WARNING: CPU: (?P<cpu>\d+) PID: (?P<pid>\d+) at (?P<loc>\S+)",
        "kernel.warn",
        "kernel_log",
        "error",
        "A kernel WARN() fired at {loc}. A stack trace follows in the log.",
        "include/asm-generic/bug.h",
    ),
    R(r"^BUG: (?P<what>.*)", "kernel.bug", "kernel_log", "critical", "Kernel BUG: {what}.", "kernel"),
    # ---------------------------------------------------------------- custom driver key=value instrumentation
    R(
        r"^(?P<tag>[A-Z][A-Z0-9_]{2,}(?: [A-Z][A-Z0-9_]{2,})?):? (?P<kv>.*?\b[\w.\[\]-]+=\S+.*)$",
        "driver.kv_trace",
        "driver_state",
        None,
        "Structured driver debug message tagged {tag} (key=value fields; emitted by custom driver instrumentation "
        "present in this kernel build).",
        "driver printk",
    ),
]

KV_RE = re.compile(r"([\w.\[\]-]+)=(\S+)")


def _fmt(t: str, d: dict[str, Any]) -> str:
    class Safe(dict[str, Any]):
        def __missing__(self, k: str) -> str:
            return "{" + k + "}"

    try:
        return t.format_map(Safe(d))
    except (ValueError, IndexError):
        return t


def classify_kernel(message: str, priority: int | None, device_prefix: str | None = None) -> Classification:
    """Classify a kernel log line. `device_prefix` is a leading 'driver BDF: ' that is stripped for matching."""
    body = message
    m = re.match(
        r"^(?P<drv>[\w-]+) (?P<dev>[0-9a-f]{4}:[0-9a-f]{2}:[0-9a-f]{2}\.\d|\d+-[\d.]+(?::\d+\.\d+)?): (?P<rest>.*)$",
        message,
    )
    data: dict[str, Any] = {}
    if m:
        body = m.group("rest")
        data["log_driver"], data["log_device"] = m.group("drv"), m.group("dev")
    psev = PRIO_SEV.get(priority if priority is not None else 6, "info")
    for r in RULES:
        mm = r.pattern.search(body)
        if not mm:
            continue
        if r.kind.startswith("pci.link.down") and data.get("log_driver") not in ("pcieport", "pciehp"):
            continue
        if r.kind == "usb.xhci_error" and data.get("log_driver") != "xhci_hcd":
            continue
        g = {k: v for k, v in mm.groupdict().items() if v is not None}
        if "port" in r.pattern.groupindex and "port" not in g and data.get("log_device"):
            g["port"] = data["log_device"]
        macs = [x for x in mm.groups() if x and re.fullmatch(MAC, x)]
        if macs:
            g["peer"] = macs[0]
        g["first"] = " (first error)" if g.get("first") else ""
        if "status" in g and r.kind == "assoc.assoc_resp":
            try:
                g["status_name"] = STATUS_NAMES.get(int(g["status"]), "unknown")
            except ValueError:
                g["status_name"] = "unknown"
        sev: Severity = r.severity or psev
        if r.kind == "assoc.assoc_resp":
            sev = "notice" if g.get("status") == "0" else "error"
        if r.kind == "pci.aer.received":
            sev = (
                "warning"
                if g.get("cls") == "Corrected"
                else "critical"
                if "Fatal)" in g.get("cls", "") and "Non" not in g.get("cls", "")
                else "error"
            )
        cat: Category = r.category
        if r.kind == "driver.kv_trace":
            kv = dict(KV_RE.findall(g.get("kv", "")))
            if len(kv) < 2:
                continue
            g["fields"] = kv
            tag = g.get("tag", "")
            if tag.startswith(("MLO_", "ROC_", "ROCEV", "EMLSR", "T2LM", "TTLM")):
                cat = "mlo"
            elif tag.startswith(("FW_", "MCU_")) or "_FW_" in tag:
                cat = "firmware"
            sev = "debug" if psev in ("info", "debug") else psev
        data.update({k: v for k, v in g.items() if k not in ("first", "kv")})
        data["rule_source"] = r.source
        summary = body if len(body) <= 200 else body[:197] + "..."
        return Classification(
            kind=r.kind,
            category=cat,
            severity=sev,
            summary=summary,
            explanation=_fmt(r.explanation, g),
            data=data,
        )
    return Classification(
        kind="kernel.message",
        category="kernel_log",
        severity=psev,
        summary=body[:200],
        data=data,
        explanation=f"Kernel log message at syslog priority {priority} not matched by a WHD "
        "classifier; shown verbatim.",
    )
