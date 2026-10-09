"""Host/system information and integration availability probe (read-only: existence/access checks)."""

from __future__ import annotations

import os

from whd import __version__
from whd.model.system import Integration, IntegrationState, SystemInfo
from whd.platform.host import Host


def _access(host: Host, path: str) -> IntegrationState:
    """ok / missing / no_permission for a path within the host sysroot."""
    p = host.root.path(path)
    if not os.path.lexists(p):
        return "missing"
    try:
        if os.path.isdir(p):
            os.listdir(p)
        else:
            with open(p, "rb"):
                pass
        return "ok"
    except PermissionError:
        return "no_permission"
    except OSError:
        return "error"


def probe_integrations(host: Host, helper_status: dict[str, object] | None = None) -> list[Integration]:
    helper_ok = bool(helper_status and helper_status.get("connected"))
    out: list[Integration] = []
    nl_err = host.nl80211_error
    out.append(
        Integration(
            name="nl80211",
            state="ok" if nl_err is None else "missing",
            detail=nl_err,
            enables="wiphy capabilities, interfaces, stations, regulatory, wireless events",
        )
    )
    for name, path, enables in (
        ("sysfs_pci", "/sys/bus/pci/devices", "PCI device inventory"),
        ("sysfs_usb", "/sys/bus/usb/devices", "USB device inventory"),
        ("ieee80211_class", "/sys/class/ieee80211", "PHY to device mapping"),
        ("udev_db", "/run/udev/data", "hwdb device names"),
        ("pci_ids", "/usr/share/misc/pci.ids", "PCI names fallback"),
        ("usb_ids", "/usr/share/misc/usb.ids", "USB names fallback"),
    ):
        st = _access(host, path)
        out.append(Integration(name=name, state=st, enables=enables))
    rel = host.uname().get("release", "")
    st = _access(host, f"/lib/modules/{rel}/modules.alias")
    out.append(
        Integration(name="modules_alias", state=st, enables="driver-match detection of unbound devices")
    )
    for name, path, enables in (
        ("tracefs", "/sys/kernel/tracing", "tracepoint capture (isolated instance)"),
        ("debugfs", "/sys/kernel/debug", "driver debugfs (allowlisted reads)"),
        ("usbmon", "/sys/kernel/debug/usb/usbmon", "USB URB capture"),
    ):
        st = _access(host, path)
        if st == "no_permission":
            st = "via_helper" if helper_ok else "no_permission"
            detail = (
                "read through whd-helper"
                if helper_ok
                else "requires root: start whd-helper (see README 'Privileged helper')"
            )
        elif st == "missing" and name == "usbmon":
            detail = "usbmon module not loaded (WHD never loads kernel modules)"
        else:
            detail = None
        out.append(Integration(name=name, state=st, detail=detail, enables=enables))
    if host.mode == "live":
        for tool, enables in (
            ("journalctl", "kernel log events"),
            ("modinfo", "module metadata"),
            ("perf", "not used in this release"),
            ("bpftool", "not used in this release"),
        ):
            pth = host.tool_path(tool)
            out.append(Integration(name=tool, state="ok" if pth else "missing", detail=pth, enables=enables))
    out.append(
        Integration(
            name="helper",
            state="ok" if helper_ok else "missing",
            detail=str((helper_status or {}).get("detail") or ""),
            enables="PCI config space (ASPM/AER/MSI), debugfs, tracefs, usbmon",
        )
    )
    return out


def system_info(host: Host, scenario: str | None, helper_status: dict[str, object] | None) -> SystemInfo:
    u = host.uname()
    osr = host.os_release()
    return SystemInfo(
        hostname=u.get("nodename", "?"),
        kernel_release=u.get("release", "?"),
        kernel_version=u.get("version"),
        arch=u.get("machine", "?"),
        distro=osr.get("PRETTY_NAME"),
        python=u.get("python"),
        whd_version=__version__,
        mode=host.mode,
        demo_scenario=scenario,
        fixture_kind=host.fixture_kind,
        fixture_description=host.description,
        fixture_events_kind=getattr(host, "meta", {}).get("events_kind"),
        fixture_events_description=getattr(host, "meta", {}).get("events_description"),
        uid=os.getuid(),
        euid=os.geteuid(),
        running_as_root=os.geteuid() == 0,
        helper=helper_status or {"connected": False},
        integrations=probe_integrations(host, helper_status),
    )
