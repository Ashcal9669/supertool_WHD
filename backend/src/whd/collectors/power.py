"""Runtime PM / PCI power state (sysfs). ASPM comes from config space via the helper."""

from __future__ import annotations

from whd.collectors.base import meta_from_log
from whd.model.device import PowerInfo
from whd.platform.sysfs import ReadLog, SysRoot


def collect_power(root: SysRoot, dev_path: str, bus: str) -> PowerInfo:
    log = ReadLog()
    p = PowerInfo()
    p.runtime_control = root.attr(f"{dev_path}/power/control", log)
    p.runtime_status = root.attr(f"{dev_path}/power/runtime_status", log)
    p.runtime_active_ms = root.attr_int(f"{dev_path}/power/runtime_active_time", log)
    p.runtime_suspended_ms = root.attr_int(f"{dev_path}/power/runtime_suspended_time", log)
    p.autosuspend_delay_ms = root.attr_int(f"{dev_path}/power/autosuspend_delay_ms", log)
    p.wakeup = root.attr(f"{dev_path}/power/wakeup", log)
    if bus == "pci":
        p.pci_power_state = root.attr(f"{dev_path}/power_state", log)
        d3 = root.attr_int(f"{dev_path}/d3cold_allowed", log)
        p.d3cold_allowed = bool(d3) if d3 is not None else None
        # Newer kernels expose ASPM controls under link/ (drivers/pci/pcie/aspm.c).
        for n in ("l0s_aspm", "l1_aspm", "l1_1_aspm", "l1_2_aspm", "l1_1_pcipm", "l1_2_pcipm", "clkpm"):
            v = root.attr_int(f"{dev_path}/link/{n}", log)
            if v is not None:
                p.aspm[n] = bool(v)
        if p.aspm:
            p.aspm_meta.availability = "ok"
            p.aspm_meta.sources = [f"{dev_path}/link/"]
        else:
            p.aspm_meta.availability = "requires_privilege"
            p.aspm_meta.note = (
                "Kernel does not expose ASPM state in sysfs link/; decoded from PCIe Link Control "
                "via the WHD privileged helper when it is running"
            )
    # drivers/base/power/sysfs.c: autosuspend_delay_ms_show() returns -EIO when the device does not
    # use autosuspend. That is a state, not a failure.
    auto = f"{dev_path}/power/autosuspend_delay_ms"
    no_auto = any(i.path == auto and i.kind == "device_error" for i in log.issues)
    log.issues = [i for i in log.issues if not (i.path == auto and i.kind == "device_error")]
    p.meta = meta_from_log(
        log, note="autosuspend not in use (autosuspend_delay_ms returned EIO)" if no_auto else None
    )
    return p
