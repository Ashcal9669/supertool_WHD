"""Driver binding, module metadata and firmware version."""

from __future__ import annotations

from typing import Any

from whd.collectors.base import meta_from_log
from whd.model.device import CandidateModule, DriverInfo, FirmwareInfo
from whd.platform.host import Host
from whd.platform.kmod import ModuleIndex
from whd.platform.sysfs import ReadLog, SysfsError

MODULE_SYSFS_ATTRS = ("version", "srcversion", "taint", "refcnt", "coresize", "initstate")


def collect_driver(
    host: Host,
    dev_path: str,
    modalias: str | None,
    kidx: ModuleIndex,
    netdevs: list[str],
    iface_paths: list[str] | None = None,
) -> tuple[DriverInfo, FirmwareInfo]:
    root = host.root
    log = ReadLog()
    d = DriverInfo()
    d.driver = root.readlink_name(f"{dev_path}/driver")
    dev_path_for_mod = dev_path
    if d.driver in (None, "usb"):
        # USB: the device binds to the generic "usb" driver; the function driver binds to an interface.
        for ip in iface_paths or []:
            drv = root.readlink_name(f"{ip}/driver")
            if drv and drv not in ("usb", "hub"):
                d.driver, dev_path_for_mod = drv, ip
                break
        else:
            if d.driver == "usb":
                d.driver = None
    d.bound = d.driver is not None
    if d.bound:
        log.sources.append(f"{dev_path_for_mod}/driver")
        d.module = root.readlink_name(f"{dev_path_for_mod}/driver/module")
    if modalias:
        for m in kidx.match(modalias):
            d.candidate_modules.append(
                CandidateModule(
                    module=m,
                    wireless=kidx.is_wireless(m),
                    loaded=root.isdir(f"/sys/module/{m}"),
                    path=kidx.paths.get(m),
                )
            )
        if kidx.available:
            log.sources.append(f"/lib/modules/{kidx.release}/modules.alias")
    mod = d.module or next((c.module for c in d.candidate_modules if c.wireless), None)
    if mod:
        for n in MODULE_SYSFS_ATTRS:
            v = root.attr(f"/sys/module/{mod}/{n}", log)
            if v is not None:
                d.module_sysfs[n] = v
        for pname in root.listdir(f"/sys/module/{mod}/parameters"):
            try:
                d.module_params[pname] = root.read_text(f"/sys/module/{mod}/parameters/{pname}", limit=4096)
            except SysfsError as e:
                d.module_params[pname] = f"<{e.issue.kind}>"
        info = host.modinfo(mod)
        if info:
            d.module_info = info
            log.sources.append(f"modinfo -0 {mod}")
        d.module_dependencies = sorted(kidx.closure(mod))
    fw = FirmwareInfo()
    flog = ReadLog()
    for nd in netdevs:
        try:
            drvinfo: dict[str, Any] = host.ethtool_drvinfo(nd)
        except OSError as e:
            from whd.platform.sysfs import ReadIssue, classify_oserror

            flog.issues.append(ReadIssue(f"ETHTOOL_GDRVINFO {nd}", classify_oserror(e), e.strerror or str(e)))
            continue
        d.ethtool = drvinfo
        flog.sources.append(f"ioctl SIOCETHTOOL ETHTOOL_GDRVINFO ({nd})")
        if drvinfo.get("fw_version"):
            fw.version = str(drvinfo["fw_version"])
        break
    fw.declared_files = d.module_info.get("firmware", [])
    d.meta = meta_from_log(log)
    fw.meta = meta_from_log(flog)
    if fw.version is None:
        fw.meta.note = (
            "Driver did not report a firmware version via ETHTOOL_GDRVINFO"
            if flog.sources
            else "No network interface available to query firmware version"
        )
        if fw.meta.availability == "ok":
            fw.meta.availability = "unavailable"
    return d, fw
