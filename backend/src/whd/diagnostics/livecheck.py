"""Readings taken at the moment a live analysis runs.

A report built from stored events says what happened; these say what is true now, so a reader can tell a past fault
from a current one. Everything here is a passive read (sysfs values already in the inventory, plus passive mt76 debugfs
files through the helper when it is running). Nothing wakes the chip and nothing is written.
"""

from __future__ import annotations

from whd.clock import boottime_ns
from whd.diagnostics.models import LiveCheck
from whd.drivers import mt76
from whd.helper.protocol import HelperError
from whd.model.device import Device
from whd.platform.host import Host


def _device_checks(d: Device, now: int) -> list[LiveCheck]:
    out: list[LiveCheck] = []
    pre = d.id

    out.append(
        LiveCheck(
            id=f"{pre}:binding",
            label="driver binding",
            value=f"{d.driver or 'no driver bound'}"
            + (f" ({d.module})" if d.module and d.module != d.driver else ""),
            status="ok" if d.driver else "attention",
            source=f"sysfs {d.sysfs_path}/driver",
            read_at_boottime_ns=now,
        )
    )
    if d.netdevs:
        out.append(
            LiveCheck(
                id=f"{pre}:operstate",
                label=f"interface {', '.join(d.netdevs)}",
                value=d.operstate or "unknown",
                status="ok" if d.operstate == "up" else "info",
                source="sysfs class/net/*/operstate",
                read_at_boottime_ns=now,
            )
        )
    if d.pci and d.pci.link and d.pci.link.current_speed:
        lk = d.pci.link
        out.append(
            LiveCheck(
                id=f"{pre}:pcie_link",
                label="PCIe link",
                value=f"{lk.current_speed} x{lk.current_width} (max {lk.max_speed} x{lk.max_width})",
                status="attention" if lk.degraded else "ok",
                source="sysfs current_link_speed / current_link_width",
                read_at_boottime_ns=now,
            )
        )
    if d.usb and d.usb.speed_mbps:
        u = d.usb
        mbps = d.usb.speed_mbps
        major = (
            int(u.usb_version.split(".")[0])
            if u.usb_version and u.usb_version.split(".")[0].isdigit()
            else None
        )
        slow = major is not None and major >= 3 and mbps < 5000
        out.append(
            LiveCheck(
                id=f"{pre}:usb_link",
                label="USB link",
                value=f"{u.speed_name or u.speed_mbps} ({mbps:g} Mb/s), device declares USB {u.usb_version or '?'}",
                status="attention" if slow else "ok",
                source="sysfs speed / version",
                read_at_boottime_ns=now,
                detail="Attached below the speed the device declares; a cable, hub or port may be limiting it."
                if slow
                else None,
            )
        )
    if d.pci and d.pci.power_state:
        out.append(
            LiveCheck(
                id=f"{pre}:pci_power",
                label="PCI power state",
                value=d.pci.power_state
                + (f", runtime {d.power.runtime_status}" if d.power.runtime_status else ""),
                status="info",
                source="sysfs power_state / power/runtime_status",
                read_at_boottime_ns=now,
            )
        )
    if d.pci and d.pci.aer:
        nonzero = {
            f"{kind}.{name}": n
            for kind, counters in d.pci.aer.items()
            for name, n in counters.items()
            if n and not name.upper().startswith("TOTAL")
        }
        out.append(
            LiveCheck(
                id=f"{pre}:aer",
                label="AER error counters",
                value=", ".join(f"{k}={v}" for k, v in sorted(nonzero.items())) or "all zero",
                status="attention" if nonzero else "ok",
                source="sysfs aer_dev_correctable / aer_dev_nonfatal / aer_dev_fatal",
                read_at_boottime_ns=now,
            )
        )
    return out


def _mt76_checks(host: Host, d: Device) -> list[LiveCheck]:
    out: list[LiveCheck] = []
    try:
        snap = mt76.read_snapshot(host, d, False)
    except HelperError as e:
        return [
            LiveCheck(
                id=f"{d.id}:mt76",
                label="mt76 debugfs",
                value="not read",
                status="unavailable",
                source="whd-helper",
                detail=str(e),
            )
        ]
    except Exception as e:  # a failed live probe must never fail the report
        return [
            LiveCheck(
                id=f"{d.id}:mt76",
                label="mt76 debugfs",
                value="not read",
                status="unavailable",
                source="whd-helper",
                detail=f"{type(e).__name__}: {e}",
            )
        ]
    at = snap.boottime_ns
    src = f"debugfs {snap.phy}/mt76/xmit-queues"
    if snap.xmit_queues:
        # in flight: descriptors queued, or the producer index ahead of the DMA index where the driver prints both
        busy = [
            q
            for q in snap.xmit_queues
            if (q.get("queued") or 0) > 0
            or (
                q.get("cpu_idx") is not None and q.get("dma_idx") is not None and q["cpu_idx"] != q["dma_idx"]
            )
        ]
        out.append(
            LiveCheck(
                id=f"{d.id}:{snap.phy}:tx_rings",
                label=f"TX/MCU rings ({snap.phy})",
                value=(
                    "in flight: " + ", ".join(f"{q['name']} queued={q.get('queued')}" for q in busy)
                    if busy
                    else "all empty (nothing in flight)"
                ),
                status="attention" if busy else "ok",
                source=src,
                read_at_boottime_ns=at,
                detail="A ring that stays non-empty across repeated reads is the signal; one read can catch normal traffic.",
            )
        )
    if snap.mlo_active_links is not None:
        out.append(
            LiveCheck(
                id=f"{d.id}:{snap.phy}:mlo_links",
                label=f"MLO active links ({snap.phy})",
                value=f"0x{snap.mlo_active_links:x} -> {snap.mlo_active_link_ids}",
                status="info",
                source=f"debugfs {snap.phy}/mt76/mlo_active_links",
                read_at_boottime_ns=at,
            )
        )
    if snap.runtime_pm:
        out.append(
            LiveCheck(
                id=f"{d.id}:{snap.phy}:pm",
                label=f"runtime PM counters ({snap.phy})",
                value=", ".join(f"{k}={v}" for k, v in snap.runtime_pm.items()),
                status="info",
                source=f"debugfs {snap.phy}/mt76/runtime_pm_stats",
                read_at_boottime_ns=at,
            )
        )
    return out


def collect(devices: list[Device], host: Host, helper_ok: bool) -> list[LiveCheck]:
    """Current readings for the devices in scope. Never raises."""
    now = boottime_ns()
    checks: list[LiveCheck] = []
    for d in devices:
        if not d.present:
            checks.append(
                LiveCheck(
                    id=f"{d.id}:present",
                    label="device",
                    value="not present on the bus right now",
                    status="attention",
                    source="sysfs",
                    read_at_boottime_ns=now,
                )
            )
            continue
        checks.extend(_device_checks(d, now))
        if mt76.is_mt76(d) and d.phys:
            if helper_ok:
                checks.extend(_mt76_checks(host, d))
            else:
                checks.append(
                    LiveCheck(
                        id=f"{d.id}:mt76",
                        label="mt76 debugfs",
                        value="not read",
                        status="unavailable",
                        source="whd-helper",
                        detail="the privileged helper is not running",
                    )
                )
    return checks
