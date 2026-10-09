"""Device inventory: cached discovery, persistence, change detection."""

from __future__ import annotations

import asyncio
import logging
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

from whd.clock import boot_to_wall, boottime_ns
from whd.discovery import Discovery, DiscoveryResult, Extension
from whd.events.bus import EventBus
from whd.model.common import Issue
from whd.model.device import Device, DeviceSummary
from whd.model.events import Category, Event, Severity
from whd.platform.host import Host
from whd.store.db import Store

log = logging.getLogger("whd.inventory")

WATCHED_FIELDS = ("driver", "module", "firmware_version", "phys", "netdevs", "operstate")


@dataclass
class Snapshot:
    devices: list[Device]
    taken_at: float
    duration_ms: float
    issues: list[Issue]
    run_id: int


@dataclass
class Diff:
    added: list[str] = field(default_factory=list)
    removed: list[str] = field(default_factory=list)
    changed: dict[str, dict[str, Any]] = field(default_factory=dict)


def _link_sig(d: Device) -> tuple[Any, ...] | None:
    if d.pci and d.pci.link:
        return (d.pci.link.current_speed, d.pci.link.current_width)
    if d.usb:
        return (d.usb.speed_mbps,)
    return None


def diff_devices(old: list[Device], new: list[Device]) -> Diff:
    o = {d.id: d for d in old}
    n = {d.id: d for d in new}
    df = Diff(added=sorted(set(n) - set(o)), removed=sorted(set(o) - set(n)))
    for i in sorted(set(o) & set(n)):
        ch: dict[str, Any] = {}
        for f in WATCHED_FIELDS:
            a, b = getattr(o[i], f), getattr(n[i], f)
            if a != b:
                ch[f] = {"from": a, "to": b}
        if _link_sig(o[i]) != _link_sig(n[i]):
            ch["link"] = {"from": _link_sig(o[i]), "to": _link_sig(n[i])}
        if ch:
            df.changed[i] = ch
    return df


class Inventory:
    def __init__(
        self,
        host: Host,
        store: Store,
        bus: EventBus | None = None,
        ttl_s: float = 5.0,
        extensions: list[Extension] | None = None,
    ) -> None:
        self.host = host
        self.store = store
        self.bus = bus
        self.ttl_s = ttl_s
        self.discovery = Discovery(host, extensions)
        self.snapshot: Snapshot | None = None
        self._lock = asyncio.Lock()
        self.on_refresh: list[Callable[[Snapshot], None]] = []

    def _run_sync(self) -> tuple[DiscoveryResult, dict[str, dict[str, Any]], int]:
        res = self.discovery.run()
        meta = self.store.upsert_devices(res.devices)
        run_id = self.store.record_discovery(
            res.started_at,
            res.duration_ms,
            self.host.mode,
            len(res.devices),
            [i.model_dump() for i in res.issues],
        )
        return res, meta, run_id

    async def refresh(self) -> tuple[Snapshot, Diff]:
        async with self._lock:
            res, meta, run_id = await asyncio.to_thread(self._run_sync)
            for d in res.devices:
                m = meta.get(d.id, {})
                d.first_seen, d.last_seen = m.get("first_seen"), m.get("last_seen")
                names = m.get("names", {})
                for nd in d.netdev_info:
                    nd.name_history = [x for x in names.get("netdev", []) if x != nd.name]
            old = self.snapshot.devices if self.snapshot else None
            snap = Snapshot(
                devices=res.devices,
                taken_at=time.time(),
                duration_ms=res.duration_ms,
                issues=res.issues,
                run_id=run_id,
            )
            df = diff_devices(old, res.devices) if old is not None else Diff()
            self.snapshot = snap
            if old is not None:
                self._emit(df, res.devices, old)
            for cb in list(self.on_refresh):
                try:
                    cb(snap)
                except Exception:
                    log.exception("inventory refresh callback failed")
            return snap, df

    def _emit(self, df: Diff, new: list[Device], old: list[Device]) -> None:
        if self.bus is None:
            return
        now = boottime_ns()
        byid = {d.id: d for d in new} | {d.id: d for d in old if d.id not in {x.id for x in new}}

        def ev(
            dev_id: str,
            kind: str,
            summary: str,
            expl: str,
            data: dict[str, Any],
            sev: Severity = "notice",
            cat: Category = "hotplug",
        ) -> None:
            assert self.bus is not None
            self.bus.publish(
                Event(
                    ts_boottime_ns=now,
                    ts_source="poll_boottime",
                    ts_wall=boot_to_wall(now),
                    source="inventory:rescan",
                    device_id=dev_id,
                    severity=sev,
                    category=cat,
                    kind=kind,
                    summary=summary,
                    explanation=expl,
                    raw=str(data),
                    data=data,
                )
            )

        for i in df.added:
            ev(
                i,
                "inventory.device_added",
                f"Device appeared: {byid[i].title}",
                "Discovery found a wireless device that was not present in the previous scan "
                "(enumeration, hotplug, or driver probe).",
                {"device_id": i},
            )
        for i in df.removed:
            ev(
                i,
                "inventory.device_removed",
                f"Device disappeared: {byid[i].title}",
                "A wireless device present in the previous scan is no longer found (removal, USB disconnect, "
                "PCI remove, or driver unbind with no other detection reason).",
                {"device_id": i},
                sev="warning",
            )
        for i, ch in df.changed.items():
            for f, v in ch.items():
                cats: dict[str, Category] = {
                    "driver": "driver_state",
                    "module": "driver_state",
                    "firmware_version": "firmware",
                    "operstate": "netdev",
                    "link": "pci_link" if byid[i].bus == "pci" else "usb_transfer",
                    "phys": "phy",
                    "netdevs": "netdev",
                }
                cat: Category = cats.get(f, "hotplug")
                ev(
                    i,
                    f"inventory.{f}_changed",
                    f"{f} changed: {v['from']} -> {v['to']}",
                    f"Between two discovery scans the device's {f} changed. This reflects state observed by "
                    "polling, not the exact moment of the transition.",
                    {"field": f, **v},
                    sev="warning" if f in ("driver", "link") else "notice",
                    cat=cat,
                )

    async def get(self, force: bool = False) -> Snapshot:
        if force or self.snapshot is None or time.time() - self.snapshot.taken_at > self.ttl_s:
            snap, _ = await self.refresh()
            return snap
        return self.snapshot

    async def device(self, device_id: str) -> Device | None:
        snap = await self.get()
        for d in snap.devices:
            if d.id == device_id:
                return d
        stored = await asyncio.to_thread(self.store.device_snapshot, device_id)
        if stored:
            d = Device.model_validate(stored)
            d.present = False
            return d
        return None

    async def summaries(self, include_absent: bool = True) -> list[DeviceSummary]:
        snap = await self.get()
        out = [
            DeviceSummary.model_validate(d.model_dump(include=set(DeviceSummary.model_fields)))
            for d in snap.devices
        ]
        if include_absent:
            present = {d.id for d in snap.devices}
            for row in await asyncio.to_thread(self.store.known_devices):
                if row["id"] in present:
                    continue
                try:
                    d = Device.model_validate_json(row["last_snapshot_json"])
                except Exception:
                    continue
                s = DeviceSummary.model_validate(d.model_dump(include=set(DeviceSummary.model_fields)))
                s.present = False
                s.first_seen, s.last_seen = row["first_seen"], row["last_seen"]
                out.append(s)
        return out
