"""Event sources. Each source is an asyncio task publishing to the EventBus.

| source          | mechanism                                     | timestamp (ts_source)            |
|-----------------|-----------------------------------------------|----------------------------------|
| journal:kernel  | `journalctl -k -f -o json` (structured JSON)  | printk time -> boottime          |
| uevent          | NETLINK_KOBJECT_UEVENT group 1                | receive_boottime                 |
| nl80211         | genl multicast config/scan/regulatory/mlme    | receive_boottime                 |
| rtnl            | NETLINK_ROUTE RTMGRP_LINK                     | receive_boottime                 |
| poll            | periodic sysfs reads (link, AER, runtime PM)  | poll_boottime                    |
| telemetry       | periodic nl80211 GET_STATION / survey, stats  | poll_boottime (samples)          |
| tracefs         | whd-helper trace_stream (instances/whd)       | tracefs_boot (trace_clock=boot)  |
| replay          | fixture/capture events (demo, replay)         | recorded                         |
"""

from __future__ import annotations

import asyncio
import contextlib
import json
import logging
import re
import shutil
import struct
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING, Any

from whd.clock import boot_to_wall, boottime_ns, mono_to_boot_offset_ns
from whd.events.attrib import DeviceIndex
from whd.events.bus import EventBus, SourceStatus
from whd.events.classify import classify_kernel
from whd.events.nl80211_events import decode_event
from whd.model.events import Category, Event, Severity, TelemetrySample, TsSource
from whd.platform.kconsts import if_flags as IFF
from whd.platform.kconsts import if_link as L
from whd.platform.kconsts import netlink as N
from whd.platform.kconsts import rtnetlink as RT
from whd.platform.netlink import Attrs, iter_msgs, open_multicast

if TYPE_CHECKING:
    from whd.platform.host import Host
    from whd.services.inventory import Inventory

log = logging.getLogger("whd.sources")


@dataclass
class Ctx:
    bus: EventBus
    index: DeviceIndex
    host: Host
    inventory: Inventory
    request_rescan: Callable[[str], None]
    settings: Any


def make_event(
    *,
    ts: int,
    ts_source: TsSource,
    source: str,
    category: Category,
    kind: str,
    summary: str,
    explanation: str,
    raw: str,
    severity: Severity = "info",
    device_id: str | None = None,
    data: dict[str, Any] | None = None,
    ts_raw: str | None = None,
) -> Event:
    return Event(
        ts_boottime_ns=ts,
        ts_source=ts_source,
        ts_raw=ts_raw,
        ts_wall=boot_to_wall(ts),
        source=source,
        device_id=device_id,
        severity=severity,
        category=category,
        kind=kind,
        summary=summary,
        explanation=explanation,
        raw=raw,
        data=data or {},
    )


class Source:
    name = "source"
    # seconds between retries after Unavailable; None = give up (for sources that start on demand)
    retry_unavailable_s: float | None = None

    def __init__(self, ctx: Ctx) -> None:
        self.ctx = ctx
        self.status: SourceStatus = ctx.bus.source(self.name)

    async def run(self) -> None:
        raise NotImplementedError

    async def supervise(self) -> None:
        backoff = 1.0
        last_unavailable: str | None = None
        while True:
            try:
                self.status.state = "running"
                if last_unavailable is not None:
                    self.status.detail = ""
                await self.run()
                return
            except asyncio.CancelledError:
                self.status.state = "stopped"
                raise
            except Unavailable as e:
                self.status.state, self.status.detail = "unavailable", str(e)
                if last_unavailable != str(e):
                    last_unavailable = str(e)
                    log.info("source unavailable", extra={"source": self.name, "detail": str(e)})
                if self.retry_unavailable_s is None:
                    return
                await asyncio.sleep(self.retry_unavailable_s)
            except Exception as e:
                self.status.state, self.status.detail = "error", repr(e)
                self.status.errors += 1
                log.exception("source failed; restarting", extra={"source": self.name})
                await asyncio.sleep(backoff)
                backoff = min(backoff * 2, 30)


class Unavailable(Exception):
    pass


# --------------------------------------------------------------------------- journal (kernel log)


class JournalSource(Source):
    name = "journal"
    CURSOR_KEY = "journal.kernel.cursor"

    def __init__(self, ctx: Ctx, backfill: int = 300) -> None:
        super().__init__(ctx)
        self.backfill = backfill
        self.boot_id: str | None = None
        with contextlib.suppress(OSError):
            self.boot_id = Path("/proc/sys/kernel/random/boot_id").read_text().strip().replace("-", "")

    def handle(self, j: dict[str, Any]) -> Event | None:
        msg = j.get("MESSAGE")
        if isinstance(msg, list):
            msg = bytes(msg).decode(errors="replace")
        if not isinstance(msg, str) or not msg:
            return None
        prio = int(j.get("PRIORITY", 6))
        src_us = j.get("_SOURCE_MONOTONIC_TIMESTAMP") or j.get("__MONOTONIC_TIMESTAMP")
        ts_source: TsSource
        ts_raw: str | None
        if src_us is not None:
            ts = int(src_us) * 1000 + mono_to_boot_offset_ns()
            ts_source = "kernel_printk" if j.get("_SOURCE_MONOTONIC_TIMESTAMP") else "journal_monotonic"
            ts_raw = f"{int(src_us) / 1e6:.6f}s (boot {j.get('_BOOT_ID', '?')[:8]})"
        else:
            ts, ts_source, ts_raw = boottime_ns(), "receive_boottime", None  # no kernel timestamp available
        c = classify_kernel(msg, prio)
        dev = self.ctx.index.by_kernel_device(j.get("_KERNEL_DEVICE"))
        method = "journald _KERNEL_DEVICE" if dev else None
        if dev is None:
            dev, method = self.ctx.index.by_text(msg)
        if dev is None and c.data.get("log_device"):
            dev = self.ctx.index.bdf.get(c.data["log_device"]) or self.ctx.index.usb_port.get(
                c.data["log_device"]
            )
            method = "device prefix in message" if dev else None
            if (
                dev is None
                and "log_device" in c.data
                and ":" in c.data["log_device"]
                and "." in c.data["log_device"]
            ):
                dev = self.ctx.index.by_ancestor_bdf(c.data["log_device"])
                method = "only tracked device below this controller/bridge" if dev else None
        data = dict(c.data)
        if method:
            data["attribution"] = method
        for k in ("_KERNEL_DEVICE", "_KERNEL_SUBSYSTEM", "_UDEV_SYSNAME"):
            if j.get(k):
                data[k.strip("_").lower()] = j[k]
        return make_event(
            ts=ts,
            ts_source=ts_source,
            ts_raw=ts_raw,
            source="journal:kernel",
            device_id=dev,
            severity=c.severity,
            category=c.category,
            kind=c.kind,
            summary=c.summary,
            explanation=c.explanation,
            raw=msg,
            data=data,
        )

    async def run(self) -> None:
        exe = self.ctx.host.tool_path("journalctl") or shutil.which("journalctl")
        if not exe:
            raise Unavailable("journalctl not found")
        cursor = (
            await asyncio.to_thread(self.ctx.bus.store.kv_get, self.CURSOR_KEY)
            if self.ctx.bus.store
            else None
        )
        args = [
            exe,
            "-k",
            "-f",
            "-o",
            "json",
            "--no-pager",
            "--output-fields",
            "MESSAGE,PRIORITY,_SOURCE_MONOTONIC_TIMESTAMP,__MONOTONIC_TIMESTAMP,_KERNEL_DEVICE,"
            "_KERNEL_SUBSYSTEM,_UDEV_SYSNAME,_BOOT_ID,__CURSOR",
        ]
        if cursor:
            args += ["--after-cursor", cursor]
        else:
            args += ["-b", "-n", str(self.backfill)]
        proc = await asyncio.create_subprocess_exec(
            *args,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            limit=1 << 22,
            # own session: a terminal Ctrl+C must not kill journalctl before we shut down cleanly
            start_new_session=True,
        )
        assert proc.stdout is not None
        n = 0
        last_cursor_save = time.monotonic()
        last_cursor: str | None = None
        try:
            while True:
                line = await proc.stdout.readline()
                if not line:
                    err = (await proc.stderr.read()).decode(errors="replace") if proc.stderr else ""
                    if "No journal files" in err or "permission" in err.lower():
                        raise Unavailable(err.strip()[:200])
                    raise RuntimeError(f"journalctl exited: {err.strip()[:200]}")
                try:
                    j = json.loads(line)
                except json.JSONDecodeError:
                    continue
                if self.boot_id and j.get("_BOOT_ID") and j["_BOOT_ID"] != self.boot_id:
                    continue
                ev = self.handle(j)
                last_cursor = j.get("__CURSOR") or last_cursor
                if ev is not None:
                    self.ctx.bus.publish(ev)
                    n += 1
                if last_cursor and self.ctx.bus.store and time.monotonic() - last_cursor_save > 2:
                    await asyncio.to_thread(self.ctx.bus.store.kv_set, self.CURSOR_KEY, last_cursor)
                    last_cursor_save = time.monotonic()
        finally:
            if last_cursor and self.ctx.bus.store:
                self.ctx.bus.store.kv_set(self.CURSOR_KEY, last_cursor)
            with contextlib.suppress(ProcessLookupError):
                proc.kill()
            with contextlib.suppress(Exception):
                await proc.wait()


# --------------------------------------------------------------------------- uevents


RELEVANT_SUBSYSTEMS = {"pci", "usb", "net", "ieee80211", "rfkill", "firmware", "pci_express", "module"}


class UeventSource(Source):
    name = "uevent"

    @staticmethod
    def parse(buf: bytes) -> dict[str, str] | None:
        if b"@" not in buf.split(b"\0", 1)[0]:
            return None  # libudev-formatted message, not a kernel uevent
        parts = buf.split(b"\0")
        out: dict[str, str] = {}
        action, _, devpath = parts[0].decode(errors="replace").partition("@")
        out["_ACTION"], out["_DEVPATH"] = action, devpath
        for p in parts[1:]:
            if b"=" in p:
                k, v = p.decode(errors="replace").split("=", 1)
                out[k] = v
        return out

    def handle(self, u: dict[str, str]) -> Event | None:
        sub = u.get("SUBSYSTEM", "")
        action = u.get("ACTION", u.get("_ACTION", ""))
        devpath = u.get("DEVPATH", u.get("_DEVPATH", ""))
        dev = self.ctx.index.by_path(devpath)
        if sub not in RELEVANT_SUBSYSTEMS and dev is None:
            return None
        if sub == "module" and u.get("_DEVPATH", "").split("/")[-1] not in self.ctx.index.modules:
            return None
        if sub == "usb" and u.get("DEVTYPE") not in ("usb_device", "usb_interface") and dev is None:
            return None
        if sub == "pci" and dev is None and action not in ("add", "remove", "bind", "unbind"):
            return None
        cat: Category = "hotplug"
        sev: Severity = "info"
        kind = f"uevent.{sub}.{action}"
        name = devpath.rsplit("/", 1)[-1]
        expl = f"Kernel uevent: {action} on {sub} object {name}."
        if action in ("bind", "unbind"):
            cat = "driver_state"
            sev = "notice" if action == "bind" else "warning"
            expl = (
                f"Driver {u.get('DRIVER', '?')} was {action}ed {'to' if action == 'bind' else 'from'} {name}."
            )
        elif action == "move":
            cat = "netdev"
            expl = f"Object renamed: {u.get('DEVPATH_OLD', '?').rsplit('/', 1)[-1]} -> {name}."
        elif action == "remove":
            sev = "warning"
        elif action == "change":
            cat = "netdev" if sub in ("net", "rfkill") else "driver_state"
        if sub == "firmware":
            cat = "firmware"
        if action in ("add", "remove", "bind", "unbind", "move") and sub in (
            "pci",
            "usb",
            "net",
            "ieee80211",
        ):
            self.ctx.request_rescan(kind)
        raw = f"{action}@{devpath} " + " ".join(f"{k}={v}" for k, v in u.items() if not k.startswith("_"))
        return make_event(
            ts=boottime_ns(),
            ts_source="receive_boottime",
            source="uevent",
            device_id=dev,
            severity=sev,
            category=cat,
            kind=kind,
            summary=f"{action} {sub} {name}",
            explanation=expl,
            raw=raw,
            data={k: v for k, v in u.items() if not k.startswith("_")}
            | ({"attribution": "devpath under device sysfs path"} if dev else {}),
        )

    async def run(self) -> None:
        try:
            s = open_multicast(N.NETLINK_KOBJECT_UEVENT, bind_groups=1)
        except OSError as e:
            raise Unavailable(f"uevent netlink: {e}") from e
        loop = asyncio.get_running_loop()
        try:
            while True:
                buf = await loop.sock_recv(s, 1 << 16)
                u = self.parse(buf)
                if u:
                    ev = self.handle(u)
                    if ev:
                        self.ctx.bus.publish(ev)
        finally:
            s.close()


# --------------------------------------------------------------------------- nl80211 multicast


class Nl80211Source(Source):
    name = "nl80211"
    GROUPS = ("config", "scan", "regulatory", "mlme")

    def handle(self, payload: bytes) -> Event:
        kind, cat, sev, summary, expl, d = decode_event(payload)
        dev = None
        method = None
        if "ifindex" in d:
            dev = self.ctx.index.ifindex.get(d["ifindex"])
            method = "ifindex"
        if dev is None and "wiphy" in d:
            dev = self.ctx.index.wiphy_idx.get(d["wiphy"])
            method = "wiphy index"
        if dev:
            d["attribution"] = method
        if kind in (
            "nl80211.new_wiphy",
            "nl80211.del_wiphy",
            "nl80211.new_interface",
            "nl80211.del_interface",
        ):
            self.ctx.request_rescan(kind)
        return make_event(
            ts=boottime_ns(),
            ts_source="receive_boottime",
            source="nl80211",
            device_id=dev,
            severity=sev,
            category=cat,
            kind=kind,
            summary=summary,
            explanation=expl,
            raw=payload.hex(),
            data=d,
        )

    async def run(self) -> None:
        nl = self.ctx.host.nl80211()
        if nl is None:
            raise Unavailable(self.ctx.host.nl80211_error or "nl80211 unavailable")
        groups = nl.src.multicast_groups()
        ids = [groups[g] for g in self.GROUPS if g in groups]
        try:
            s = open_multicast(N.NETLINK_GENERIC, ids)
        except OSError as e:
            raise Unavailable(f"nl80211 multicast: {e}") from e
        fam = nl.src.family_id
        loop = asyncio.get_running_loop()
        try:
            while True:
                buf = await loop.sock_recv(s, 1 << 20)
                for m in iter_msgs(buf):
                    if m.type == fam:
                        self.ctx.bus.publish(self.handle(m.payload))
        finally:
            s.close()


# --------------------------------------------------------------------------- rtnetlink link state


IFINFO = struct.Struct("=BxHiII")  # family, type, index, flags, change
OPER = {v: k.removeprefix("IF_OPER_") for k, v in IFF.DEFINES.items() if k.startswith("IF_OPER_")}
OPER.update(
    {
        v: k.removeprefix("IF_OPER_")
        for e in IFF.ENUMS.values()
        for k, v in e.items()
        if k.startswith("IF_OPER_")
    }
)


class RtnlSource(Source):
    name = "rtnl"

    def __init__(self, ctx: Ctx) -> None:
        super().__init__(ctx)
        self.last: dict[int, tuple[str | None, bool, bool]] = {}

    def handle(self, mtype: int, payload: bytes) -> Event | None:
        if len(payload) < IFINFO.size:
            return None
        _fam, _type, idx, flags, _change = IFINFO.unpack_from(payload)
        dev = self.ctx.index.ifindex.get(idx)
        if dev is None:
            return None
        a = Attrs.parse(payload[IFINFO.size :])
        name = a.str(L.IFLA_IFNAME)
        oper = a.u8(L.IFLA_OPERSTATE)
        opername = OPER.get(oper) if oper is not None else None
        up, running = bool(flags & IFF.IFF_UP), bool(flags & IFF.IFF_RUNNING)
        if mtype == RT.RTM_DELLINK:
            self.last.pop(idx, None)
            return make_event(
                ts=boottime_ns(),
                ts_source="receive_boottime",
                source="rtnl",
                device_id=dev,
                severity="warning",
                category="netdev",
                kind="netdev.removed",
                summary=f"{name} removed",
                explanation="RTM_DELLINK: the network interface was unregistered.",
                raw=payload.hex(),
                data={"ifindex": idx, "ifname": name},
            )
        state = (opername, up, running)
        prev = self.last.get(idx)
        self.last[idx] = state
        if prev == state:
            return None
        if prev is not None and prev[0] == opername and prev[1] == up and prev[2] == running:
            return None
        sev: Severity = "notice" if opername == "UP" else "warning" if prev and prev[0] == "UP" else "info"
        return make_event(
            ts=boottime_ns(),
            ts_source="receive_boottime",
            source="rtnl",
            device_id=dev,
            severity=sev,
            category="netdev",
            kind="netdev.state",
            summary=f"{name} operstate {opername} "
            f"admin {'up' if up else 'down'}{' running' if running else ''}",
            explanation="RTM_NEWLINK: interface operational/admin state changed "
            f"(previous: {prev[0] if prev else 'unknown'}).",
            raw=payload.hex(),
            data={
                "ifindex": idx,
                "ifname": name,
                "operstate": opername,
                "up": up,
                "running": running,
                "flags": f"0x{flags:x}",
            },
        )

    async def run(self) -> None:
        try:
            s = open_multicast(N.NETLINK_ROUTE, bind_groups=RT.RTMGRP_LINK)
        except OSError as e:
            raise Unavailable(f"rtnetlink: {e}") from e
        loop = asyncio.get_running_loop()
        try:
            while True:
                buf = await loop.sock_recv(s, 1 << 16)
                for m in iter_msgs(buf):
                    if m.type in (RT.RTM_NEWLINK, RT.RTM_DELLINK):
                        ev = self.handle(m.type, m.payload)
                        if ev:
                            self.ctx.bus.publish(ev)
        finally:
            s.close()


# --------------------------------------------------------------------------- sysfs pollers


@dataclass
class _DevState:
    values: dict[str, Any] = field(default_factory=dict)


class SysfsPoller(Source):
    """Polls bus/power attributes and emits events only when they change. Detection granularity is the
    polling interval; events say so in their explanation."""

    name = "poll"

    def __init__(self, ctx: Ctx, interval: float = 2.0) -> None:
        super().__init__(ctx)
        self.interval = interval
        self.state: dict[str, _DevState] = {}

    def _read(self, path: str) -> str | None:
        return self.ctx.host.root.attr(path)

    def sample(self, dev_id: str, path: str, bus: str) -> dict[str, Any]:
        v: dict[str, Any] = {
            "runtime_status": self._read(f"{path}/power/runtime_status"),
        }
        if bus == "pci":
            v["link"] = (self._read(f"{path}/current_link_speed"), self._read(f"{path}/current_link_width"))
            v["power_state"] = self._read(f"{path}/power_state")
            for k in ("correctable", "fatal", "nonfatal"):
                t = self._read(f"{path}/aer_dev_{k}")
                if t is not None:
                    from whd.collectors.pci import parse_aer

                    v[f"aer_{k}"] = parse_aer(t)
        elif bus == "usb":
            v["speed"] = self._read(f"{path}/speed")
            port = self.ctx.host.root.realpath(f"{path}/port")
            if port:
                v["over_current_count"] = self._read(f"{port}/over_current_count")
        return v

    def diff(self, dev_id: str, path: str, old: dict[str, Any], new: dict[str, Any]) -> list[Event]:
        out: list[Event] = []
        now = boottime_ns()
        note = f" Detected by sysfs polling (interval {self.interval:.0f}s); the change happened since the previous poll."
        for k, nv in new.items():
            ov = old.get(k)
            if ov == nv or ov is None:
                continue
            if k.startswith("aer_"):
                deltas = {n: c - ov.get(n, 0) for n, c in nv.items() if c != ov.get(n, 0)}
                if not deltas:
                    continue
                cls = k.removeprefix("aer_")
                sev: Severity = (
                    "warning" if cls == "correctable" else "error" if cls == "nonfatal" else "critical"
                )
                out.append(
                    make_event(
                        ts=now,
                        ts_source="poll_boottime",
                        source="poll:aer",
                        device_id=dev_id,
                        severity=sev,
                        category="pci_error",
                        kind=f"pci.aer.counter.{cls}",
                        summary=f"AER {cls} counters increased: "
                        + ", ".join(f"{n}+{d}" for n, d in deltas.items()),
                        explanation=f"The device's {cls} AER counters (aer_dev_{cls}) increased." + note,
                        raw=json.dumps({"before": ov, "after": nv}),
                        data={"deltas": deltas, "class": cls},
                    )
                )
            elif k == "link":
                out.append(
                    make_event(
                        ts=now,
                        ts_source="poll_boottime",
                        source="poll:pci_link",
                        device_id=dev_id,
                        severity="warning",
                        category="pci_link",
                        kind="pci.link.changed",
                        summary=f"PCIe link {ov[0]} x{ov[1]} -> {nv[0]} x{nv[1]}",
                        explanation="Negotiated link speed/width changed (retraining, ASPM/"
                        "bandwidth management, or link down)." + note,
                        raw=json.dumps({"before": ov, "after": nv}),
                        data={"before": ov, "after": nv},
                    )
                )
            elif k == "runtime_status":
                out.append(
                    make_event(
                        ts=now,
                        ts_source="poll_boottime",
                        source="poll:power",
                        device_id=dev_id,
                        severity="debug" if nv in ("active", "suspended") else "warning",
                        category="power",
                        kind="power.runtime_status",
                        summary=f"runtime PM {ov} -> {nv}",
                        explanation="Runtime PM status changed." + note,
                        raw=f"{path}/power/runtime_status: {ov} -> {nv}",
                        data={"from": ov, "to": nv},
                    )
                )
            elif k == "power_state":
                out.append(
                    make_event(
                        ts=now,
                        ts_source="poll_boottime",
                        source="poll:power",
                        device_id=dev_id,
                        severity="notice",
                        category="power",
                        kind="power.d_state",
                        summary=f"PCI power state {ov} -> {nv}",
                        explanation="PCI D-state changed." + note,
                        raw=f"{path}/power_state: {ov} -> {nv}",
                        data={"from": ov, "to": nv},
                    )
                )
            elif k == "speed":
                out.append(
                    make_event(
                        ts=now,
                        ts_source="poll_boottime",
                        source="poll:usb",
                        device_id=dev_id,
                        severity="warning",
                        category="usb_transfer",
                        kind="usb.speed_changed",
                        summary=f"USB speed {ov} -> {nv} Mb/s",
                        explanation="Negotiated USB speed changed (re-enumeration or fallback)." + note,
                        raw=f"{path}/speed: {ov} -> {nv}",
                        data={"from": ov, "to": nv},
                    )
                )
            elif k == "over_current_count":
                out.append(
                    make_event(
                        ts=now,
                        ts_source="poll_boottime",
                        source="poll:usb",
                        device_id=dev_id,
                        severity="error",
                        category="usb_error",
                        kind="usb.overcurrent_count",
                        summary=f"USB port over-current count {ov} -> {nv}",
                        explanation="The hub port's over-current counter increased." + note,
                        raw=f"over_current_count: {ov} -> {nv}",
                        data={"from": ov, "to": nv},
                    )
                )
        return out

    def poll_once(self) -> list[Event]:
        snap = self.ctx.inventory.snapshot
        if snap is None:
            return []
        out: list[Event] = []
        for d in snap.devices:
            if d.bus not in ("pci", "usb"):
                continue
            new = self.sample(d.id, d.sysfs_path, d.bus)
            st = self.state.setdefault(d.id, _DevState())
            if st.values:
                out += self.diff(d.id, d.sysfs_path, st.values, new)
            st.values = new
        return out

    async def run(self) -> None:
        while True:
            for ev in await asyncio.to_thread(self.poll_once):
                self.ctx.bus.publish(ev)
            await asyncio.sleep(self.interval)


# --------------------------------------------------------------------------- telemetry (Phase 4)


class TelemetryPoller(Source):
    """Periodic station/survey/netdev sampling for live charts. Read-only nl80211 GET dumps."""

    name = "telemetry"

    def __init__(self, ctx: Ctx, interval: float = 1.0) -> None:
        super().__init__(ctx)
        self.interval = interval
        self.prev: dict[str, tuple[int, dict[str, int]]] = {}  # key -> (boottime_ns, counters)
        self.assoc: dict[str, set[str]] = {}
        self.survey_every = 5
        self.tick = 0

    def _rate(self, key: str, now: int, counters: dict[str, int | None]) -> dict[str, float | None]:
        cur: dict[str, int] = {k: v for k, v in counters.items() if v is not None}
        out: dict[str, float | None] = {}
        prev = self.prev.get(key)
        if prev is not None:
            dt = (now - prev[0]) / 1e9
            for k, v in cur.items():
                pv = prev[1].get(k)
                out[k] = (v - pv) / dt if pv is not None and dt > 0 and v >= pv else None
        self.prev[key] = (now, cur)
        return out

    def sample_once(self) -> tuple[list[TelemetrySample], list[Event]]:
        snap = self.ctx.inventory.snapshot
        nl = self.ctx.host.nl80211()
        samples: list[TelemetrySample] = []
        events: list[Event] = []
        if snap is None:
            return samples, events
        self.tick += 1
        for d in snap.devices:
            for n in d.netdev_info:
                now = boottime_ns()
                wall = boot_to_wall(now)
                st = self.ctx.host.root
                ctrs = {
                    k: st.attr_int(f"/sys/class/net/{n.name}/statistics/{k}")
                    for k in (
                        "rx_bytes",
                        "tx_bytes",
                        "rx_packets",
                        "tx_packets",
                        "rx_errors",
                        "tx_errors",
                        "rx_dropped",
                        "tx_dropped",
                    )
                }
                rates = self._rate(f"nd:{n.name}", now, ctrs)
                samples.append(
                    TelemetrySample(
                        ts_boottime_ns=now,
                        ts_wall=wall,
                        device_id=d.id,
                        series=f"netdev:{n.name}",
                        values={f"{k}_per_s": v for k, v in rates.items()},
                    )
                )
                if nl is None or n.ifindex is None or n.wifi is None:
                    continue
                try:
                    stas = nl.stations(n.ifindex)
                except Exception:
                    stas = []
                macs = {s.mac for s in stas}
                prev_macs = self.assoc.get(n.name)
                if prev_macs is not None and macs != prev_macs:
                    for gone in prev_macs - macs:
                        events.append(
                            make_event(
                                ts=now,
                                ts_source="poll_boottime",
                                source="telemetry",
                                device_id=d.id,
                                severity="notice",
                                category="association",
                                kind="station.gone",
                                summary=f"{n.name}: station {gone} no longer listed",
                                explanation="The station disappeared from the nl80211 "
                                "station dump between two telemetry polls.",
                                raw=gone,
                                data={"peer": gone, "ifname": n.name},
                            )
                        )
                    for new in macs - prev_macs:
                        events.append(
                            make_event(
                                ts=now,
                                ts_source="poll_boottime",
                                source="telemetry",
                                device_id=d.id,
                                severity="info",
                                category="association",
                                kind="station.new",
                                summary=f"{n.name}: station {new} listed",
                                explanation="A station appeared in the nl80211 station dump.",
                                raw=new,
                                data={"peer": new, "ifname": n.name},
                            )
                        )
                self.assoc[n.name] = macs
                for s in stas:
                    r = self._rate(
                        f"sta:{n.name}:{s.mac}",
                        now,
                        {
                            "tx_retries": s.tx_retries,
                            "tx_failed": s.tx_failed,
                            "rx_bytes": s.rx_bytes,
                            "tx_bytes": s.tx_bytes,
                            "beacon_loss": s.beacon_loss,
                            "rx_drop_misc": s.rx_drop_misc,
                        },
                    )
                    vals: dict[str, float | int | None] = {
                        "signal_dbm": s.signal_dbm,
                        "signal_avg_dbm": s.signal_avg_dbm,
                        "tx_bitrate_mbps": s.tx_rate.bitrate_mbps if s.tx_rate else None,
                        "rx_bitrate_mbps": s.rx_rate.bitrate_mbps if s.rx_rate else None,
                        "tx_mcs": s.tx_rate.mcs if s.tx_rate else None,
                        "rx_mcs": s.rx_rate.mcs if s.rx_rate else None,
                        "tx_nss": s.tx_rate.nss if s.tx_rate else None,
                        "tx_retries_per_s": r.get("tx_retries"),
                        "tx_failed_per_s": r.get("tx_failed"),
                        "rx_bytes_per_s": r.get("rx_bytes"),
                        "tx_bytes_per_s": r.get("tx_bytes"),
                        "beacon_loss": s.beacon_loss,
                        "rx_drop_misc_per_s": r.get("rx_drop_misc"),
                        "inactive_ms": s.inactive_ms,
                    }
                    for i, c in enumerate(s.chain_signal_dbm):
                        vals[f"chain{i}_dbm"] = c
                    samples.append(
                        TelemetrySample(
                            ts_boottime_ns=now,
                            ts_wall=wall,
                            device_id=d.id,
                            series=f"station:{n.name}:{s.mac}",
                            values=vals,
                        )
                    )
                    for link in s.links:
                        lr = self._rate(
                            f"stl:{n.name}:{s.mac}:{link.link_id}",
                            now,
                            {
                                "tx_bytes": link.tx_bytes,
                                "rx_bytes": link.rx_bytes,
                                "tx_retries": link.tx_retries,
                                "tx_failed": link.tx_failed,
                            },
                        )
                        samples.append(
                            TelemetrySample(
                                ts_boottime_ns=now,
                                ts_wall=wall,
                                device_id=d.id,
                                series=f"link:{n.name}:{s.mac}:{link.link_id}",
                                values={
                                    "signal_dbm": link.signal_dbm,
                                    "tx_bitrate_mbps": link.tx_rate.bitrate_mbps if link.tx_rate else None,
                                    "rx_bitrate_mbps": link.rx_rate.bitrate_mbps if link.rx_rate else None,
                                    "tx_bytes_per_s": lr.get("tx_bytes"),
                                    "rx_bytes_per_s": lr.get("rx_bytes"),
                                    "tx_retries_per_s": lr.get("tx_retries"),
                                },
                            )
                        )
                if self.tick % self.survey_every == 1:
                    try:
                        sv = [x for x in nl.survey(n.ifindex) if x.in_use]
                    except Exception:
                        sv = []
                    for x in sv:
                        busy = (x.busy_ms / x.time_ms * 100) if x.busy_ms is not None and x.time_ms else None
                        samples.append(
                            TelemetrySample(
                                ts_boottime_ns=now,
                                ts_wall=wall,
                                device_id=d.id,
                                series=f"survey:{n.name}",
                                values={"freq_mhz": x.freq_mhz, "noise_dbm": x.noise_dbm, "busy_pct": busy},
                            )
                        )
        return samples, events

    async def run(self) -> None:
        while True:
            samples, events = await asyncio.to_thread(self.sample_once)
            for s in samples:
                self.ctx.bus.publish_sample(s)
            for e in events:
                self.ctx.bus.publish(e)
            self.status.events += len(samples)
            await asyncio.sleep(self.interval)


# --------------------------------------------------------------------------- tracefs (via helper)


TRACE_LINE = re.compile(
    r"^\s*(?P<task>.+?)-(?P<pid>\d+)\s+(?:\(\s*[-\d]+\)\s+)?\[(?P<cpu>\d+)\]\s+(?:(?P<flags>[\w.]{4,6})\s+)?"
    r"(?P<ts>\d+\.\d+):\s+(?P<event>[\w.:-]+):\s?(?P<body>.*)$"
)
KV = re.compile(r"(\w+)[=:]\s?([^\s,]+)")


def trace_category(group: str, event: str) -> tuple[Category, Severity]:
    if group == "mt76" and event.startswith("mlo"):
        return "mlo", "debug"
    if group in ("mt76", "mt792x", "mt7921", "mt7925"):
        return "trace", "debug"
    if group == "mac80211":
        if event.startswith("drv_"):
            return "driver_state", "debug"
        return "association" if "assoc" in event or "auth" in event else "trace", "debug"
    if group == "cfg80211":
        return ("association" if event.startswith("cfg80211_") else "driver_state"), "debug"
    if group in ("pci",):
        return "pci_link", "info"
    if group in ("xhci-hcd", "usbcore"):
        return "usb_transfer", "debug"
    return "trace", "debug"


def parse_trace_line(line: str, event_groups: dict[str, str], clock: str) -> dict[str, Any] | None:
    m = TRACE_LINE.match(line)
    if not m:
        return None
    ev = m.group("event")
    group = event_groups.get(ev, ev.split(":")[0] if ":" in ev else "?")
    ts_s = m.group("ts")
    sec, frac = ts_s.split(".")
    ns = int(sec) * 1_000_000_000 + int(frac.ljust(9, "0")[:9])
    body = m.group("body")
    fields = dict(KV.findall(body))
    first = body.split(None, 1)[0] if body.strip() else ""
    if first and "=" not in first and ":" not in first:
        fields.setdefault("wiphy", first)  # mt76/mac80211 tracepoints print the wiphy name first
    return {
        "task": m.group("task").strip(),
        "pid": int(m.group("pid")),
        "cpu": int(m.group("cpu")),
        "event": ev,
        "group": group,
        "ts_ns": ns,
        "clock": clock,
        "body": body,
        "fields": fields,
    }


def trace_event_from_line(
    index: DeviceIndex, line: str, event_groups: dict[str, str], clock: str, offset: int = 0
) -> Event | None:
    """Convert one ftrace text line from WHD's tracefs instance into an Event (shared by live + demo)."""
    p = parse_trace_line(line, event_groups, clock)
    if p is None:
        return None
    cat, sev = trace_category(p["group"], p["event"])
    dev, method = index.by_text(p["body"])
    ts = p["ts_ns"] + offset if clock in ("boot", "mono") else boottime_ns()
    ts_source: TsSource = {"boot": "tracefs_boot", "mono": "tracefs_mono"}.get(clock, "receive_boottime")  # type: ignore[assignment]
    data = {k: v for k, v in p.items() if k not in ("body",)}
    if method:
        data["attribution"] = method
    return make_event(
        ts=ts,
        ts_source=ts_source,
        ts_raw=f"{p['ts_ns'] / 1e9:.6f} ({clock})",
        source=f"tracefs:{p['group']}",
        device_id=dev,
        severity=sev,
        category=cat,
        kind=f"trace.{p['group']}.{p['event']}",
        summary=f"{p['event']}: {p['body'][:160]}",
        explanation=f"Tracepoint {p['group']}:{p['event']} fired (isolated WHD tracefs instance; "
        f"fields as printed by the tracepoint's TP_printk).",
        raw=line,
        data=data,
    )


class TraceSource(Source):
    """Streams an isolated tracefs instance through whd-helper."""

    name = "tracefs"

    def __init__(self, ctx: Ctx, events: list[str], buffer_kb: int, max_seconds: int) -> None:
        super().__init__(ctx)
        self.events = events
        self.buffer_kb = buffer_kb
        self.max_seconds = max_seconds
        self.started: dict[str, Any] | None = None
        self.result: dict[str, Any] | None = None
        self.lines = 0

    async def run(self) -> None:
        helper = self.ctx.host.helper
        if helper is None or not helper.available:
            raise Unavailable("whd-helper not running (tracefs requires root)")
        event_groups: dict[str, str] = {}
        clock = "boot"
        offset = 0
        async for msg in helper.stream(
            "trace_stream", events=self.events, buffer_kb=self.buffer_kb, max_seconds=self.max_seconds
        ):
            if "stream_start" in msg:
                self.started = msg["stream_start"]
                clock = self.started.get("clock", "boot")
                for spec in self.started.get("events", []):
                    g, e = spec.split("/")
                    event_groups[e] = g
                if clock == "mono":
                    offset = mono_to_boot_offset_ns()
                self.status.detail = f"instance {self.started.get('instance')} clock={clock}"
                continue
            if "result" in msg:
                self.result = msg["result"]
                return
            for line in msg.get("stream", []):
                ev = trace_event_from_line(self.ctx.index, line, event_groups, clock, offset)
                if ev is None:
                    continue
                self.lines += 1
                self.ctx.bus.publish(ev)
            if msg.get("dropped"):
                self.status.detail = f"dropped {msg['dropped']} lines (rate limit)"


# --------------------------------------------------------------------------- replay


class ReplaySource(Source):
    """Replays recorded events (fixture events.jsonl or a capture) with original relative timing.
    Timestamps are rebased to now; the original timestamp and provenance stay in ts_raw/data."""

    name = "replay"

    def __init__(
        self,
        ctx: Ctx,
        events: list[Event],
        speed: float = 1.0,
        loop: bool = False,
        session: str | None = None,
        max_gap_s: float = 5.0,
        period_s: float | None = None,
    ) -> None:
        super().__init__(ctx)
        self.period_s = period_s
        self.events = sorted(events, key=lambda e: e.ts_boottime_ns)
        self.speed = max(0.05, speed)
        self.loop = loop
        self.session = session
        self.max_gap_s = max_gap_s
        self.position = 0

    async def run(self) -> None:
        if not self.events:
            raise Unavailable("nothing to replay")
        while True:
            base_orig = self.events[0].ts_boottime_ns
            base_now = boottime_ns()
            prev = base_orig
            shift = 0
            for i, e in enumerate(self.events):
                gap = (e.ts_boottime_ns - prev) / 1e9
                if gap > self.max_gap_s:
                    shift += int((gap - self.max_gap_s) * 1e9)
                    gap = self.max_gap_s
                if gap > 0:
                    await asyncio.sleep(gap / self.speed)
                prev = e.ts_boottime_ns
                ne = e.model_copy(deep=True)
                ne.id = None
                ne.ts_raw = f"orig {e.ts_boottime_ns / 1e9:.6f}s ({e.ts_source})" + (
                    f" {e.ts_raw}" if e.ts_raw else ""
                )
                ne.ts_source = "recorded"
                ne.ts_boottime_ns = base_now + int((e.ts_boottime_ns - base_orig - shift) / self.speed)
                ne.ts_wall = boot_to_wall(ne.ts_boottime_ns)
                ne.session = self.session
                ne.data = dict(ne.data) | {"replayed_from": self.session or "fixture"}
                self.position = i + 1
                self.ctx.bus.publish(ne)
            if not self.loop:
                return
            elapsed = (boottime_ns() - base_now) / 1e9
            await asyncio.sleep(
                max(1.0, (self.period_s or 0) / self.speed - elapsed) if self.period_s else 2.0
            )


def load_jsonl_events(path: Path) -> list[Event]:
    out = []
    for line in path.read_text().splitlines():
        line = line.strip()
        if line:
            out.append(Event.model_validate_json(line))
    return out


__all__ = [
    "Ctx",
    "JournalSource",
    "Nl80211Source",
    "ReplaySource",
    "RtnlSource",
    "Source",
    "SysfsPoller",
    "TelemetryPoller",
    "TraceSource",
    "UeventSource",
    "Unavailable",
    "load_jsonl_events",
    "make_event",
]


# --------------------------------------------------------------------------- usbmon (optional)

USBMON_TYPES = {"C": "Control", "Z": "Isoc", "I": "Interrupt", "B": "Bulk"}


def parse_usbmon_line(line: str) -> dict[str, Any] | None:
    """Parse one usbmon 'text' format line (Documentation/usb/usbmon.rst).

    `URB_TAG TIMESTAMP_US EVENT(S|C|E) ADDR[:Ci:bus:dev:ep] STATUS|s SETUP.. LENGTH [DATA_TAG DATA...]`
    """
    t = line.split()
    if len(t) < 6 or t[2] not in ("S", "C", "E"):
        return None
    addr = t[3].split(":")
    if len(addr) != 4 or len(addr[0]) != 2 or addr[0][0] not in USBMON_TYPES or addr[0][1] not in ("i", "o"):
        return None
    try:
        ts_us = int(t[1])
        bus, dev, ep = int(addr[1]), int(addr[2]), int(addr[3])
        idx = 4
        setup: list[str] | None = None
        status = 0
        if t[idx] == "s":
            setup = t[idx + 1 : idx + 6]
            idx += 6
            status = -115  # setup stage of a submit has no status
        else:
            status = int(t[idx].split(":")[0])
            idx += 1
        length = int(t[idx])
    except (ValueError, IndexError):
        return None
    return {
        "tag": t[0],
        "ts_us": ts_us,
        "event": t[2],
        "xfer": USBMON_TYPES[addr[0][0]],
        "dir": "in" if addr[0][1] == "i" else "out",
        "bus": bus,
        "dev": dev,
        "ep": ep,
        "status": status,
        "length": length,
        "setup": setup,
    }


@dataclass
class _EpAcc:
    submit: int = 0
    complete: int = 0
    bytes: int = 0
    errors: int = 0


class UsbmonSource(Source):
    """Streams usbmon text via whd-helper (usbmon must already be loaded; WHD never loads modules).

    Per-URB data is aggregated into 1 Hz telemetry (`usbmon:<device>` with per-endpoint counters) and every URB
    error becomes an event (capped at 20/s with a summary event for the remainder)."""

    name = "usbmon"
    MAX_ERR_EVENTS_PER_S = 20

    def __init__(self, ctx: Ctx, buses: list[int], max_seconds: int = 3600) -> None:
        super().__init__(ctx)
        self.buses = buses
        self.max_seconds = max_seconds
        self.acc: dict[tuple[str, str], _EpAcc] = {}
        self.err_budget = self.MAX_ERR_EVENTS_PER_S
        self.suppressed = 0
        self.lines = 0

    def flush(self) -> None:
        now = boottime_ns()
        per_dev: dict[str, dict[str, float | int | None]] = {}
        for (dev, ep), a in self.acc.items():
            v = per_dev.setdefault(dev, {})
            v[f"{ep}.submit"], v[f"{ep}.complete"], v[f"{ep}.bytes"], v[f"{ep}.errors"] = (
                a.submit,
                a.complete,
                a.bytes,
                a.errors,
            )
        for dev, vals in per_dev.items():
            self.ctx.bus.publish_sample(
                TelemetrySample(
                    ts_boottime_ns=now, ts_wall=boot_to_wall(now), device_id=dev, series="usbmon", values=vals
                )
            )
        if self.suppressed:
            self.ctx.bus.publish(
                make_event(
                    ts=now,
                    ts_source="receive_boottime",
                    source="usbmon",
                    severity="warning",
                    category="usb_error",
                    kind="usb.urb.errors_suppressed",
                    summary=f"{self.suppressed} further URB errors suppressed (rate cap)",
                    explanation="More than 20 URB errors/s occurred; only the first 20 per second are reported as events.",
                    raw=str(self.suppressed),
                    data={"suppressed": self.suppressed},
                )
            )
        self.acc.clear()
        self.err_budget, self.suppressed = self.MAX_ERR_EVENTS_PER_S, 0

    def handle_line(self, line: str) -> Event | None:
        u = parse_usbmon_line(line)
        if u is None:
            return None
        self.lines += 1
        dev = self.ctx.index.usb_busdev.get((u["bus"], u["dev"]))
        if dev is None:
            return None  # not one of the wireless devices WHD tracks
        ep = f"ep{u['ep']}{'i' if u['dir'] == 'in' else 'o'}"
        a = self.acc.setdefault((dev, ep), _EpAcc())
        if u["event"] == "S":
            a.submit += 1
            if u["dir"] == "out":
                a.bytes += u["length"]
            return None
        a.complete += 1
        if u["dir"] == "in":
            a.bytes += u["length"]
        if u["status"] == 0:
            return None
        a.errors += 1
        if self.err_budget <= 0:
            self.suppressed += 1
            return None
        self.err_budget -= 1
        import errno as _errno

        name = _errno.errorcode.get(-u["status"], str(u["status"])) if u["status"] < 0 else str(u["status"])
        now = u["ts_us"] * 1000 + mono_to_boot_offset_ns()
        return make_event(
            ts=now,
            ts_source="usbmon_monotonic",
            ts_raw=f"{u['ts_us'] / 1e6:.6f}s (CLOCK_MONOTONIC)",
            source="usbmon",
            device_id=dev,
            severity="error",
            category="usb_error",
            kind="usb.urb.error",
            summary=f"URB error {name} on {u['xfer']} {u['dir']} ep{u['ep']} (bus {u['bus']} dev {u['dev']}, "
            f"{u['length']} B)",
            explanation=f"A {u['xfer']} URB completed with status {u['status']} ({name}). Status 0 is success; "
            "negative values are -errno from the USB core (e.g. -EPROTO/-EILSEQ are bus-level "
            "transaction errors, -ENODEV the device vanished, -EPIPE a stall).",
            raw=line,
            data=u,
        )

    async def run(self) -> None:
        helper = self.ctx.host.helper
        if helper is None or not helper.available:
            raise Unavailable("whd-helper not running (usbmon requires root)")
        if not self.buses:
            raise Unavailable("no USB wireless devices to monitor")

        async def one(bus: int) -> None:
            async for msg in helper.stream("usbmon_stream", bus=str(bus), max_seconds=self.max_seconds):
                for line in msg.get("stream", []):
                    ev = self.handle_line(line)
                    if ev is not None:
                        self.ctx.bus.publish(ev)

        async def ticker() -> None:
            while True:
                await asyncio.sleep(1.0)
                self.flush()

        tasks = [asyncio.create_task(one(b)) for b in self.buses] + [asyncio.create_task(ticker())]
        try:
            done, _ = await asyncio.wait(tasks, return_when=asyncio.FIRST_EXCEPTION)
            for t in done:
                if t.exception():
                    exc = t.exception()
                    if exc is not None and getattr(exc, "code", "") == "missing":
                        raise Unavailable(str(exc))
                    raise exc  # type: ignore[misc]
        finally:
            for t in tasks:
                t.cancel()
