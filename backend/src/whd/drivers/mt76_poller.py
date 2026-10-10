"""Read-only periodic sampling of passive mt76 debugfs files (queue rings, link mask, PM counters).

Only files classified `passive` by the helper policy are read (no chip wake, no MMIO, no MCU). Samples feed the
TX/RX queue activity views; changes in the MLO active-link mask and runtime PM wake counters become events.
"""

from __future__ import annotations

import asyncio
from typing import Any

from whd.clock import boot_to_wall, boottime_ns
from whd.drivers import mt76
from whd.events.sources import Source, Unavailable, make_event
from whd.helper.protocol import HelperError
from whd.model.events import TelemetrySample


class Mt76Poller(Source):
    name = "mt76"
    retry_unavailable_s = 5.0  # the privileged helper may be started after the server

    def __init__(self, ctx: Any, interval: float = 1.0) -> None:
        super().__init__(ctx)
        self.interval = interval
        self.prev_q: dict[str, int] = {}
        self.prev_links: dict[str, int] = {}
        self.prev_wakes: dict[str, int] = {}
        self.avail: dict[str, set[str]] = {}

    def _targets(self) -> list[tuple[str, str]]:
        snap = self.ctx.inventory.snapshot
        if snap is None:
            return []
        return [(d.id, phy) for d in snap.devices if mt76.is_mt76(d) for phy in d.phys]

    def _read(self, phy: str, path: str) -> str | None:
        h = self.ctx.host.helper
        assert h is not None
        try:
            return str(h.call("debugfs_read", 5.0, phy=phy, path=path).get("text") or "")
        except HelperError:
            return None

    def sample_once(self) -> tuple[list[TelemetrySample], list[Any]]:
        samples: list[TelemetrySample] = []
        events: list[Any] = []
        for dev_id, phy in self._targets():
            now = boottime_ns()
            wall = boot_to_wall(now)
            x = self._read(phy, "mt76/xmit-queues")
            if x is not None:
                vals: dict[str, float | int | None] = {}
                for q in mt76.parse_xmit_queues(x):
                    n = q["name"]
                    vals[f"{n}.queued"] = q.get("queued")
                    ci = q.get("cpu_idx")
                    key = f"{phy}:x:{n}"
                    if ci is not None:
                        if key in self.prev_q:
                            vals[f"{n}.submitted"] = ci - self.prev_q[key]
                        self.prev_q[key] = ci
                samples.append(
                    TelemetrySample(
                        ts_boottime_ns=now,
                        ts_wall=wall,
                        device_id=dev_id,
                        series=f"mt76q:{phy}:xmit",
                        values=vals,
                    )
                )
            r = self._read(phy, "mt76/rx-queues")
            if r is not None:
                vals = {}
                for q in mt76.parse_rx_queues(r):
                    i = q["queue"]
                    vals[f"rx{i}.queued"] = q["hw_queued"]
                    key = f"{phy}:r:{i}"
                    if key in self.prev_q:
                        vals[f"rx{i}.advanced"] = (q["head"] - self.prev_q[key]) % max(q["hw_queued"] + 1, 1)
                    self.prev_q[key] = q["head"]
                samples.append(
                    TelemetrySample(
                        ts_boottime_ns=now,
                        ts_wall=wall,
                        device_id=dev_id,
                        series=f"mt76q:{phy}:rx",
                        values=vals,
                    )
                )
            a = self._read(phy, "mt76/mlo_active_links")
            if a:
                try:
                    mask = int(a.strip(), 0)
                except ValueError:
                    mask = None
                if mask is not None:
                    old = self.prev_links.get(f"{dev_id}:{phy}")
                    self.prev_links[f"{dev_id}:{phy}"] = mask
                    if old is not None and old != mask:
                        added = sorted(set(mt76.bitmask_links(mask)) - set(mt76.bitmask_links(old)))
                        removed = sorted(set(mt76.bitmask_links(old)) - set(mt76.bitmask_links(mask)))
                        events.append(
                            make_event(
                                ts=now,
                                ts_source="poll_boottime",
                                source="mt76:debugfs",
                                device_id=dev_id,
                                severity="notice",
                                category="mlo",
                                kind="mt76.mlo_active_links_changed",
                                summary=f"MLO active links 0x{old:x} -> 0x{mask:x} (+{added} -{removed})",
                                explanation="debugfs mt76/mlo_active_links changed between polls (driver-reported "
                                "active MLO link mask). Detected by polling; the exact instant is not known.",
                                raw=f"mlo_active_links: {old:#x} -> {mask:#x}",
                                data={
                                    "from": old,
                                    "to": mask,
                                    "added_links": added,
                                    "removed_links": removed,
                                },
                            )
                        )
            p = self._read(phy, "mt76/runtime_pm_stats")
            if p:
                st = mt76.parse_runtime_pm(p)
                w = st.get("low_power_wakes")
                if w is not None:
                    old_w = self.prev_wakes.get(f"{dev_id}:{phy}")
                    self.prev_wakes[f"{dev_id}:{phy}"] = w
                    samples.append(
                        TelemetrySample(
                            ts_boottime_ns=now,
                            ts_wall=wall,
                            device_id=dev_id,
                            series=f"mt76pm:{phy}",
                            values=dict(st),
                        )
                    )
                    if old_w is not None and w - old_w >= 20:
                        events.append(
                            make_event(
                                ts=now,
                                ts_source="poll_boottime",
                                source="mt76:debugfs",
                                device_id=dev_id,
                                severity="info",
                                category="power",
                                kind="mt76.pm_wake_burst",
                                summary=f"{w - old_w} low-power wakes in {self.interval:.0f}s",
                                explanation="runtime_pm_stats 'low power wakes' counter jumped; the chip left doze "
                                "that many times since the previous poll.",
                                raw=p,
                                data={"delta": w - old_w},
                            )
                        )
        return samples, events

    async def run(self) -> None:
        h = self.ctx.host.helper
        if h is None or not h.available:
            raise Unavailable("whd-helper not running (mt76 debugfs requires root)")
        while True:
            samples, events = await asyncio.to_thread(self.sample_once)
            for s in samples:
                self.ctx.bus.publish_sample(s)
            for e in events:
                self.ctx.bus.publish(e)
            self.status.events += len(samples)
            await asyncio.sleep(self.interval)
