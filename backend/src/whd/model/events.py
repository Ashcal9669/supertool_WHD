from __future__ import annotations

from typing import Any, Literal

from pydantic import Field

from whd.model.common import Model

Severity = Literal["debug", "info", "notice", "warning", "error", "critical"]
SEVERITY_RANK: dict[str, int] = {"debug": 0, "info": 1, "notice": 2, "warning": 3, "error": 4, "critical": 5}

TsSource = Literal[
    "tracefs_boot",  # tracefs instance trace_clock=boot: CLOCK_BOOTTIME at the event
    "tracefs_mono",  # tracefs instance trace_clock=mono: CLOCK_MONOTONIC, converted with the boot offset
    "kernel_printk",  # printk timestamp (local_clock), converted with a boot-time offset
    "journal_monotonic",  # journald __MONOTONIC_TIMESTAMP (CLOCK_MONOTONIC), converted
    "receive_boottime",  # no kernel timestamp: CLOCK_BOOTTIME when WHD received it
    "poll_boottime",  # derived by WHD from a periodic read; CLOCK_BOOTTIME of the read
    "netlink_boottime",  # kernel-provided boottime value inside the message (e.g. ASSOC_AT_BOOTTIME)
    "usbmon_monotonic",  # usbmon text timestamp (CLOCK_MONOTONIC microseconds), converted
    "recorded",  # replayed from a capture/fixture: original provenance preserved in ts_raw
]

Category = Literal[
    "kernel_log",
    "pci_error",
    "pci_link",
    "usb_error",
    "usb_transfer",
    "hotplug",
    "driver_state",
    "firmware",
    "association",
    "phy",
    "mlo",
    "reset",
    "power",
    "scan",
    "regulatory",
    "trace",
    "telemetry",
    "netdev",
    "diagnostic",
    "system",
]


class Event(Model):
    id: int | None = None
    ts_boottime_ns: int = Field(description="Canonical timestamp: CLOCK_BOOTTIME nanoseconds")
    ts_source: TsSource
    ts_raw: str | None = Field(default=None, description="Original timestamp in its own clock domain")
    ts_wall: float = Field(description="Derived wall clock (unix seconds) - display only")
    source: str
    device_id: str | None = None
    severity: Severity = "info"
    category: Category
    kind: str
    summary: str
    explanation: str
    raw: str
    data: dict[str, Any] = Field(default_factory=dict)
    demo: bool = False
    session: str | None = None


class EventFilter(Model):
    device_id: str | None = None
    categories: list[str] | None = None
    min_severity: Severity | None = None
    sources: list[str] | None = None
    kinds: list[str] | None = None
    text: str | None = None
    since_ns: int | None = None
    until_ns: int | None = None

    def matches(self, e: Event) -> bool:
        if self.device_id and e.device_id != self.device_id:
            return False
        if self.categories and e.category not in self.categories:
            return False
        if self.min_severity and SEVERITY_RANK[e.severity] < SEVERITY_RANK[self.min_severity]:
            return False
        if self.sources and not any(e.source.startswith(s) for s in self.sources):
            return False
        if self.kinds and not any(e.kind.startswith(k) for k in self.kinds):
            return False
        if self.since_ns is not None and e.ts_boottime_ns < self.since_ns:
            return False
        if self.until_ns is not None and e.ts_boottime_ns > self.until_ns:
            return False
        if self.text:
            t = self.text.lower()
            if t not in e.summary.lower() and t not in e.raw.lower() and t not in e.kind.lower():
                return False
        return True


class TelemetrySample(Model):
    """A periodic numeric sample (for charts). Not an event; kept in a bounded ring."""

    ts_boottime_ns: int
    ts_wall: float
    device_id: str | None
    series: str
    values: dict[str, float | int | None]
    demo: bool = False
