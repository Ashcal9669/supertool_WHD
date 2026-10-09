"""Clock domains and conversions (see docs/clock-domains.md).

Canonical event time is CLOCK_BOOTTIME in nanoseconds: it is monotonic, does
not jump with NTP/settimeofday, and keeps counting across suspend, which is what
kernel trace_clock=boot and nl80211 *_BOOTTIME attributes use.
"""

from __future__ import annotations

import time


def boottime_ns() -> int:
    return time.clock_gettime_ns(time.CLOCK_BOOTTIME)


def monotonic_ns() -> int:
    return time.clock_gettime_ns(time.CLOCK_MONOTONIC)


def mono_to_boot_offset_ns() -> int:
    """CLOCK_BOOTTIME - CLOCK_MONOTONIC right now = total time spent suspended since boot.

    Converting a CLOCK_MONOTONIC stamp t with the *current* offset is exact if
    no suspend happened between t and now; otherwise the result is late by the
    suspend duration. Callers record ts_source so this caveat stays visible.
    """
    a = time.clock_gettime_ns(time.CLOCK_MONOTONIC)
    b = time.clock_gettime_ns(time.CLOCK_BOOTTIME)
    c = time.clock_gettime_ns(time.CLOCK_MONOTONIC)
    return b - (a + c) // 2


def boot_to_wall(ts_boot_ns: int) -> float:
    """Derived wall clock for display: now_wall - (now_boot - ts)."""
    return time.time() - (boottime_ns() - ts_boot_ns) / 1e9


def wall_to_boot(wall: float) -> int:
    return boottime_ns() - int((time.time() - wall) * 1e9)
