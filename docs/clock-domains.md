# Clock domains and timestamp conversion

WHD correlates events from sources that each use a different clock. Every event stores **one canonical timestamp**
and the provenance needed to judge how far to trust it.

| Field | Meaning |
|---|---|
| `ts_boottime_ns` | **Canonical.** `CLOCK_BOOTTIME` in nanoseconds (monotonic, keeps counting across suspend). All sorting, windows, incident clustering and replay use this. |
| `ts_source` | Where the stamp came from (table below). |
| `ts_raw` | The original value in its own clock domain, as a string (e.g. `10766.704939 (boot)`). |
| `ts_wall` | **Derived**, display only: `now_wall - (now_boot - ts_boottime_ns)`. Not used for logic; it shifts if the system clock is stepped. |

## Sources and conversions

| `ts_source` | Producer | Original clock | Conversion to `CLOCK_BOOTTIME` | Accuracy / caveat |
|---|---|---|---|---|
| `tracefs_boot` | tracefs instance `instances/whd` with `trace_clock=boot` | `CLOCK_BOOTTIME` (ns) | none (identical clock) | Exact. The helper selects `boot` whenever the kernel offers it. |
| `tracefs_mono` | same instance, if only `mono` is available | `CLOCK_MONOTONIC` (ns) | `ts + (BOOTTIME - MONOTONIC)` at receive time | Exact apart from the suspend caveat below. If neither clock exists the helper falls back to `local` and WHD stamps `receive_boottime`. |
| `kernel_printk` | journald `_SOURCE_MONOTONIC_TIMESTAMP` (printk `local_clock`, µs) | `CLOCK_MONOTONIC`-aligned | `ts = mono_us*1000 + (BOOTTIME - MONOTONIC)` measured at receive time | Exact if no suspend occurred between the message and its receipt; otherwise late by the suspend time. µs resolution. |
| `journal_monotonic` | journald `__MONOTONIC_TIMESTAMP` (when the source stamp is absent) | `CLOCK_MONOTONIC` | same as above | Receipt-time of journald, not of printk. |
| `usbmon_monotonic` | usbmon text line timestamp (µs) | `CLOCK_MONOTONIC` | same offset method | Same suspend caveat. |
| `receive_boottime` | uevent, nl80211 multicast, rtnetlink | none supplied by the kernel in the message | `CLOCK_BOOTTIME` read when WHD dequeues the message | Latency = scheduling + queueing (typically sub-millisecond, unbounded under load). Message order from one socket is exact. |
| `poll_boottime` | sysfs/debugfs pollers, inventory rescans, telemetry | derived from a periodic read | `CLOCK_BOOTTIME` of the read | **Only accurate to the polling interval** (2 s for sysfs, 1 s for telemetry/debugfs). Event text says so. |
| `netlink_boottime` | values the kernel itself supplies in a message (e.g. `NL80211_STA_INFO_ASSOC_AT_BOOTTIME`) | `CLOCK_BOOTTIME` | none | Reserved for such attributes. |
| `recorded` | capture/fixture replay | rebased | `base_now + (orig - orig_first)/speed` | Original stamp preserved in `ts_raw`; gaps longer than the replay's `max_gap` are compressed. |

## The monotonic→boottime offset

`offset = CLOCK_BOOTTIME - CLOCK_MONOTONIC` equals total suspended time since boot. WHD samples both clocks around a
`CLOCK_BOOTTIME` read (`clock.mono_to_boot_offset_ns`) and applies the *current* offset. Messages older than the last
suspend would be placed too late by the suspended duration; WHD does not track suspend history, and says so in the
analysis `limits`.

## Ordering guarantees

* Within one source: exact (arrival order, or the source's own timestamps).
* Across kernel sources (printk vs tracefs): comparable at µs level when both timestamps are kernel-supplied.
* Anything involving `receive_boottime` or `poll_boottime`: comparable only at the latency/poll granularity. The
  diagnostic engine reports ordering of observations, never causation, for this reason.
