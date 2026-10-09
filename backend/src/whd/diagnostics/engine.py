"""Evidence-based diagnostic engine.

Pipeline (all deterministic, no language model):
  events -> significant events -> incidents (time clusters) -> observations / patterns / correlations
         -> hypotheses (explicit rules; always `unconfirmed`) -> missing instrumentation -> follow-up tests

Rules of the road
  * Observations are mechanical facts with event-id evidence. Hypotheses reference observations, list contradicting
    evidence and unknowns, and are never promoted to causes (`cause_confirmed` is always False).
  * Absence of evidence is reported as a *missing instrumentation* item, never as evidence of absence.
  * Ordering of events across layers is reported as observed order; log timestamps have different resolutions
    (see limits), so order within about a poll interval is not trustworthy.
"""

from __future__ import annotations

import statistics
import time
import uuid
from collections import Counter, defaultdict
from itertools import pairwise
from typing import Any

from whd import __version__
from whd.diagnostics.models import (
    Correlation,
    DiagnosticReport,
    FollowUp,
    Hypothesis,
    Incident,
    IncidentEvent,
    Layer,
    MissingInstrumentation,
    Observation,
    ObsKind,
    Pattern,
    Scope,
)
from whd.model.device import Device
from whd.model.events import SEVERITY_RANK, Event

LAYER_BY_CATEGORY: dict[str, Layer] = {
    "pci_error": "bus",
    "pci_link": "bus",
    "usb_error": "bus",
    "usb_transfer": "bus",
    "hotplug": "bus",
    "power": "bus",
    "driver_state": "driver",
    "trace": "driver",
    "kernel_log": "driver",
    "telemetry": "driver",
    "system": "driver",
    "diagnostic": "driver",
    "firmware": "firmware",
    "reset": "firmware",
    "association": "mac80211",
    "phy": "mac80211",
    "mlo": "mac80211",
    "scan": "mac80211",
    "regulatory": "mac80211",
    "netdev": "netdev",
}
LAYER_ORDER: list[Layer] = ["bus", "driver", "firmware", "mac80211", "netdev"]

SIGNIFICANT_PREFIXES = (
    "reset.",
    "firmware.init_done",
    "firmware.patch_load",
    "uevent.pci.bind",
    "uevent.pci.unbind",
    "uevent.usb",
    "netdev.state",
    "netdev.removed",
    "assoc.associated",
    "assoc.authenticate",
    "nl80211.connect",
    "nl80211.disconnect",
    "nl80211.deauthenticate",
    "nl80211.disassociate",
    "nl80211.port_authorized",
    "mt76.mlo_active_links_changed",
    "usb.enumerate",
    "usb.disconnect",
    "usb.reset",
    "pci.link.changed",
    "inventory.",
)
BUS_FAULT_KINDS = (
    "pci.aer.received",
    "pci.aer.bus_error",
    "pci.aer.counter.nonfatal",
    "pci.aer.counter.fatal",
    "pci.link.changed",
    "pci.link.down",
    "pci.not_ready",
    "usb.urb.error",
    "usb.reset",
    "usb.disconnect",
    "usb.descriptor_error",
    "usb.address_error",
    "usb.xhci_error",
    "usb.overcurrent",
    "usb.speed_changed",
)
CLUSTER_GAP_S = 8.0
CORRELATION_WINDOW_S = 6.0

DISCLAIMER = (
    "This report lists observations and unconfirmed hypotheses derived from captured evidence. WHD does not "
    "assert a root cause. Hypotheses are starting points for the listed follow-up tests."
)


def layer_of(e: Event) -> Layer:
    return LAYER_BY_CATEGORY.get(e.category, "driver")


def is_significant(e: Event) -> bool:
    if e.kind.startswith("trace.") and not (e.kind == "trace.mt76.mcu_resp" and _f(e, "timeout") == "1"):
        return False
    if SEVERITY_RANK[e.severity] >= SEVERITY_RANK["warning"]:
        return True
    return e.kind.startswith(SIGNIFICANT_PREFIXES)


def _f(e: Event, key: str) -> str | None:
    fields = (e.data or {}).get("fields")
    return fields.get(key) if isinstance(fields, dict) else None


def _is_mcu_timeout(e: Event) -> bool:
    return e.kind == "firmware.mcu_timeout" or (e.kind == "trace.mt76.mcu_resp" and _f(e, "timeout") == "1")


# --------------------------------------------------------------------------------------------------- incidents


def cluster_incidents(sig: list[Event], gap_s: float = CLUSTER_GAP_S) -> list[list[Event]]:
    groups: list[list[Event]] = []
    for e in sorted(sig, key=lambda x: x.ts_boottime_ns):
        if groups and (e.ts_boottime_ns - groups[-1][-1].ts_boottime_ns) / 1e9 <= gap_s:
            groups[-1].append(e)
        else:
            groups.append([e])
    # a cluster of only routine state events (no warning+) is not an incident
    return [g for g in groups if any(SEVERITY_RANK[e.severity] >= SEVERITY_RANK["warning"] for e in g)]


def _is_core(e: Event) -> bool:
    return SEVERITY_RANK[e.severity] >= SEVERITY_RANK["warning"] or e.kind.startswith("reset.")


def build_incident(idx: int, evs: list[Event]) -> Incident:
    """Incident timing is anchored on the fault evidence (warning+ or reset events). Routine state changes in the
    cluster (bind, association, firmware load) are kept for counts and context but never count as 'first observed'."""
    core = [e for e in evs if _is_core(e)] or evs
    t0 = core[0].ts_boottime_ns
    first_by_layer: dict[Layer, Event] = {}
    for e in core:
        first_by_layer.setdefault(layer_of(e), e)
    seq = [
        IncidentEvent(
            id=e.id,
            ts_boottime_ns=e.ts_boottime_ns,
            rel_s=round((e.ts_boottime_ns - t0) / 1e9, 3),
            layer=lay,
            severity=e.severity,
            kind=e.kind,
            summary=e.summary[:160],
        )
        for lay, e in sorted(first_by_layer.items(), key=lambda kv: kv[1].ts_boottime_ns)
    ]
    earliest = [s.layer for s in seq if s.rel_s <= 1.0]
    sev = max(evs, key=lambda e: SEVERITY_RANK[e.severity]).severity
    return Incident(
        id=f"I{idx}",
        device_ids=sorted({e.device_id for e in evs if e.device_id}),
        start_ns=t0,
        end_ns=evs[-1].ts_boottime_ns,
        duration_s=round((evs[-1].ts_boottime_ns - t0) / 1e9, 3),
        severity=sev,
        event_count=len(evs),
        layers=[s.layer for s in seq],
        sequence=seq,
        earliest_layers=earliest,
        kinds=dict(Counter(e.kind for e in evs)),
    )


# --------------------------------------------------------------------------------------------------- patterns


def find_patterns(sig: list[Event]) -> list[Pattern]:
    by: dict[tuple[str | None, str], list[Event]] = defaultdict(list)
    for e in sig:
        if SEVERITY_RANK[e.severity] >= SEVERITY_RANK["warning"]:
            by[(e.device_id, e.kind)].append(e)
    out: list[Pattern] = []
    for (dev, kind), evs in sorted(by.items(), key=lambda kv: -len(kv[1])):
        if len(evs) < 3:
            continue
        evs.sort(key=lambda e: e.ts_boottime_ns)
        ts = [e.ts_boottime_ns / 1e9 for e in evs]
        gaps = [b - a for a, b in pairwise(ts)]
        med = statistics.median(gaps)
        cv = (
            (statistics.pstdev(gaps) / statistics.mean(gaps))
            if len(gaps) > 1 and statistics.mean(gaps) > 0
            else 0.0
        )
        burst = max(ts) - min(ts) < 5 * max(med, 1.0) and len(evs) >= 3 and med < 2.0
        reg = "burst" if burst else "periodic" if cv < 0.25 and len(evs) >= 4 else "irregular"
        out.append(
            Pattern(
                id=f"P{len(out) + 1}",
                device_id=dev,
                kind=kind,
                count=len(evs),
                first_ns=evs[0].ts_boottime_ns,
                last_ns=evs[-1].ts_boottime_ns,
                median_interval_s=round(med, 3),
                min_interval_s=round(min(gaps), 3),
                max_interval_s=round(max(gaps), 3),
                regularity=reg,  # type: ignore[arg-type]
                note=(
                    f"{len(evs)} occurrences; intervals median {med:.2f}s (min {min(gaps):.2f}, max {max(gaps):.2f}); "
                    f"coefficient of variation {cv:.2f}"
                ),
                evidence_event_ids=[e.id for e in evs if e.id][:12],
            )
        )
    return out[:12]


# --------------------------------------------------------------------------------------------------- correlations


def find_correlations(incidents: list[list[Event]]) -> list[Correlation]:
    pair_inc: Counter[tuple[str, str]] = Counter()
    pair_before: Counter[tuple[str, str]] = Counter()
    lags: dict[tuple[str, str], list[float]] = defaultdict(list)
    layer_of_kind: dict[str, Layer] = {}
    for inc in incidents:
        first: dict[str, Event] = {}
        for e in inc:
            if SEVERITY_RANK[e.severity] >= SEVERITY_RANK["warning"] or e.kind.startswith("reset."):
                first.setdefault(e.kind, e)
                layer_of_kind[e.kind] = layer_of(e)
        kinds = sorted(first)
        for i, a in enumerate(kinds):
            for b in kinds[i + 1 :]:
                ea, eb = first[a], first[b]
                lo, hi = (a, b) if ea.ts_boottime_ns <= eb.ts_boottime_ns else (b, a)
                lag = abs(eb.ts_boottime_ns - ea.ts_boottime_ns) / 1e9
                pair_inc[(lo, hi)] += 1
                if lag <= CORRELATION_WINDOW_S:
                    pair_before[(lo, hi)] += 1
                    lags[(lo, hi)].append(lag)
    out: list[Correlation] = []
    for (a, b), n in sorted(pair_inc.items(), key=lambda kv: (-kv[1], kv[0])):
        nb = pair_before[(a, b)]
        if nb == 0:
            continue
        la = sorted(lags[(a, b)])
        out.append(
            Correlation(
                id=f"C{len(out) + 1}",
                a_kind=a,
                b_kind=b,
                a_layer=layer_of_kind[a],
                b_layer=layer_of_kind[b],
                incidents_with_both=n,
                incidents_a_before_b=nb,
                median_lag_s=round(statistics.median(la), 3),
                max_window_s=CORRELATION_WINDOW_S,
                note=(
                    f"In {nb} of {len(incidents)} incident(s) '{a}' was observed first and '{b}' followed within "
                    f"{CORRELATION_WINDOW_S:.0f}s (median lag {statistics.median(la):.2f}s). "
                    + (
                        "Single occurrence: no repeatability evidence."
                        if nb < 2
                        else "Repeated, but still only an ordering of observations."
                    )
                ),
            )
        )
        if len(out) >= 15:
            break
    return out


# --------------------------------------------------------------------------------------------------- follow-ups

FOLLOW_UPS: dict[str, FollowUp] = {
    f.id: f
    for f in [
        FollowUp(
            id="F-mcu-trace",
            title="Capture MCU command lifecycle around the failure",
            how="Apply the optional mt76 tracepoint patch (docs/patches/0001) to a build you control, then run a WHD "
            "capture with trace events mt76/mcu_send,mcu_resp. Shows which command stalled and prior latencies.",
            distinguishes=["H-fw-unresponsive"],
            safety="needs-user-action",
            whd_feature="mt76 tab → Instrumentation coverage → patch proposals",
        ),
        FollowUp(
            id="F-aer",
            title="Compare PCIe AER counters and status before/after an incident",
            how="Device → Bus tab shows AER counters (sysfs) and, with the helper, decoded AER registers. Note "
            "whether uncorrectable status bits or fatal counters change at the failure instant.",
            distinguishes=["H-bus-precedes", "H-fw-unresponsive", "H-pcie-degraded"],
            safety="read-only",
            whd_feature="Device → Bus",
        ),
        FollowUp(
            id="F-link",
            title="Watch negotiated PCIe link width/speed across the incident",
            how="Keep the Timeline open (pci.link.changed events) or start a capture; compare with the root port "
            "capabilities in the topology view. Retraining at the same instant as the fault points at the link.",
            distinguishes=["H-bus-precedes", "H-pcie-degraded"],
            safety="read-only",
            whd_feature="Timeline / Topology",
        ),
        FollowUp(
            id="F-repeat",
            title="Repeat the capture under the same workload",
            how="Run another capture of equal length with the same traffic. Compare incident count and interval "
            "(Diagnostics → patterns). Repeatability separates a systematic fault from a one-off.",
            distinguishes=["H-fw-unresponsive", "H-bus-precedes", "H-usb-instability", "H-ap-initiated"],
            safety="read-only",
            whd_feature="Captures",
        ),
        FollowUp(
            id="F-usbmon",
            title="Capture usbmon around the failure",
            how="With usbmon already loaded, start the usbmon capture (Captures page). Check which endpoint's URBs "
            "complete with errors first and whether errors precede the reset.",
            distinguishes=["H-usb-instability", "H-bus-precedes"],
            safety="read-only",
            whd_feature="Captures → usbmon",
        ),
        FollowUp(
            id="F-usb-physical",
            title="Rule out the physical USB path",
            how="Move the adapter to another port (preferably a direct motherboard port, not a hub) and use a "
            "different cable; re-run the capture.",
            distinguishes=["H-usb-instability"],
            safety="needs-user-action",
        ),
        FollowUp(
            id="F-ap",
            title="Check the access point's view of the disconnect",
            how="Compare with AP logs or a second client's capture of the same period; reason codes in WHD show what "
            "mac80211 reported, not why the peer sent it.",
            distinguishes=["H-ap-initiated"],
            safety="needs-user-action",
        ),
        FollowUp(
            id="F-pm",
            title="Check whether power-management transitions coincide with failures",
            how="Compare power events (runtime PM, ownership handshake) with the incident start in the Timeline. A "
            "controlled A/B with runtime PM control set to 'on' (a configuration change you must make yourself) "
            "would test it.",
            distinguishes=["H-pm-adjacent"],
            safety="needs-user-action",
            whd_feature="Device → Power / Timeline",
        ),
        FollowUp(
            id="F-fwfile",
            title="Verify the firmware files the driver requested",
            how="Device → Driver & firmware lists files declared by the module; confirm they exist under "
            "/lib/firmware and match the driver version, and read the kernel log around probe.",
            distinguishes=["H-fw-load"],
            safety="read-only",
            whd_feature="Device → Driver & firmware",
        ),
    ]
}


# --------------------------------------------------------------------------------------------------- engine


class _Obs:
    def __init__(self) -> None:
        self.items: list[Observation] = []

    def add(
        self, kind: ObsKind, text: str, ev: list[Event] | None = None, device_id: str | None = None
    ) -> str:
        oid = f"O{len(self.items) + 1}"
        self.items.append(
            Observation(
                id=oid,
                kind=kind,
                text=text,
                device_id=device_id,
                evidence_event_ids=[e.id for e in (ev or []) if e.id][:12],
            )
        )
        return oid


def _first(evs: list[Event], pred: Any) -> Event | None:
    return next((e for e in evs if pred(e)), None)


def analyze(
    events: list[Event],
    devices: list[Device],
    *,
    window_s: float | None = None,
    coverage: dict[str, str] | None = None,
    helper_ok: bool = False,
    demo: bool = False,
    capture_id: str | None = None,
    device_filter: str | None = None,
) -> DiagnosticReport:
    events = sorted(events, key=lambda e: e.ts_boottime_ns)
    sig = [e for e in events if is_significant(e)]
    obs = _Obs()
    groups = cluster_incidents(sig)
    incidents = [build_incident(i + 1, g) for i, g in enumerate(groups)]
    patterns = find_patterns(sig)
    corr = find_correlations(groups)
    devmap = {d.id: d for d in devices}
    warn = [e for e in sig if SEVERITY_RANK[e.severity] >= SEVERITY_RANK["warning"]]
    unattributed = sum(1 for e in events if not e.device_id)

    # ----- observations
    obs.add(
        "count",
        f"{len(events)} events analyzed, {len(sig)} significant (severity ≥ warning or state-changing "
        f"kinds), {len(warn)} at warning or above; {len(incidents)} incident(s) (events within "
        f"{CLUSTER_GAP_S:.0f}s of each other).",
    )
    if unattributed:
        obs.add(
            "coverage",
            f"{unattributed} event(s) carry no device attribution (e.g. kernel printk lines without a "
            "device prefix); they are included in time-based incident clustering but not assigned to a device.",
        )
    kinds = Counter(e.kind for e in warn)
    for kind, n in kinds.most_common(8):
        ev = [e for e in warn if e.kind == kind]
        obs.add(
            "first_last",
            f"'{kind}': {n}x (warning+), first {_rel(ev[0], events)}, last {_rel(ev[-1], events)}.",
            ev,
        )
    for d in devices:
        if device_filter and d.id != device_filter:
            continue
        if d.pci and d.pci.link:
            lk = d.pci.link
            obs.add(
                "state",
                f"{d.id}: PCIe link {lk.current_speed} x{lk.current_width} (maximum {lk.max_speed} "
                f"x{lk.max_width}); {'below maximum' if lk.degraded else 'at maximum'}.",
                device_id=d.id,
            )
        if d.power.aspm:
            obs.add(
                "state",
                f"{d.id}: ASPM L0s {'on' if d.power.aspm.get('l0s_enabled') else 'off'}, L1 "
                f"{'on' if d.power.aspm.get('l1_enabled') else 'off'} (decoded from Link Control).",
                device_id=d.id,
            )
        if d.driver:
            taint = d.driver_info.module_sysfs.get("taint", "")
            obs.add(
                "state",
                f"{d.id}: driver {d.driver} (module {d.module}), firmware "
                f"{d.firmware_version or 'version not reported'}"
                f"{', out-of-tree module (taint O)' if 'O' in taint else ''}.",
                device_id=d.id,
            )
        else:
            obs.add("state", f"{d.id}: no driver bound.", device_id=d.id)
    for inc in incidents:
        chain = " → ".join(f"{s.layer}@+{s.rel_s:g}s" for s in inc.sequence)
        obs.add(
            "timing",
            f"Incident {inc.id} ({inc.severity}, {inc.duration_s:g}s, {inc.event_count} events): first "
            f"significant event per layer in observed order: {chain}.",
            [ev for ev in groups[int(inc.id[1:]) - 1] if ev.id][:6],
        )
    for p in patterns:
        obs.add(
            "recurrence", f"{p.id}: {p.kind} on {p.device_id or 'unattributed'} — {p.note} ({p.regularity})."
        )

    # ----- hypotheses
    hyps: list[Hypothesis] = []
    missing: list[MissingInstrumentation] = []

    def cov(item: str) -> str:
        return (coverage or {}).get(item, "unknown")

    # H-fw-unresponsive
    fw_incs = []
    for g in groups:
        to = _first(g, _is_mcu_timeout)
        rs = _first(g, lambda e: e.kind in ("reset.chip_reset", "reset.chip_reset_failed"))
        if (
            to
            and rs
            and rs.ts_boottime_ns >= to.ts_boottime_ns
            and (rs.ts_boottime_ns - to.ts_boottime_ns) / 1e9 <= 10
        ):
            fw_incs.append((g, to, rs))
    if fw_incs:
        contra: list[str] = []
        ev_ids: list[int] = []
        sup: list[str] = []
        for g, to, rs in fw_incs:
            retry = [e for e in g if e.kind == "firmware.mcu_retry" and e.ts_boottime_ns <= to.ts_boottime_ns]
            sup.append(
                obs.add(
                    "timing",
                    f"MCU timeout ('{to.kind}') at {_rel(to, events)} followed by "
                    f"'{rs.kind}' {(rs.ts_boottime_ns - to.ts_boottime_ns) / 1e9:.2f}s later"
                    f"{f' after {len(retry)} retry message(s)' if retry else ''}.",
                    [*retry, to, rs],
                )
            )
            ev_ids += [e.id for e in (*retry, to, rs) if e.id]
            before = [
                e
                for e in g
                if e.ts_boottime_ns < to.ts_boottime_ns
                and e.kind
                in (
                    "pci.aer.received",
                    "pci.aer.bus_error",
                    "pci.aer.counter.nonfatal",
                    "pci.aer.counter.fatal",
                    "pci.link.down",
                    "pci.not_ready",
                    "usb.urb.error",
                    "usb.disconnect",
                    "pci.link.changed",
                )
            ]
            if before:
                contra.append(
                    obs.add(
                        "timing",
                        "Bus-level event(s) preceded the MCU timeout in the same incident: "
                        f"{', '.join(sorted({e.kind for e in before}))} — the bus may be the "
                        "initiator rather than the firmware.",
                        before,
                    )
                )
        if not any(e.kind.startswith("trace.mt76.mcu_") for e in events):
            missing.append(
                MissingInstrumentation(
                    id="M-mcu",
                    what="MCU command submit/response tracepoints",
                    why_it_matters="Without them it is unknown which command stalled, its prior latency, and whether "
                    "responses were slow or absent before the timeout.",
                    proposal="docs/patches/0001-mt76-trace-mcu-command-lifecycle.diff (optional, compile-tested only)",
                )
            )
        missing.append(
            MissingInstrumentation(
                id="M-reset-stages",
                what="Reset/recovery stage tracepoints",
                why_it_matters="Recovery duration and the stage that failed are only inferable from log text.",
                proposal="Proposal only (no diff): mt792x:reset_stage tracepoints around the recovery sequence.",
            )
        )
        hyps.append(
            Hypothesis(
                id="H-fw-unresponsive",
                title="MCU/firmware stopped answering host commands",
                statement=(
                    "In "
                    f"{len(fw_incs)} incident(s) an MCU command timed out and the driver then reset the chip. This is "
                    "consistent with the firmware (or the host↔firmware command path) becoming unresponsive. The "
                    "evidence places the boundary at the host driver ↔ MCU command channel, not at the radio or the "
                    "network."
                ),
                confidence="moderate" if len(fw_incs) >= 2 and not contra else "low",
                failure_boundary="host driver ↔ MCU/firmware command channel",
                supporting=sup,
                supporting_event_ids=ev_ids[:20],
                contradicting=contra,
                unknowns=[
                    "Whether the firmware crashed, hung on one command, or the DMA/interrupt path stalled: all produce "
                    "the same log lines.",
                    "Why the command was sent at that moment (what triggered it).",
                    "Whether a bus fault happened without being logged (corrected AER is rate-limited/not logged).",
                ],
                missing_instrumentation=[m.id for m in missing if m.id in ("M-mcu", "M-reset-stages")],
                follow_up_ids=["F-mcu-trace", "F-aer", "F-repeat"],
            )
        )

    # H-bus-precedes
    bus_first = []
    for g in groups:
        b = _first(
            g, lambda e: e.kind in BUS_FAULT_KINDS and SEVERITY_RANK[e.severity] >= SEVERITY_RANK["warning"]
        )
        later = [
            e
            for e in g
            if layer_of(e) in ("driver", "firmware")
            and SEVERITY_RANK[e.severity] >= SEVERITY_RANK["warning"]
            and b
            and e.ts_boottime_ns > b.ts_boottime_ns
        ]
        if (
            b
            and later
            and (later[0].ts_boottime_ns - b.ts_boottime_ns) / 1e9 <= 8
            and layer_of(g[0]) == "bus"
            and g[0].kind in BUS_FAULT_KINDS
        ):
            bus_first.append((g, b, later[0]))
    if bus_first:
        sup = []
        ev_ids = []
        for _g, b, lt in bus_first:
            sup.append(
                obs.add(
                    "timing",
                    f"Bus event '{b.kind}' at {_rel(b, events)} was the first significant event of its "
                    f"incident; driver/firmware '{lt.kind}' followed {(lt.ts_boottime_ns - b.ts_boottime_ns) / 1e9:.2f}s "
                    "later.",
                    [b, lt],
                )
            )
            ev_ids += [e.id for e in (b, lt) if e.id]
        benign = all(
            b.kind == "pci.aer.counter.correctable" or b.severity == "warning" for _, b, _ in bus_first
        )
        hyps.append(
            Hypothesis(
                id="H-bus-precedes",
                title="A bus-level event preceded the driver/firmware errors",
                statement=(
                    "In "
                    f"{len(bus_first)} incident(s) the earliest significant event was on the bus (PCIe/USB) and "
                    "driver or firmware errors followed within seconds. The bus may have contributed. Ordering alone "
                    "does not show causation; corrected PCIe errors in particular are routinely benign."
                ),
                confidence="low",
                failure_boundary="bus / link (unproven)",
                supporting=sup,
                supporting_event_ids=ev_ids[:20],
                contradicting=(
                    []
                    if not benign
                    else [
                        obs.add(
                            "state",
                            "The preceding bus events are corrected/warning-level "
                            "only (no uncorrectable AER or link-down), which weakens this hypothesis.",
                        )
                    ]
                ),
                unknowns=[
                    "Whether the bus event is the cause, a symptom of the same underlying fault, or a coincidence.",
                    "Polling granularity (2 s) limits ordering precision for sysfs-detected bus events.",
                ],
                follow_up_ids=["F-aer", "F-link", "F-usbmon", "F-repeat"],
            )
        )

    # H-pcie-degraded
    for d in devices:
        if device_filter and d.id != device_filter:
            continue
        plk = d.pci.link if d.pci else None
        if plk and plk.degraded:
            o1 = obs.add(
                "state",
                f"{d.id}: negotiated PCIe link ({plk.current_speed} x{plk.current_width}) is below the "
                f"maximum ({plk.max_speed} x{plk.max_width}).",
                device_id=d.id,
            )
            cor = [
                e
                for e in events
                if e.device_id == d.id and e.kind in ("pci.aer.counter.correctable", "pci.link.changed")
            ]
            o2 = obs.add(
                "count",
                f"{len(cor)} correctable-AER/link-change event(s) for this device in the window.",
                cor,
                d.id,
            )
            hyps.append(
                Hypothesis(
                    id="H-pcie-degraded",
                    title=f"PCIe link for {d.id} is operating below its capability",
                    statement="The link trained below the maximum speed/width. Reasons include slot/riser limits, power "
                    "management, or signal-integrity retraining; sysfs alone cannot say which.",
                    confidence="low",
                    failure_boundary="PCIe link",
                    supporting=[o1, o2],
                    unknowns=[
                        "Whether the maximum is reachable by the platform (sysfs reports device and port capabilities)."
                    ],
                    follow_up_ids=["F-link", "F-aer"],
                )
            )

    # H-usb-instability
    usb_evs = [
        e
        for e in warn
        if e.kind
        in (
            "usb.reset",
            "usb.disconnect",
            "usb.urb.error",
            "usb.descriptor_error",
            "usb.address_error",
            "usb.xhci_error",
            "usb.speed_changed",
        )
    ]
    if len(usb_evs) >= 2:
        c = Counter(e.kind for e in usb_evs)
        sup = [
            obs.add(
                "count",
                "USB transport events: " + ", ".join(f"{k}x{v}" for k, v in c.most_common()) + ".",
                usb_evs,
            )
        ]
        hyps.append(
            Hypothesis(
                id="H-usb-instability",
                title="The USB transport is unstable",
                statement="Resets, disconnects and/or URB completion errors were observed. Common contributors are "
                "port/cable/hub quality, bus power, and host-controller problems; the data cannot discriminate.",
                confidence="moderate" if len(usb_evs) >= 5 else "low",
                failure_boundary="USB host/device transport",
                supporting=sup,
                supporting_event_ids=[e.id for e in usb_evs if e.id][:20],
                unknowns=[
                    "Whether errors originate in the device, cable, hub, or xHCI controller.",
                    "usbmon data (URB-level ordering) is needed to see which transfer failed first.",
                ],
                missing_instrumentation=["M-usbmon"]
                if not any(e.kind.startswith("usb.urb") for e in events)
                else [],
                follow_up_ids=["F-usbmon", "F-usb-physical", "F-repeat"],
            )
        )
        if not any(e.kind.startswith("usb.urb") for e in events):
            missing.append(
                MissingInstrumentation(
                    id="M-usbmon",
                    what="URB-level (usbmon) data",
                    why_it_matters="Without URB traces the first failing transfer/endpoint is unknown.",
                    proposal="Load usbmon yourself (WHD never loads modules) and start a usbmon capture.",
                )
            )

    # H-ap-initiated
    ap = [
        e
        for e in events
        if e.kind in ("assoc.deauth_by_ap", "assoc.disassoc_by_ap", "assoc.timeout", "assoc.connection_lost")
        or (
            e.kind in ("nl80211.disconnect", "nl80211.deauthenticate", "nl80211.disassociate")
            and (e.data or {}).get("by_ap")
        )
    ]
    loc = [e for e in events if e.kind == "assoc.deauth_local"]
    if ap:
        reasons = Counter(
            str((e.data or {}).get("reason") or (e.data or {}).get("rname") or "n/a") for e in ap
        )
        o = obs.add(
            "count",
            f"{len(ap)} disconnect event(s) reported by mac80211/nl80211 as peer-initiated or lost "
            f"link (reasons: {dict(reasons)}); {len(loc)} local-choice deauth(s).",
            ap,
        )
        hyps.append(
            Hypothesis(
                id="H-ap-initiated",
                title="The peer (AP) ended or dropped the association",
                statement="mac80211 reported the disconnect as received from the AP (or a lost connection). The reason code "
                "states what the peer said, not why.",
                confidence="low",
                failure_boundary="wireless link / AP",
                supporting=[o],
                supporting_event_ids=[e.id for e in ap if e.id][:20],
                contradicting=(
                    [
                        obs.add(
                            "count",
                            f"{len(loc)} local-choice deauthentication(s) were also logged, so not all "
                            "disconnects were peer-initiated.",
                            loc,
                        )
                    ]
                    if loc
                    else []
                ),
                unknowns=["AP-side logs are not available to WHD."],
                follow_up_ids=["F-ap", "F-repeat"],
            )
        )

    # H-pm-adjacent
    pm_hits = []
    for g in groups:
        first_err = _first(g, lambda e: SEVERITY_RANK[e.severity] >= SEVERITY_RANK["error"])
        if not first_err:
            continue
        pm = [
            e
            for e in events
            if e.kind
            in ("power.ownership_failed", "power.dstate_failed", "power.runtime_status", "power.d_state")
            and 0 <= (first_err.ts_boottime_ns - e.ts_boottime_ns) / 1e9 <= 2.0
        ]
        if pm:
            pm_hits.append((first_err, pm))
    if pm_hits:
        sup = [
            obs.add(
                "timing",
                f"Power transition(s) {sorted({e.kind for e in pm})} within 2s before error "
                f"'{fe.kind}' at {_rel(fe, events)}.",
                [*pm, fe],
            )
            for fe, pm in pm_hits
        ]
        hyps.append(
            Hypothesis(
                id="H-pm-adjacent",
                title="A power-management transition was adjacent to the first error",
                statement="Runtime PM/ownership transitions occurred shortly before the first error of an incident. Runtime "
                "PM transitions are frequent in normal operation, so adjacency alone is weak evidence.",
                confidence="low",
                failure_boundary="power management (unproven)",
                supporting=sup,
                unknowns=["The base rate of these transitions when no error occurs (not measured here)."],
                follow_up_ids=["F-pm", "F-repeat"],
            )
        )

    # H-fw-load
    fl = [
        e
        for e in warn
        if e.kind
        in ("firmware.file_missing", "firmware.load_error", "driver.probe_failed", "driver.init_error")
    ]
    if fl:
        o = obs.add(
            "count",
            "Initialization/firmware-load failures: " + "; ".join(sorted({e.summary[:80] for e in fl})) + ".",
            fl,
        )
        hyps.append(
            Hypothesis(
                id="H-fw-load",
                title="Driver initialization or firmware loading failed",
                statement="The kernel log shows a probe/init/firmware-load failure; the device is unusable until it is fixed.",
                confidence="moderate",
                failure_boundary="driver probe / firmware load",
                supporting=[o],
                supporting_event_ids=[e.id for e in fl if e.id][:20],
                unknowns=["Whether the file is missing, mismatched, or rejected by the device."],
                follow_up_ids=["F-fwfile"],
            )
        )

    # ----- generic missing instrumentation (derived, with reasons)
    if not helper_ok:
        missing.append(
            MissingInstrumentation(
                id="M-helper",
                what="Privileged helper not connected",
                why_it_matters="PCIe config space (AER/ASPM/link registers), tracefs, debugfs and usbmon are unavailable; "
                "several hypotheses cannot be tested.",
                proposal="Start whd-helper (make helper); it only performs fixed read-only operations.",
            )
        )
    if unattributed:
        missing.append(
            MissingInstrumentation(
                id="M-attribution",
                what="Device attribution for custom driver printk lines",
                why_it_matters=f"{unattributed} event(s) cannot be tied to a specific adapter; with several adapters, "
                "per-device analysis misses them.",
                proposal="Use dev_info()/dev_dbg() (device-prefixed) for driver debug lines; WHD attributes by prefix.",
            )
        )
    for item, label in (
        ("mcu_lifecycle", "MCU command lifecycle"),
        ("tid_to_link", "TID-to-link mapping"),
        ("fw_timeouts_recovery", "Firmware recovery stages"),
    ):
        if cov(item) in ("partial", "missing", "log_only") and not any(
            m.id == f"M-cov-{item}" for m in missing
        ):
            missing.append(
                MissingInstrumentation(
                    id=f"M-cov-{item}",
                    what=f"{label}: {cov(item)} on this kernel",
                    why_it_matters="See the mt76 instrumentation coverage report for the exact missing interfaces.",
                )
            )
    if not any(e.source.startswith("tracefs") for e in events) and any(
        h.id in ("H-fw-unresponsive",) for h in hyps
    ):
        missing.append(
            MissingInstrumentation(
                id="M-no-trace",
                what="No tracepoint capture in this window",
                why_it_matters="Datapath/command tracepoints could narrow down what the driver was doing before the failure.",
                proposal="Start a trace session (mt76 tab) before reproducing.",
            )
        )

    fus = [FOLLOW_UPS[i] for i in dict.fromkeys(i for h in hyps for i in h.follow_up_ids)]
    limits = [
        "Timestamps come from different clocks: kernel printk (µs, converted with the current CLOCK_BOOTTIME offset; "
        "off by any suspend time), tracefs boot clock (ns), and WHD receive time for netlink/uevent events. Events "
        "from sysfs polling are accurate only to the polling interval (2 s).",
        "Only events WHD received are analyzed; WHD has no kernel history from before it started except the journal "
        "backfill, and journald/ratelimit can drop messages.",
        "Hypotheses use fixed, documented rules; absence of a hypothesis does not mean absence of a problem.",
    ]
    devs = sorted({e.device_id for e in events if e.device_id})
    scope = Scope(
        device_ids=devs,
        window_s=window_s,
        event_count=len(events),
        significant_event_count=len(sig),
        sources=sorted({e.source.split(":")[0] for e in events}),
        first_ns=events[0].ts_boottime_ns if events else None,
        last_ns=events[-1].ts_boottime_ns if events else None,
        demo=demo,
        capture_id=capture_id,
        unattributed_events=unattributed,
    )
    if not events:
        obs.add("count", "No events in the analyzed scope; nothing to correlate.")
    _ = devmap
    return DiagnosticReport(
        report_id="dx-" + uuid.uuid4().hex[:8],
        generated_at=time.time(),
        whd_version=__version__,
        scope=scope,
        disclaimer=DISCLAIMER,
        observations=obs.items,
        incidents=incidents,
        patterns=patterns,
        correlations=corr,
        hypotheses=hyps,
        missing_instrumentation=missing,
        follow_ups=fus,
        limits=limits,
    )


def _rel(e: Event, events: list[Event]) -> str:
    t0 = events[0].ts_boottime_ns if events else e.ts_boottime_ns
    return f"+{(e.ts_boottime_ns - t0) / 1e9:.1f}s"
