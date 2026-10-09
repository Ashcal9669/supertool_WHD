"""Diagnostic report model. Observations, hypotheses and (never-asserted) causes are separate lists on purpose."""

from __future__ import annotations

from typing import Literal

from pydantic import Field

from whd.model.common import Model

Layer = Literal["bus", "driver", "firmware", "mac80211", "netdev"]


ObsKind = Literal["count", "first_last", "state", "timing", "recurrence", "coverage"]


class Observation(Model):
    """A fact derived mechanically from events/inventory. Never interpretive."""

    id: str
    kind: ObsKind
    text: str
    evidence_event_ids: list[int] = Field(default_factory=list)
    device_id: str | None = None


class IncidentEvent(Model):
    id: int | None
    ts_boottime_ns: int
    rel_s: float
    layer: Layer
    severity: str
    kind: str
    summary: str


class Incident(Model):
    id: str
    device_ids: list[str]
    start_ns: int
    end_ns: int
    duration_s: float
    severity: str
    event_count: int
    layers: list[Layer]
    sequence: list[IncidentEvent] = Field(
        description="first observed significant event per layer, in time order"
    )
    earliest_layers: list[Layer] = Field(description="layers with a significant event in the first second")
    kinds: dict[str, int]


class Pattern(Model):
    id: str
    device_id: str | None
    kind: str
    count: int
    first_ns: int
    last_ns: int
    median_interval_s: float | None
    min_interval_s: float | None
    max_interval_s: float | None
    regularity: Literal["periodic", "irregular", "burst"]
    note: str
    evidence_event_ids: list[int] = Field(default_factory=list)


class Correlation(Model):
    id: str
    a_kind: str
    b_kind: str
    a_layer: Layer
    b_layer: Layer
    incidents_with_both: int
    incidents_a_before_b: int
    median_lag_s: float | None
    max_window_s: float
    note: str


class Hypothesis(Model):
    id: str
    title: str
    statement: str
    status: Literal["unconfirmed"] = "unconfirmed"
    confidence: Literal["low", "moderate"] = "low"
    failure_boundary: str | None = Field(
        default=None, description="where the evidence places the boundary, if at all"
    )
    supporting: list[str] = Field(description="observation ids")
    supporting_event_ids: list[int] = Field(default_factory=list)
    contradicting: list[str] = Field(default_factory=list)
    unknowns: list[str] = Field(default_factory=list)
    missing_instrumentation: list[str] = Field(default_factory=list)
    follow_up_ids: list[str] = Field(default_factory=list)


class FollowUp(Model):
    id: str
    title: str
    how: str
    distinguishes: list[str] = Field(description="hypothesis ids this test helps separate")
    safety: Literal["read-only", "needs-user-action"]
    whd_feature: str | None = None


class MissingInstrumentation(Model):
    id: str
    what: str
    why_it_matters: str
    proposal: str | None = None


class Scope(Model):
    device_ids: list[str]
    window_s: float | None
    event_count: int
    significant_event_count: int
    sources: list[str]
    first_ns: int | None
    last_ns: int | None
    demo: bool
    capture_id: str | None = None
    imported: bool = False
    unattributed_events: int = 0


class DiagnosticReport(Model):
    report_id: str
    generated_at: float
    whd_version: str
    scope: Scope
    cause_confirmed: bool = Field(default=False, description="always false: WHD does not assert root causes")
    disclaimer: str
    observations: list[Observation]
    incidents: list[Incident]
    patterns: list[Pattern]
    correlations: list[Correlation]
    hypotheses: list[Hypothesis]
    missing_instrumentation: list[MissingInstrumentation]
    follow_ups: list[FollowUp]
    limits: list[str]
