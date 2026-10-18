"""API/report models for MLO evidence. Every claim carries the observations it rests on and its limits."""

from __future__ import annotations

from typing import Any, Literal

from pydantic import Field

from whd.model.common import Model

# What an evidence item is. A reader must be able to tell a request from a result from a verified delivery.
StageClass = Literal[
    "queued_request",  # something asked for (frame queued, command sent, ROC requested)
    "core_complete",  # a kernel core operation reported done (mac80211/cfg80211)
    "firmware_result",  # firmware answered (status code / return value)
    "verified_delivery",  # a frame demonstrably reached the stack after security checks
    "observation",  # context only
]

# Why a value is missing. Never collapsed into "no": absence of evidence is not evidence of absence.
GapKind = Literal[
    "no_collector",  # nothing on this system can supply it
    "not_traced",  # a collector exists but was not running for this window
    "absent_while_collected",  # the collector was running and recorded nothing for it
    "not_applicable",
]

TriState = Literal["yes", "no", "unknown", "driver_only"]


class Scope(Model):
    """Every observation belongs to exactly one boot, device, association epoch and (optionally) link lifetime."""

    boot_id: str
    device_id: str
    association_epoch: str | None
    link_id: int | None = None
    link_lifetime: str | None = None
    interface: str | None = None
    interface_lifetime: str | None = None
    phy: str | None = None


class EvidenceRef(Model):
    event_id: int | None = None
    ts_boottime_ns: int | None = None
    kind: str
    text: str = ""
    source: str = "event"  # event | debugfs | nl80211 | sysfs | pcap


class Gap(Model):
    kind: GapKind
    what: str
    collector: str | None = None  # which tracepoint/tag/tool would supply it
    detail: str | None = None


class Dimension(Model):
    value: TriState
    basis: str
    evidence: list[EvidenceRef] = Field(default_factory=list)
    limits: str | None = None
    historical: bool = False  # true when derived from past events rather than a reading taken now


class LinkState(Model):
    link_id: int
    scope: Scope
    mac: str | None = None
    bssid: str | None = None
    freq_mhz: int | None = None
    channel: int | None = None
    band: str | None = None
    width_mhz: int | None = None
    wcid: int | None = None
    negotiated: Dimension
    active: Dimension
    fw_programmed: Dimension
    authorized: Dimension
    authenticated_delivery: Dimension
    counters: dict[str, Any] = Field(default_factory=dict)
    conflicts: list[str] = Field(default_factory=list)


class StageObs(Model):
    stage: str
    stage_class: StageClass
    ts_boottime_ns: int | None
    result: str | None = None  # status / ret as observed; never reinterpreted
    link_id: int | None = None
    token: str | None = None  # request cookie when the evidence carries one
    evidence: list[EvidenceRef] = Field(default_factory=list)
    note: str | None = None


class Epoch(Model):
    interface: str | None = None
    interface_lifetime: str | None = None
    id: str  # "<boot>:<n>"
    boot_id: str
    device_id: str
    local_address: str | None
    peer: str | None
    start_ns: int
    end_ns: int | None
    started_observed: bool  # false when WHD saw the epoch already in progress
    outcome: Literal["associated", "rejected", "timed_out", "disconnected", "in_progress", "unknown"]
    stages: list[StageObs]
    first_missing: str | None
    missing: list[str]
    gaps: list[Gap] = Field(default_factory=list)
    flags: list[str] = Field(default_factory=list)
    request_tokens: list[str] = Field(default_factory=list)
    historical: bool = True
