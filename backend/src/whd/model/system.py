from __future__ import annotations

from typing import Literal

from pydantic import Field

from whd.model.common import Model

IntegrationState = Literal["ok", "missing", "no_permission", "via_helper", "disabled", "error"]


class Integration(Model):
    name: str
    state: IntegrationState
    detail: str | None = None
    enables: str


class SystemInfo(Model):
    hostname: str
    kernel_release: str
    kernel_version: str | None = None
    arch: str
    distro: str | None = None
    python: str | None = None
    whd_version: str
    mode: Literal["live", "demo"]
    demo_scenario: str | None = None
    fixture_kind: str | None = None
    fixture_description: str | None = None
    fixture_events_kind: str | None = None
    fixture_events_description: str | None = None
    uid: int
    euid: int
    running_as_root: bool
    helper: dict[str, object] = Field(default_factory=dict)
    integrations: list[Integration] = Field(default_factory=list)
