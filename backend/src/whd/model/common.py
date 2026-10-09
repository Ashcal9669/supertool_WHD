from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field


class Model(BaseModel):
    """Base for API models: defaulted fields are always present in responses (schema says required)."""

    model_config = ConfigDict(json_schema_serialization_defaults_required=True)


Availability = Literal["ok", "partial", "unavailable", "requires_privilege", "unsupported", "error"]
IssueKind = Literal["not_exposed", "requires_privilege", "device_error", "unsupported", "error"]


class Issue(Model):
    source: str
    kind: IssueKind
    detail: str


class SectionMeta(Model):
    """Provenance attached to every data section shown in the UI."""

    availability: Availability = "ok"
    sources: list[str] = Field(default_factory=list)
    issues: list[Issue] = Field(default_factory=list)
    note: str | None = None


class Section(Model):
    meta: SectionMeta = Field(default_factory=SectionMeta)
