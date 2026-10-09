from __future__ import annotations

from whd.model.common import Issue, SectionMeta
from whd.platform.sysfs import ReadIssue, ReadLog


def issue(i: ReadIssue) -> Issue:
    return Issue(source=i.path, kind=i.kind, detail=i.detail)


def meta_from_log(
    log: ReadLog, expected: int | None = None, note: str | None = None, ignore_not_exposed: bool = True
) -> SectionMeta:
    """Availability: ok if all reads worked; partial if some failed; unavailable if none worked.

    `not_exposed` (ENOENT) attributes are normal for optional sysfs files, so by
    default they are recorded but do not downgrade availability.
    """
    issues = [issue(i) for i in log.issues]
    hard = [i for i in log.issues if not (ignore_not_exposed and i.kind == "not_exposed")]
    if not log.sources and log.issues:
        if all(i.kind == "requires_privilege" for i in log.issues):
            av = "requires_privilege"
        else:
            av = "unavailable"
    elif hard:
        av = "partial"
    else:
        av = "ok"
    return SectionMeta(availability=av, sources=list(dict.fromkeys(log.sources)), issues=issues, note=note)  # type: ignore[arg-type]
