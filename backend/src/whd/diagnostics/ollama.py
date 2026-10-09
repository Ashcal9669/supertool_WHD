"""Optional local Ollama integration: summarize an already-computed diagnostic report.

* WHD works fully without this module being used. Nothing here feeds back into analysis.
* The prompt contains only report fields (observations, incident sequences, hypotheses, follow-ups), never raw
  logs, tokens or keys. MAC addresses are masked unless disabled.
* Output is labeled as generated text, checked for citations of ids that do not exist, and for phrasing that
  asserts a root cause.
"""

from __future__ import annotations

import json
import re
import time
from typing import Any
from urllib.parse import urlparse

import httpx

from whd.capture.manager import Redactor
from whd.diagnostics.models import DiagnosticReport
from whd.model.common import Model

MODEL_RE = re.compile(r"^[A-Za-z0-9_.:/-]{1,100}$")
ID_RE = re.compile(r"\b([OHFPCMI]-?[A-Za-z0-9-]*\d*)\b")

SYSTEM = (
    "You summarize a Linux wireless-hardware diagnostic report for an engineer. Rules: use ONLY facts in the JSON "
    "report; do not invent devices, numbers, log lines, causes or fixes. The report's hypotheses are UNCONFIRMED: "
    "present them as hypotheses and never as the cause. Cite ids in brackets like [O3], [H-fw-unresponsive], [F-repeat] "
    "for every claim. If the report has few observations say so plainly. Keep it under 250 words. Use exactly three "
    "headings: 'Observed', 'Hypotheses (unconfirmed)', 'Next tests'."
)


class OllamaStatus(Model):
    url: str
    reachable: bool
    loopback: bool
    models: list[dict[str, Any]]
    configured_model: str | None
    error: str | None = None


class Summary(Model):
    generated_by: str
    model: str
    report_id: str
    text: str
    elapsed_s: float
    eval_tokens: int | None
    warnings: list[str]
    not_evidence: bool = True
    prompt_chars: int


def is_loopback(url: str) -> bool:
    h = urlparse(url).hostname or ""
    return h in ("localhost", "127.0.0.1", "::1")


def report_for_prompt(rep: DiagnosticReport, redact: bool) -> str:
    d = {
        "scope": rep.scope.model_dump(exclude={"sources"}),
        "observations": [{"id": o.id, "text": o.text} for o in rep.observations][:40],
        "incidents": [
            {
                "id": i.id,
                "severity": i.severity,
                "duration_s": i.duration_s,
                "sequence": [f"{s.layer}@+{s.rel_s}s {s.kind}" for s in i.sequence],
            }
            for i in rep.incidents
        ][:12],
        "patterns": [
            {"id": p.id, "note": p.note, "kind": p.kind, "regularity": p.regularity} for p in rep.patterns
        ],
        "correlations": [{"id": c.id, "note": c.note} for c in rep.correlations][:8],
        "hypotheses": [
            {
                "id": h.id,
                "title": h.title,
                "statement": h.statement,
                "confidence": h.confidence,
                "supporting": h.supporting,
                "contradicting": h.contradicting,
                "unknowns": h.unknowns,
                "follow_ups": h.follow_up_ids,
            }
            for h in rep.hypotheses
        ],
        "missing_instrumentation": [{"id": m.id, "what": m.what} for m in rep.missing_instrumentation],
        "follow_ups": [{"id": f.id, "title": f.title} for f in rep.follow_ups],
    }
    text = json.dumps(d, indent=1)
    return Redactor().text(text) if redact else text


def check_summary(text: str, rep: DiagnosticReport) -> list[str]:
    valid = (
        {o.id for o in rep.observations}
        | {h.id for h in rep.hypotheses}
        | {f.id for f in rep.follow_ups}
        | {i.id for i in rep.incidents}
        | {p.id for p in rep.patterns}
        | {c.id for c in rep.correlations}
        | {m.id for m in rep.missing_instrumentation}
    )
    warns = []
    cited = set(re.findall(r"\[([A-Za-z][A-Za-z0-9-]*\d*|[A-Za-z]-[A-Za-z0-9-]+)\]", text))
    bad = sorted(c for c in cited if c not in valid)
    if bad:
        warns.append(f"cites ids that are not in the report: {', '.join(bad)}")
    if not cited:
        warns.append("no report ids are cited; claims cannot be traced to evidence")
    if re.search(
        r"\broot cause\b[^.\n]{0,60}\b(is|was|being)\b|\bis caused by\b|\bwas caused by\b", text, re.I
    ):
        warns.append("wording may assert a cause; the report states no confirmed cause")
    for h in ("Observed", "Hypotheses", "Next tests"):
        if h.lower() not in text.lower():
            warns.append(f"missing expected heading '{h}'")
    return warns


class OllamaClient:
    def __init__(self, base_url: str, configured_model: str | None = None) -> None:
        self.base = base_url.rstrip("/")
        self.model = configured_model

    async def status(self) -> OllamaStatus:
        try:
            async with httpx.AsyncClient(timeout=httpx.Timeout(3.0)) as c:
                r = await c.get(f"{self.base}/api/tags")
                r.raise_for_status()
            models = [
                {
                    "name": m["name"],
                    "size": m.get("size"),
                    "parameters": (m.get("details") or {}).get("parameter_size"),
                }
                for m in r.json().get("models", [])
            ]
            return OllamaStatus(
                url=self.base,
                reachable=True,
                loopback=is_loopback(self.base),
                models=models,
                configured_model=self.model,
            )
        except (httpx.HTTPError, ValueError, KeyError) as e:
            return OllamaStatus(
                url=self.base,
                reachable=False,
                loopback=is_loopback(self.base),
                models=[],
                configured_model=self.model,
                error=f"{type(e).__name__}: {e}",
            )

    async def summarize(
        self, rep: DiagnosticReport, model: str | None, redact: bool = True, timeout_s: float = 240.0
    ) -> Summary:
        model = model or self.model
        if not model or not MODEL_RE.match(model):
            raise ValueError("a valid model name is required")
        st = await self.status()
        if not st.reachable:
            raise ConnectionError(f"Ollama not reachable at {self.base}: {st.error}")
        if model not in {m["name"] for m in st.models}:
            raise ValueError(f"model {model!r} is not installed in Ollama (WHD never pulls models)")
        prompt = f"Diagnostic report (JSON):\n{report_for_prompt(rep, redact)}\n\nWrite the summary now."
        body = {
            "model": model,
            "system": SYSTEM,
            "prompt": prompt,
            "stream": False,
            "keep_alive": "1m",
            "options": {"temperature": 0.1, "num_predict": 600, "num_ctx": 8192},
        }
        t0 = time.monotonic()
        async with httpx.AsyncClient(timeout=httpx.Timeout(timeout_s, connect=3.0)) as c:
            r = await c.post(f"{self.base}/api/generate", json=body)
            r.raise_for_status()
        j = r.json()
        text = str(j.get("response", "")).strip()
        return Summary(
            generated_by=f"ollama:{model}",
            model=model,
            report_id=rep.report_id,
            text=text,
            elapsed_s=round(time.monotonic() - t0, 2),
            eval_tokens=j.get("eval_count"),
            warnings=check_summary(text, rep),
            prompt_chars=len(prompt),
        )
