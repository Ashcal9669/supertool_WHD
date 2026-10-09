import { useMutation, useQuery } from "@tanstack/react-query";
import { useState } from "react";
import { Link } from "react-router-dom";
import { api, post } from "../api/client";
import { useInventory } from "../api/hooks";
import type { DiagnosticReport, Hypothesis, LlmSummary, OllamaStatus } from "../api/types";
import { Badge, Button, Empty, ErrorBox, Panel } from "../components/ui";
import { LAYER_LABEL } from "../lib/layers";
import { bootSec } from "../lib/format";

const tone = (c: string) => (c === "moderate" ? "warn" : "dim");

function HypothesisCard({ h, rep }: { h: Hypothesis; rep: DiagnosticReport }) {
  const obs = new Map(rep.observations.map((o) => [o.id, o]));
  const fus = new Map(rep.follow_ups.map((f) => [f.id, f]));
  return (
    <div className="rounded border-2 border-dashed border-warn/60 bg-warn/5 p-3" data-testid="hypothesis">
      <div className="flex flex-wrap items-center gap-2">
        <Badge tone="warn">UNCONFIRMED HYPOTHESIS</Badge>
        <Badge tone={tone(h.confidence)}>confidence: {h.confidence}</Badge>
        <b>{h.title}</b>
        <span className="mono text-[11px] text-dim">{h.id}</span>
      </div>
      <p className="mt-1">{h.statement}</p>
      {h.failure_boundary && <p className="mt-1 text-[12px]"><span className="kv-key">evidence points at boundary:</span> {h.failure_boundary}</p>}
      <div className="mt-2 grid gap-3 lg:grid-cols-3">
        <div><p className="kv-key font-semibold">Supporting observations</p>
          <ul className="text-[12px]">{h.supporting.map((id) => <li key={id}><span className="mono text-ok">{id}</span> {obs.get(id)?.text}</li>)}</ul></div>
        <div><p className="kv-key font-semibold">Contradicting / weakening</p>
          {h.contradicting.length === 0 ? <p className="text-[12px] text-dim">none found in this window</p> : (
            <ul className="text-[12px]">{h.contradicting.map((id) => <li key={id}><span className="mono text-err">{id}</span> {obs.get(id)?.text}</li>)}</ul>)}</div>
        <div><p className="kv-key font-semibold">Unknowns</p>
          <ul className="list-disc pl-4 text-[12px]">{h.unknowns.map((u) => <li key={u}>{u}</li>)}</ul></div>
      </div>
      <div className="mt-2 flex flex-wrap gap-1 text-[11px]">
        <span className="kv-key">tests that would help:</span>
        {h.follow_up_ids.map((id) => <Badge key={id} tone="accent" title={fus.get(id)?.how}>{id}: {fus.get(id)?.title}</Badge>)}
      </div>
    </div>
  );
}

function Llm({ rep }: { rep: DiagnosticReport }) {
  const st = useQuery({ queryKey: ["llm-status"], queryFn: () => api<OllamaStatus>("/diagnostics/llm/status"), staleTime: 15000 });
  const [model, setModel] = useState("");
  const sum = useMutation({ mutationFn: () => post<LlmSummary>("/diagnostics/llm/summarize", { report_id: rep.report_id, model: model || st.data?.configured_model || st.data?.models[0]?.name }) });
  return (
    <Panel title="Optional: local LLM summary (Ollama)" right={<Badge tone={st.data?.reachable ? "ok" : "dim"}>{st.data?.reachable ? "ollama reachable" : "ollama not available"}</Badge>}>
      {!st.data?.reachable ? (
        <p className="text-dim">Ollama is not reachable at {st.data?.url}. Everything above works without it; the summary is only a convenience.</p>
      ) : (
        <div className="space-y-2">
          <div className="flex flex-wrap items-center gap-2">
            <select aria-label="model" value={model} onChange={(e) => setModel(e.target.value)} className="rounded border border-line bg-bg px-1.5 py-1">
              <option value="">{st.data.configured_model ? `configured: ${st.data.configured_model}` : "choose model…"}</option>
              {st.data.models.map((m) => <option key={m.name as string} value={m.name as string}>{String(m.name)} {m.parameters ? `(${String(m.parameters)})` : ""}</option>)}
            </select>
            <Button tone="primary" disabled={sum.isPending || (!model && !st.data.configured_model)} onClick={() => sum.mutate()}>{sum.isPending ? "Generating…" : "Summarize report"}</Button>
            <span className="text-[11px] text-dim">Sends only the report fields above (MACs masked) to {st.data.url}{st.data.loopback ? " (loopback)" : " (NOT loopback)"}.</span>
          </div>
          {sum.error && <ErrorBox error={sum.error} />}
          {sum.data && (
            <div className="rounded border border-accent/40 bg-accent/5 p-3" data-testid="llm-summary">
              <div className="mb-2 flex flex-wrap items-center gap-2"><Badge tone="accent">AI-GENERATED TEXT</Badge><span className="mono text-[11px]">{sum.data.generated_by} · {sum.data.elapsed_s}s · {sum.data.eval_tokens ?? "?"} tokens</span><span className="text-[11px] text-warn">not evidence — verify against the report</span></div>
              <pre className="whitespace-pre-wrap text-[12px]">{sum.data.text}</pre>
              {sum.data.warnings.length > 0 && <ul className="mt-2 list-disc pl-4 text-[11px] text-warn">{sum.data.warnings.map((w) => <li key={w}>{w}</li>)}</ul>}
            </div>
          )}
        </div>
      )}
    </Panel>
  );
}

export function DiagnosticsPage() {
  const inv = useInventory();
  const [device, setDevice] = useState("");
  const [windowS, setWindowS] = useState(3600);
  const [capture, setCapture] = useState("");
  const caps = useQuery({ queryKey: ["captures"], queryFn: () => api<Array<{ id: string; name: string }>>("/captures") });
  const run = useMutation({ mutationFn: () => post<DiagnosticReport>("/diagnostics/analyze", { device_id: device || null, window_s: windowS, capture_id: capture || null }) });
  const rep = run.data;
  return (
    <div className="space-y-3">
      <h1 className="text-lg font-semibold">Diagnostics</h1>
      <div className="panel flex flex-wrap items-end gap-3 p-3">
        <label className="flex flex-col gap-0.5"><span className="kv-key">device</span>
          <select aria-label="device" value={device} onChange={(e) => setDevice(e.target.value)} className="rounded border border-line bg-bg px-1.5 py-1"><option value="">all</option>{inv.data?.devices.map((d) => <option key={d.id} value={d.id}>{d.id.slice(0, 32)}</option>)}</select></label>
        <label className="flex flex-col gap-0.5"><span className="kv-key">window</span>
          <select aria-label="window" value={windowS} onChange={(e) => setWindowS(Number(e.target.value))} disabled={!!capture} className="rounded border border-line bg-bg px-1.5 py-1">{[300, 900, 3600, 21600, 86400].map((w) => <option key={w} value={w}>{w >= 3600 ? `${w / 3600} h` : `${w / 60} min`}</option>)}</select></label>
        <label className="flex flex-col gap-0.5"><span className="kv-key">or analyze capture</span>
          <select aria-label="capture" value={capture} onChange={(e) => setCapture(e.target.value)} className="rounded border border-line bg-bg px-1.5 py-1"><option value="">(live history)</option>{caps.data?.map((c) => <option key={c.id} value={c.id}>{c.name} · {c.id}</option>)}</select></label>
        <Button tone="primary" onClick={() => run.mutate()} disabled={run.isPending}>{run.isPending ? "Analyzing…" : "Analyze"}</Button>
        <p className="text-[11px] text-dim">Deterministic rules over captured events; no language model involved.</p>
      </div>
      {run.error && <ErrorBox error={run.error} />}
      {!rep ? <Empty>Run an analysis to see observations, incidents, recurring patterns, correlations, unconfirmed hypotheses, missing instrumentation and suggested tests.</Empty> : (
        <>
          <div role="note" className="rounded border border-line bg-panel2 p-2 text-[12px]">
            <b>{rep.scope.demo ? "DEMO DATA · " : ""}</b>{rep.disclaimer} <span className="mono text-dim">report {rep.report_id} · {rep.scope.event_count} events ({rep.scope.significant_event_count} significant) · {rep.scope.unattributed_events} unattributed</span>
          </div>
          <Panel title={`Observations (${rep.observations.length}) — facts with evidence`}>
            <ul className="space-y-0.5 text-[12px]">{rep.observations.map((o) => <li key={o.id}><span className="mono text-ok">{o.id}</span> <span className="text-dim">[{o.kind}]</span> {o.text}{o.evidence_event_ids.length > 0 && <span className="mono text-[10px] text-dim"> events {o.evidence_event_ids.slice(0, 6).join(",")}</span>}</li>)}</ul>
          </Panel>
          <div className="grid gap-3 xl:grid-cols-2">
            <Panel title={`Incidents (${rep.incidents.length})`}>
              {rep.incidents.length === 0 ? <Empty>No incident (no warning+ events clustered).</Empty> : rep.incidents.map((i) => (
                <div key={i.id} className="mb-3 rounded border border-line p-2">
                  <div className="flex flex-wrap items-center gap-2"><Badge tone={i.severity === "critical" || i.severity === "error" ? "err" : "warn"}>{i.severity}</Badge><b>{i.id}</b><span className="text-dim">{i.duration_s}s · {i.event_count} events · starts {bootSec(i.start_ns)}s boottime</span></div>
                  <ol className="mono mt-1 text-[11px]">{i.sequence.map((s) => <li key={s.layer}><span className="text-dim">+{s.rel_s}s</span> <span className="text-accent">{LAYER_LABEL[s.layer]}</span> {s.kind}: {s.summary.slice(0, 70)}</li>)}</ol>
                  <p className="text-[10px] text-dim">first warning+/reset event per layer, in observed order (not causal)</p>
                </div>))}
            </Panel>
            <div className="space-y-3">
              <Panel title={`Recurring patterns (${rep.patterns.length})`}>
                {rep.patterns.length === 0 ? <Empty>none (needs ≥3 occurrences of a warning+ kind)</Empty> : <ul className="text-[12px]">{rep.patterns.map((p) => <li key={p.id}><Badge tone={p.regularity === "periodic" ? "warn" : "dim"}>{p.regularity}</Badge> <span className="mono">{p.kind}</span> — {p.note}</li>)}</ul>}
              </Panel>
              <Panel title={`Timing correlations (${rep.correlations.length})`}>
                {rep.correlations.length === 0 ? <Empty>none</Empty> : <ul className="max-h-60 overflow-auto text-[12px]">{rep.correlations.map((c) => <li key={c.id} className="mb-1"><span className="mono text-dim">{c.a_layer}→{c.b_layer}</span> {c.note}</li>)}</ul>}
              </Panel>
            </div>
          </div>
          <Panel title={`Hypotheses (${rep.hypotheses.length}) — unconfirmed, separate from observations`}>
            {rep.hypotheses.length === 0 ? <Empty>No rule matched. That does not mean there is no problem.</Empty> : <div className="space-y-3">{rep.hypotheses.map((h) => <HypothesisCard key={h.id} h={h} rep={rep} />)}</div>}
          </Panel>
          <div className="grid gap-3 xl:grid-cols-2">
            <Panel title={`Missing instrumentation (${rep.missing_instrumentation.length})`}>
              {rep.missing_instrumentation.length === 0 ? <Empty>nothing flagged</Empty> : <ul className="space-y-2 text-[12px]">{rep.missing_instrumentation.map((m) => <li key={m.id}><b>{m.what}</b> <span className="mono text-[10px] text-dim">{m.id}</span><br />{m.why_it_matters}{m.proposal && <><br /><span className="text-accent">↳ {m.proposal}</span></>}</li>)}</ul>}
              <p className="mt-2 text-[11px]">The <Link className="text-accent hover:underline" to="/">device</Link> mt76 tab shows the full coverage matrix and patch proposals.</p>
            </Panel>
            <Panel title={`Suggested follow-up tests (${rep.follow_ups.length})`}>
              {rep.follow_ups.length === 0 ? <Empty>none</Empty> : <ul className="space-y-2 text-[12px]">{rep.follow_ups.map((f) => <li key={f.id}><Badge tone={f.safety === "read-only" ? "ok" : "warn"}>{f.safety}</Badge> <b>{f.title}</b> <span className="mono text-[10px] text-dim">{f.id}</span><br />{f.how}{f.whd_feature && <span className="text-dim"> (WHD: {f.whd_feature})</span>}</li>)}</ul>}
            </Panel>
          </div>
          <Panel title="Limits of this analysis"><ul className="list-disc pl-4 text-[12px] text-dim">{rep.limits.map((l) => <li key={l}>{l}</li>)}</ul></Panel>
          <Llm rep={rep} />
        </>
      )}
    </div>
  );
}
