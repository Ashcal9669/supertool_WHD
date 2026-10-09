import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useState } from "react";
import { api, post } from "../api/client";
import type { Device, Mt76Instrumentation, Mt76Snapshot, TagSummary, TraceAggregate } from "../api/types";
import { TimeChart, type SeriesDef } from "../components/TimeChart";
import { Badge, Button, Empty, ErrorBox, KV, Loading, Panel, Tabs } from "../components/ui";
import { bootSec } from "../lib/format";

const STATUS_TONE = { available: "ok", partial: "warn", log_only: "accent", missing: "err" } as const;

function Coverage({ d }: { d: Device }) {
  const q = useQuery({ queryKey: ["mt76-instr", d.id], queryFn: () => api<Mt76Instrumentation>(`/devices/${encodeURIComponent(d.id)}/mt76/instrumentation`), staleTime: 20000 });
  const patches = useQuery({ queryKey: ["patches"], queryFn: () => api<Array<{ id: string; file: string; summary: string; adds: string[]; validated: string; available: boolean }>>("/patches") });
  const [patch, setPatch] = useState<string | null>(null);
  const body = useQuery({ queryKey: ["patch", patch], enabled: !!patch, queryFn: () => api<string>(`/patches/${patch}`) });
  if (q.isLoading) return <Loading what="Discovering mt76 instrumentation" />;
  if (q.error) return <ErrorBox error={q.error} />;
  const ins = q.data!;
  return (
    <div className="space-y-3">
      {!ins.helper_available && <div className="rounded border border-accent/40 bg-accent/10 p-2 text-accent">{ins.helper_note ?? "Privileged helper not available."} Tracepoint and debugfs discovery needs it; availability below is marked “cannot check”, not “absent”.</div>}
      {ins.custom_instrumentation.length > 0 && (
        <Panel title="Kernel-specific instrumentation discovered on this kernel">
          <div className="flex flex-wrap gap-1">{ins.custom_instrumentation.map((c) => <Badge key={c} tone="accent">{c}</Badge>)}</div>
          <p className="mt-1 text-[11px] text-dim">Discovered at runtime ({ins.kernel_release}); other kernels may not have these.</p>
        </Panel>
      )}
      <Panel title={`Coverage by diagnostic category (${ins.items.length})`}>
        <div className="space-y-2">
          {ins.items.map((i) => (
            <div key={i.id} className="rounded border border-line p-2">
              <div className="flex items-center gap-2">
                <Badge tone={STATUS_TONE[i.status]}>{i.status.replace("_", " ")}</Badge>
                <span className="font-semibold">{i.category}</span>
                <span className="text-dim">{i.summary}</span>
              </div>
              <div className="mt-1 flex flex-wrap gap-1">
                {i.sources.map((s) => (
                  <span key={s.kind + s.name} title={`${s.role}${s.tier ? ` · tier ${s.tier}` : ""}${s.detail ? ` — ${s.detail}` : ""}`}
                    className={`mono rounded border px-1.5 py-0.5 text-[10px] ${s.found ? "border-ok/40 text-ok" : "border-line text-dim line-through"} ${s.role === "primary" ? "font-bold" : ""}`}>
                    {s.kind}:{s.name}
                  </span>
                ))}
              </div>
              {i.missing && <p className="mt-1 text-[11px] text-warn">{i.missing}</p>}
              {i.proposal && <p className="mt-1 text-[11px] text-accent">↳ {i.proposal}</p>}
            </div>
          ))}
        </div>
        <p className="mt-2 text-[10px] text-dim">Bold = primary source (all must be present for “available”). Strikethrough = not found on this kernel. Log sources only appear when the event occurs.</p>
      </Panel>
      <div className="grid gap-3 lg:grid-cols-2">
        <Panel title={`Tracepoints (${ins.tracepoints.length})`}>
          <div className="max-h-72 overflow-auto"><table className="mono w-full text-[11px]"><tbody>
            {ins.tracepoints.filter((t) => t.group.startsWith("mt7")).map((t) => (
              <tr key={t.group + t.name} className="align-top border-b border-line/30"><td className="pr-2 text-accent">{t.group}:{t.name}</td><td className="text-dim">{t.fields.map((f) => f.split(" ").slice(-1)[0].replace(/\[.*/, "")).join(" ")}</td></tr>
            ))}
            <tr><td colSpan={2} className="pt-2 text-dim">+ {ins.tracepoints.filter((t) => !t.group.startsWith("mt7")).length} mac80211/cfg80211 tracepoints</td></tr>
          </tbody></table></div>
        </Panel>
        <Panel title={`debugfs (${ins.debugfs.length}) — read policy`}>
          <div className="max-h-72 overflow-auto"><table className="mono w-full text-[11px]"><tbody>
            {ins.debugfs.map((e) => (
              <tr key={e.path} className="border-b border-line/30" title={e.policy}>
                <td className="pr-2">{e.path}</td>
                <td><Badge tone={e.tier === "passive" ? "ok" : e.tier === "wakes_device" ? "warn" : e.tier === "never" ? "err" : e.tier ? "accent" : "dim"}>{e.tier ?? "not allowlisted"}</Badge></td>
              </tr>
            ))}
          </tbody></table></div>
          <p className="mt-1 text-[10px] text-dim">passive = memory only · wakes_device = takes the mt76 mutex and wakes the chip · mmio/mcu = needs explicit allow (not offered) · never = write/action or firmware-dump nodes</p>
        </Panel>
      </div>
      <Panel title="Optional kernel patch proposals (never applied by WHD)">
        {(patches.data ?? []).map((p) => (
          <div key={p.id} className="mb-2">
            <p><span className="mono text-accent">{p.id}</span> adds {p.adds.map((a) => <Badge key={a}>{a}</Badge>)}</p>
            <p className="text-[12px]">{p.summary}</p>
            <p className="text-[11px] text-dim">Validation: {p.validated}</p>
            <Button onClick={() => setPatch(patch === p.id ? null : p.id)}>{patch === p.id ? "Hide diff" : "View diff"}</Button>
            {patch === p.id && <pre className="mono mt-2 max-h-96 overflow-auto rounded bg-bg p-2 text-[11px]">{body.data ?? "loading…"}</pre>}
          </div>
        ))}
      </Panel>
    </div>
  );
}

const XMIT: SeriesDef[] = [
  { key: "WFDMA0.queued", label: "WFDMA0 queued", color: "#22d3ee" }, { key: "MCUWM.queued", label: "MCU WM queued", color: "#f472b6" },
  { key: "MCUFWQ.queued", label: "MCU FW queued", color: "#a78bfa" },
];
const SUBM: SeriesDef[] = [
  { key: "WFDMA0.submitted", label: "WFDMA0 submitted/s", color: "#34d399" }, { key: "MCUWM.submitted", label: "MCU WM cmds/s", color: "#f472b6" },
];
const RXQ: SeriesDef[] = [0, 1, 2].map((i) => ({ key: `rx${i}.advanced`, label: `RX${i} advanced/s`, color: ["#38bdf8", "#fbbf24", "#a78bfa"][i] }));

function Queues({ d, snap }: { d: Device; snap?: Mt76Snapshot }) {
  const phy = d.phys[0];
  return (
    <div className="space-y-3">
      <div className="grid gap-3 xl:grid-cols-2">
        <TimeChart title="TX / MCU ring occupancy (debugfs xmit-queues, 1 Hz)" series={`mt76q:${phy}:xmit`} defs={XMIT} />
        <TimeChart title="Ring submissions per second (cpu_idx delta)" series={`mt76q:${phy}:xmit`} defs={SUBM} />
        <TimeChart title="RX ring head advance per second" series={`mt76q:${phy}:rx`} defs={RXQ} />
      </div>
      {snap && (
        <div className="grid gap-3 lg:grid-cols-2">
          <Panel title="TX / MCU rings (latest read)">
            <table className="mono w-full text-[12px]"><thead className="text-dim"><tr><th className="text-left">ring</th><th>queued</th><th>head</th><th>tail</th><th>cpu_idx</th><th>dma_idx</th></tr></thead>
              <tbody>{snap.xmit_queues.map((q) => <tr key={String(q.name)}><td>{String(q.name)}</td><td className="text-center">{String(q.queued)}</td><td className="text-center">{String(q.head)}</td><td className="text-center">{String(q.tail)}</td><td className="text-center">{String(q.cpu_idx)}</td><td className="text-center">{String(q.dma_idx)}</td></tr>)}</tbody></table>
            <p className="mt-1 text-[10px] text-dim">cpu_idx ≠ dma_idx means descriptors are in flight to the device.</p>
          </Panel>
          <Panel title="RX rings (latest read)">
            <table className="mono w-full text-[12px]"><thead className="text-dim"><tr><th>queue</th><th>hw-queued</th><th>head</th><th>tail</th></tr></thead>
              <tbody>{snap.rx_queues.map((q) => <tr key={q.queue}><td className="text-center">{q.queue}</td><td className="text-center">{q.hw_queued}</td><td className="text-center">{q.head}</td><td className="text-center">{q.tail}</td></tr>)}</tbody></table>
          </Panel>
        </div>
      )}
    </div>
  );
}

function Station({ snap }: { snap: Mt76Snapshot }) {
  return (
    <div className="space-y-3">
      <div className="grid gap-3 lg:grid-cols-2">
        <Panel title="MLO state (debugfs)">
          <KV rows={[
            ["mlo_active_links", snap.mlo_active_links !== null && snap.mlo_active_links !== undefined ? `0x${snap.mlo_active_links.toString(16)} → links [${snap.mlo_active_link_ids.join(", ")}]` : null],
            ["mlo_str_cap", snap.mlo_str_cap],
            ["forced TX link", snap.settings.mlo_force_tx_link ? (snap.settings.mlo_force_tx_link === "255" ? "255 (not forced)" : snap.settings.mlo_force_tx_link) : null],
            ["link2 RSSI override", snap.settings.mlo_link2_rssi_override],
            ["mlo_diag_trace", snap.settings.mlo_diag_trace],
          ]} />
        </Panel>
        <Panel title="Runtime PM / settings">
          <KV rows={[...Object.entries(snap.runtime_pm).map(([k, v]) => [k, String(v)] as [string, string]), ...Object.entries(snap.settings).filter(([k]) => !k.startsWith("mlo_")).map(([k, v]) => [k, v] as [string, string])]} />
        </Panel>
      </div>
      <Panel title="Per-link statistics (debugfs link_stats)">
        {snap.link_stats.length === 0 ? <Empty>{snap.include_wake ? "not exposed by this driver build" : "Not read: this file wakes the chip. Use “Read with chip wake”."}</Empty> : (
          <table className="mono w-full text-[12px]"><thead className="text-dim"><tr><th>wcid</th><th>link</th><th>phy</th><th>valid</th><th>tx bytes</th><th>tx pkts</th><th>rx bytes</th><th>rx pkts</th><th>rate</th><th>bw</th><th>mcs</th><th>nss</th></tr></thead>
            <tbody>{snap.link_stats.map((r) => <tr key={`${r.wcid}-${r.link}`} className={r.valid ? "" : "text-dim"}><td>{String(r.wcid)}</td><td>{String(r.link)}</td><td>{String(r.phy)}</td><td>{r.valid ? "yes" : "no"}</td><td>{String(r.tx_bytes)}</td><td>{String(r.tx_pkts)}</td><td>{String(r.rx_bytes)}</td><td>{String(r.rx_pkts)}</td><td>{String(r.rate_kbps)} kb/s</td><td>{r.bw_mhz ? String(r.bw_mhz) : `enum ${String(r.bw_enum)}`}</td><td>{String(r.mcs)}</td><td>{String(r.nss)}</td></tr>)}</tbody></table>
        )}
      </Panel>
      <Panel title="WCID table (debugfs mlo_wcid_dump)">
        {snap.wcid_dump.length === 0 ? <Empty>{snap.include_wake ? "not exposed by this driver build" : "Not read (wakes the chip)."}</Empty> : (
          <table className="mono w-full text-[12px]"><thead className="text-dim"><tr><th>wcid</th><th>link</th><th>valid</th><th>cipher</th><th>hw key</th><th>sta</th><th>BA/AMPDU TIDs</th><th>ampdu_state</th><th>rx_check_pn</th></tr></thead>
            <tbody>{snap.wcid_dump.map((r) => <tr key={`${r.wcid}-${r.link}`} className={r.valid ? "" : "text-dim"}><td>{String(r.wcid)}</td><td>{String(r.link)}</td><td>{r.valid ? "yes" : "no"}</td><td>{String(r.cipher)}</td><td>{String(r.hw_key_idx)}</td><td>{String(r.sta)}</td>
              <td>{(r.aggr_active as number[]).length ? (r.aggr_active as number[]).join(",") : "—"}</td><td>{String(r.ampdu_state)}</td><td>{String(r.rx_check_pn)}</td></tr>)}</tbody></table>
        )}
      </Panel>
      {snap.skipped.length > 0 && <p className="text-[11px] text-dim">Skipped: {snap.skipped.map((s) => `${s.path} (${s.reason})`).join("; ")}</p>}
    </div>
  );
}

interface Preset { name: string; events: string[] }

function TraceControl({ d }: { d: Device }) {
  const qc = useQueryClient();
  const presets = useQuery({ queryKey: ["trace-presets"], queryFn: () => api<Preset[]>("/trace/presets"), staleTime: 60000 });
  const PRESETS = presets.data ?? [];
  const [preset, setPreset] = useState(0);
  const [secs, setSecs] = useState(120);
  const status = useQuery({ queryKey: ["trace-status"], queryFn: () => api<{ active: boolean; lines: number; events: string[]; detail: string | null }>("/trace/status"), refetchInterval: 2000 });
  const start = useMutation({ mutationFn: () => post("/trace/start", { events: PRESETS[preset]?.events ?? [], buffer_kb: 4096, max_seconds: secs }), onSuccess: () => qc.invalidateQueries({ queryKey: ["trace-status"] }) });
  const stop = useMutation({ mutationFn: () => post("/trace/stop"), onSuccess: () => qc.invalidateQueries({ queryKey: ["trace-status"] }) });
  const agg = useQuery({ queryKey: ["mt76-agg", d.id], queryFn: () => api<TraceAggregate>(`/devices/${encodeURIComponent(d.id)}/mt76/trace-aggregate?window_s=900`), refetchInterval: 3000 });
  const a = agg.data;
  const tids = a ? [...new Set(a.tid_link.map((c) => c.tid))].sort((x, y) => x - y) : [];
  const lks = a ? [...new Set(a.tid_link.map((c) => c.link))].sort((x, y) => x - y) : [];
  const max = Math.max(1, ...(a?.tid_link.map((c) => c.count) ?? [1]));
  return (
    <div className="space-y-3">
      <Panel title="Trace session (isolated tracefs instance; WHD never touches the global trace buffer)">
        <div className="flex flex-wrap items-center gap-2">
          <select aria-label="preset" value={preset} onChange={(e) => setPreset(Number(e.target.value))} className="rounded border border-line bg-bg px-1.5 py-1">
            {PRESETS.map((p, i) => <option key={p.name} value={i}>{p.name} ({p.events.length})</option>)}
          </select>
          <label className="flex items-center gap-1">max <input type="number" min={5} max={3600} value={secs} onChange={(e) => setSecs(Number(e.target.value))} className="w-20 rounded border border-line bg-bg px-1 py-1" /> s</label>
          <Button tone="primary" disabled={start.isPending || !!status.data?.active || PRESETS.length === 0} onClick={() => start.mutate()}>Start trace</Button>
          <Button tone="danger" disabled={!status.data?.active} onClick={() => stop.mutate()}>Stop</Button>
          {status.data?.active ? <Badge tone="ok">tracing · {status.data.lines} lines</Badge> : <Badge>idle</Badge>}
        </div>
        {(start.error || stop.error) && <div className="mt-2"><ErrorBox error={start.error ?? stop.error} /></div>}
        <p className="mt-1 text-[11px] text-dim">{PRESETS.length === 0 ? "No tracepoints discovered (helper not running or tracefs unavailable). " : `Events: ${PRESETS[preset]?.events.join(", ")}. `} Requires the privileged helper. Tracing only enables tracepoints in WHD's own instance; it does not change the driver or interfaces.</p>
      </Panel>
      <div className="grid gap-3 xl:grid-cols-2">
        <Panel title="Observed TX link per TID (mt76:mlo_tx_select, last 15 min)">
          {tids.length === 0 ? <Empty>No mlo_tx_select events captured. Start the “MLO datapath” trace while traffic flows.</Empty> : (
            <table className="mono text-[12px]"><thead className="text-dim"><tr><th className="pr-3">TID \ link</th>{lks.map((l) => <th key={l} className="px-3">link {l}</th>)}</tr></thead>
              <tbody>{tids.map((t) => <tr key={t}><td>TID {t}</td>{lks.map((l) => { const c = a!.tid_link.find((x) => x.tid === t && x.link === l)?.count ?? 0; return <td key={l} className="px-3 text-center" style={{ background: `rgba(34,211,238,${(c / max) * 0.7})` }}>{c || ""}</td>; })}</tr>)}</tbody></table>
          )}
          {a?.notes.map((n) => <p key={n} className="mt-2 text-[10px] text-dim">{n}</p>)}
        </Panel>
        <Panel title="Per-link datapath activity">
          {!a || a.links.length === 0 ? <Empty>No link-tagged events yet.</Empty> : (
            <table className="mono w-full text-[12px]"><thead className="text-dim"><tr><th>link</th><th>tx sel</th><th>tx done</th><th>acked</th><th>ack err</th><th>free failed</th><th>rx</th><th>rx decrypted</th></tr></thead>
              <tbody>{a.links.map((l) => <tr key={l.link}><td>{l.link}</td><td>{l.tx_selected}</td><td>{l.tx_completions}</td><td>{l.tx_acked}</td><td className={l.tx_ack_errors ? "text-err" : ""}>{l.tx_ack_errors}</td><td className={l.txfree_failed ? "text-err" : ""}>{l.txfree_failed}</td><td>{l.rx_frames}</td><td>{l.rx_decrypted}</td></tr>)}</tbody></table>
          )}
          {a && a.path_counts && Object.keys(a.path_counts).length > 0 && <p className="mt-1 text-[11px] text-dim">TX path ids: {Object.entries(a.path_counts).map(([k, v]) => `${k}×${v}`).join(" ")}</p>}
        </Panel>
      </div>
      <Panel title={`Link migrations (TX path changed for a flow) — ${a?.migrations.length ?? 0}`}>
        {!a || a.migrations.length === 0 ? <Empty>none observed</Empty> : (
          <table className="mono w-full text-[11px]"><tbody>{a.migrations.slice(-40).reverse().map((m, i) => <tr key={i}><td className="text-dim">{bootSec(m.ts_boottime_ns)}s</td><td>{m.flow}</td><td>link {m.from_link} → <span className="text-accent">link {m.to_link}</span></td><td className="text-dim">orig link {m.orig_link ?? "?"}</td></tr>)}</tbody></table>
        )}
      </Panel>
    </div>
  );
}

function Tags({ d }: { d: Device }) {
  const q = useQuery({ queryKey: ["mt76-tags", d.id], queryFn: () => api<TagSummary[]>(`/devices/${encodeURIComponent(d.id)}/mt76/driver-tags?window_s=86400`), refetchInterval: 5000 });
  if (q.isLoading) return <Loading />;
  return (
    <Panel title="Driver instrumentation messages by tag (key=value printk)">
      {(q.data ?? []).length === 0 ? <Empty>No tagged driver messages in the last 24 h.</Empty> : (
        <table className="mono w-full text-[11px]"><thead className="text-dim"><tr><th className="text-left">tag</th><th>count</th><th className="text-left">latest fields</th></tr></thead>
          <tbody>{q.data!.map((t) => <tr key={t.tag} className="align-top border-b border-line/30"><td className="pr-2 text-accent">{t.tag}</td><td className="text-center">{t.count}</td><td className="break-all text-dim">{Object.entries(t.last_fields).slice(0, 10).map(([k, v]) => `${k}=${v}`).join(" ")}</td></tr>)}</tbody></table>
      )}
    </Panel>
  );
}

export function Mt76Tab({ d }: { d: Device }) {
  const [tab, setTab] = useState<"coverage" | "queues" | "station" | "trace" | "tags">("coverage");
  const [wake, setWake] = useState(false);
  const snap = useQuery({ queryKey: ["mt76-snap", d.id, wake], queryFn: () => api<Mt76Snapshot>(`/devices/${encodeURIComponent(d.id)}/mt76/snapshot?wake=${wake}`), refetchInterval: 5000, enabled: tab === "queues" || tab === "station", retry: false });
  return (
    <div className="space-y-3">
      <Tabs value={tab} onChange={setTab} tabs={[{ id: "coverage", label: "Instrumentation coverage" }, { id: "queues", label: "Queues & rings" }, { id: "station", label: "Station / links" }, { id: "trace", label: "Datapath trace" }, { id: "tags", label: "Driver log tags" }]} />
      {(tab === "queues" || tab === "station") && (
        <div className="flex items-center gap-2">
          <Button tone={wake ? "primary" : "default"} onClick={() => { if (wake || window.confirm("Reading link_stats / mlo_wcid_dump / tx_stats takes the mt76 mutex and wakes the chip from runtime power save. These reads change nothing else. Continue?")) setWake(!wake); }}>
            {wake ? "Chip-wake reads ON" : "Read with chip wake"}
          </Button>
          <span className="text-[11px] text-dim">default reads are passive (driver memory only)</span>
          {snap.error && <span className="text-err">{(snap.error as Error).message}</span>}
        </div>
      )}
      {tab === "coverage" && <Coverage d={d} />}
      {tab === "queues" && <Queues d={d} snap={snap.data} />}
      {tab === "station" && (snap.data ? <Station snap={snap.data} /> : snap.isLoading ? <Loading /> : <Empty>Snapshot unavailable (see message above).</Empty>)}
      {tab === "trace" && <TraceControl d={d} />}
      {tab === "tags" && <Tags d={d} />}
    </div>
  );
}
