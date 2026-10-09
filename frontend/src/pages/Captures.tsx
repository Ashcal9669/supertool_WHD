import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useState } from "react";
import { api, del, post } from "../api/client";
import { useInventory } from "../api/hooks";
import type { CaptureInfo, WhdEvent } from "../api/types";
import { CATEGORIES, EventTable, SEVERITIES } from "../components/events";
import { Badge, Button, Empty, ErrorBox, KV, Loading, Panel } from "../components/ui";
import { bootSec, bytes } from "../lib/format";

function Create() {
  const qc = useQueryClient();
  const inv = useInventory();
  const [name, setName] = useState("capture");
  const [device, setDevice] = useState("");
  const [sev, setSev] = useState("");
  const [cats, setCats] = useState<string[]>([]);
  const [maxEvents, setMaxEvents] = useState(50000);
  const [maxMb, setMaxMb] = useState(32);
  const [maxSec, setMaxSec] = useState(300);
  const [trace, setTrace] = useState("");
  const presets = useQuery({ queryKey: ["trace-presets"], queryFn: () => api<Array<{ name: string; events: string[] }>>("/trace/presets"), staleTime: 60000 });
  const create = useMutation({
    mutationFn: () => post<CaptureInfo>("/captures", {
      name, device_id: device || null, min_severity: sev || null, categories: cats.length ? cats : null,
      max_events: maxEvents, max_bytes: maxMb * 1024 * 1024, max_seconds: maxSec,
      trace_events: presets.data?.find((p) => p.name === trace)?.events ?? null,
    }),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["captures"] }),
  });
  const field = "rounded border border-line bg-bg px-1.5 py-1";
  return (
    <Panel title="New capture">
      <div className="flex flex-wrap items-end gap-3">
        <label className="flex flex-col gap-0.5"><span className="kv-key">name</span><input aria-label="capture name" className={field} value={name} onChange={(e) => setName(e.target.value)} /></label>
        <label className="flex flex-col gap-0.5"><span className="kv-key">device scope</span>
          <select aria-label="device scope" className={field} value={device} onChange={(e) => setDevice(e.target.value)}>
            <option value="">all devices</option>{inv.data?.devices.map((d) => <option key={d.id} value={d.id}>{d.id.slice(0, 30)}</option>)}</select></label>
        <label className="flex flex-col gap-0.5"><span className="kv-key">min severity</span>
          <select aria-label="capture severity" className={field} value={sev} onChange={(e) => setSev(e.target.value)}><option value="">any</option>{SEVERITIES.map((s) => <option key={s}>{s}</option>)}</select></label>
        <label className="flex flex-col gap-0.5"><span className="kv-key">max events (circular)</span><input type="number" className={`${field} w-28`} value={maxEvents} min={100} max={500000} onChange={(e) => setMaxEvents(Number(e.target.value))} /></label>
        <label className="flex flex-col gap-0.5"><span className="kv-key">max size (MiB)</span><input type="number" className={`${field} w-20`} value={maxMb} min={1} max={256} onChange={(e) => setMaxMb(Number(e.target.value))} /></label>
        <label className="flex flex-col gap-0.5"><span className="kv-key">max duration (s)</span><input type="number" className={`${field} w-24`} value={maxSec} min={5} max={86400} onChange={(e) => setMaxSec(Number(e.target.value))} /></label>
        <label className="flex flex-col gap-0.5"><span className="kv-key">tracepoints (discovered, needs helper)</span>
          <select aria-label="capture tracepoints" className={field} value={trace} onChange={(e) => setTrace(e.target.value)}>
            <option value="">none</option>{(presets.data ?? []).map((p) => <option key={p.name}>{p.name}</option>)}</select></label>
        <Button tone="primary" onClick={() => create.mutate()} disabled={create.isPending}>Start capture</Button>
      </div>
      <div className="mt-2 flex flex-wrap gap-1">
        {CATEGORIES.map((c) => <button key={c} onClick={() => setCats((x) => (x.includes(c) ? x.filter((y) => y !== c) : [...x, c]))} className={`rounded border px-1.5 py-0.5 text-[10px] ${cats.includes(c) ? "border-accent text-accent" : "border-line text-dim"}`}>{c}</button>)}
        <span className="text-[10px] text-dim">(no category selected = all)</span>
      </div>
      {create.error && <div className="mt-2"><ErrorBox error={create.error} /></div>}
      <p className="mt-2 text-[10px] text-dim">Hard caps: 500 000 events, 256 MiB, 24 h, 3 concurrent captures. When a limit is hit the oldest events are dropped (circular buffer) or the capture stops (duration).</p>
    </Panel>
  );
}

function Detail({ c }: { c: CaptureInfo }) {
  const evs = useQuery({ queryKey: ["cap-events", c.id, c.stats.events_kept], queryFn: () => api<WhdEvent[]>(`/captures/${c.id}/events?limit=1500`) });
  const [redact, setRedact] = useState(true);
  const links = ["json", "jsonl", "csv", "trace"] as const;
  return (
    <div className="mt-2 space-y-2 border-t border-line pt-2">
      <div className="flex flex-wrap items-center gap-2">
        {links.map((f) => <a key={f} className="rounded border border-line px-2 py-0.5 text-[12px] hover:border-accent hover:text-accent" href={`/api/v1/captures/${c.id}/export?format=${f}`} download>{f === "trace" ? "trace (ftrace text)" : f.toUpperCase()}</a>)}
        <a className="rounded border border-accent/60 px-2 py-0.5 text-[12px] text-accent" href={`/api/v1/captures/${c.id}/bundle?redact_macs=${redact}`} download>Diagnostic bundle (.zip)</a>
        <label className="flex items-center gap-1 text-[11px]"><input type="checkbox" checked={redact} onChange={(e) => setRedact(e.target.checked)} /> mask MAC addresses</label>
      </div>
      <KV cols={2} rows={[
        ["events kept / seen", `${c.stats.events_kept} / ${c.stats.events_seen}`], ["dropped (oldest)", String(c.stats.events_dropped_oldest)],
        ["size", bytes(c.stats.bytes_kept)], ["telemetry samples", String(c.stats.telemetry_samples)],
        ["span", c.stats.first_ts_ns && c.stats.last_ts_ns ? `${bootSec(c.stats.first_ts_ns)} → ${bootSec(c.stats.last_ts_ns)} (boottime s)` : null],
        ["stop reason", c.stats.stop_reason], ["severity", Object.entries(c.stats.by_severity).map(([k, v]) => `${k}:${v}`).join(" ")],
        ["categories", Object.entries(c.stats.by_category).map(([k, v]) => `${k}:${v}`).join(" ")],
      ]} />
      {evs.isLoading ? <Loading /> : evs.error ? <ErrorBox error={evs.error} /> : <div className="max-h-96 overflow-auto"><EventTable events={evs.data ?? []} /></div>}
    </div>
  );
}

export function CapturesPage() {
  const qc = useQueryClient();
  const q = useQuery({ queryKey: ["captures"], queryFn: () => api<CaptureInfo[]>("/captures"), refetchInterval: 2000 });
  const [open, setOpen] = useState<string | null>(null);
  const [speed, setSpeed] = useState(4);
  const stop = useMutation({ mutationFn: (id: string) => post(`/captures/${id}/stop`), onSuccess: () => qc.invalidateQueries({ queryKey: ["captures"] }) });
  const rm = useMutation({ mutationFn: (id: string) => del(`/captures/${id}`), onSuccess: () => qc.invalidateQueries({ queryKey: ["captures"] }) });
  const replay = useMutation({ mutationFn: (id: string) => post(`/captures/${id}/replay`, { speed }), onSuccess: () => qc.invalidateQueries({ queryKey: ["replay"] }) });
  const usb = useQuery({ queryKey: ["usbmon"], queryFn: () => api<{ usbmon_present: boolean; active: boolean; helper: boolean; buses: number[]; note: string }>("/usbmon/status") });
  const usbStart = useMutation({ mutationFn: () => post("/usbmon/start", { max_seconds: 300 }), onSuccess: () => qc.invalidateQueries({ queryKey: ["usbmon"] }) });
  const usbStop = useMutation({ mutationFn: () => post("/usbmon/stop"), onSuccess: () => qc.invalidateQueries({ queryKey: ["usbmon"] }) });
  return (
    <div className="space-y-3">
      <h1 className="text-lg font-semibold">Diagnostic captures</h1>
      <Create />
      <Panel title="usbmon (optional USB URB capture)" right={usb.data && <Badge tone={usb.data.usbmon_present ? "ok" : "dim"}>{usb.data.usbmon_present ? "usbmon present" : "usbmon not loaded"}</Badge>}>
        <div className="flex flex-wrap items-center gap-2">
          <Button disabled={!usb.data?.usbmon_present || usb.data.active || usb.data.buses.length === 0} onClick={() => usbStart.mutate()}>Start usbmon (5 min cap)</Button>
          <Button tone="danger" disabled={!usb.data?.active} onClick={() => usbStop.mutate()}>Stop</Button>
          <span className="text-[11px] text-dim">{usb.data?.note} {usb.data && usb.data.buses.length === 0 ? "No USB wireless devices present." : ""} Buffers are bounded: 1 Hz aggregates + ≤20 error events/s.</span>
        </div>
        {(usbStart.error || usbStop.error) && <div className="mt-2"><ErrorBox error={usbStart.error ?? usbStop.error} /></div>}
      </Panel>
      {q.isLoading ? <Loading /> : q.error ? <ErrorBox error={q.error} /> : (q.data ?? []).length === 0 ? <Empty>No captures yet.</Empty> : (
        <div className="space-y-2">
          {q.data!.map((c) => (
            <div key={c.id} className="panel p-3" data-testid="capture-row">
              <div className="flex flex-wrap items-center gap-2">
                <Badge tone={c.state === "running" ? "ok" : c.state === "expired" ? "warn" : "dim"}>{c.state}</Badge>
                {c.mode === "demo" && <Badge tone="demo">demo</Badge>}
                <b>{c.name}</b><span className="mono text-dim">{c.id}</span>
                <span className="text-[12px] text-dim">{c.stats.events_kept} events · {bytes(c.stats.bytes_kept)}{c.seconds_remaining !== null && c.seconds_remaining !== undefined ? ` · ${Math.round(c.seconds_remaining)} s left` : ""}</span>
                <div className="ml-auto flex items-center gap-2">
                  {c.state === "running" && <Button tone="danger" onClick={() => stop.mutate(c.id)}>Stop</Button>}
                  {c.state !== "running" && (<>
                    <label className="flex items-center gap-1 text-[11px]">replay ×<select aria-label="replay speed" value={speed} onChange={(e) => setSpeed(Number(e.target.value))} className="rounded border border-line bg-bg">{[1, 2, 4, 10].map((s) => <option key={s}>{s}</option>)}</select></label>
                    <Button onClick={() => replay.mutate(c.id)} disabled={c.stats.events_kept === 0}>Replay</Button>
                  </>)}
                  <Button onClick={() => setOpen(open === c.id ? null : c.id)}>{open === c.id ? "Hide" : "Details / export"}</Button>
                  <Button onClick={() => { if (window.confirm(`Delete capture ${c.name}?`)) rm.mutate(c.id); }}>Delete</Button>
                </div>
              </div>
              {open === c.id && <Detail c={c} />}
            </div>
          ))}
        </div>
      )}
      {replay.error && <ErrorBox error={replay.error} />}
    </div>
  );
}
