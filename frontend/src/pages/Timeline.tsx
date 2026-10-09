import { useQuery } from "@tanstack/react-query";
import { useEffect, useMemo, useState } from "react";
import { api } from "../api/client";
import { useInventory } from "../api/hooks";
import type { EventPage, WhdEvent } from "../api/types";
import { CATEGORIES, EventDetail, EventTable, SEVERITIES, SevBadge, Swimlanes } from "../components/events";
import { Badge, Button, Panel } from "../components/ui";
import { eventStream, type StreamFilter } from "../hooks/eventStream";
import { useEventStream } from "../hooks/useEventStream";

function useNowNs(serverBootNs: number | null): number {
  const [anchor, setAnchor] = useState<{ srv: number; local: number } | null>(null);
  const [, tick] = useState(0);
  useEffect(() => {
    if (serverBootNs) setAnchor({ srv: serverBootNs, local: performance.now() });
  }, [serverBootNs]);
  useEffect(() => {
    const t = setInterval(() => tick((x) => x + 1), 1000);
    return () => clearInterval(t);
  }, []);
  return anchor ? anchor.srv + (performance.now() - anchor.local) * 1e6 : 0;
}

export function TimelinePage({ deviceId }: { deviceId?: string }) {
  const stream = useEventStream();
  const inv = useInventory();
  const [device, setDevice] = useState(deviceId ?? "");
  const [cats, setCats] = useState<string[]>([]);
  const [minSev, setMinSev] = useState("info");
  const [text, setText] = useState("");
  const [windowS, setWindowS] = useState(300);
  const [paused, setPaused] = useState<WhdEvent[] | null>(null);
  const [picked, setPicked] = useState<WhdEvent | null>(null);
  const filter: StreamFilter = useMemo(() => ({ device_id: device || undefined, categories: cats, min_severity: minSev, text: text || undefined }), [device, cats, minSev, text]);
  useEffect(() => { eventStream.setFilter(filter); }, [filter]);
  useEffect(() => () => eventStream.setFilter({}), []);
  const params = new URLSearchParams({ limit: "1000", order: "desc", min_severity: minSev });
  if (device) params.set("device_id", device);
  if (cats.length) params.set("categories", cats.join(","));
  if (text) params.set("text", text);
  const history = useQuery({ queryKey: ["events", params.toString()], queryFn: () => api<EventPage>(`/events?${params}`) });
  const merged = useMemo(() => {
    const m = new Map<number, WhdEvent>();
    for (const e of history.data?.events ?? []) if (e.id !== null && e.id !== undefined) m.set(e.id, e);
    for (const e of stream.events) if (e.id !== null && e.id !== undefined) m.set(e.id, e);
    return [...m.values()].sort((a, b) => a.ts_boottime_ns - b.ts_boottime_ns || (a.id ?? 0) - (b.id ?? 0));
  }, [history.data, stream.events]);
  const shown = paused ?? merged;
  const nowNs = useNowNs(stream.serverBootNs);
  const counts = useMemo(() => {
    const c: Record<string, number> = {};
    for (const e of shown) c[e.severity] = (c[e.severity] ?? 0) + 1;
    return c;
  }, [shown]);
  return (
    <div className="space-y-3">
      <div className="flex flex-wrap items-center gap-2">
        {!deviceId && <h1 className="mr-2 text-lg font-semibold">Event timeline</h1>}
        <Badge tone={stream.connected ? "ok" : "warn"}>{stream.connected ? "live" : stream.connecting ? "connecting" : "disconnected"}</Badge>
        {stream.reconnects > 0 && <span className="text-[11px] text-dim">{stream.reconnects} reconnects (resumed from id {stream.lastId})</span>}
        {stream.dropped > 0 && <Badge tone="warn" title="events dropped by the bounded per-client queue">{stream.dropped} dropped</Badge>}
        <div className="ml-auto flex flex-wrap items-center gap-2">
          {!deviceId && (
            <select aria-label="device" value={device} onChange={(e) => setDevice(e.target.value)} className="rounded border border-line bg-bg px-1.5 py-1">
              <option value="">all devices</option>
              {inv.data?.devices.map((d) => <option key={d.id} value={d.id}>{d.title.slice(0, 40)} ({d.id.slice(0, 22)})</option>)}
            </select>
          )}
          <select aria-label="minimum severity" value={minSev} onChange={(e) => setMinSev(e.target.value)} className="rounded border border-line bg-bg px-1.5 py-1">
            {SEVERITIES.map((s) => <option key={s} value={s}>≥ {s}</option>)}
          </select>
          <input aria-label="search" placeholder="search…" value={text} onChange={(e) => setText(e.target.value)} className="w-44 rounded border border-line bg-bg px-2 py-1" />
          <Button onClick={() => setPaused(paused ? null : [...merged])} tone={paused ? "primary" : "default"}>{paused ? "Resume" : "Pause"}</Button>
        </div>
      </div>
      <div className="flex flex-wrap gap-1">
        {CATEGORIES.map((c) => (
          <button key={c} onClick={() => setCats((x) => (x.includes(c) ? x.filter((y) => y !== c) : [...x, c]))}
            className={`rounded border px-1.5 py-0.5 text-[10px] ${cats.includes(c) ? "border-accent text-accent" : "border-line text-dim hover:text-text"}`}>{c}</button>
        ))}
        {cats.length > 0 && <button className="text-[10px] text-dim underline" onClick={() => setCats([])}>clear</button>}
      </div>
      <Panel title="Live timeline (CLOCK_BOOTTIME)" right={
        <div className="flex items-center gap-2 text-[11px]">
          {SEVERITIES.filter((s) => counts[s]).map((s) => <span key={s} className="flex items-center gap-1"><SevBadge s={s} />{counts[s]}</span>)}
          <select aria-label="window" value={windowS} onChange={(e) => setWindowS(Number(e.target.value))} className="rounded border border-line bg-bg px-1">
            {[60, 300, 1800, 7200, 86400].map((w) => <option key={w} value={w}>{w >= 3600 ? `${w / 3600}h` : `${w / 60}m`}</option>)}
          </select>
        </div>}>
        {nowNs ? <Swimlanes events={shown} nowNs={nowNs} windowS={windowS} onPick={setPicked} /> : <p className="text-dim">waiting for server clock…</p>}
        {picked && <div className="mt-2"><EventDetail e={picked} /></div>}
      </Panel>
      <Panel title={`Events (${shown.length})`} right={history.isFetching ? <span className="text-[11px] text-dim">loading history…</span> : undefined}>
        <div className="max-h-[60vh] overflow-auto"><EventTable events={shown} showDevice={!deviceId} /></div>
      </Panel>
      {!deviceId && stream.sources.length > 0 && (
        <Panel title="Event sources">
          <div className="flex flex-wrap gap-2">
            {stream.sources.map((s) => (
              <Badge key={s.name} tone={s.state === "running" ? "ok" : s.state === "unavailable" ? "dim" : "warn"} title={s.detail ?? ""}>
                {s.name}: {s.state} · {s.events}
              </Badge>
            ))}
          </div>
        </Panel>
      )}
    </div>
  );
}
