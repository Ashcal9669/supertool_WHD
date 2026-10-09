import { useQuery } from "@tanstack/react-query";
import { useEffect, useMemo, useState } from "react";
import { useSearchParams } from "react-router-dom";
import { api } from "../api/client";
import { useDevice, useInventory } from "../api/hooks";
import type { CaptureInfo, Device, EventPage, TelemetrySample, WhdEvent } from "../api/types";
import { Badge, Button, Empty, ErrorBox, Loading, Panel, Tabs } from "../components/ui";
import { CaptureViewContext } from "../hooks/captureView";
import { eventStream } from "../hooks/eventStream";
import { useEventStream } from "../hooks/useEventStream";
import { bootSec } from "../lib/format";
import { ErrorPropagation } from "../viz/ErrorPropagation";
import { FirmwareSequence } from "../viz/FirmwareSequence";
import { QueueActivity } from "../viz/QueueActivity";
import { UsbFlow } from "../viz/UsbFlow";

const ALL = "";

export function VizPage() {
  const [sp, setSp] = useSearchParams();
  const capId = sp.get("capture") ?? "";
  const inv = useInventory();
  const caps = useQuery({ queryKey: ["captures"], queryFn: () => api<CaptureInfo[]>("/captures") });
  const cap = caps.data?.find((c) => c.id === capId);
  const present = (inv.data?.devices ?? []).filter((d) => d.present);
  const [sel, setSel] = useState<string>("");
  const [tab, setTab] = useState<"errors" | "queues" | "usb" | "fw">("errors");
  const [windowS, setWindowS] = useState(600);
  const stream = useEventStream();

  // ---- live source
  const liveId = sel || present[0]?.id;
  const hist = useQuery({ queryKey: ["viz-hist", liveId], enabled: !capId && !!liveId, queryFn: () => api<EventPage>(`/events?device_id=${encodeURIComponent(liveId!)}&limit=3000&min_severity=debug&order=desc`), refetchInterval: 10000 });
  // ---- capture source
  const capEvents = useQuery({ queryKey: ["cap-events-all", capId], enabled: !!capId, queryFn: async () => {
    // info+ only (a debug printk flood would otherwise crowd out the events these views are about), all pages
    const out: WhdEvent[] = [];
    for (let offset = 0; offset < 200000; offset += 20000) {
      const page = await api<WhdEvent[]>(`/captures/${capId}/events?limit=20000&offset=${offset}&min_severity=info`);
      out.push(...page);
      if (page.length < 20000) break;
    }
    return out;
  } });
  const capTel = useQuery({ queryKey: ["cap-tel", capId], enabled: !!capId, queryFn: () => api<TelemetrySample[]>(`/captures/${capId}/telemetry`) });
  const capDevs = useQuery({ queryKey: ["cap-devs", capId], enabled: !!capId, queryFn: () => api<Device[]>(`/captures/${capId}/devices`) });
  const liveDev = useDevice(capId ? undefined : liveId);

  const all = useMemo(() => capEvents.data ?? [], [capEvents.data]);
  const span = useMemo(() => {
    if (!all.length) return null;
    return { first: all[0].ts_boottime_ns, last: all[all.length - 1].ts_boottime_ns };
  }, [all]);
  const [frac, setFrac] = useState(1);
  const [playing, setPlaying] = useState(false);
  const [speed, setSpeed] = useState(1);
  useEffect(() => { setFrac(1); setPlaying(false); setSel(""); }, [capId]);
  useEffect(() => {
    if (!playing) return;
    const t = setInterval(() => setFrac((f) => { const n = f + 0.004 * speed; if (n >= 1) { setPlaying(false); return 1; } return n; }), 100);
    return () => clearInterval(t);
  }, [playing, speed]);
  useEffect(() => {
    // queue/USB views need a concrete device: default to the first one in the capture's own inventory
    if (capId && capDevs.data && capDevs.data.length > 0) setSel(capDevs.data[0].id);
  }, [capId, capDevs.data]);
  const cursorNs = span && capId ? span.first + frac * (span.last - span.first) : null;

  const capDeviceIds = useMemo(() => {
    const ids = new Set<string>((capDevs.data ?? []).map((d) => d.id));
    for (const e of all) if (e.device_id) ids.add(e.device_id);
    return [...ids];
  }, [capDevs.data, all]);
  const devId = capId ? sel : liveId;
  const device: Device | undefined = capId ? capDevs.data?.find((d) => d.id === devId) : liveDev.data;

  const events = useMemo(() => {
    if (capId) {
      const upto = cursorNs ?? Infinity;
      const from = windowS >= 86400 ? -Infinity : upto - windowS * 1e9;
      return all.filter((e) => (!devId || e.device_id === devId || e.device_id === null) && e.ts_boottime_ns <= upto && e.ts_boottime_ns >= from);
    }
    const m = new Map<number, WhdEvent>();
    for (const e of hist.data?.events ?? []) if (e.id) m.set(e.id, e);
    for (const e of stream.events) if (e.id && e.device_id === liveId) m.set(e.id, e);
    const cutoff = (stream.serverBootNs ?? Math.max(0, ...[...m.values()].map((e) => e.ts_boottime_ns))) - windowS * 1e9;
    return [...m.values()].filter((e) => e.ts_boottime_ns >= cutoff).sort((a, b) => a.ts_boottime_ns - b.ts_boottime_ns);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [capId, all, devId, cursorNs, windowS, hist.data, stream.events, liveId, eventStream.state.serverBootNs]);

  const view = useMemo(() => (capId ? { samples: capTel.data ?? [], cursorNs } : null), [capId, capTel.data, cursorNs]);
  if (inv.isLoading || caps.isLoading) return <Loading />;
  if (!capId && present.length === 0) return <Empty>No wireless devices present on this host. Import a capture from the Captures page to visualize one from another machine.</Empty>;
  const noDevice = capId && devId && !device;
  return (
    <CaptureViewContext.Provider value={view}>
      <div className="space-y-3">
        <div className="flex flex-wrap items-center gap-2">
          <h1 className="text-lg font-semibold">Visualizations</h1>
          <select aria-label="source" value={capId} onChange={(e) => setSp(e.target.value ? { capture: e.target.value } : {})} className="rounded border border-line bg-bg px-1.5 py-1">
            <option value="">Live (this host)</option>
            {(caps.data ?? []).filter((c) => c.state !== "running").map((c) => <option key={c.id} value={c.id}>{c.state === "imported" ? "IMPORTED · " : ""}{c.name} · {c.id}</option>)}
          </select>
          {!capId ? (
            <select aria-label="device" value={liveId} onChange={(e) => setSel(e.target.value)} className="rounded border border-line bg-bg px-1.5 py-1">
              {present.map((d) => <option key={d.id} value={d.id}>{d.title.slice(0, 48)} · {d.id.slice(0, 26)}</option>)}
            </select>
          ) : (
            <select aria-label="device" value={sel} onChange={(e) => setSel(e.target.value)} className="rounded border border-line bg-bg px-1.5 py-1">
              <option value={ALL}>all devices / unattributed</option>
              {capDeviceIds.map((id) => <option key={id} value={id}>{id.slice(0, 40)}</option>)}
            </select>
          )}
          <select aria-label="window" value={windowS} onChange={(e) => setWindowS(Number(e.target.value))} className="rounded border border-line bg-bg px-1.5 py-1">
            {[60, 300, 600, 3600, 86400].map((w) => <option key={w} value={w}>{w >= 86400 ? "everything up to cursor" : `last ${w >= 3600 ? `${w / 3600} h` : `${w / 60} min`}`}</option>)}
          </select>
          {capId && cap && <Badge tone={cap.state === "imported" ? "accent" : "dim"}>{cap.state === "imported" ? "IMPORTED CAPTURE — recorded elsewhere" : "stored capture"}</Badge>}
          {cap?.mode === "demo" && <Badge tone="demo">demo data</Badge>}
        </div>
        {capId && span && (
          <div className="panel flex flex-wrap items-center gap-3 p-2" data-testid="cursor-bar">
            <Button onClick={() => { if (frac >= 1) setFrac(0); setPlaying(!playing); }}>{playing ? "Pause" : "Play"}</Button>
            <select aria-label="playback speed" value={speed} onChange={(e) => setSpeed(Number(e.target.value))} className="rounded border border-line bg-bg px-1 py-0.5">{[1, 2, 5, 10].map((s) => <option key={s} value={s}>×{s}</option>)}</select>
            <input aria-label="playback position" type="range" min={0} max={1000} value={Math.round(frac * 1000)} onChange={(e) => { setPlaying(false); setFrac(Number(e.target.value) / 1000); }} className="min-w-[240px] flex-1" />
            <span className="mono text-[11px] text-dim">{bootSec(span.first)}s → <b className="text-text">{cursorNs ? bootSec(cursorNs) : "—"}s</b> → {bootSec(span.last)}s (origin boottime) · {events.length} events in view</span>
          </div>
        )}
        <Tabs value={tab} onChange={setTab} tabs={[{ id: "errors", label: "Error propagation" }, { id: "fw", label: "Firmware command sequence" }, { id: "queues", label: "TX/RX queue activity" }, { id: "usb", label: "USB transfer flow" }]} />
        {(capEvents.error || capTel.error) && <ErrorBox error={capEvents.error ?? capTel.error} />}
        {capId && capEvents.isLoading && <Loading what="Loading capture" />}
        {tab === "errors" && <Panel title="Error propagation through the driver stack"><ErrorPropagation events={events} /></Panel>}
        {tab === "fw" && <Panel title="Firmware command / response sequence"><FirmwareSequence events={events} /></Panel>}
        {tab === "queues" && (device ? <QueueActivity d={device} /> : <Empty>{noDevice || capId ? "This capture has no device inventory for the selected device, so ring/queue views need a WHD bundle (not a raw log)." : "Select a device."}</Empty>)}
        {tab === "usb" && (device ? <Panel title="USB transfers (usbmon)"><UsbFlow d={device} /></Panel> : <Empty>{capId ? "No USB device inventory stored with this capture." : "Select a device."}</Empty>)}
      </div>
    </CaptureViewContext.Provider>
  );
}
