import { useQuery } from "@tanstack/react-query";
import { useMemo, useState } from "react";
import { api } from "../api/client";
import { useDevice, useInventory } from "../api/hooks";
import type { EventPage, WhdEvent } from "../api/types";
import { Empty, ErrorBox, Loading, Panel, Tabs } from "../components/ui";
import { eventStream } from "../hooks/eventStream";
import { useEventStream } from "../hooks/useEventStream";
import { ErrorPropagation } from "../viz/ErrorPropagation";
import { FirmwareSequence } from "../viz/FirmwareSequence";
import { QueueActivity } from "../viz/QueueActivity";
import { UsbFlow } from "../viz/UsbFlow";

export function VizPage() {
  const inv = useInventory();
  const present = (inv.data?.devices ?? []).filter((d) => d.present);
  const [sel, setSel] = useState<string>("");
  const id = sel || present[0]?.id;
  const dev = useDevice(id);
  const [tab, setTab] = useState<"errors" | "queues" | "usb" | "fw">("errors");
  const [windowS, setWindowS] = useState(600);
  const stream = useEventStream();
  const hist = useQuery({ queryKey: ["viz-hist", id], enabled: !!id, queryFn: () => api<EventPage>(`/events?device_id=${encodeURIComponent(id!)}&limit=3000&min_severity=debug&order=desc`), refetchInterval: 10000 });
  const events = useMemo(() => {
    const m = new Map<number, WhdEvent>();
    for (const e of hist.data?.events ?? []) if (e.id) m.set(e.id, e);
    for (const e of stream.events) if (e.id && e.device_id === id) m.set(e.id, e);
    const cutoff = (stream.serverBootNs ?? Math.max(0, ...[...m.values()].map((e) => e.ts_boottime_ns))) - windowS * 1e9;
    return [...m.values()].filter((e) => e.ts_boottime_ns >= cutoff).sort((a, b) => a.ts_boottime_ns - b.ts_boottime_ns);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [hist.data, stream.events, id, windowS, eventStream.state.serverBootNs]);
  if (inv.isLoading) return <Loading />;
  if (present.length === 0) return <Empty>No wireless devices present.</Empty>;
  return (
    <div className="space-y-3">
      <div className="flex flex-wrap items-center gap-2">
        <h1 className="text-lg font-semibold">Visualizations</h1>
        <select aria-label="device" value={id} onChange={(e) => setSel(e.target.value)} className="rounded border border-line bg-bg px-1.5 py-1">
          {present.map((d) => <option key={d.id} value={d.id}>{d.title.slice(0, 48)} · {d.id.slice(0, 26)}</option>)}
        </select>
        <select aria-label="window" value={windowS} onChange={(e) => setWindowS(Number(e.target.value))} className="rounded border border-line bg-bg px-1.5 py-1">
          {[60, 300, 600, 3600, 86400].map((w) => <option key={w} value={w}>last {w >= 3600 ? `${w / 3600} h` : `${w / 60} min`}</option>)}
        </select>
        <span className="text-[11px] text-dim">All animation is driven by observed events/telemetry; idle = still.</span>
      </div>
      <Tabs value={tab} onChange={setTab} tabs={[{ id: "errors", label: "Error propagation" }, { id: "fw", label: "Firmware command sequence" }, { id: "queues", label: "TX/RX queue activity" }, { id: "usb", label: "USB transfer flow" }]} />
      {dev.error && <ErrorBox error={dev.error} />}
      {tab === "errors" && <Panel title="Error propagation through the driver stack"><ErrorPropagation events={events} /></Panel>}
      {tab === "fw" && <Panel title="Firmware command / response sequence"><FirmwareSequence events={events} /></Panel>}
      {tab === "queues" && dev.data && <QueueActivity d={dev.data} />}
      {tab === "usb" && dev.data && <Panel title="USB transfers (usbmon)"><UsbFlow d={dev.data} /></Panel>}
    </div>
  );
}
