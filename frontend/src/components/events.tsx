import { AnimatePresence, motion } from "framer-motion";
import { useMemo, useState } from "react";
import type { WhdEvent } from "../api/types";
import { bootSec, wallTime } from "../lib/format";
import { Badge } from "./ui";

export const SEV_COLOR: Record<string, string> = {
  debug: "#64748b", info: "#38bdf8", notice: "#34d399", warning: "#fbbf24", error: "#f87171", critical: "#e11d48",
};
export const SEVERITIES = ["debug", "info", "notice", "warning", "error", "critical"];
export const CATEGORIES = [
  "kernel_log", "pci_error", "pci_link", "usb_error", "usb_transfer", "hotplug", "driver_state", "firmware",
  "association", "phy", "mlo", "reset", "power", "scan", "regulatory", "trace", "telemetry", "netdev", "diagnostic",
  "system",
];

export function SevBadge({ s }: { s: string }) {
  return <span className="mono rounded px-1 text-[10px] uppercase" style={{ color: SEV_COLOR[s], border: `1px solid ${SEV_COLOR[s]}66` }}>{s}</span>;
}

export function EventDetail({ e }: { e: WhdEvent }) {
  return (
    <div className="space-y-2 border-l-2 border-accent/40 bg-bg/60 p-3 text-[12px]">
      <p>{e.explanation}</p>
      <div className="mono grid gap-x-6 gap-y-0.5 text-[11px] md:grid-cols-2">
        <span><span className="text-dim">CLOCK_BOOTTIME</span> {bootSec(e.ts_boottime_ns)} s</span>
        <span><span className="text-dim">timestamp source</span> {e.ts_source}{e.ts_raw ? ` · raw ${e.ts_raw}` : ""}</span>
        <span><span className="text-dim">wall (derived)</span> {new Date(e.ts_wall * 1000).toISOString()}</span>
        <span><span className="text-dim">source</span> {e.source}</span>
        <span><span className="text-dim">device</span> {e.device_id ?? "unattributed"} {e.data?.attribution ? `(${String(e.data.attribution)})` : ""}</span>
        <span><span className="text-dim">id</span> {e.id}{e.session ? ` · session ${e.session}` : ""}{e.demo ? " · DEMO" : ""}</span>
      </div>
      <p className="kv-key">Raw evidence</p>
      <pre className="mono max-h-48 overflow-auto whitespace-pre-wrap break-all rounded bg-panel p-2 text-[11px]">{e.raw}</pre>
      {Object.keys(e.data ?? {}).length > 0 && (
        <details>
          <summary className="cursor-pointer text-dim">Decoded fields</summary>
          <pre className="mono max-h-48 overflow-auto text-[11px]">{JSON.stringify(e.data, null, 1)}</pre>
        </details>
      )}
    </div>
  );
}

export function EventTable({ events, showDevice = true, max = 1000 }: { events: WhdEvent[]; showDevice?: boolean; max?: number }) {
  const [open, setOpen] = useState<number | null>(null);
  const rows = useMemo(() => events.slice(-max).reverse(), [events, max]);
  return (
    <div className="overflow-auto">
      <table className="w-full text-[12px]">
        <thead className="sticky top-0 z-10 bg-panel text-left text-dim">
          <tr><th className="px-2 py-1">time</th><th>sev</th><th>category</th><th>kind</th>{showDevice && <th>device</th>}<th>summary</th></tr>
        </thead>
        <tbody>
          <AnimatePresence initial={false}>
            {rows.map((e) => (
              <motion.tr key={`${e.id}-${e.ts_boottime_ns}`} layout="position" initial={{ opacity: 0, backgroundColor: "#22d3ee22" }}
                animate={{ opacity: 1, backgroundColor: "#00000000" }} transition={{ duration: 0.6 }}
                className="cursor-pointer border-b border-line/40 align-top hover:bg-panel2"
                onClick={() => setOpen(open === e.id ? null : (e.id ?? null))}>
                <td className="mono whitespace-nowrap px-2 py-0.5 text-dim" title={`boottime ${bootSec(e.ts_boottime_ns)}s (${e.ts_source})`}>{wallTime(e.ts_wall)}</td>
                <td><SevBadge s={e.severity} /></td>
                <td className="whitespace-nowrap">{e.category}</td>
                <td className="mono whitespace-nowrap text-[11px] text-dim">{e.kind}</td>
                {showDevice && <td className="mono max-w-40 truncate text-[11px]" title={e.device_id ?? ""}>{e.device_id ? e.device_id.split(":").slice(0, 3).join(":") : "—"}</td>}
                <td className="w-full">
                  <span className="break-all">{e.summary}</span>
                  {e.demo && <span className="ml-1"><Badge tone="demo">demo</Badge></span>}
                  {e.session?.startsWith("replay:") && <span className="ml-1"><Badge tone="accent">replay</Badge></span>}
                  {open === e.id && <div className="mt-1" onClick={(x) => x.stopPropagation()}><EventDetail e={e} /></div>}
                </td>
              </motion.tr>
            ))}
          </AnimatePresence>
        </tbody>
      </table>
    </div>
  );
}

/** Swimlane view: one lane per category, events placed by CLOCK_BOOTTIME within the window. */
export function Swimlanes({ events, nowNs, windowS, onPick }: {
  events: WhdEvent[]; nowNs: number; windowS: number; onPick?: (e: WhdEvent) => void;
}) {
  const start = nowNs - windowS * 1e9;
  const visible = events.filter((e) => e.ts_boottime_ns >= start && e.ts_boottime_ns <= nowNs + 5e9);
  const lanes = CATEGORIES.filter((c) => visible.some((e) => e.category === c));
  const W = 1000;
  const laneH = 22;
  const H = Math.max(1, lanes.length) * laneH + 20;
  const x = (ns: number) => Math.min(W, Math.max(0, ((ns - start) / (windowS * 1e9)) * W));
  return (
    <svg viewBox={`0 0 ${W + 110} ${H}`} className="w-full" role="img" aria-label="event swimlanes">
      {lanes.map((c, i) => (
        <g key={c} transform={`translate(0 ${i * laneH})`}>
          <text x={0} y={14} fill="#7b8aa8" fontSize={10}>{c}</text>
          <line x1={110} x2={110 + W} y1={laneH - 2} y2={laneH - 2} stroke="#1e2a44" />
          {visible.filter((e) => e.category === c).map((e) => (
            <motion.circle key={`${e.id}-${e.ts_boottime_ns}`} cx={110 + x(e.ts_boottime_ns)} cy={10} initial={{ r: 9, opacity: 0.2 }} animate={{ r: e.severity === "debug" ? 2 : 3.5, opacity: 1 }}
              transition={{ duration: 0.5 }} fill={SEV_COLOR[e.severity]} onClick={() => onPick?.(e)} style={{ cursor: "pointer" }}>
              <title>{`${wallTime(e.ts_wall)} ${e.kind}: ${e.summary}`}</title>
            </motion.circle>
          ))}
        </g>
      ))}
      {[0, 0.25, 0.5, 0.75, 1].map((f) => (
        <text key={f} x={110 + f * W} y={H - 4} fill="#475569" fontSize={9} textAnchor="middle">-{Math.round((1 - f) * windowS)}s</text>
      ))}
      {lanes.length === 0 && <text x={110} y={14} fill="#475569" fontSize={11}>no events in window</text>}
    </svg>
  );
}
