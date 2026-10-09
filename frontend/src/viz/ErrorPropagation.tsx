import { motion } from "framer-motion";
import { useMemo } from "react";
import type { WhdEvent } from "../api/types";
import { Empty } from "../components/ui";
import { LAYERS, LAYER_LABEL, layerOf, type Layer } from "../lib/layers";
import { SEV_COLOR } from "../components/events";
import { wallTime } from "../lib/format";

const RANK: Record<string, number> = { debug: 0, info: 1, notice: 2, warning: 3, error: 4, critical: 5 };

/**
 * Shows warning+ events per driver-stack layer on a shared time axis and links the first observed event in each
 * layer in time order. This is an *ordering of observations*, not a causal claim: a later layer may merely log
 * sooner or later than an earlier one.
 */
export function ErrorPropagation({ events, minSeverity = "warning" }: { events: WhdEvent[]; minSeverity?: string }) {
  const sel = useMemo(() => events.filter((e) => RANK[e.severity] >= RANK[minSeverity]).sort((a, b) => a.ts_boottime_ns - b.ts_boottime_ns), [events, minSeverity]);
  if (sel.length === 0) return <Empty>No {minSeverity}+ events in this window.</Empty>;
  const t0 = sel[0].ts_boottime_ns;
  const t1 = Math.max(sel[sel.length - 1].ts_boottime_ns, t0 + 1e9);
  const W = 860;
  const x = (ns: number) => 150 + ((ns - t0) / (t1 - t0)) * (W - 170);
  const firstByLayer = new Map<Layer, WhdEvent>();
  for (const e of sel) if (!firstByLayer.has(layerOf(e))) firstByLayer.set(layerOf(e), e);
  const chain = [...firstByLayer.values()];
  const laneY = (l: Layer) => 34 + LAYERS.indexOf(l) * 46;
  const H = 34 + LAYERS.length * 46;
  return (
    <div className="space-y-2">
      <svg viewBox={`0 0 ${W} ${H}`} className="w-full" role="img" aria-label="error propagation through the driver stack">
        {LAYERS.map((l) => (
          <g key={l}><text x={4} y={laneY(l) + 4} fill="#7b8aa8" fontSize={11}>{LAYER_LABEL[l]}</text><line x1={150} x2={W - 10} y1={laneY(l)} y2={laneY(l)} stroke="#1e2a44" /></g>
        ))}
        {chain.slice(1).map((e, i) => {
          const a = chain[i];
          return <motion.path key={e.id} d={`M ${x(a.ts_boottime_ns)} ${laneY(layerOf(a))} C ${x(a.ts_boottime_ns)} ${(laneY(layerOf(a)) + laneY(layerOf(e))) / 2}, ${x(e.ts_boottime_ns)} ${(laneY(layerOf(a)) + laneY(layerOf(e))) / 2}, ${x(e.ts_boottime_ns)} ${laneY(layerOf(e))}`}
            fill="none" stroke="#22d3ee" strokeWidth={1.5} strokeDasharray="4 3" initial={{ pathLength: 0 }} animate={{ pathLength: 1 }} transition={{ duration: 0.8, delay: i * 0.25 }} />;
        })}
        {sel.map((e) => (
          <circle key={`${e.id}-${e.ts_boottime_ns}`} cx={x(e.ts_boottime_ns)} cy={laneY(layerOf(e))} r={firstByLayer.get(layerOf(e)) === e ? 6 : 3.5} fill={SEV_COLOR[e.severity]} stroke={firstByLayer.get(layerOf(e)) === e ? "#e2e8f0" : "none"}>
            <title>{`${wallTime(e.ts_wall)} [${e.severity}] ${e.kind}: ${e.summary}`}</title>
          </circle>
        ))}
      </svg>
      <ol className="mono text-[11px]">
        {chain.map((e, i) => (
          <li key={e.id}>
            <span className="text-dim">{i === 0 ? "first observed" : `+${((e.ts_boottime_ns - chain[0].ts_boottime_ns) / 1e9).toFixed(2)}s`}</span>{" "}
            <span className="text-accent">{LAYER_LABEL[layerOf(e)]}</span> — {e.kind}: {e.summary.slice(0, 100)}
          </li>
        ))}
      </ol>
      <p className="text-[10px] text-dim">Observation order only. “First observed” marks the earliest {minSeverity}+ event seen in each layer; it does not establish cause. Layers with no events in the window are not drawn on the chain.</p>
    </div>
  );
}
