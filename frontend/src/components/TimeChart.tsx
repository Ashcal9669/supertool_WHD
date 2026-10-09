import { useEffect, useRef } from "react";
import uPlot from "uplot";
import "uplot/dist/uPlot.min.css";
import type { TelemetrySample } from "../api/types";
import { eventStream } from "../hooks/eventStream";

export interface SeriesDef {
  key: string;
  label: string;
  color: string;
  scale?: string;
}

/** Live uPlot chart for one telemetry series (values come from the real samples only; gaps stay gaps). */
export function TimeChart({ series, defs, title, windowS = 300, height = 150, initial = [], unit }: {
  series: string; defs: SeriesDef[]; title: string; windowS?: number; height?: number; initial?: TelemetrySample[];
  unit?: string;
}) {
  const box = useRef<HTMLDivElement>(null);
  const plot = useRef<uPlot | null>(null);
  useEffect(() => {
    if (!box.current) return;
    const opts: uPlot.Options = {
      width: box.current.clientWidth || 400,
      height,
      legend: { show: true },
      cursor: { drag: { x: true, y: false } },
      scales: { x: { time: true } },
      axes: [
        { stroke: "#7b8aa8", grid: { stroke: "#1e2a44" }, ticks: { stroke: "#1e2a44" } },
        { stroke: "#7b8aa8", grid: { stroke: "#1e2a44" }, ticks: { stroke: "#1e2a44" }, label: unit, size: 50 },
      ],
      series: [{}, ...defs.map((d) => ({ label: d.label, stroke: d.color, width: 1.5, spanGaps: false, points: { show: false } }))],
    };
    const u = new uPlot(opts, [[], ...defs.map(() => [])] as unknown as uPlot.AlignedData, box.current);
    plot.current = u;
    const ro = new ResizeObserver(() => {
      if (box.current) u.setSize({ width: box.current.clientWidth, height });
    });
    ro.observe(box.current);
    const render = () => {
      const pts = [...initial.filter((s) => s.series === series), ...(eventStream.telemetry.get(series) ?? [])];
      const seen = new Set<number>();
      const uniq = pts.filter((p) => (seen.has(p.ts_boottime_ns) ? false : (seen.add(p.ts_boottime_ns), true)))
        .sort((a, b) => a.ts_boottime_ns - b.ts_boottime_ns);
      const cutoff = Date.now() / 1000 - windowS;
      const vis = uniq.filter((p) => p.ts_wall >= cutoff);
      const xs = vis.map((p) => p.ts_wall);
      const ys = defs.map((d) => vis.map((p) => {
        const v = (p.values as Record<string, number | null>)[d.key];
        return v === undefined ? null : v;
      }));
      u.setData([xs, ...ys] as unknown as uPlot.AlignedData);
    };
    render();
    const t = setInterval(render, 1000);
    return () => {
      clearInterval(t);
      ro.disconnect();
      u.destroy();
    };
  }, [series, defs, height, windowS, initial, unit]);
  return (
    <div className="panel p-2">
      <p className="mb-1 text-[11px] uppercase tracking-wider text-dim">{title}</p>
      <div ref={box} className="w-full" />
    </div>
  );
}
