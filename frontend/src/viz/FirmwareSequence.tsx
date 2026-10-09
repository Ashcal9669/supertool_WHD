import { useMemo } from "react";
import type { WhdEvent } from "../api/types";
import { Empty } from "../components/ui";
import { wallTime } from "../lib/format";

const LANES = ["Host driver", "MCU / firmware", "Chip / bus"] as const;
const X = [90, 330, 570];

interface Msg { e: WhdEvent; from: number; to: number; label: string; color: string; dashed?: boolean; note?: string }

export function toMessages(events: WhdEvent[]): Msg[] {
  const out: Msg[] = [];
  for (const e of events) {
    const f = ((e.data ?? {}) as Record<string, unknown>).fields as Record<string, string> | undefined;
    switch (e.kind) {
      case "trace.mt76.mcu_send":
        out.push({ e, from: 0, to: 1, label: `cmd ${f?.cmd ?? "?"} seq ${f?.seq ?? "?"}`, color: "#22d3ee", note: f?.retry && f.retry !== "0" ? `retry ${f.retry}` : undefined });
        break;
      case "trace.mt76.mcu_resp":
        out.push({ e, from: 1, to: 0, label: f?.timeout === "1" ? `TIMEOUT seq ${f?.seq}` : `resp seq ${f?.seq} ret ${f?.ret}`, color: f?.timeout === "1" ? "#f87171" : "#34d399", dashed: true, note: f?.latency_us ? `${(Number(f.latency_us) / 1000).toFixed(1)} ms` : undefined });
        break;
      case "firmware.mcu_retry": out.push({ e, from: 0, to: 1, label: `retry ${(e.data as Record<string, string>).cmd}`, color: "#fbbf24", note: "log" }); break;
      case "firmware.mcu_timeout": out.push({ e, from: 1, to: 0, label: `timeout seq ${(e.data as Record<string, string>).seq}`, color: "#f87171", dashed: true, note: "log" }); break;
      case "reset.chip_reset": out.push({ e, from: 0, to: 2, label: "chip reset", color: "#f87171" }); break;
      case "firmware.patch_load": out.push({ e, from: 0, to: 2, label: "load patch", color: "#a78bfa" }); break;
      case "firmware.version": out.push({ e, from: 1, to: 0, label: `${(e.data as Record<string, string>).which} fw version`, color: "#a78bfa", dashed: true }); break;
      case "firmware.init_done": out.push({ e, from: 1, to: 0, label: "firmware init done", color: "#34d399", dashed: true }); break;
      case "power.ownership_failed": out.push({ e, from: 0, to: 1, label: `${(e.data as Record<string, string>).who}-own failed`, color: "#f87171" }); break;
      default: break;
    }
  }
  return out;
}

/** Host/firmware/chip sequence diagram built only from observed MCU/firmware events. */
export function FirmwareSequence({ events, limit = 28 }: { events: WhdEvent[]; limit?: number }) {
  const msgs = useMemo(() => toMessages([...events].sort((a, b) => a.ts_boottime_ns - b.ts_boottime_ns)).slice(-limit), [events, limit]);
  if (msgs.length === 0) return <Empty>No MCU/firmware events observed. Command send/response pairs need the optional <code className="mono">mt76:mcu_send</code>/<code className="mono">mcu_resp</code> tracepoints (patch proposal 0001); without them only timeouts, retries, resets and firmware load steps appear (from the kernel log).</Empty>;
  const rowH = 30;
  const H = 50 + msgs.length * rowH;
  return (
    <div className="overflow-auto">
      <svg viewBox={`0 0 760 ${H}`} className="w-full min-w-[640px]" role="img" aria-label="firmware command sequence">
        <defs>
          {["#22d3ee", "#34d399", "#f87171", "#fbbf24", "#a78bfa"].map((c) => (
            <marker key={c} id={`ah${c.slice(1)}`} viewBox="0 0 10 10" refX="9" refY="5" markerWidth="6" markerHeight="6" orient="auto"><path d="M0 0 L10 5 L0 10 z" fill={c} /></marker>
          ))}
        </defs>
        {LANES.map((l, i) => (
          <g key={l}>
            <text x={X[i]} y={16} textAnchor="middle" fill="#d6deeb" fontSize={12} fontWeight={600}>{l}</text>
            <line x1={X[i]} x2={X[i]} y1={24} y2={H - 6} stroke="#334155" strokeDasharray="3 4" />
          </g>
        ))}
        {msgs.map((m, i) => {
          const y = 44 + i * rowH;
          const x1 = X[m.from];
          const x2 = X[m.to];
          return (
            <g key={`${m.e.id}-${i}`}>
              <line x1={x1} x2={x2 + (x2 > x1 ? -6 : 6)} y1={y} y2={y} stroke={m.color} strokeWidth={1.6} strokeDasharray={m.dashed ? "5 3" : undefined} markerEnd={`url(#ah${m.color.slice(1)})`} />
              <text x={(x1 + x2) / 2} y={y - 5} fill={m.color} fontSize={10.5} textAnchor="middle">{m.label}{m.note ? ` · ${m.note}` : ""}</text>
              <text x={752} y={y + 3} fill="#64748b" fontSize={9} textAnchor="end">{wallTime(m.e.ts_wall)}</text>
              <title>{m.e.summary}</title>
            </g>
          );
        })}
      </svg>
    </div>
  );
}
