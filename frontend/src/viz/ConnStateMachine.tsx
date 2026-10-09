import { motion } from "framer-motion";
import { useMemo } from "react";
import type { WhdEvent } from "../api/types";
import { wallTime } from "../lib/format";

export const STATES = ["DISCONNECTED", "SCANNING", "AUTHENTICATING", "ASSOCIATING", "ASSOCIATED", "AUTHORIZED"] as const;
export type ConnState = (typeof STATES)[number];

/** Map an observed event to the connection state it evidences (null = not a state transition). */
export function stateFor(e: WhdEvent): ConnState | null {
  const d = (e.data ?? {}) as Record<string, unknown>;
  const k = e.kind;
  if (k === "nl80211.trigger_scan" || k === "nl80211.start_sched_scan") return "SCANNING";
  if (k === "assoc.authenticate" || k === "assoc.auth_tx") return "AUTHENTICATING";
  if (k === "nl80211.authenticate") return d.timed_out ? "DISCONNECTED" : "AUTHENTICATING";
  if (k === "assoc.authenticated" || k === "assoc.assoc_tx") return "ASSOCIATING";
  if (k === "assoc.assoc_resp") return d.status === "0" ? "ASSOCIATED" : "DISCONNECTED";
  if (k === "nl80211.associate") return d.timed_out || (d.status_code ?? 0) !== 0 ? "DISCONNECTED" : "ASSOCIATED";
  if (k === "assoc.associated" || k === "nl80211.roam") return "ASSOCIATED";
  if (k === "nl80211.connect") return (d.status_code ?? 0) === 0 && !d.timed_out ? "ASSOCIATED" : "DISCONNECTED";
  if (k === "nl80211.port_authorized") return "AUTHORIZED";
  if (["nl80211.disconnect", "nl80211.deauthenticate", "nl80211.disassociate", "assoc.deauth_local", "assoc.deauth_by_ap",
    "assoc.disassoc_by_ap", "assoc.connection_lost", "assoc.timeout", "station.gone"].includes(k)) return "DISCONNECTED";
  return null;
}

export interface Transition { from: ConnState | null; to: ConnState; e: WhdEvent }

export function deriveTransitions(events: WhdEvent[]): Transition[] {
  const out: Transition[] = [];
  let cur: ConnState | null = null;
  let preScan: ConnState | null = null;
  for (const e of [...events].sort((a, b) => a.ts_boottime_ns - b.ts_boottime_ns)) {
    let s = stateFor(e);
    if (e.kind === "nl80211.new_scan_results" || e.kind === "nl80211.scan_aborted") s = cur === "SCANNING" ? preScan ?? "DISCONNECTED" : null;
    if (!s || s === cur) continue;
    if (s === "SCANNING") preScan = cur;
    out.push({ from: cur, to: s, e });
    cur = s;
  }
  return out;
}

const POS: Record<ConnState, [number, number]> = {
  DISCONNECTED: [70, 60], SCANNING: [70, 160], AUTHENTICATING: [260, 60], ASSOCIATING: [450, 60], ASSOCIATED: [640, 60],
  AUTHORIZED: [640, 160],
};
const EDGES: [ConnState, ConnState][] = [
  ["DISCONNECTED", "SCANNING"], ["SCANNING", "DISCONNECTED"], ["DISCONNECTED", "AUTHENTICATING"], ["AUTHENTICATING", "ASSOCIATING"],
  ["ASSOCIATING", "ASSOCIATED"], ["ASSOCIATED", "AUTHORIZED"], ["AUTHORIZED", "DISCONNECTED"], ["ASSOCIATED", "DISCONNECTED"],
  ["AUTHENTICATING", "DISCONNECTED"], ["ASSOCIATING", "DISCONNECTED"],
];

/** Connection state machine driven only by observed events; falls back to the station-dump snapshot. */
export function ConnStateMachine({ events, snapshotConnected }: { events: WhdEvent[]; snapshotConnected: boolean | null }) {
  const transitions = useMemo(() => deriveTransitions(events), [events]);
  const last = transitions[transitions.length - 1];
  const current: ConnState | null = last?.to ?? (snapshotConnected === null ? null : snapshotConnected ? "ASSOCIATED" : "DISCONNECTED");
  const lastEdge = last?.from ? `${last.from}->${last.to}` : null;
  return (
    <div className="space-y-2">
      <svg viewBox="0 0 760 210" className="w-full" role="img" aria-label="connection state machine">
        <defs>
          <marker id="arr" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse">
            <path d="M 0 0 L 10 5 L 0 10 z" fill="#475569" />
          </marker>
        </defs>
        {EDGES.map(([a, b]) => {
          const [x1, y1] = POS[a];
          const [x2, y2] = POS[b];
          const active = lastEdge === `${a}->${b}`;
          const bend = a === "AUTHORIZED" || (a === "ASSOCIATED" && b === "DISCONNECTED") ? 60 : a === "SCANNING" ? -30 : 0;
          const mx = (x1 + x2) / 2;
          const my = (y1 + y2) / 2 + bend + (b === "DISCONNECTED" && a !== "SCANNING" ? 25 : 0);
          return (
            <motion.path key={`${a}${b}`} d={`M ${x1} ${y1} Q ${mx} ${my} ${x2} ${y2}`} fill="none" markerEnd="url(#arr)"
              stroke={active ? "#22d3ee" : "#334155"} strokeWidth={active ? 2.5 : 1}
              initial={false} animate={{ pathLength: 1, opacity: active ? 1 : 0.6 }}
              strokeDasharray={active ? "6 4" : undefined} />
          );
        })}
        {STATES.map((s) => {
          const [x, y] = POS[s];
          const on = s === current;
          return (
            <g key={s} transform={`translate(${x} ${y})`}>
              <motion.rect x={-62} y={-17} width={124} height={34} rx={8} fill={on ? "#0e7490" : "#121b2f"}
                stroke={on ? "#22d3ee" : "#1e2a44"} animate={on ? { scale: [1, 1.08, 1] } : { scale: 1 }}
                transition={{ duration: 0.6 }} />
              <text textAnchor="middle" y={4} fontSize={10.5} fill={on ? "#e2e8f0" : "#7b8aa8"}>{s}</text>
            </g>
          );
        })}
      </svg>
      <p className="text-[11px] text-dim">
        {last ? <>Current state from event <span className="mono">{last.e.kind}</span> at {wallTime(last.e.ts_wall)}.</>
          : snapshotConnected === null ? "No association events or station data yet."
          : "No association events observed yet; state taken from the current nl80211 station dump."}
      </p>
      {transitions.length > 0 && (
        <ol className="mono max-h-40 overflow-auto text-[11px]">
          {transitions.slice(-12).reverse().map((t, i) => (
            <li key={i}><span className="text-dim">{wallTime(t.e.ts_wall)}</span> {t.from ?? "?"} → <span className="text-accent">{t.to}</span> <span className="text-dim">({t.e.kind}: {t.e.summary.slice(0, 70)})</span></li>
          ))}
        </ol>
      )}
    </div>
  );
}
