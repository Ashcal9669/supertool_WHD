import { AnimatePresence, motion } from "framer-motion";
import { useEffect, useRef, useState } from "react";
import type { LiveInterface, WhdEvent } from "../api/types";
import { wallTime } from "../lib/format";

interface LinkView {
  id: number;
  freq: number | null | undefined;
  channel: number | null | undefined;
  width: string | null | undefined;
  signal?: number | null;
  tx?: number | null;
  rx?: number | null;
  removedAt?: number;
  addedAt?: number;
}

const bandOf = (f?: number | null) => (!f ? "?" : f < 3000 ? "2.4 GHz" : f < 5925 ? "5 GHz" : "6 GHz");
const BAND_COLOR: Record<string, string> = { "2.4 GHz": "#a78bfa", "5 GHz": "#38bdf8", "6 GHz": "#34d399", "?": "#64748b" };

/**
 * MLO link activation/deactivation, driven by successive nl80211 snapshots (interface MLO_LINKS and per-link
 * station info) plus MLO-category events. A link that disappears between polls is shown as deactivated.
 */
export function MloLinks({ iface, events }: { iface: LiveInterface; events: WhdEvent[] }) {
  const prev = useRef<Map<number, LinkView>>(new Map());
  const [links, setLinks] = useState<LinkView[]>([]);
  useEffect(() => {
    const sta = iface.stations[0];
    const now = Date.now();
    const cur = new Map<number, LinkView>();
    for (const l of iface.interface.mlo_links) {
      const sl = sta?.links.find((x) => x.link_id === l.link_id);
      const old = prev.current.get(l.link_id);
      cur.set(l.link_id, {
        id: l.link_id, freq: l.freq_mhz, channel: l.channel, width: l.width, signal: sl?.signal_dbm,
        tx: sl?.tx_rate?.bitrate_mbps, rx: sl?.rx_rate?.bitrate_mbps,
        addedAt: old && !old.removedAt ? old.addedAt : now,
      });
    }
    for (const [id, old] of prev.current) {
      if (!cur.has(id)) {
        const removedAt = old.removedAt ?? now;
        if (now - removedAt < 15000) cur.set(id, { ...old, removedAt });
      }
    }
    prev.current = cur;
    setLinks([...cur.values()].sort((a, b) => a.id - b.id));
  }, [iface]);
  const mloEvents = events.filter((e) => e.category === "mlo").slice(-8).reverse();
  if (links.length === 0 && mloEvents.length === 0)
    return <p className="text-dim">No MLO links on this interface (not an MLD association, or the driver does not report links via nl80211).</p>;
  return (
    <div className="space-y-2">
      <div className="flex flex-wrap gap-3">
        <AnimatePresence>
          {links.map((l) => {
            const band = bandOf(l.freq);
            const fresh = l.addedAt && Date.now() - l.addedAt < 4000;
            return (
              <motion.div key={l.id} layout initial={{ opacity: 0, scale: 0.7 }}
                animate={{ opacity: l.removedAt ? 0.35 : 1, scale: 1, boxShadow: fresh ? "0 0 0 4px #34d39955" : "0 0 0 0 #0000" }}
                exit={{ opacity: 0, scale: 0.7 }} transition={{ duration: 0.5 }}
                className="w-56 rounded border bg-panel2 p-2" style={{ borderColor: l.removedAt ? "#f87171" : BAND_COLOR[band] }}>
                <div className="flex items-center gap-2">
                  <span className="font-semibold">link {l.id}</span>
                  <span className="text-[10px]" style={{ color: BAND_COLOR[band] }}>{band}</span>
                  <span className="ml-auto text-[10px]">{l.removedAt ? <span className="text-err">DEACTIVATED</span> : fresh ? <span className="text-ok">ACTIVATED</span> : <span className="text-ok">active</span>}</span>
                </div>
                <div className="mono mt-1 text-[11px]">
                  <div>{l.freq ?? "?"} MHz ch {l.channel ?? "?"} · {l.width ?? "?"}</div>
                  <div className="text-dim">signal {l.signal ?? "n/a"} dBm · tx {l.tx ?? "n/a"} · rx {l.rx ?? "n/a"} Mb/s</div>
                </div>
                {l.signal !== undefined && l.signal !== null && (
                  <div className="mt-1 h-1.5 rounded bg-bg"><motion.div className="h-1.5 rounded" style={{ background: BAND_COLOR[band] }} animate={{ width: `${Math.max(2, Math.min(100, (l.signal + 95) * 1.6))}%` }} /></div>
                )}
              </motion.div>
            );
          })}
        </AnimatePresence>
      </div>
      {mloEvents.length > 0 && (
        <div>
          <p className="kv-key">Recent MLO events</p>
          <ul className="mono text-[11px]">{mloEvents.map((e) => <li key={`${e.id}-${e.ts_boottime_ns}`}><span className="text-dim">{wallTime(e.ts_wall)}</span> {e.kind} {e.summary.slice(0, 110)}</li>)}</ul>
        </div>
      )}
    </div>
  );
}
