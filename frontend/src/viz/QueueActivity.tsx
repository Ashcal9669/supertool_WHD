import { motion } from "framer-motion";
import type { Device } from "../api/types";
import { Empty } from "../components/ui";
import { num, useSeries } from "../hooks/useTelemetry";
import { ringKeys, ringName } from "../lib/rings";

function Ring({ label, queued, max, rate, rateLabel, danger }: { label: string; queued: number | null; max: number; rate: number | null; rateLabel: string; danger?: boolean }) {
  const frac = queued === null ? 0 : Math.min(1, queued / Math.max(1, max));
  const speed = rate && rate > 0 ? Math.max(0.35, 3 / Math.log10(rate + 10)) : 0;
  return (
    <div className="panel p-2">
      <div className="mb-1 flex items-center justify-between"><span className="font-semibold">{label}</span>
        <span className="mono text-[11px] text-dim">{queued === null ? "n/a" : `${queued} queued`} · {rate === null ? "n/a" : `${Math.round(rate)} ${rateLabel}`}</span></div>
      <div className="relative h-5 overflow-hidden rounded bg-bg">
        <motion.div className="absolute inset-y-0 left-0" style={{ background: danger ? "#f87171" : "#22d3ee33", borderRight: `2px solid ${danger ? "#f87171" : "#22d3ee"}` }} animate={{ width: `${frac * 100}%` }} transition={{ type: "spring", stiffness: 120, damping: 20 }} />
        {speed > 0 && [0, 1, 2, 3].map((i) => (
          <motion.span key={i} className="absolute top-1/2 h-1.5 w-1.5 -translate-y-1/2 rounded-full bg-accent"
            initial={{ left: "0%" }} animate={{ left: "100%" }} transition={{ duration: speed * 2, repeat: Infinity, delay: (i * speed * 2) / 4, ease: "linear" }} />
        ))}
      </div>
      <p className="mt-0.5 text-[10px] text-dim">particle speed ∝ measured rate; bar = occupancy relative to the largest value seen in the window</p>
    </div>
  );
}

/** TX/MCU/RX ring activity from 1 Hz debugfs samples (mt76q:* series). Nothing animates without samples. */
export function QueueActivity({ d }: { d: Device }) {
  if (d.phys.length === 0) return <Empty>No PHY registered for this device.</Empty>;
  return (
    <div className="space-y-4">
      {d.phys.map((phy) => (
        <div key={phy}>
          {d.phys.length > 1 && <p className="mb-1 mono text-[11px] text-dim">{phy}</p>}
          <PhyRings d={d} phy={phy} />
        </div>
      ))}
    </div>
  );
}

function PhyRings({ d, phy }: { d: Device; phy: string }) {
  const xs = useSeries(`mt76q:${phy}:xmit`, d.id);
  const rx = useSeries(`mt76q:${phy}:rx`, d.id);
  if (xs.length === 0 && rx.length === 0)
    return <Empty>No ring samples yet. They come from passive debugfs reads via the privileged helper (mt76 devices only).</Empty>;
  const lx = xs[xs.length - 1];
  const lr = rx[rx.length - 1];
  const maxOf = (arr: typeof xs, k: string) => Math.max(1, ...arr.map((s) => num(s, k) ?? 0));
  return (
    <div className="grid gap-3 md:grid-cols-2 xl:grid-cols-3">
      {ringKeys(xs, ".queued").map((key) => {
        const k = ringName(key, ".queued");
        // MCU command rings (named by the driver) with entries queued but nothing submitted in the last second
        const cmdRing = /^MCU/i.test(k) && !/FW/i.test(k);
        return (
          <Ring key={k} label={`TX ring ${k}`} queued={num(lx, `${k}.queued`)} max={maxOf(xs, `${k}.queued`)} rate={num(lx, `${k}.submitted`)} rateLabel="submits/s" danger={cmdRing && (num(lx, `${k}.queued`) ?? 0) > 0 && (num(lx, `${k}.submitted`) ?? 1) === 0} />
        );
      })}
      {ringKeys(rx, ".queued").map((key) => {
        const k = ringName(key, ".queued");
        return <Ring key={k} label={`RX ring ${k.replace(/^rx/, "")}`} queued={num(lr, `${k}.queued`)} max={maxOf(rx, `${k}.queued`)} rate={num(lr, `${k}.advanced`)} rateLabel="adv/s" />;
      })}
      <p className="text-[11px] text-dim md:col-span-2 xl:col-span-3">Red MCU ring = commands queued while nothing was submitted in the last second (possible stuck command). Rates are cpu_idx/head deltas between 1 Hz debugfs reads.</p>
    </div>
  );
}
