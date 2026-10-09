import { motion } from "framer-motion";
import type { Device } from "../api/types";
import { Empty } from "../components/ui";
import { num, useSeries } from "../hooks/useTelemetry";

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
  const phy = d.phys[0];
  const xs = useSeries(`mt76q:${phy}:xmit`, d.id);
  const rx = useSeries(`mt76q:${phy}:rx`, d.id);
  if (!phy) return <Empty>No PHY registered for this device.</Empty>;
  if (xs.length === 0 && rx.length === 0)
    return <Empty>No ring samples yet. They come from passive debugfs reads via the privileged helper (mt76 devices only).</Empty>;
  const lx = xs[xs.length - 1];
  const lr = rx[rx.length - 1];
  const maxOf = (arr: typeof xs, k: string) => Math.max(1, ...arr.map((s) => num(s, k) ?? 0));
  return (
    <div className="grid gap-3 md:grid-cols-2 xl:grid-cols-3">
      {[["WFDMA0", "TX data ring (WFDMA0)"], ["MCUWM", "MCU command ring (WM)"], ["MCUFWQ", "MCU firmware-download ring"]].map(([k, label]) => (
        <Ring key={k} label={label} queued={num(lx, `${k}.queued`)} max={maxOf(xs, `${k}.queued`)} rate={num(lx, `${k}.submitted`)} rateLabel="submits/s" danger={k === "MCUWM" && (num(lx, "MCUWM.queued") ?? 0) > 0 && (num(lx, "MCUWM.submitted") ?? 1) === 0} />
      ))}
      {[0, 1, 2].map((i) => (
        <Ring key={i} label={`RX ring ${i}`} queued={num(lr, `rx${i}.queued`)} max={maxOf(rx, `rx${i}.queued`)} rate={num(lr, `rx${i}.advanced`)} rateLabel="adv/s" />
      ))}
      <p className="text-[11px] text-dim md:col-span-2 xl:col-span-3">Red MCU ring = commands queued while nothing was submitted in the last second (possible stuck command). Rates are cpu_idx/head deltas between 1 Hz debugfs reads.</p>
    </div>
  );
}
