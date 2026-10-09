import { AnimatePresence, motion } from "framer-motion";
import { useEffect, useMemo, useState } from "react";
import type { Device, WhdEvent } from "../api/types";
import { Badge, Empty } from "../components/ui";
import { eventStream } from "../hooks/eventStream";
import { num, useSeries } from "../hooks/useTelemetry";
import { useEventStream } from "../hooks/useEventStream";

interface Flash { id: number; ep: string; at: number }

/** USB host ↔ endpoint transfer flow from usbmon 1 Hz aggregates (`usbmon` series) and URB error events. */
export function UsbFlow({ d }: { d: Device }) {
  useEventStream();
  const series = useSeries("usbmon", d.id, 120);
  const [flashes, setFlashes] = useState<Flash[]>([]);
  useEffect(() => {
    const off = eventStream.onEvent((e: WhdEvent) => {
    if (e.device_id !== d.id || e.kind !== "usb.urb.error") return;
    const ep = `ep${(e.data as Record<string, unknown>).ep}${(e.data as Record<string, unknown>).dir === "in" ? "i" : "o"}`;
    setFlashes((f) => [...f.slice(-20), { id: e.id ?? Math.random(), ep, at: Date.now() }]);
    });
    return () => {
      off();
    };
  }, [d.id]);
  useEffect(() => {
    const t = setInterval(() => setFlashes((f) => f.filter((x) => Date.now() - x.at < 3000)), 1000);
    return () => clearInterval(t);
  }, []);
  const eps = useMemo(() => (d.usb?.interfaces ?? []).flatMap((i) => i.endpoints.map((e) => ({ key: `ep${e.number}${e.direction === "in" ? "i" : "o"}`, ...e, iface: i.number }))), [d.usb]);
  if (!d.usb) return <Empty>Not a USB device.</Empty>;
  const last = series[series.length - 1];
  const H = Math.max(180, eps.length * 34 + 40);
  const y = (i: number) => 30 + i * 34;
  return (
    <div className="space-y-2">
      {series.length === 0 && (
        <div className="rounded border border-accent/40 bg-accent/10 p-2 text-accent">
          No usbmon data. Transfer flow needs usbmon (kernel module already loaded; WHD never loads modules) and the
          privileged helper; start a capture with <code className="mono">POST /api/v1/usbmon/start</code> or the button on the Captures page. Endpoints below show static configuration only.
        </div>
      )}
      <svg viewBox={`0 0 760 ${H}`} className="w-full" role="img" aria-label="USB transfer flow">
        <rect x={10} y={H / 2 - 40} width={120} height={80} rx={8} fill="#121b2f" stroke="#475569" />
        <text x={70} y={H / 2 - 6} fill="#d6deeb" fontSize={12} textAnchor="middle">xHCI host</text>
        <text x={70} y={H / 2 + 10} fill="#7b8aa8" fontSize={10} textAnchor="middle">bus {d.usb.busnum} · {d.usb.speed_name ?? `${d.usb.speed_mbps} Mb/s`}</text>
        <rect x={250} y={H / 2 - 40} width={120} height={80} rx={8} fill="#121b2f" stroke="#22d3ee" />
        <text x={310} y={H / 2 - 6} fill="#d6deeb" fontSize={12} textAnchor="middle">{d.usb.product ?? "device"}</text>
        <text x={310} y={H / 2 + 10} fill="#7b8aa8" fontSize={10} textAnchor="middle">{(d.usb.vendor_id ?? 0).toString(16)}:{(d.usb.product_id ?? 0).toString(16)}</text>
        <line x1={130} x2={250} y1={H / 2} y2={H / 2} stroke="#475569" strokeWidth={3} />
        {eps.map((e, i) => {
          const cnt = num(last, `${e.key}.submit`) ?? 0;
          const errs = num(last, `${e.key}.errors`) ?? 0;
          const bytes = num(last, `${e.key}.bytes`) ?? 0;
          const flash = flashes.some((f) => f.ep === e.key);
          const col = flash || errs > 0 ? "#f87171" : e.direction === "in" ? "#38bdf8" : "#34d399";
          const n = Math.min(5, Math.ceil(Math.log10(cnt + 1) * 1.6));
          return (
            <g key={`${e.iface}-${e.address}`}>
              <path d={`M 370 ${H / 2} C 440 ${H / 2}, 440 ${y(i)}, 500 ${y(i)}`} fill="none" stroke={col} strokeOpacity={0.4} strokeWidth={1.5} />
              <rect x={500} y={y(i) - 13} width={250} height={26} rx={5} fill="#0d1424" stroke={col} />
              <text x={508} y={y(i) + 4} fontSize={11} fill="#d6deeb">EP 0x{e.address.toString(16).padStart(2, "0")} {e.direction} {e.type}</text>
              <text x={742} y={y(i) + 4} fontSize={10} fill="#7b8aa8" textAnchor="end">{series.length ? `${Math.round(cnt)} URB/s · ${Math.round(bytes / 1024)} KiB/s${errs ? ` · ${errs} err` : ""}` : `${e.max_packet_size} B max`}</text>
              {series.length > 0 && cnt > 0 && Array.from({ length: n }).map((_, k) => (
                <motion.circle key={k} r={3.5} fill={col} initial={{ offsetDistance: "0%" }} animate={{ offsetDistance: "100%" }}
                  style={{ offsetPath: `path("M ${e.direction === "out" ? "370" : "500"} ${e.direction === "out" ? H / 2 : y(i)} C 440 ${e.direction === "out" ? H / 2 : y(i)}, 440 ${e.direction === "out" ? y(i) : H / 2}, ${e.direction === "out" ? "500" : "370"} ${e.direction === "out" ? y(i) : H / 2}")` }}
                  transition={{ duration: 1.4, repeat: Infinity, delay: (k * 1.4) / n, ease: "linear" }} />
              ))}
              <AnimatePresence>{flash && <motion.circle key="f" cx={500} cy={y(i)} r={14} fill="none" stroke="#f87171" initial={{ opacity: 1, r: 4 }} animate={{ opacity: 0, r: 18 }} exit={{ opacity: 0 }} transition={{ duration: 1 }} />}</AnimatePresence>
            </g>
          );
        })}
      </svg>
      <p className="text-[11px] text-dim">Particles per endpoint ∝ log(URBs submitted in the last second); red = URB completion errors (usbmon status ≠ 0). Direction is host→device for OUT, device→host for IN. {series.length > 0 && <Badge tone="ok">live usbmon</Badge>}</p>
    </div>
  );
}
