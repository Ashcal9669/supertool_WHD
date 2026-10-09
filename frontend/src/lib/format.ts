export const hex = (v: number | null | undefined, w = 4) =>
  v === null || v === undefined ? null : `0x${v.toString(16).padStart(w, "0")}`;

export function bytes(n: number | null | undefined): string | null {
  if (n === null || n === undefined) return null;
  const u = ["B", "KiB", "MiB", "GiB", "TiB"];
  let i = 0;
  let v = n;
  while (v >= 1024 && i < u.length - 1) {
    v /= 1024;
    i++;
  }
  return `${v.toFixed(i ? 1 : 0)} ${u[i]}`;
}

export function ms(n: number | null | undefined): string | null {
  if (n === null || n === undefined) return null;
  if (n < 1000) return `${n} ms`;
  const s = n / 1000;
  if (s < 120) return `${s.toFixed(1)} s`;
  const m = s / 60;
  if (m < 120) return `${m.toFixed(1)} min`;
  return `${(m / 60).toFixed(1)} h`;
}

export function ago(ts: number | null | undefined): string | null {
  if (!ts) return null;
  const d = Date.now() / 1000 - ts;
  if (d < 60) return `${Math.round(d)}s ago`;
  if (d < 3600) return `${Math.round(d / 60)}m ago`;
  if (d < 86400) return `${Math.round(d / 3600)}h ago`;
  return new Date(ts * 1000).toLocaleString();
}

export function wallTime(ts: number): string {
  const d = new Date(ts * 1000);
  return d.toLocaleTimeString(undefined, { hour12: false }) + "." + String(d.getMilliseconds()).padStart(3, "0");
}

export const bootSec = (ns: number) => (ns / 1e9).toFixed(6);
