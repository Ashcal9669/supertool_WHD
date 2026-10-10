import type { SeriesDef } from "../components/TimeChart";
import type { TelemetrySample } from "../api/types";

const PALETTE = ["#22d3ee", "#f472b6", "#a78bfa", "#34d399", "#fbbf24", "#38bdf8", "#fb923c", "#e879f9"];

/** Ring/queue names come from the driver's own debugfs output and differ per chip: never assume them. */
export function ringKeys(samples: TelemetrySample[], suffix: string): string[] {
  const seen: string[] = [];
  for (const s of samples)
    for (const k of Object.keys(s.values ?? {}))
      if (k.endsWith(suffix) && !seen.includes(k)) seen.push(k);
  return seen.sort((a, b) => a.localeCompare(b, undefined, { numeric: true }));
}

export const ringName = (key: string, suffix: string): string => key.slice(0, key.length - suffix.length);

export function ringDefs(keys: string[], suffix: string, unit: string): SeriesDef[] {
  return keys.map((k, i) => ({ key: k, label: `${ringName(k, suffix)} ${unit}`, color: PALETTE[i % PALETTE.length] }));
}
