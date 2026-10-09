import { useQuery } from "@tanstack/react-query";
import { useContext, useEffect, useMemo, useState } from "react";
import { api } from "../api/client";
import type { TelemetrySample } from "../api/types";
import { CaptureViewContext } from "./captureView";
import { eventStream } from "./eventStream";
import { useEventStream } from "./useEventStream";

/** Samples of one telemetry series: REST history merged with the live WebSocket ring; re-renders at 1 Hz. */
export function useSeries(series: string, deviceId?: string, windowS = 300): TelemetrySample[] {
  useEventStream();
  const cv = useContext(CaptureViewContext);
  const [, tick] = useState(0);
  const initial = useQuery({
    enabled: !cv,
    queryKey: ["tel-series", series, deviceId],
    queryFn: () => api<TelemetrySample[]>(`/telemetry?series_prefix=${encodeURIComponent(series)}${deviceId ? `&device_id=${encodeURIComponent(deviceId)}` : ""}&limit=3000`),
    staleTime: 30000,
  });
  useEffect(() => {
    const t = setInterval(() => tick((x) => x + 1), 1000);
    return () => clearInterval(t);
  }, []);
  const hist = initial.data;
  return useMemo(() => {
    if (cv) {
      const upto = cv.cursorNs;
      return cv.samples.filter((s) => s.series === series && (upto === null || s.ts_boottime_ns <= upto)).slice(-300);
    }
    const seen = new Set<number>();
    const cutoff = Date.now() / 1000 - windowS;
    return [...(hist ?? []).filter((s) => s.series === series), ...(eventStream.telemetry.get(series) ?? [])]
      .filter((s) => (seen.has(s.ts_boottime_ns) ? false : (seen.add(s.ts_boottime_ns), true)) && s.ts_wall >= cutoff)
      .sort((a, b) => a.ts_boottime_ns - b.ts_boottime_ns);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [hist, series, windowS, cv, eventStream.state.version]);
}

export const num = (s: TelemetrySample | undefined, k: string): number | null => {
  const v = (s?.values as Record<string, number | null> | undefined)?.[k];
  return v === undefined ? null : v;
};
