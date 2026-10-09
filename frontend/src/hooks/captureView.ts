import { createContext } from "react";
import type { TelemetrySample } from "../api/types";

/**
 * When set, visualizations read telemetry from a stored/imported capture instead of the live stream, and only
 * show data up to `cursorNs` (the playback position).
 */
export interface CaptureView {
  samples: TelemetrySample[];
  cursorNs: number | null;
}

export const CaptureViewContext = createContext<CaptureView | null>(null);
