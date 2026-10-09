/**
 * Singleton WebSocket client for /api/v1/stream.
 * - reconnects with exponential backoff and resumes from the last received event id (server replays the gap
 *   from SQLite, bounded to 2000 events)
 * - keeps bounded in-memory buffers (events + per-series telemetry rings)
 * - exposes a subscribe/getSnapshot API for useSyncExternalStore
 */
import { wsUrl } from "../api/client";
import type { TelemetrySample, WhdEvent } from "../api/types";

export interface StreamFilter {
  device_id?: string;
  categories?: string[];
  min_severity?: string;
  text?: string;
  sources?: string[];
}

export interface SourceStatus { name: string; state: string; detail: string | null; events: number; errors: number }

export interface StreamState {
  connected: boolean;
  connecting: boolean;
  reconnects: number;
  lastId: number | null;
  dropped: number;
  serverBootNs: number | null;
  mode: string | null;
  sources: SourceStatus[];
  events: WhdEvent[];
  version: number;
}

const MAX_EVENTS = 5000;
const MAX_POINTS = 900;
const FLUSH_MS = 250;

type Listener = () => void;

class EventStream {
  private ws: WebSocket | null = null;
  private listeners = new Set<Listener>();
  private eventListeners = new Set<(e: WhdEvent) => void>();
  private telListeners = new Set<(s: TelemetrySample) => void>();
  private retry = 0;
  private timer: ReturnType<typeof setTimeout> | null = null;
  private filter: StreamFilter = {};
  private wantTelemetry = true;
  private refs = 0;
  telemetry = new Map<string, TelemetrySample[]>();
  state: StreamState = {
    connected: false, connecting: false, reconnects: 0, lastId: null, dropped: 0, serverBootNs: null, mode: null,
    sources: [], events: [], version: 0,
  };

  subscribe = (l: Listener) => {
    this.listeners.add(l);
    return () => this.listeners.delete(l);
  };
  getSnapshot = () => this.state;
  onEvent(fn: (e: WhdEvent) => void) {
    this.eventListeners.add(fn);
    return () => this.eventListeners.delete(fn);
  }
  onTelemetry(fn: (s: TelemetrySample) => void) {
    this.telListeners.add(fn);
    return () => this.telListeners.delete(fn);
  }

  private emit(patch: Partial<StreamState>) {
    this.state = { ...this.state, ...patch, version: this.state.version + 1 };
    this.listeners.forEach((l) => l());
  }

  acquire() {
    this.refs++;
    if (this.refs === 1) this.connect();
  }
  release() {
    this.refs = Math.max(0, this.refs - 1);
    if (this.refs === 0) this.close();
  }

  setFilter(f: StreamFilter) {
    this.filter = f;
    if (this.ws?.readyState === WebSocket.OPEN) {
      this.ws.send(JSON.stringify({ type: "filter", ...this.toParams(f) }));
    }
    this.buf = [];
    this.emit({ events: [], lastId: this.state.lastId });
  }

  private toParams(f: StreamFilter): Record<string, string> {
    const p: Record<string, string> = {};
    if (f.device_id) p.device_id = f.device_id;
    if (f.categories?.length) p.categories = f.categories.join(",");
    if (f.min_severity) p.min_severity = f.min_severity;
    if (f.text) p.text = f.text;
    if (f.sources?.length) p.sources = f.sources.join(",");
    return p;
  }

  private connect() {
    if (this.ws) return;
    const params = new URLSearchParams(this.toParams(this.filter));
    if (this.wantTelemetry) params.set("telemetry", "1");
    if (this.state.lastId !== null) params.set("since_id", String(this.state.lastId));
    this.emit({ connecting: true });
    const ws = new WebSocket(wsUrl(`/stream?${params}`));
    this.ws = ws;
    ws.onopen = () => {
      this.retry = 0;
      this.emit({ connected: true, connecting: false });
    };
    ws.onmessage = (m) => this.handle(JSON.parse(m.data));
    ws.onclose = (ev) => {
      this.ws = null;
      this.emit({ connected: false, connecting: false });
      if (this.refs > 0 && ev.code !== 4401) {
        const delay = Math.min(30000, 500 * 2 ** this.retry++);
        this.timer = setTimeout(() => {
          this.emit({ reconnects: this.state.reconnects + 1 });
          this.connect();
        }, delay);
      }
    };
    ws.onerror = () => ws.close();
  }

  private close() {
    if (this.timer) clearTimeout(this.timer);
    this.timer = null;
    this.ws?.close();
    this.ws = null;
  }

  // Events arrive far faster than the UI needs to repaint (a trace can deliver thousands per second).
  // Buffer them and publish one new state object at most every FLUSH_MS.
  private buf: WhdEvent[] = [];
  private flushTimer: ReturnType<typeof setTimeout> | null = null;
  private scheduleFlush() {
    if (this.flushTimer) return;
    this.flushTimer = setTimeout(() => {
      this.flushTimer = null;
      if (this.buf.length === 0) return;
      const merged = this.state.events.concat(this.buf);
      const events = merged.length > MAX_EVENTS ? merged.slice(merged.length - MAX_EVENTS) : merged;
      const lastId = this.buf.reduce((m, e) => Math.max(m, e.id ?? 0), this.state.lastId ?? 0);
      this.buf = [];
      this.emit({ events, lastId });
    }, FLUSH_MS);
  }

  private handle(msg: Record<string, unknown>) {
    switch (msg.type) {
      case "hello":
        this.emit({ serverBootNs: msg.server_boottime_ns as number, mode: msg.mode as string });
        break;
      case "event": {
        const e = msg.event as WhdEvent;
        this.buf.push(e);
        this.scheduleFlush();
        this.eventListeners.forEach((fn) => fn(e));
        break;
      }
      case "telemetry": {
        const s = msg.sample as TelemetrySample;
        const arr = this.telemetry.get(s.series) ?? [];
        arr.push(s);
        if (arr.length > MAX_POINTS) arr.splice(0, arr.length - MAX_POINTS);
        this.telemetry.set(s.series, arr);
        this.telListeners.forEach((fn) => fn(s));
        break;
      }
      case "status":
        this.emit({ dropped: msg.dropped as number, sources: msg.sources as SourceStatus[], serverBootNs: msg.server_boottime_ns as number });
        break;
      default:
        break;
    }
  }
}

export const eventStream = new EventStream();
