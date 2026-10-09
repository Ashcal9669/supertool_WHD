import { describe, expect, test } from "vitest";
import type { TopoEdge, TopoNode, WhdEvent } from "../api/types";
import { layerOf, LAYERS } from "../lib/layers";
import { layeredLayout } from "../viz/layout";
import { deriveTransitions, stateFor } from "../viz/ConnStateMachine";
import { toMessages } from "../viz/FirmwareSequence";

const ev = (kind: string, ts: number, extra: Partial<WhdEvent> = {}): WhdEvent => ({
  id: ts, ts_boottime_ns: ts * 1e9, ts_source: "receive_boottime", ts_raw: null, ts_wall: ts, source: "t", device_id: "d",
  severity: "info", category: "association", kind, summary: kind, explanation: "", raw: "", data: {}, demo: false, session: null,
  ...extra,
});

describe("layer mapping", () => {
  test("every category maps to a known layer; unknown falls back to driver", () => {
    for (const c of ["pci_error", "firmware", "association", "netdev", "reset", "usb_transfer"]) expect(LAYERS).toContain(layerOf(ev("x", 1, { category: c as WhdEvent["category"] })));
    expect(layerOf(ev("x", 1, { category: "reset" }))).toBe("firmware");
    expect(layerOf(ev("x", 1, { category: "pci_link" }))).toBe("bus");
  });
});

describe("connection state machine", () => {
  test("derives transitions only from observed events, in time order", () => {
    const evs = [
      ev("assoc.associated", 5), ev("assoc.authenticate", 1), ev("assoc.authenticated", 2), ev("assoc.assoc_resp", 4, { data: { status: "0" } }),
      ev("nl80211.port_authorized", 6), ev("assoc.deauth_by_ap", 9), ev("kernel.message", 10),
    ];
    const t = deriveTransitions(evs);
    expect(t.map((x) => x.to)).toEqual(["AUTHENTICATING", "ASSOCIATING", "ASSOCIATED", "AUTHORIZED", "DISCONNECTED"]);
    expect(t[0].from).toBeNull();
    expect(stateFor(ev("kernel.message", 1))).toBeNull();
  });
  test("failed association response goes to DISCONNECTED; scan returns to prior state", () => {
    expect(stateFor(ev("assoc.assoc_resp", 1, { data: { status: "17" } }))).toBe("DISCONNECTED");
    const t = deriveTransitions([ev("assoc.associated", 1), ev("nl80211.trigger_scan", 2), ev("nl80211.new_scan_results", 3)]);
    expect(t.map((x) => x.to)).toEqual(["ASSOCIATED", "SCANNING", "ASSOCIATED"]);
  });
});

describe("firmware sequence extraction", () => {
  test("pairs send/response, marks timeouts, ignores unrelated events", () => {
    const f = (fields: Record<string, string>) => ({ data: { fields } });
    const msgs = toMessages([
      ev("trace.mt76.mcu_send", 1, f({ cmd: "00020027", seq: "1", retry: "0" })),
      ev("trace.mt76.mcu_resp", 2, f({ seq: "1", ret: "0", timeout: "0", latency_us: "1500" })),
      ev("trace.mt76.mcu_resp", 3, f({ seq: "2", ret: "-110", timeout: "1", latency_us: "6000000" })),
      ev("assoc.associated", 4), ev("reset.chip_reset", 5),
    ]);
    expect(msgs.map((m) => m.label)).toEqual(["cmd 00020027 seq 1", "resp seq 1 ret 0", "TIMEOUT seq 2", "chip reset"]);
    expect(msgs[1].note).toBe("1.5 ms");
    expect(msgs[2].color).toBe("#f87171");
    expect(msgs[0].from).toBe(0);
    expect(msgs[3].to).toBe(2);
  });
});

describe("topology layout", () => {
  const n = (id: string): TopoNode => ({ id, kind: "other", label: id, sublabel: null, device_id: null, sysfs_path: null, state: {}, attrs: {}, evidence: "" });
  const e = (s: string, t: string): TopoEdge => ({ id: `${s}->${t}`, source: s, target: t, kind: "bus", label: null, state: {} });
  test("ranks follow edge depth, siblings spread horizontally, deterministic", () => {
    const nodes = ["root", "bridge", "dev", "drv", "fw"].map(n);
    const edges = [e("root", "bridge"), e("bridge", "dev"), e("dev", "drv"), e("drv", "fw")];
    const a = layeredLayout(nodes, edges);
    expect([...a.values()].map((p) => p.y)).toEqual([0, 96, 192, 288, 384]);
    expect(new Set([...a.values()].map((p) => p.x)).size).toBe(1);
    const nodes2 = [...nodes, n("usb")];
    const b = layeredLayout(nodes2, [...edges, e("dev", "usb")]);
    expect(b.get("usb")!.y).toBe(b.get("drv")!.y);
    expect(b.get("usb")!.x).not.toBe(b.get("drv")!.x);
    expect(JSON.stringify([...layeredLayout(nodes2, [...edges, e("dev", "usb")])])).toBe(JSON.stringify([...b]));
  });
  test("cycles do not hang", () => {
    const p = layeredLayout([n("a"), n("b")], [e("a", "b"), e("b", "a")]);
    expect(p.size).toBe(2);
  });
});
