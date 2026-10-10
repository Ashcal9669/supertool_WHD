import { describe, expect, it } from "vitest";
import type { TelemetrySample } from "../api/types";
import { ringDefs, ringKeys, ringName } from "../lib/rings";

const sample = (values: Record<string, number | null>): TelemetrySample =>
  ({ ts_boottime_ns: 1, ts_wall: 1, device_id: "d", series: "s", values, demo: false }) as unknown as TelemetrySample;

describe("rings", () => {
  it("takes ring names from the samples, not from any chip", () => {
    const xs = [sample({ "WFDMA0.queued": 1, "MCUWM.queued": 0 }), sample({ "TXQ2.queued": 3, "TXQ10.queued": 1, "TXQ2.submitted": 4 })];
    expect(ringKeys(xs, ".queued")).toEqual(["MCUWM.queued", "TXQ2.queued", "TXQ10.queued", "WFDMA0.queued"]);
    expect(ringKeys(xs, ".submitted")).toEqual(["TXQ2.submitted"]);
    expect(ringName("TXQ2.queued", ".queued")).toBe("TXQ2");
  });
  it("builds one distinct-colour series per ring", () => {
    const defs = ringDefs(["a.queued", "b.queued"], ".queued", "queued");
    expect(defs.map((d) => d.label)).toEqual(["a queued", "b queued"]);
    expect(new Set(defs.map((d) => d.color)).size).toBe(2);
  });
  it("handles no samples", () => {
    expect(ringKeys([], ".queued")).toEqual([]);
  });
});
