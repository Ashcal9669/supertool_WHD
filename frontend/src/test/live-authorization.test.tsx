import { render, screen } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { vi } from "vitest";
import type { Device } from "../api/types";
import * as client from "../api/client";
import { LivePhyTab } from "../device/LivePhyTab";

vi.mock("../components/TimeChart", () => ({ TimeChart: () => null }));
vi.mock("../hooks/useEventStream", () => ({ useEventStream: () => ({ events: [] }) }));

test("decoded uppercase nl80211 authorization reaches the current connection display", async () => {
  const d = { id: "fixture-device", wiphys: [] } as unknown as Device;
  const spy = vi.spyOn(client, "api").mockImplementation((path) => {
    if (path.endsWith("/wireless/live")) return Promise.resolve({ boot_id: "boot-a", notes: [], capability_summary: {}, regulatory: [], other_interfaces_on_wiphy: [], interfaces: [{ interface: { ifindex: 7, name: "wifi-fixture", iftype: "STATION", mlo_links: [], wdev: 11 }, connected: true, errors: {}, stations: [{ mac: "02:00:00:00:00:01", flags: { AUTHORIZED: true }, chain_signal_dbm: [], links: [] }], survey: [], scan: [] }] }) as never;
    if (path.startsWith("/events")) return Promise.resolve({ events: [] }) as never;
    return Promise.resolve([]) as never;
  });
  try {
    render(<QueryClientProvider client={new QueryClient({ defaultOptions: { queries: { retry: false } } })}><LivePhyTab d={d} /></QueryClientProvider>);
    expect(await screen.findByText(/Current state from fresh nl80211 station reading: AUTHORIZED/)).toBeVisible();
  } finally { spy.mockRestore(); }
});
