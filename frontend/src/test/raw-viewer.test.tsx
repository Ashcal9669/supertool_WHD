import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { fireEvent, render, screen } from "@testing-library/react";
import { vi } from "vitest";
import * as client from "../api/client";
import type { Device } from "../api/types";
import { RawViewer } from "../device/RawViewer";

test("raw viewer explains blocked files without reading them and disables wake reads for ineligible adapters", async () => {
  const reads: string[] = [];
  const spy = vi.spyOn(client, "api").mockImplementation((path) => {
    if (path.includes('/raw-files?')) return Promise.resolve({ device_id: "fixture-device", phy: "phy-test", truncated: false, files: [
      { path: "mt76/chip_reset", tier: "never", policy: "write-only action: triggers chip reset", mode: "--w-------" },
      { path: "mt76/acq", tier: "mmio", policy: "per-AC PLE queue occupancy (hardware register read)", mode: "-r--------" },
      { path: "mt76/new_node", tier: null, policy: "not on the WHD debugfs allowlist", mode: "-r--------" },
      { path: "mt76/link_stats", tier: "wakes_device", policy: "reading wakes the chip", mode: "-r--------" },
      { path: "mt76/deep-sleep", tier: "passive", policy: "deep sleep flag (memory)", mode: "-rw-------" },
    ] }) as never;
    reads.push(path);
    return Promise.resolve({ text: "0\n", bytes: 2, binary: false, truncated: false, elapsed_ms: 0.1, read_at_boottime_ns: 1, read_at_wall: 1 }) as never;
  });
  try {
    render(<QueryClientProvider client={new QueryClient({ defaultOptions: { queries: { retry: false } } })}><RawViewer d={{ id: "fixture-device", active_test_eligible: false, demo: false } as Device} phy="phy-test" /></QueryClientProvider>);
    expect(await screen.findByText(/Access labels describe read effects/)).toBeVisible();
    expect(screen.getByRole('checkbox')).toBeDisabled();
    for (const name of ['mt76/chip_reset', 'mt76/acq', 'mt76/new_node', 'mt76/link_stats']) {
      fireEvent.click(screen.getByRole('button', { name: new RegExp(name) }));
      expect(reads).toEqual([]);
    }
    expect(screen.getByText(/MT7922 exclusively/)).toBeVisible();
    fireEvent.click(screen.getByRole('button', { name: /mt76\/deep-sleep/ }));
    expect(await screen.findByTestId('raw-text')).toHaveTextContent('0');
    expect(reads).toHaveLength(1);
  } finally { spy.mockRestore(); }
});
