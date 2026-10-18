import { render, screen, within } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { MemoryRouter } from "react-router-dom";
import * as client from "../api/client";
import type { DeviceSummary } from "../api/types";
import { InventoryPage } from "../pages/Inventory";

test("inventory separates presence, binding, DOWN and active-test policy without hiding adapters", async () => {
  const base = { bus: "pci", sysfs_path: "/fixture/pci", vendor_id: 0x14c3, product_id: 0x0616,
    vendor_name: "MediaTek", product_name: null, driver: "mt7921e_git", module: "mt7921e_git", firmware_version: null,
    phys: ["phy0"], netdevs: ["wifi22"], operstate: "down", detection: [], first_seen: 1, last_seen: 1,
    present: true, demo: false, active_test_eligible: true, active_test_reason: "verified MT7922 active-test target" };
  const devices = [
    { ...base, id: "mt22", title: "MT7922 DOWN" },
    { ...base, id: "mt27", title: "MT7927 DOWN", product_id: 0x7927, active_test_eligible: false, active_test_reason: "active testing restricted to MT7922" },
    { ...base, id: "unbound", title: "Unbound adapter", driver: null, module: null, phys: [], netdevs: [], operstate: null, active_test_eligible: false, active_test_reason: "driver not verified" },
    { ...base, id: "stored-absent", title: "Stored adapter", present: false },
    { ...base, id: "demo", title: "Fixture adapter", demo: true },
  ] as DeviceSummary[];
  const spy = vi.spyOn(client, "api").mockImplementation(path => {
    if (path === "/devices") return Promise.resolve({ devices, issues: [], duration_ms: 1, taken_at: 1 }) as never;
    if (path === "/system") return Promise.resolve({ integrations: [] }) as never;
    return Promise.reject(new Error(`Unexpected request: ${path}`));
  });
  try {
    render(<QueryClientProvider client={new QueryClient({ defaultOptions: { queries: { retry: false } } })}><MemoryRouter><InventoryPage /></MemoryRouter></QueryClientProvider>);
    const mt22 = within(await screen.findByRole("link", { name: /MT7922 DOWN/ }));
    expect(mt22.getByText("present", { exact: true })).toBeVisible();
    expect(mt22.getAllByText("mt7921e_git")).toHaveLength(2);
    expect(mt22.getByText("down", { exact: true })).toBeVisible();
    expect(mt22.getByText("eligible", { exact: true })).toBeVisible();
    expect(mt22.getByText("verified MT7922 active-test target")).toBeVisible();
    const mt27 = within(screen.getByRole("link", { name: /MT7927 DOWN/ }));
    expect(mt27.getByText("present", { exact: true })).toBeVisible();
    expect(mt27.getByText("not eligible", { exact: true })).toBeVisible();
    expect(mt27.getByText("active testing restricted to MT7922")).toBeVisible();
    const unbound = within(screen.getByRole("link", { name: /Unbound adapter/ }));
    expect(unbound.getByText("present", { exact: true })).toBeVisible();
    expect(unbound.getByText("not bound")).toBeVisible();
    expect(unbound.getByText("n/a")).toBeVisible();
    expect(within(screen.getByRole("link", { name: /Stored adapter/ })).getByText("absent")).toBeVisible();
    expect(within(screen.getByRole("link", { name: /Stored adapter/ })).getByText("not eligible")).toBeVisible();
    expect(within(screen.getByRole("link", { name: /Fixture adapter/ })).getByText("not eligible")).toBeVisible();
  } finally { spy.mockRestore(); }
});
