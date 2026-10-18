import { expect, test } from "@playwright/test";
import { login, trackErrors } from "./util";

test("served inventory distinguishes present down adapters and their PCI topology paths", async ({ page }, info) => {
  const done = trackErrors(page);
  await login(page);
  const inventory = await (await page.request.get("/api/v1/devices")).json();
  const mt27 = inventory.devices.find((d: { vendor_id: number; product_id: number; present: boolean }) => d.vendor_id === 0x14c3 && d.product_id === 0x7927 && d.present);
  const mt22 = inventory.devices.find((d: { vendor_id: number; product_id: number; present: boolean }) => d.vendor_id === 0x14c3 && d.product_id === 0x0616 && d.present);
  expect(mt27).toBeTruthy(); expect(mt22).toBeTruthy();
  expect(mt27.active_test_eligible).toBe(false); expect(mt22.active_test_eligible).toBe(true);
  for (const d of [mt27, mt22]) {
    const card = page.locator("a.panel").filter({ hasText: d.id });
    await expect(card).toContainText("present");
    await expect(card.getByText("absent", { exact: true })).toHaveCount(0);
    await expect(card).toContainText(d.driver);
    for (const name of [...d.phys, ...d.netdevs]) await expect(card).toContainText(name);
    await expect(card).toContainText(d.operstate);
  }
  await page.screenshot({ path: info.outputPath("inventory-both.png"), fullPage: true });
  await page.getByRole("link", { name: "Topology", exact: true }).click();
  const topology = await (await page.request.get("/api/v1/topology")).json();
  const details = await Promise.all([mt27, mt22].map(async d => (await page.request.get(`/api/v1/devices/${encodeURIComponent(d.id)}`)).json()));
  expect(details[0].sysfs_path).not.toBe(details[1].sysfs_path);
  for (const d of details) {
    const pci = topology.nodes.find((n: { kind: string; sysfs_path: string }) => n.kind === "pci_device" && n.sysfs_path === d.sysfs_path);
    expect(pci).toBeTruthy();
    await expect(page.locator(`.react-flow__node[data-id=${JSON.stringify(pci.id)}]`)).toBeVisible();
    for (const name of [...d.phys, ...d.netdevs]) await expect(page.locator(".react-flow__node").filter({ hasText: name }).first()).toBeVisible();
  }
  await page.screenshot({ path: info.outputPath("topology-both.png"), fullPage: true });
  await page.getByRole("link", { name: "Wi-Fi evidence", exact: true }).click();
  await page.getByLabel("Wi-Fi device").selectOption(mt27.id);
  await expect(page.getByTestId("mlo-evidence")).toBeVisible();
  await expect(page.getByRole("button", { name: "Run bound measurement" })).toHaveCount(0);
  done();
});
