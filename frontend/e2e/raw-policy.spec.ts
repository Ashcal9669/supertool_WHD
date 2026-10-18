import { expect, test } from "@playwright/test";
import { login, trackErrors } from "./util";

test("served raw viewer explains restricted nodes without issuing their reads", async ({ page }, info) => {
  const done = trackErrors(page);
  await login(page);
  const inventory = await (await page.request.get('/api/v1/devices')).json();
  const device = inventory.devices.find((d: { present: boolean; product_id: number; vendor_id: number }) => d.present && d.vendor_id === 0x14c3 && d.product_id === 0x7927);
  expect(device).toBeTruthy();
  const listing = await (await page.request.get(`/api/v1/devices/${encodeURIComponent(device.id)}/mt76/raw-files`)).json();
  const reads: string[] = [];
  page.on('request', request => { if (request.url().includes('/mt76/raw?')) reads.push(request.url()); });
  await page.goto(`/device/${encodeURIComponent(device.id)}?tab=mt76`);
  await page.getByRole('button', { name: 'Raw files', exact: true }).click();
  await expect(page.getByText(/Access labels describe read effects/)).toBeVisible();
  await expect(page.getByRole('checkbox', { name: 'allow reads that wake the chip' })).toBeDisabled();
  const actions = listing.files.filter((f: { tier: string }) => ['mmio', 'mcu', 'never'].includes(f.tier));
  expect(actions.length).toBeGreaterThan(0);
  for (const f of actions) {
    await page.getByLabel('filter files').fill(f.path);
    await page.getByRole('button', { name: new RegExp(f.path.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')) }).click();
    await expect(page.getByText(`Read blocked: ${f.policy}`, { exact: true })).toBeVisible();
  }
  expect(reads).toEqual([]);
  const activate = listing.files.find((f: { path: string }) => f.path === 'mt76/mlo_activate_now');
  if (activate) expect(activate.tier).toBe('never');
  await page.screenshot({ path: info.outputPath('raw-policy.png'), fullPage: true });
  done();
});
