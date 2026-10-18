import { expect, test } from "@playwright/test";
import { login, trackErrors } from "./util";

test("served Wi-Fi Evidence retains fresh readings and separates unassigned observations", async ({ page }, info) => {
  const done = trackErrors(page);
  await login(page);
  const inventory = await (await page.request.get('/api/v1/devices')).json();
  const devices = inventory.devices.filter((d: { present: boolean; netdevs: string[] }) => d.present && d.netdevs.length);
  expect(devices.length).toBeGreaterThan(0);
  for (const d of devices) {
    const path = `/api/v1/devices/${encodeURIComponent(d.id)}`;
    const rep = await (await page.request.get(`${path}/mlo/evidence`)).json();
    const live = await (await page.request.get(`${path}/wireless/live`)).json();
    const iface = live.interfaces.find((i: { interface: { name: string } }) => i.interface.name === rep.current_observations.interface);
    expect(iface).toBeTruthy();
    expect(rep.current_observations.connected).toBe(iface.connected);
    await page.goto(`/device/${encodeURIComponent(d.id)}?tab=mlo`);
    await expect(page.getByText('Collected current observations', { exact: true })).toBeVisible();
    await expect(page.getByText('Station authorization (MLD)', { exact: true })).toBeVisible();
    if (rep.current_observations.packed_link_mask != null) {
      await expect(page.getByText(`0x${rep.current_observations.packed_link_mask.toString(16)}`, { exact: true })).toBeVisible();
    }
    expect(rep.unassigned_observations.every((e: { device_id: string | null }) => e.device_id === null)).toBe(true);
    await page.screenshot({ path: info.outputPath(`evidence-${d.product_id}.png`), fullPage: true });
    await page.goto(`/device/${encodeURIComponent(d.id)}?tab=live`);
    const expected = !rep.current_observations.connected ? 'DISCONNECTED' : rep.current_observations.station_authorized ? 'AUTHORIZED' : 'ASSOCIATED';
    await expect(page.getByText(new RegExp(`Current state from fresh nl80211 station reading: ${expected}`)).first()).toBeVisible();
  }
  done();
});
