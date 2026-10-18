import { expect, test } from "@playwright/test";
import { login, trackErrors } from "./util";

test("served current state agrees with fresh wireless readings, history stays historical", async ({ page }, info) => {
  const done = trackErrors(page);
  await login(page);
  const inventory = await (await page.request.get("/api/v1/devices")).json();
  for (const d of inventory.devices.filter((d: { present: boolean; netdevs: string[] }) => d.present && d.netdevs.length)) {
    const live = await (await page.request.get(`/api/v1/devices/${encodeURIComponent(d.id)}/wireless/live`)).json();
    await page.goto(`/device/${encodeURIComponent(d.id)}?tab=live`);
    for (const li of live.interfaces.filter((li: { interface: { iftype: string } }) => ["STATION", "P2P_CLIENT"].includes(li.interface.iftype))) {
      if (li.connected !== null) await expect(page.getByText(`Current state from fresh nl80211 station reading: ${li.connected ? "ASSOCIATED" : "DISCONNECTED"}. Authorization requires a separate observation.`).first()).toBeVisible();
    }
    await expect(page.getByText(/Current state from event/)).toHaveCount(0);
    await page.screenshot({ path: info.outputPath(`current-${d.product_id}.png`), fullPage: true });
  }
  done();
});


test("served UI never treats an old association fixture as current", async ({ page }, info) => {
  await login(page);
  const inventory = await (await page.request.get("/api/v1/devices")).json();
  const d = inventory.devices.find((d: { present: boolean; product_id: number }) => d.present && d.product_id === 0x7927);
  expect(d).toBeTruthy();
  const live = await (await page.request.get(`/api/v1/devices/${encodeURIComponent(d.id)}/wireless/live`)).json();
  expect(live.interfaces[0].connected).toBe(false);
  // Only historical event input is a fixture; current station data and UI assets are the actual served implementation.
  await page.route("**/api/v1/events?**", async route => {
    const response = await route.fetch();
    const json = await response.json();
    json.events = [{ id: 987654321, device_id: d.id, kind: "assoc.associated", ts_boottime_ns: 1, ts_wall: 1, summary: "old association fixture", data: { boot_id: "historical-fixture-boot" } }];
    await route.fulfill({ response, json });
  });
  await page.goto(`/device/${encodeURIComponent(d.id)}?tab=live`);
  await expect(page.getByText(/Current state from fresh nl80211 station reading: DISCONNECTED/)).toBeVisible();
  await expect(page.getByText(/Historical transitions/)).toBeVisible();
  await expect(page.getByText(/historical-fixture-boot/)).toBeVisible();
  await expect(page.getByText(/Current state from event/)).toHaveCount(0);
  await page.screenshot({ path: info.outputPath("historical-fixture-current-disconnected.png"), fullPage: true });
});
