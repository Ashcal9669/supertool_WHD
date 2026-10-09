import { expect, test } from "@playwright/test";
import { login, trackErrors } from "./util";

const DMESG = `[    0.000000] Linux version 6.8.0 (build@otherhost) #1 SMP
[   12.345678] mt7925e 0000:07:00.0: ASIC revision: 7927
[   13.000000] mt7925e 0000:07:00.0: Loading firmware patch: mediatek/mt7927/PATCH.bin
[   20.000000] wlan0: authenticate with 02:ee:aa:11:22:33 (local address=02:aa:bb:cc:dd:ee)
[   20.200000] wlan0: associated
[  100.100000] mt7925e 0000:07:00.0: Retry message 00020027 (seq 12)
[  103.100000] mt7925e 0000:07:00.0: Message 00020027 (seq 12) timeout
[  103.200000] mt7925e 0000:07:00.0: chip reset
[  103.900000] wlan0: deauthenticated from 02:ee:aa:11:22:33 (Reason: 7=CLASS3_FRAME_FROM_NONASSOC_STA)
`;

test("import a raw dmesg log from another machine, diagnose and visualize it", async ({ page }) => {
  test.setTimeout(90_000);
  const done = trackErrors(page);
  await login(page);
  await page.getByRole("link", { name: "Captures" }).click();
  await page.getByLabel("capture file").setInputFiles({ name: "otherhost.dmesg", mimeType: "text/plain", buffer: Buffer.from(DMESG) });
  await page.getByLabel("import name").fill("otherhost crash");
  await page.getByRole("button", { name: "Import", exact: true }).click();
  const res = page.getByTestId("import-result");
  await expect(res).toContainText("format dmesg", { timeout: 15_000 });
  await expect(res).toContainText("IMPORTED");
  await expect(res).toContainText("0 device snapshot");
  // diagnose
  await res.getByRole("link", { name: "Diagnose" }).click();
  await page.getByRole("button", { name: "Analyze" }).click();
  await expect(page.getByText(/IMPORTED CAPTURE \(recorded elsewhere/)).toBeVisible({ timeout: 20_000 });
  await expect(page.getByText("MCU/firmware stopped answering host commands")).toBeVisible();
  await expect(page.getByText("UNCONFIRMED HYPOTHESIS").first()).toBeVisible();
  await expect(page.getByText(/Imported capture: timestamps are in the origin machine/)).toBeVisible();
  // visualize with playback cursor
  await page.getByRole("link", { name: "Visualizations" }).click();
  const opt = page.getByLabel("source").locator("option", { hasText: "otherhost crash" }).first();
  await page.getByLabel("source").selectOption((await opt.getAttribute("value"))!);
  await expect(page.getByTestId("cursor-bar")).toBeVisible({ timeout: 15_000 });
  await expect(page.getByText("IMPORTED CAPTURE — recorded elsewhere")).toBeVisible();
  const all = await page.getByTestId("cursor-bar").innerText();
  const n1 = Number(/(\d+) events in view/.exec(all)![1]);
  expect(n1).toBeGreaterThan(3);
  await page.getByLabel("playback position").fill("0");
  await expect(page.getByTestId("cursor-bar")).toContainText(/\b[0-3] events in view/);
  await page.getByLabel("playback position").fill("1000");
  await expect(page.getByTestId("cursor-bar")).toContainText(`${n1} events in view`);
  await page.getByRole("button", { name: "Firmware command sequence" }).click();
  await expect(page.getByText(/timeout seq 12/).first()).toBeVisible();
  done();
});

test.describe("bundle from another server", () => {
  test.skip(!process.env.WHD_SOURCE_URL, "set WHD_SOURCE_URL/WHD_SOURCE_TOKEN to export a bundle from another WHD");
  test("import a diagnostic bundle exported elsewhere", async ({ page, request }) => {
    test.setTimeout(120_000);
    const src = process.env.WHD_SOURCE_URL!;
    const h = { Authorization: `Bearer ${process.env.WHD_SOURCE_TOKEN}` };
    const created = await request.post(`${src}/api/v1/captures`, { headers: h, data: { name: "from-elsewhere", max_seconds: 60 } });
    const id = (await created.json()).id;
    await new Promise((r) => setTimeout(r, 12_000));
    await request.post(`${src}/api/v1/captures/${id}/stop`, { headers: h });
    const bundle = await request.get(`${src}/api/v1/captures/${id}/bundle`, { headers: h });
    expect(bundle.ok()).toBeTruthy();
    const done = trackErrors(page);
    await login(page);
    await page.getByRole("link", { name: "Captures" }).click();
    await page.getByLabel("capture file").setInputFiles({ name: "bundle.zip", mimeType: "application/zip", buffer: await bundle.body() });
    await page.getByRole("button", { name: "Import", exact: true }).click();
    const res = page.getByTestId("import-result");
    await expect(res).toContainText("format whd-bundle", { timeout: 20_000 });
    await expect(res).toContainText(/[1-9]\d* device snapshot/);
    await res.getByRole("link", { name: "Visualize" }).click();
    await expect(page.getByTestId("cursor-bar")).toBeVisible({ timeout: 15_000 });
    await page.getByRole("button", { name: "TX/RX queue activity" }).click();
    await expect(page.getByText("TX data ring (WFDMA0)")).toBeVisible({ timeout: 15_000 });
    done();
  });
});
