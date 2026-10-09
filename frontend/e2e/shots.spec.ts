import { expect, test, type Page } from "@playwright/test";
import fs from "node:fs";
import { login } from "./util";

// Generates README screenshots from DEMO-mode servers only (fixture data, masked MACs). Skipped unless WHD_SHOTS is set.
test.skip(!process.env.WHD_SHOTS, "set WHD_SHOTS=<output dir>");
const OUT = process.env.WHD_SHOTS ?? "";
// Generic guard (nothing personal is listed here): non-synthetic MACs, private IPs, home paths, e-mail addresses.
// Extra case-insensitive regex sources can be supplied via WHD_SHOT_FORBIDDEN (separated by ';;').
const FORBIDDEN: RegExp[] = [
  /\b(?!02:|ff:ff:ff:ff:ff:ff|00:00:00:00:00:00)(?:[0-9a-f]{2}:){5}[0-9a-f]{2}\b/i,
  /\b(?:10|192\.168|172\.(?:1[6-9]|2\d|3[01]))\.\d+\.\d+(?:\.\d+)?\b/,
  /\/home\/[\w.-]+/,
  /[\w.+-]+@[\w-]+\.[a-z]{2,}/i,
  ...(process.env.WHD_SHOT_FORBIDDEN ?? "").split(";;").filter(Boolean).map((x) => new RegExp(x, "i")),
];

async function shot(page: Page, name: string, fullPage = false) {
  const text = await page.locator("body").innerText();
  for (const re of FORBIDDEN) expect(text, `${name}: page text matches ${re}`).not.toMatch(re);
  fs.mkdirSync(OUT, { recursive: true });
  await page.screenshot({ path: `${OUT}/${name}.png`, fullPage });
}
const tab = (page: Page, n: string) => page.getByRole("button", { name: n, exact: true }).click();

test("pcie demo screens", async ({ page }) => {
  test.setTimeout(240_000);
  await page.setViewportSize({ width: 1440, height: 900 });
  await login(page);
  await page.waitForTimeout(Number(process.env.WHD_SHOT_WAIT ?? 30_000)); // let the scripted incident stream in
  await shot(page, "01-inventory");
  await page.locator("a[href^='/device/']").first().click();
  await expect(page.getByText("Bus path (discovered)")).toBeVisible();
  await shot(page, "02-device-overview");
  await tab(page, "Bus"); await page.waitForTimeout(500); await shot(page, "03-pcie-bus");
  await tab(page, "Wireless PHY"); await page.waitForTimeout(500); await shot(page, "04-wireless-phy-caps");
  await tab(page, "mt76"); await expect(page.getByText("Coverage by diagnostic category")).toBeVisible(); await page.waitForTimeout(500);
  await shot(page, "05-mt76-coverage");
  await page.getByRole("link", { name: "Topology" }).click(); await page.waitForTimeout(1500); await shot(page, "06-topology");
  await page.getByRole("link", { name: "Timeline" }).click(); await page.getByLabel("minimum severity").selectOption("notice");
  await page.waitForTimeout(2000); await shot(page, "07-timeline");
  await page.getByRole("link", { name: "Visualizations" }).click(); await page.waitForTimeout(2000);
  await shot(page, "08-viz-error-propagation");
  await tab(page, "Firmware command sequence"); await page.waitForTimeout(1200); await shot(page, "09-viz-firmware-sequence");
  await tab(page, "TX/RX queue activity"); await page.waitForTimeout(2500); await shot(page, "10-viz-queue-activity");
  await page.getByRole("link", { name: "Diagnostics" }).click();
  await page.getByRole("button", { name: "Analyze" }).click();
  await expect(page.getByText("UNCONFIRMED HYPOTHESIS").first()).toBeVisible({ timeout: 30_000 });
  await page.waitForTimeout(800);
  await shot(page, "11-diagnostics", true);
});

test("capture import screens", async ({ page }) => {
  test.setTimeout(120_000);
  await page.setViewportSize({ width: 1440, height: 900 });
  const dm = fs.readFileSync(process.env.WHD_SAMPLE_DMESG!);
  await login(page);
  await page.getByRole("link", { name: "Captures" }).click();
  await page.getByLabel("capture file").setInputFiles({ name: "sample-otherhost.dmesg", mimeType: "text/plain", buffer: dm });
  await page.getByLabel("import name").fill("other machine: MCU timeout");
  await page.getByRole("button", { name: "Import", exact: true }).click();
  await expect(page.getByTestId("import-result")).toContainText("format dmesg", { timeout: 20_000 });
  await shot(page, "12-import");
  await page.getByTestId("import-result").getByRole("link", { name: "Visualize" }).click();
  await expect(page.getByTestId("cursor-bar")).toBeVisible({ timeout: 15_000 });
  await page.waitForTimeout(1200);
  await shot(page, "13-imported-visualize");
});

test("usb demo screens", async ({ page }) => {
  test.setTimeout(240_000);
  await page.setViewportSize({ width: 1440, height: 900 });
  await login(page);
  await page.waitForTimeout(20_000);
  await page.locator("a[href^='/device/']").first().click();
  await tab(page, "Bus"); await page.waitForTimeout(500); await shot(page, "14-usb-bus");
  await tab(page, "Live PHY"); await page.waitForTimeout(6000); await shot(page, "15-live-phy", true);
  await page.getByRole("link", { name: "Visualizations" }).click();
  await tab(page, "USB transfer flow"); await page.waitForTimeout(2500); await shot(page, "16-viz-usb-flow");
});
