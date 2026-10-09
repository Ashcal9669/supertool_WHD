import { test } from "@playwright/test";
import { login } from "./util";

// Not an assertion test: writes screenshots for visual review when WHD_SCREENS is set.
test.skip(!process.env.WHD_SCREENS, "set WHD_SCREENS=dir to capture screenshots");

test("screens", async ({ page }) => {
  const dir = process.env.WHD_SCREENS!;
  await login(page);
  await page.screenshot({ path: `${dir}/inventory.jpg`, fullPage: false, type: "jpeg", quality: 55 });
  await page.locator("a[href^='/device/']").first().click();
  for (const tab of (process.env.WHD_TABS ?? "Overview,Bus,Wireless PHY").split(",")) {
    await page.getByRole("button", { name: tab, exact: true }).click();
    await page.waitForTimeout(800);
    await page.screenshot({ path: `${dir}/tab-${tab.replace(/\W+/g, "_")}.jpg`, fullPage: false, type: "jpeg", quality: 55 });
  }
  for (const p of (process.env.WHD_PAGES ?? "").split(",").filter(Boolean)) {
    await page.goto(p);
    await page.waitForTimeout(1500);
    await page.screenshot({ path: `${dir}/page${p.replace(/\W+/g, "_")}.jpg`, fullPage: false, type: "jpeg", quality: 55 });
  }
});

test("viz screens", async ({ page }) => {
  test.skip(!process.env.WHD_VIZ, "set WHD_VIZ=1");
  const dir = process.env.WHD_SCREENS!;
  await login(page);
  await page.goto("/viz");
  await page.waitForTimeout(2500);
  for (const [tab, name] of [["Error propagation", "errors"], ["Firmware command sequence", "fw"], ["TX/RX queue activity", "queues"], ["USB transfer flow", "usb"]]) {
    await page.getByRole("button", { name: tab, exact: true }).click();
    await page.waitForTimeout(1500);
    await page.screenshot({ path: `${dir}/viz-${name}.jpg`, type: "jpeg", quality: 55 });
  }
});

test("diag screen", async ({ page }) => {
  test.skip(!process.env.WHD_DIAG, "set WHD_DIAG=1");
  const dir = process.env.WHD_SCREENS!;
  await login(page);
  await page.goto("/diagnostics");
  await page.getByRole("button", { name: "Analyze" }).click();
  await page.waitForTimeout(3000);
  await page.screenshot({ path: `${dir}/diag.jpg`, type: "jpeg", quality: 55, fullPage: true });
});
