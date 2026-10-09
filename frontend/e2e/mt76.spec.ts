import { expect, test } from "@playwright/test";
import { login, trackErrors } from "./util";

test("mt76 tab: coverage, queues, trace session", async ({ page }) => {
  const done = trackErrors(page);
  await login(page);
  await page.locator("a[href^='/device/']").first().click();
  await page.getByRole("button", { name: "mt76", exact: true }).click();
  await expect(page.getByText("Coverage by diagnostic category")).toBeVisible();
  await expect(page.getByText("MCU command and response activity")).toBeVisible();
  await expect(page.getByText("Not found: tracepoint mt76:mcu_send")).toBeVisible();
  await page.getByRole("button", { name: "View diff" }).click();
  await expect(page.locator("pre").filter({ hasText: "trace_mcu_send" })).toBeVisible();
  await page.getByRole("button", { name: "Queues & rings" }).click();
  await expect(page.getByText("TX / MCU rings (latest read)")).toBeVisible();
  await expect(page.getByRole("cell", { name: "WFDMA0" })).toBeVisible();
  await expect(page.locator(".uplot").first()).toBeVisible();
  await page.getByRole("button", { name: "Datapath trace" }).click();
  await page.getByRole("button", { name: "Start trace" }).click();
  await expect(page.getByText(/tracing · \d+ lines/)).toBeVisible({ timeout: 10000 });
  await page.getByRole("button", { name: "Stop", exact: true }).click();
  await expect(page.getByText("idle")).toBeVisible({ timeout: 10000 });
  await page.getByRole("button", { name: "Driver log tags" }).click();
  done();
});
