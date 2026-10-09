import { expect, test } from "@playwright/test";
import { login, trackErrors } from "./util";

test("topology renders discovered nodes and opens details", async ({ page }) => {
  const done = trackErrors(page);
  await login(page);
  await page.getByRole("link", { name: "Topology" }).click();
  await expect(page.locator(".react-flow__node").first()).toBeVisible();
  const count = await page.locator(".react-flow__node").count();
  expect(count).toBeGreaterThan(3);
  await page.locator(".react-flow__node").filter({ hasText: "driver" }).first().click();
  await expect(page.getByText("open device inspector")).toBeVisible();
  done();
});

test("timeline connects to the live stream and shows history", async ({ page }) => {
  const done = trackErrors(page);
  await login(page);
  await page.getByRole("link", { name: "Timeline" }).click();
  await expect(page.getByText("live", { exact: true })).toBeVisible({ timeout: 15000 });
  await page.getByLabel("minimum severity").selectOption("debug");
  await expect(page.locator("tbody tr").first()).toBeVisible({ timeout: 15000 });
  await page.locator("tbody tr").first().click();
  await expect(page.getByText("Raw evidence")).toBeVisible();
  done();
});
