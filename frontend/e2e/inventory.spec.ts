import { expect, test } from "@playwright/test";
import { login, trackErrors } from "./util";

test("login, inventory, device detail tabs", async ({ page }) => {
  const done = trackErrors(page);
  await page.goto("/");
  await expect(page.getByLabel("Access token")).toBeVisible();
  await page.getByLabel("Access token").fill("wrong-token");
  await page.getByRole("button", { name: "Sign in" }).click();
  await expect(page.getByText("invalid token")).toBeVisible();
  await login(page);
  const card = page.locator("a[href^='/device/']").first();
  await expect(card).toBeVisible();
  await card.click();
  for (const tab of ["Overview", "Bus", "Driver & firmware", "Wireless PHY", "Interfaces", "Power", "Evidence"]) {
    await page.getByRole("button", { name: tab, exact: true }).click();
    await expect(page.locator("main")).not.toContainText("Something went wrong");
  }
  await page.getByRole("button", { name: "Wireless PHY", exact: true }).click();
  await expect(page.getByText("Channel widths:")).toBeVisible();
  await page.getByRole("link", { name: "System" }).click();
  await expect(page.getByRole("heading", { name: "Integrations" })).toBeVisible();
  done();
});
