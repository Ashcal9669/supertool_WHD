import { expect, test } from "@playwright/test";
import { login, trackErrors } from "./util";

test("MT7922 hardware capture exposes ordinary paths, monitored EAPOL and provenance", async ({ page }, info) => {
  const capture = process.env.WHD_MT7922_CAPTURE;
  test.skip(!capture, "requires a recorded MT7922 hardware capture");
  const done = trackErrors(page);
  await login(page);
  await page.goto(`/mlo?capture=${encodeURIComponent(capture!)}`);
  await expect(page.getByRole("heading", { name: "Wi-Fi evidence", exact: true })).toBeVisible();
  await expect(page.getByText("HISTORICAL CAPTURE", { exact: true })).toBeVisible();
  await expect(page.getByText("Per-link evidence states", { exact: true })).toHaveCount(0);
  await expect(page.getByLabel("packet link")).toHaveCount(0);
  await page.getByText(/stack_rx · observation/).first().click();
  await expect(page.locator("details[open] > pre").filter({ hasText: "skbaddr" }).first()).toBeVisible();
  await expect(page.getByText(/key_install_request · queued_request/).first()).toBeVisible();
  await expect(page.getByText(/EAPOL.*M1.*M2.*M3.*M4/).first()).toBeVisible();
  await expect(page.getByText(/co-located monitor shares/).first()).toBeVisible();
  const download = page.waitForEvent("download");
  await page.getByRole("link", { name: "Download original evidence bundle", exact: true }).click();
  const bundle = await download;
  await bundle.saveAs(info.outputPath("mt7922-evidence.zip"));
  await page.screenshot({ path: info.outputPath("mt7922-evidence.png"), fullPage: true });
  done();
});
