import { expect, test } from "@playwright/test";
import { login, trackErrors } from "./util";

test("recorded MLO evidence preserves raw observations and downloadable provenance", async ({ page }, testInfo) => {
  const capture = process.env.WHD_MLO_CAPTURE;
  test.skip(!capture, "WHD_MLO_CAPTURE must identify a recorded MT7927 MLO capture");
  const done = trackErrors(page);
  await login(page);
  await expect(page.getByRole("link", { name: "Wi-Fi evidence", exact: true })).toHaveAttribute("href", "/mlo");
  await page.goto(`/mlo?capture=${encodeURIComponent(capture!)}`);
  await expect(page.getByTestId("mlo-evidence")).toBeVisible();
  await expect(page.getByText("Per-link evidence states")).toBeVisible();
  await expect(page.getByLabel("packet link")).toBeVisible();
  await expect(page.getByText("HISTORICAL CAPTURE", { exact: true })).toBeVisible();
  await page.getByText(/userspace_submit · queued_request/).first().click();
  await expect(page.locator("pre").filter({ hasText: '"-I"' }).first()).toBeVisible();
  const download = page.waitForEvent("download");
  await page.getByRole("link", { name: "Download original evidence bundle", exact: true }).click();
  const bundle = await download;
  expect(bundle.suggestedFilename()).toMatch(/\.zip$/);
  await bundle.saveAs(testInfo.outputPath("evidence-bundle.zip"));
  await page.screenshot({ path: testInfo.outputPath("mlo-evidence.png"), fullPage: true });
  done();
});
