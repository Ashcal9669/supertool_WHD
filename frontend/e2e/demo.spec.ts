import { expect, test } from "@playwright/test";
import { login, trackErrors } from "./util";

// Runs against a server started with: whd serve --demo mt7927-pcie-host (WHD_DEMO_SPEED=4)
test.describe("demo mode", () => {
  test.skip(!process.env.WHD_DEMO, "needs a demo-mode server (set WHD_DEMO=1 WHD_URL=...)");

  test("banner, visualizations, capture, export and replay", async ({ page }) => {
    test.setTimeout(120_000);
    const done = trackErrors(page);
    await login(page);
    await expect(page.getByTestId("demo-banner")).toContainText("SYNTHETIC EVENT STREAM");
    await expect(page.getByTestId("demo-banner")).toContainText("DEMO MODE");
    // start a capture first so it records the scripted incident
    await page.getByRole("link", { name: "Captures" }).click();
    await page.getByLabel("capture name").fill("e2e-incident");
    await page.getByRole("button", { name: "Start capture" }).click();
    await expect(page.getByTestId("capture-row").first()).toContainText("running");
    // wait for the incident: MCU timeout at t=52 s of an 84 s story, 4x speed
    await page.getByRole("link", { name: "Visualizations" }).click();
    await expect(page.getByText("Error propagation through the driver stack")).toBeVisible();
    await expect(page.locator("svg[aria-label='error propagation through the driver stack'] circle").first()).toBeVisible({ timeout: 60_000 });
    await expect(page.getByText(/first observed/).first()).toBeVisible();
    await page.getByRole("button", { name: "Firmware command sequence" }).click();
    await expect(page.locator("svg[aria-label='firmware command sequence']")).toBeVisible({ timeout: 30_000 });
    await expect(page.getByText(/TIMEOUT seq 12|timeout seq 12/).first()).toBeVisible({ timeout: 60_000 });
    await page.getByRole("button", { name: "TX/RX queue activity" }).click();
    await expect(page.getByText("TX data ring (WFDMA0)")).toBeVisible({ timeout: 20_000 });
    // stop capture, details, replay
    await page.getByRole("link", { name: "Captures" }).click();
    await page.getByTestId("capture-row").first().getByRole("button", { name: "Stop" }).click();
    await expect(page.getByTestId("capture-row").first()).toContainText("stopped");
    await page.getByRole("button", { name: "Details / export" }).first().click();
    const href = await page.getByRole("link", { name: "CSV" }).getAttribute("href");
    expect(href).toContain("/export?format=csv");
    const csv = await page.request.get(href!);
    expect(csv.ok()).toBeTruthy();
    expect((await csv.text()).split("\n").length).toBeGreaterThan(5);
    const bundle = await page.request.get((await page.getByRole("link", { name: /Diagnostic bundle/ }).getAttribute("href"))!);
    expect(bundle.headers()["content-type"]).toBe("application/zip");
    await page.getByLabel("replay speed").first().selectOption("10");
    await page.getByRole("button", { name: "Replay", exact: true }).first().click();
    await expect(page.getByTestId("replay-banner")).toBeVisible({ timeout: 10_000 });
    await page.getByRole("button", { name: "Stop replay" }).click();
    await expect(page.getByTestId("replay-banner")).toBeHidden({ timeout: 10_000 });
    done();
  });

  test("topology and live PHY render in demo mode", async ({ page }) => {
    const done = trackErrors(page);
    await login(page);
    await page.locator("a[href^='/device/']").first().click();
    await page.getByRole("button", { name: "mt76", exact: true }).click();
    await expect(page.getByText("Coverage by diagnostic category")).toBeVisible();
    await page.getByRole("button", { name: "Datapath trace" }).click();
    await expect(page.getByText(/Observed TX link per TID/)).toBeVisible();
    done();
  });
});

test.describe("diagnostics (demo)", () => {
  test.skip(!process.env.WHD_DEMO, "needs a demo-mode server");
  test("analysis separates observations from unconfirmed hypotheses; llm optional", async ({ page }) => {
    test.setTimeout(240_000);
    const done = trackErrors(page);
    await login(page);
    await page.getByRole("link", { name: "Diagnostics" }).click();
    await page.getByRole("button", { name: "Analyze" }).click();
    await expect(page.getByText(/Observations \(\d+\)/)).toBeVisible({ timeout: 20_000 });
    await expect(page.getByText("does not assert a root cause")).toBeVisible();
    await expect(page.getByText("UNCONFIRMED HYPOTHESIS").first()).toBeVisible({ timeout: 20_000 });
    await expect(page.getByTestId("hypothesis").first()).toContainText("Unknowns");
    if (process.env.WHD_LLM) {
      await page.getByLabel("model").selectOption("llama3.2:3b");
      await page.getByRole("button", { name: "Summarize report" }).click();
      await expect(page.getByTestId("llm-summary")).toContainText("AI-GENERATED TEXT", { timeout: 200_000 });
      await expect(page.getByTestId("llm-summary")).toContainText("not evidence");
    }
    done();
  });
});
