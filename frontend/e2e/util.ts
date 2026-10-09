import { expect, type Page } from "@playwright/test";

export const TOKEN = process.env.WHD_TOKEN ?? "";

/** Collect uncaught page errors and console errors; assert none at the end of a test. */
export function trackErrors(page: Page): () => void {
  const errors: string[] = [];
  page.on("pageerror", (e) => errors.push(`pageerror: ${e.message}`));
  page.on("console", (m) => {
    if (m.type() === "error" && !m.text().includes("401")) errors.push(`console: ${m.text()}`);
  });
  return () => expect(errors, errors.join("\n")).toEqual([]);
}

export async function login(page: Page) {
  await page.goto("/");
  await page.getByLabel("Access token").fill(TOKEN);
  await page.getByRole("button", { name: "Sign in" }).click();
  await expect(page.getByRole("heading", { name: "Wireless devices" })).toBeVisible();
}
