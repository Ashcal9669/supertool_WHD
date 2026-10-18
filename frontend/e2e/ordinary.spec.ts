import { expect, test } from "@playwright/test";
import { readFile } from "node:fs/promises";
import { resolve, sep } from "node:path";
import { trackErrors } from "./util";

// All API responses are recorded test data; this spec never calls a hardware backend.
test("ordinary capture retains association, security and downloads without MLO states", async ({ page }) => {
  const done = trackErrors(page);
  const unexpected: string[] = [];
  const device = { id: "mt7922", title: "MT7922", vendor_id: 0x14c3, product_id: 0x0616, netdevs: ["wifi22"], present: true, demo: false };
  const report = {
    protocol: "ordinary", device_id: device.id, mode: "imported", capture_id: "ordinary-fixture",
    current_state: null, snapshot_states: [], windows: [],
    packets: [{ id: "packet-a", scope: { boot_id: "boot-a", association_epoch: "assoc-a", link_id: null, link_lifetime: null },
      first_missing: "security", correlation: "unjoined", acked: null, delivered: true, authenticated_delivery: null,
      observations: [{ stage: "stack_rx", stage_class: "observation", ts_boottime_ns: 200, elapsed_ns: 0, raw: "Recorded ordinary RX", identifiers: {}, decoded: {}, evidence: [] }], gaps: [], limits: [] }],
    epochs: [{ id: "assoc-a", outcome: "associated", first_missing: null, flags: [], gaps: [],
      stages: [{ stage: "eapol_m1_rx", stage_class: "observation", ts_boottime_ns: 100, result: null, evidence: [], note: "Recorded EAPOL" }] }],
    observations: [], unattributed_events: 0, counter_semantics: [], limits: ["Security collector unavailable"],
  };
  const staticRoot = process.env.WHD_STATIC_DIR ? resolve(process.env.WHD_STATIC_DIR) : undefined;
  await page.route(staticRoot ? "**/*" : "**/api/v1/**", async route => {
    const path = new URL(route.request().url()).pathname;
    if (staticRoot && !path.startsWith("/api/v1/")) {
      const target = path.startsWith("/assets/") ? resolve(staticRoot, `.${path}`) : resolve(staticRoot, "index.html");
      if (!target.startsWith(`${staticRoot}${sep}`)) { unexpected.push(path); await route.abort(); return; }
      const contentType = target.endsWith(".js") ? "application/javascript" : target.endsWith(".css") ? "text/css" : "text/html";
      await route.fulfill({ body: await readFile(target), contentType });
      return;
    }
    const responses: Record<string, unknown> = {
      "/api/v1/auth/session": { authenticated: true },
      "/api/v1/system": { mode: "demo", fixture_kind: "recorded", hostname: "fixture", kernel_release: "fixture", arch: "test" },
      "/api/v1/replay/status": { active: false },
      "/api/v1/captures/ordinary-fixture/devices": [device],
      "/api/v1/captures/ordinary-fixture/mlo/evidence": report,
      "/api/v1/captures/ordinary-fixture/mlo/air": [],
      "/api/v1/captures/ordinary-fixture/wifi/stack": [],
    };
    if (!(path in responses)) { unexpected.push(path); await route.abort(); return; }
    await route.fulfill({ json: responses[path] });
  });
  await page.goto("/mlo?capture=ordinary-fixture");
  await expect(page.getByRole("heading", { name: "Wi-Fi evidence", exact: true })).toBeVisible();
  await expect(page.getByText("HISTORICAL CAPTURE", { exact: true })).toBeVisible();
  await expect(page.getByText("Per-link evidence states", { exact: true })).toHaveCount(0);
  await expect(page.getByLabel("packet link")).toHaveCount(0);
  await expect(page.getByText(/link UNKNOWN|link 0|steering/i)).toHaveCount(0);
  await page.getByText(/stack_rx · observation/).click();
  await expect(page.getByText("Recorded ordinary RX", { exact: true })).toBeVisible();
  await page.getByText(/eapol_m1_rx · observation/).click();
  await expect(page.getByText("Recorded EAPOL", { exact: true })).toBeVisible();
  await expect(page.getByText("Security collector unavailable", { exact: true })).toBeVisible();
  await expect(page.getByRole("link", { name: "Download evidence JSON" })).toHaveAttribute("href", /captures\/ordinary-fixture\/mlo\/evidence/);
  await expect(page.getByRole("link", { name: "Download original evidence bundle" })).toHaveAttribute("href", "/api/v1/captures/ordinary-fixture/bundle?redact_macs=false");
  await expect(page.getByRole("button", { name: "Run bound measurement" })).toHaveCount(0);
  const upload = page.getByRole("button", { name: "Import stack evidence" });
  await expect(upload).toBeDisabled();
  await page.getByLabel("stack PCAP").setInputFiles({ name: "ethernet.pcap", mimeType: "application/vnd.tcpdump.pcap", buffer: Buffer.from("fixture bytes") });
  await page.getByLabel("captured interface").selectOption("wifi22");
  await page.getByLabel("stack direction").selectOption("rx");
  await page.getByLabel("wall minus boot offset (ns)").fill("0");
  await expect(upload).toBeDisabled();
  await page.getByLabel("capture boot UUID").fill("invalid-boot");
  await expect(upload).toBeDisabled();
  await page.getByLabel("capture boot UUID").fill("a070fcc7-1234-4567-89ab-123456789abc");
  await expect(upload).toBeEnabled();
  expect(unexpected).toEqual([]);
  done();
});
