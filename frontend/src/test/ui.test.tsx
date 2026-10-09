import { fireEvent, render, screen } from "@testing-library/react";
import { DemoBanner } from "../components/DemoBanner";
import { AvailabilityBadge, KV } from "../components/ui";
import type { SystemInfo } from "../api/types";

const sys = (mode: "live" | "demo"): SystemInfo => ({
  hostname: "h", kernel_release: "6.x", kernel_version: null, arch: "x86_64", distro: null, python: null,
  whd_version: "0.1.0", mode, demo_scenario: mode === "demo" ? "mt7921u-usb" : null,
  fixture_kind: mode === "demo" ? "synthetic" : null, fixture_description: "desc", fixture_events_kind: null, fixture_events_description: null, uid: 1000, euid: 1000,
  running_as_root: false, helper: {}, integrations: [],
});

test("demo banner only in demo mode and labels synthetic data", () => {
  const { rerender } = render(<DemoBanner system={sys("live")} />);
  expect(screen.queryByTestId("demo-banner")).toBeNull();
  rerender(<DemoBanner system={sys("demo")} />);
  expect(screen.getByTestId("demo-banner")).toHaveTextContent("DEMO MODE — SYNTHETIC DATA");
  expect(screen.getByTestId("demo-banner")).toHaveTextContent("mt7921u-usb");
});

test("KV renders missing values as 'not exposed' instead of guessing", () => {
  render(<KV rows={[["a", null], ["b", "x"], ["c", undefined]]} />);
  expect(screen.getAllByText("not exposed")).toHaveLength(2);
  expect(screen.getByText("x")).toBeInTheDocument();
});

test("availability badge reveals sources and issues", () => {
  render(<AvailabilityBadge meta={{ availability: "partial", sources: ["/sys/x"], issues: [{ source: "/sys/y", kind: "requires_privilege", detail: "EACCES" }], note: null }} />);
  const btn = screen.getByRole("button");
  expect(btn).toHaveTextContent("partial · 1");
  fireEvent.click(btn);
  expect(screen.getByText("/sys/x")).toBeInTheDocument();
  expect(screen.getByText(/requires_privilege/)).toBeInTheDocument();
});
