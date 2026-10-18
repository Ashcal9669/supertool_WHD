import { fireEvent, render, screen } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { MemoryRouter } from "react-router-dom";
import * as client from "../api/client";
import type { Device, EvidenceReport, LiveInterface, WhdEvent } from "../api/types";
import { EvidenceView, MloEvidencePanel } from "../device/MloEvidenceTab";
import { MloLinks } from "../viz/MloLinks";
import { MloPage } from "../pages/Mlo";
import { deviceTabs } from "../device/registry";
import { ConnStateMachine } from "../viz/ConnStateMachine";

// The tab registry imports uPlot, which reads the browser's pixel-ratio media query.
vi.hoisted(() => {
  Object.defineProperty(window, "matchMedia", { configurable: true, value: () => ({
    matches: false, addEventListener() {}, removeEventListener() {}, addListener() {}, removeListener() {},
  }) });
});

const ordinaryReport = {
  device_id: "mt7922", protocol: "ordinary", mode: "live", capture_id: "ordinary-cap",
  current_state: null, snapshot_states: [],
  windows: [{ scope: { boot_id: "boot-a", association_epoch: "assoc-a" }, state: { boot_id: "boot-a", links: [], perturbations: [] },
    firmware: { links: [], ops: [], flags: [], gaps: [] }, rx_frames: [],
    rx_summary: { frames: 0 } }],
  epochs: [{ id: "assoc-a", outcome: "associated", first_missing: "key_install_fw", flags: [], gaps: [],
    stages: [{ stage: "eapol_m1_rx", stage_class: "observation", result: null, ts_boottime_ns: 100, evidence: [], note: "EAPOL observed" }] }],
  packets: [{ id: "ordinary-packet", scope: { boot_id: "boot-a", association_epoch: "assoc-a", link_id: null },
    first_missing: "security", correlation: "unjoined", acked: null, delivered: true, authenticated_delivery: null, gaps: [], limits: [],
    observations: [{ stage: "stack_rx", stage_class: "observation", ts_boottime_ns: 200, elapsed_ns: 0, identifiers: {}, decoded: {}, evidence: [], raw: "ordinary RX raw" }] }],
  observations: [], unattributed_events: 0, limits: ["Security collector unavailable"], counter_semantics: [],
} as unknown as EvidenceReport;

test("ordinary evidence retains packet/security and EAPOL observations without link states", () => {
  render(<EvidenceView report={ordinaryReport} />);
  expect(screen.getByText("ordinary RX raw")).toBeInTheDocument();
  expect(screen.getByText(/eapol_m1_rx/)).toBeInTheDocument();
  expect(screen.getByText("Security collector unavailable", { selector: "p" })).toBeVisible();
  expect(screen.getByText(/Authenticated delivery is unknown without correlated security evidence/)).toBeVisible();
  expect(screen.queryByText("Per-link evidence states")).toBeNull();
  expect(screen.queryByLabelText("packet link")).toBeNull();
  expect(screen.queryByRole("columnheader", { name: "Link" })).toBeNull();
  expect(screen.queryByText(/link UNKNOWN|link 0|steering/i)).toBeNull();
});

test("recorded MLO evidence retains per-link controls", () => {
  render(<EvidenceView report={{ ...ordinaryReport, protocol: "mlo", windows: [] } as unknown as EvidenceReport} />);
  expect(screen.getByText("Per-link evidence states")).toBeInTheDocument();
  expect(screen.getByLabelText("packet link")).toBeInTheDocument();
});

test("unknown protocol never manufactures MLO states", () => {
  render(<EvidenceView report={{ ...ordinaryReport, protocol: "unknown" } as unknown as EvidenceReport} />);
  expect(screen.queryByText("Per-link evidence states")).toBeNull();
  expect(screen.queryByLabelText("packet link")).toBeNull();
  expect(screen.getByText("ordinary RX raw")).toBeInTheDocument();
});

test("unobserved EAPOL stages stay UNKNOWN despite an old COMPLETED observation", () => {
  const old = { id: 77, kind: "supplicant.state", summary: "COMPLETED", raw: "old boot: COMPLETED", ts_boottime_ns: 10, data: { state: "COMPLETED", boot_id: "old-boot" } } as unknown as WhdEvent;
  const gaps = ["eapol_m1_rx", "eapol_m2_tx", "eapol_m3_rx", "eapol_m4_tx"].map(what => ({ what, kind: "no_collector" as const, collector: null, detail: "Control-port EAPOL was not collected" }));
  render(<EvidenceView report={{ ...ordinaryReport, observations: [old], epochs: [{ ...ordinaryReport.epochs[0], outcome: "unknown", stages: [], first_missing: "eapol_m1_rx", gaps }] } as EvidenceReport} />);
  for (const stage of ["eapol_m1_rx", "eapol_m2_tx", "eapol_m3_rx", "eapol_m4_tx"]) expect(screen.getByText(`${stage}: UNKNOWN`, { exact: false, selector: "p" })).toBeVisible();
  expect(screen.getByText("assoc-a · unknown")).toBeInTheDocument();
  expect(screen.queryByText("assoc-a · associated")).toBeNull();
  expect(screen.getByText(/authenticated delivery UNKNOWN/)).toBeInTheDocument();
});

test("old supplicant COMPLETED does not synthesize an association state", () => {
  const old = { kind: "supplicant.state", summary: "COMPLETED", ts_boottime_ns: 10, data: { state: "COMPLETED", boot_id: "old-boot" } } as unknown as WhdEvent;
  render(<ConnStateMachine events={[old]} snapshotConnected={null} />);
  expect(screen.getByText("No association events or station data yet.")).toBeInTheDocument();
  expect(screen.queryByText(/Current state from event/)).toBeNull();
});

test.each(["ordinary", "unknown"])("%s stack upload requires explicit captured provenance and refreshes the first gap", async protocol => {
  const d = { id: "mt7922", title: "MT7922", netdevs: ["wifi22"], present: false } as unknown as Device;
  const file = new File(["pcap bytes"], "ethernet.pcap", { type: "application/vnd.tcpdump.pcap" });
  const saved = { import_id: "stack-one", events: [], limits: ["Stack capture does not prove decryption"], original_retained: true, sha256: "sha256-fixture", pcap_artifact: "stack-one.pcap", report_artifact: "stack-one.json" };
  let uploaded = false;
  const spy = vi.spyOn(client, "api").mockImplementation((path, init) => {
    if (path === "/captures/ordinary-cap/devices") return Promise.resolve([d]) as never;
    if (path.includes("/mlo/evidence")) return Promise.resolve({ ...ordinaryReport, protocol,
      packets: ordinaryReport.packets.map(p => ({ ...p, first_missing: uploaded ? "txd" : "security" })) }) as never;
    if (path.endsWith("/mlo/air")) return Promise.resolve([]) as never;
    if (path.includes("/wifi/stack") && init?.method === "POST") { uploaded = true; return Promise.resolve(saved) as never; }
    if (path.endsWith("/wifi/stack")) return Promise.resolve(uploaded ? [saved] : []) as never;
    return Promise.reject(new Error(`Unexpected request: ${path}`));
  });
  try {
    render(<QueryClientProvider client={new QueryClient({ defaultOptions: { queries: { retry: false } } })}><MemoryRouter initialEntries={["/mlo?capture=ordinary-cap"]}><MloPage /></MemoryRouter></QueryClientProvider>);
    const button = await screen.findByRole("button", { name: "Import stack evidence" });
    expect(button).toBeDisabled();
    fireEvent.change(screen.getByLabelText("stack PCAP"), { target: { files: [file] } });
    expect(button).toBeDisabled();
    fireEvent.change(screen.getByLabelText("captured interface"), { target: { value: "wifi22" } });
    expect(button).toBeDisabled();
    fireEvent.change(screen.getByLabelText("stack direction"), { target: { value: "rx" } });
    expect(button).toBeDisabled();
    fireEvent.change(screen.getByLabelText("wall minus boot offset (ns)"), { target: { value: "1.5" } });
    expect(button).toBeDisabled();
    fireEvent.change(screen.getByLabelText("wall minus boot offset (ns)"), { target: { value: "-1234567890123456789" } });
    expect(button).toBeDisabled();
    fireEvent.change(screen.getByLabelText("capture boot UUID"), { target: { value: "not-a-uuid" } });
    expect(button).toBeDisabled();
    fireEvent.change(screen.getByLabelText("capture boot UUID"), { target: { value: "a070fcc7-1234-4567-89ab-123456789abc" } });
    expect(button).toBeEnabled();
    fireEvent.click(button);
    expect(await screen.findByText("First missing stage: txd")).toBeInTheDocument();
    expect(screen.queryByText("First missing stage: security")).toBeNull();
    const [path, init] = spy.mock.calls.find(([, options]) => options?.method === "POST")!;
    const query = new URL(path, "http://fixture").searchParams;
    expect(query.get("direction")).toBe("rx");
    expect(query.get("interface")).toBe("wifi22");
    expect(query.get("wall_minus_boot_ns")).toBe("-1234567890123456789");
    expect(query.get("boot_id")).toBe("a070fcc7-1234-4567-89ab-123456789abc");
    expect(init?.body).toBe(file);
    expect(init?.headers).toEqual({ "content-type": "application/vnd.tcpdump.pcap" });
    expect(await screen.findByText("Stack capture does not prove decryption", { selector: "p" })).toBeVisible();
    expect(screen.getByRole("link", { name: "Download stack PCAP" })).toHaveAttribute("href", "/api/v1/captures/ordinary-cap/artifacts/stack-one.pcap");
    expect(screen.getByRole("link", { name: "Download stack report" })).toHaveAttribute("href", "/api/v1/captures/ordinary-cap/artifacts/stack-one.json");
    expect(screen.queryByText("Per-link evidence states")).toBeNull();
  } finally { spy.mockRestore(); }
});

test("stack upload preserves backend boot/bounds validation errors and form values", async () => {
  const d = { id: "mt7922", netdevs: ["wifi22"] } as unknown as Device;
  const boot = "a070fcc7-1234-4567-89ab-123456789abc";
  const detail = "PCAP boot_id does not match recorded capture provenance; use the boot UUID from the capture bundle.";
  const spy = vi.spyOn(client, "api").mockImplementation((path, init) => {
    if (init?.method === "POST") return Promise.reject(new client.ApiError(422, detail));
    return Promise.resolve(path.includes("/mlo/evidence") ? ordinaryReport : []) as never;
  });
  try {
    render(<QueryClientProvider client={new QueryClient({ defaultOptions: { queries: { retry: false } } })}><MemoryRouter><MloEvidencePanel deviceId={d.id} captureId="ordinary-cap" d={d} /></MemoryRouter></QueryClientProvider>);
    const button = await screen.findByRole("button", { name: "Import stack evidence" });
    fireEvent.change(screen.getByLabelText("stack PCAP"), { target: { files: [new File(["pcap"], "stack.pcap")] } });
    fireEvent.change(screen.getByLabelText("captured interface"), { target: { value: "wifi22" } });
    fireEvent.change(screen.getByLabelText("stack direction"), { target: { value: "tx" } });
    fireEvent.change(screen.getByLabelText("wall minus boot offset (ns)"), { target: { value: "0" } });
    fireEvent.change(screen.getByLabelText("capture boot UUID"), { target: { value: boot } });
    fireEvent.click(button);
    expect(await screen.findByText(`422: ${detail}`)).toBeVisible();
    expect(screen.getByLabelText("capture boot UUID")).toHaveValue(boot);
    expect(screen.getByLabelText("captured interface")).toHaveValue("wifi22");
    expect(screen.getByLabelText("wall minus boot offset (ns)")).toHaveValue("0");
    expect(screen.getByText("First missing stage: security")).toBeInTheDocument();
  } finally { spy.mockRestore(); }
});

test("stack upload stays disabled when a captured device owner is unavailable", async () => {
  const spy = vi.spyOn(client, "api").mockImplementation(path => Promise.resolve(path.includes("/mlo/evidence") ? ordinaryReport : []) as never);
  try {
    render(<QueryClientProvider client={new QueryClient({ defaultOptions: { queries: { retry: false } } })}><MemoryRouter><MloEvidencePanel deviceId="mt7922" captureId="ordinary-cap" /></MemoryRouter></QueryClientProvider>);
    const button = await screen.findByRole("button", { name: "Import stack evidence" });
    fireEvent.change(screen.getByLabelText("stack PCAP"), { target: { files: [new File(["pcap"], "stack.pcap")] } });
    fireEvent.change(screen.getByLabelText("stack direction"), { target: { value: "tx" } });
    fireEvent.change(screen.getByLabelText("wall minus boot offset (ns)"), { target: { value: "0" } });
    expect(screen.getByText(/UNKNOWN — uploads disabled/)).toBeInTheDocument();
    expect(button).toBeDisabled();
    expect(screen.getByLabelText("captured interface")).toHaveValue("");
    expect(spy.mock.calls.some(([, init]) => init?.method === "POST")).toBe(false);
  } finally { spy.mockRestore(); }
});

test("ordinary current view discovers monitor capabilities without MLO states", async () => {
  const d = { id: "mt7922", vendor_id: 0x14c3, product_id: 0x0616, present: true, demo: false, netdevs: ["wifi22"], extensions: {} } as unknown as Device;
  const spy = vi.spyOn(client, "api").mockImplementation(path => Promise.resolve(path === "/mlo/monitors" ? { note: "co-located monitor" } : { ...ordinaryReport, capture_id: null }) as never);
  try {
    render(<QueryClientProvider client={new QueryClient({ defaultOptions: { queries: { retry: false } } })}><MemoryRouter><MloEvidencePanel deviceId={d.id} d={d} /></MemoryRouter></QueryClientProvider>);
    expect(await screen.findByText(/co-located monitor/)).toBeInTheDocument();
    expect(screen.queryByText("Per-link evidence states")).toBeNull();
  } finally { spy.mockRestore(); }
});

test.each([false, true])("passive page retains MT7927 URL selection and all present devices (demo=%s)", async (demo) => {
  const a = { id: "mt7922", title: "MT7922", vendor_id: 0x14c3, product_id: 0x0616, present: true, demo, netdevs: ["wifi22"], extensions: {} } as unknown as Device;
  const b = { ...a, id: "mt7927", title: "MT7927", product_id: 0x7927 };
  const spy = vi.spyOn(client, "api").mockImplementation(path => {
    if (path === "/devices") return Promise.resolve({ devices: [b, a, { ...a, id: "absent", present: false, demo: false }] }) as never;
    if (path === "/devices/mt7922") return Promise.resolve(a) as never;
    if (path === "/devices/mt7927") return Promise.resolve(b) as never;
    if (path === "/mlo/monitors") return Promise.resolve([]) as never;
    if (path.startsWith("/devices/mt7927/mlo/evidence")) return Promise.resolve({ ...ordinaryReport, device_id: b.id, capture_id: null }) as never;
    return Promise.reject(new Error(`Unexpected request: ${path}`));
  });
  try {
    render(<QueryClientProvider client={new QueryClient({ defaultOptions: { queries: { retry: false } } })}><MemoryRouter initialEntries={["/mlo?device=mt7927"]}><MloPage /></MemoryRouter></QueryClientProvider>);
    expect(await screen.findByText("ordinary RX raw")).toBeInTheDocument();
    expect(screen.getByRole("combobox", { name: "Wi-Fi device" })).toHaveValue("mt7927");
    expect(screen.getByRole("option", { name: /MT7927/ })).toBeVisible();
    expect(screen.getByRole("option", { name: /MT7922/ })).toBeVisible();
    expect(screen.queryByRole("option", { name: /absent/ })).toBeNull();
    expect(screen.queryByRole("button", { name: "Run bound measurement" })).toBeNull();
    expect(spy.mock.calls.every(([path]) => !path.includes("wake=true"))).toBe(true);
  } finally { spy.mockRestore(); }
});

const activeDevice = { id: "mt22", vendor_id: 0x14c3, product_id: 0x0616, present: true, demo: false,
  driver: "mt7921e", operstate: "down", netdevs: ["wifi22"], extensions: {}, active_test_eligible: true,
  active_test_reason: "verified MT7922 active-test target" } as unknown as Device;

test.each([
  ["verified DOWN", {}, true],
  ["git driver", { driver: "mt7921e_git" }, true],
  ["policy denied", { active_test_eligible: false }, false],
  ["policy missing", { active_test_eligible: undefined }, false],
  ["unbound", { driver: null }, false],
  ["wrong driver", { driver: "mt7925e" }, false],
  ["different chip", { product_id: 0x7927 }, false],
  ["demo", { demo: true }, false],
  ["demo stored", { demo: true, present: false }, false],
  ["absent", { present: false }, false],
])("active controls enforce identity, driver and policy: %s", async (_name, overrides, active) => {
  const d = { ...activeDevice, ...overrides } as Device;
  const spy = vi.spyOn(client, "api").mockImplementation(path => Promise.resolve(path === "/mlo/monitors" ? [] : { ...ordinaryReport, capture_id: null }) as never);
  try {
    render(<QueryClientProvider client={new QueryClient({ defaultOptions: { queries: { retry: false } } })}><MemoryRouter><MloEvidencePanel deviceId={d.id} d={d} /></MemoryRouter></QueryClientProvider>);
    if (d.present || d.demo) expect(await screen.findByText("ordinary RX raw")).toBeInTheDocument();
    if (active) expect(screen.getByRole("button", { name: "Run bound measurement" })).toBeVisible();
    else expect(screen.queryByRole("button", { name: "Run bound measurement" })).toBeNull();
    expect(spy.mock.calls.every(([path]) => !path.includes("wake=true"))).toBe(true);
  } finally { spy.mockRestore(); }
});

test.each([activeDevice, { ...activeDevice, product_id: 0x7927 }, { ...activeDevice, demo: true }])("Wi-Fi evidence tab is passive and available for $product_id demo=$demo", d => {
  const tab = deviceTabs.find(t => t.id === "mlo")!;
  expect(!tab.when || tab.when(d)).toBe(true);
});

test("a listed nl80211 link does not claim active or authenticated delivery", () => {
  const iface = { interface: { mlo_links: [{ link_id: 7, freq_mhz: 5200, channel: 40 }] }, stations: [] } as unknown as LiveInterface;
  render(<MloLinks iface={iface} events={[]} />);
  expect(screen.getByText(/active: UNKNOWN/)).toBeInTheDocument();
  expect(screen.queryByText("ACTIVATED")).toBeNull();
});

test("historical air imports survive reload and selector changes retain their stored downloads", async () => {
  const report = { device_id: "d", mode: "imported", capture_id: "cap-a", windows: [], epochs: [], packets: [], observations: [], limits: [], unattributed_events: 0, counter_semantics: [] };
  const air = { import_id: "air-one", filename: "segment-one.pcap", origin: "independent", pcap_artifact: "air-one.pcap", report_artifact: "air-one.json", frames: [], limits: [], health: "unknown", can_establish_absence: false };
  const spy = vi.spyOn(client, "api").mockImplementation((path) => Promise.resolve(path.endsWith("/air") ? [air] : report) as never);
  const tree = () => <QueryClientProvider client={new QueryClient({ defaultOptions: { queries: { retry: false } } })}><MemoryRouter><MloEvidencePanel deviceId="d" captureId="cap-a" /></MemoryRouter></QueryClientProvider>;
  try {
    const rendered = render(tree());
    expect(await screen.findByText("segment-one.pcap")).toBeInTheDocument();
    expect(screen.getByRole("option", { name: "Co-located monitor (same PHY)" })).toHaveValue("same_phy");
    fireEvent.change(screen.getByLabelText("air capture origin"), { target: { value: "ap_local" } });
    expect(screen.getByRole("link", { name: "Download original PCAP" })).toHaveAttribute("href", "/api/v1/captures/cap-a/artifacts/air-one.pcap");
    rendered.unmount(); render(tree());
    expect(await screen.findByText("segment-one.pcap")).toBeInTheDocument();
  } finally { spy.mockRestore(); }
});

test("same-PHY EAPOL observations retain frequency and addresses without claiming a clock or association join", async () => {
  const air = { import_id: "air-eapol", filename: "monitor-header.pcap", origin: "same_phy", pcap_artifact: "air-eapol.pcap", report_artifact: "air-eapol.json", limits: ["co-located monitor is not independent RF proof"],
    frames: [1, 2, 3, 4].map(message => ({ timestamp: 100 + message, freq_mhz: message < 3 ? 5320 : 5180, addr1: "02:00:00:00:00:01", addr2: "02:00:00:00:00:02", eapol: { message, key_info: 8, replay_counter: 1, basis: "pairwise key-info; no key data decoded" } })) };
  const spy = vi.spyOn(client, "api").mockImplementation(path => Promise.resolve(path.endsWith("/mlo/air") ? [air] : path.endsWith("/wifi/stack") ? [] : { ...ordinaryReport, epochs: [] }) as never);
  try {
    render(<QueryClientProvider client={new QueryClient({ defaultOptions: { queries: { retry: false } } })}><MemoryRouter><MloEvidencePanel deviceId="mt7922" captureId="ordinary-cap" /></MemoryRouter></QueryClientProvider>);
    expect(await screen.findByText("Observed EAPOL: M1 (1), M2 (1), M3 (1), M4 (1)")).toBeVisible();
    expect(screen.getByText(/Clock and association-epoch join: UNKNOWN/)).toBeVisible();
    expect(screen.getByRole("columnheader", { name: "Transmitter (addr2)" })).toBeVisible();
    expect(screen.getByRole("columnheader", { name: "Receiver (addr1)" })).toBeVisible();
    expect(screen.getAllByRole("cell", { name: "5320 MHz" })).toHaveLength(2);
    expect(screen.getAllByRole("cell", { name: "5180 MHz" })).toHaveLength(2);
    expect(screen.getAllByRole("cell", { name: "02:00:00:00:00:02" })).toHaveLength(4);
    expect(screen.getAllByRole("cell", { name: "02:00:00:00:00:01" })).toHaveLength(4);
    expect(screen.queryByText(/handshake complete|port authorized|authenticated delivery YES/i)).toBeNull();
    expect(screen.getByText("co-located monitor is not independent RF proof", { selector: "p" })).toBeVisible();
  } finally { spy.mockRestore(); }
});

test("historical packet evidence exposes first gap and raw observations", () => {
  const rep = { device_id: "test-device", historical: true, capture_id: "cap-test", mode: "fixture",
    windows: [], epochs: [], packets: [{ id: "packet-1", scope: { boot_id: "boot-a", device_id: "test-device", association_epoch: null, link_id: 7 },
      first_missing: "txd", correlation: "unjoined", limits: [], gaps: [{ what: "txd", kind: "no_collector" }],
      observations: [{ stage: "stack_tx", stage_class: "queued_request", ts_boottime_ns: 100, elapsed_ns: 0, identifiers: {}, decoded: {}, raw: "queue raw", evidence: [] }] }],
    observations: [], limits: [], unattributed_events: 0, counter_semantics: [] } as unknown as EvidenceReport;
  render(<EvidenceView report={rep} />);
  expect(screen.getByText(/HISTORICAL/)).toBeInTheDocument();
  expect(screen.getByText(/First missing stage: txd/)).toBeInTheDocument();
  fireEvent.click(screen.getByText(/stack_tx/));
  expect(screen.getByText("queue raw")).toBeInTheDocument();
});


test("fresh disconnected snapshot takes precedence over historical association", () => {
  const old = { id: 91, kind: "assoc.associated", ts_boottime_ns: 10, ts_wall: 1, summary: "associated", data: { boot_id: "old-boot" } } as unknown as WhdEvent;
  render(<ConnStateMachine events={[old]} snapshotConnected={false} />);
  expect(screen.getByText(/Current state from fresh nl80211/)).toHaveTextContent("DISCONNECTED");
  expect(screen.getByText(/Historical transitions/)).toBeVisible();
  expect(screen.queryByText(/Current state from event/)).toBeNull();
});

test("historical association cannot establish current state without a fresh reading", () => {
  const old = { id: 92, kind: "assoc.associated", ts_boottime_ns: 10, ts_wall: 1, summary: "associated", data: { boot_id: "old-boot" } } as unknown as WhdEvent;
  render(<ConnStateMachine events={[old]} snapshotConnected={null} />);
  expect(screen.getByText(/Current state UNKNOWN/)).toBeVisible();
});


test("firmware partner transport observations remain expandable with source limits", () => {
  render(<EvidenceView report={{ ...ordinaryReport, mcu_transport: [{ event_id: 321, envelope: { phase: "response", reason: "safe_result_status", cookie: "7", actual_seq: "2" }, raw_hex: "05000000", decoded: { firmware_status: 5 }, layout_match: "matched", matches_loaded_build: null }] } as EvidenceReport} />);
  fireEvent.click(screen.getByText("MCU partner transport observation 1"));
  expect(screen.getByText(/"firmware_status": 5/)).toBeVisible();
  expect(screen.getByText(/loaded module Build ID equivalence/)).toBeVisible();
});

test("fresh station authorization can establish current authorized state without historical events", () => {
  render(<ConnStateMachine events={[]} snapshotConnected={true} snapshotAuthorized={true} />);
  expect(screen.getByText(/Current state from fresh nl80211 station reading: AUTHORIZED/)).toBeVisible();
});

test("evidence exposes collected facts and unassigned driver returns without claiming ownership", () => {
  const unassigned = { id: 99, device_id: null, kind: "driver.kv_trace", summary: "MLO_FW_STA_RET", raw: "ret=-110", ts_boottime_ns: 10, data: { tag: "MLO_FW_STA_RET", fields: { ret: "-110", wcid: "9" } } } as unknown as WhdEvent;
  render(<EvidenceView report={{ ...ordinaryReport, current_observations: { interface: "wifi-observed", station_authorized: true }, unassigned_observations: [unassigned] } as EvidenceReport} />);
  expect(screen.getByText("wifi-observed")).toBeVisible();
  expect(screen.getByText("Station authorization (MLD)")).toBeVisible();
  expect(screen.getByText("Unassigned driver observations (1)")).toBeVisible();
  expect(screen.getByText(/ret=-110 wcid=9/)).toBeVisible();
  fireEvent.click(screen.getByText(/MLO_FW_STA_RET.*observation 99/));
  expect(screen.getByText("ret=-110")).toBeVisible();
  expect(screen.getByText(/not used as proof for the selected adapter/)).toBeVisible();
});
