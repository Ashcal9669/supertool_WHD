import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useState } from "react";
import { Link } from "react-router-dom";
import { api, post } from "../api/client";
import type { AirReport, Device, EvidenceReport, ExperimentResult, MloState, Mt76Instrumentation } from "../api/types";
import type { components } from "../api/schema";
import { Badge, Button, Empty, ErrorBox, Loading, Panel } from "../components/ui";

export function isLiveEvidenceDevice(d: Pick<Device, "vendor_id" | "product_id" | "present" | "demo" | "driver" | "active_test_eligible">) {
  return d.present && !d.demo && d.active_test_eligible === true && d.vendor_id === 0x14c3 && d.product_id === 0x0616
    && (d.driver === "mt7921e" || d.driver === "mt7921e_git");
}

const dimensions = ["negotiated", "active", "fw_programmed", "authorized", "authenticated_delivery"] as const;
const labels = ["Negotiated / valid", "Active", "Firmware-programmed", "Authorized", "Authenticated delivery"];
const field = "rounded border border-line bg-panel2 px-2 py-1 text-xs";

function observationFields(data: Record<string, unknown>): string {
  const fields = data.fields;
  if (!fields || typeof fields !== "object") return "";
  const values = fields as Record<string, unknown>;
  return ["cmd", "ret", "status", "wcid", "fw_idx", "resolved_link", "desc_band", "chfreq", "token", "link", "link_id"].filter(key => key in values).map(key => `${key}=${String(values[key]).slice(0, 64)}`).join(" ");
}

function Raw({ value }: { value: unknown }) {
  return <pre className="mono max-h-80 overflow-auto whitespace-pre-wrap break-all p-2 text-[11px]">{typeof value === "string" ? value : JSON.stringify(value, null, 2)}</pre>;
}

export function LinkStates({ state, historical }: { state: MloState; historical: boolean }) {
  return <div className="overflow-x-auto"><p className="mono text-xs text-dim">boot {state.boot_id} · association {state.association_epoch ?? "UNKNOWN"} · interface {state.interface ?? "UNKNOWN"} · PHY {state.phy ?? "UNKNOWN"}</p>
    <table className="w-full text-xs"><thead><tr><th>Link / identity</th>{labels.map(label => <th key={label}>{label}</th>)}</tr></thead><tbody>{state.links.map(link => <tr key={link.link_id}>
      <td className="p-2">link {link.link_id}<br />WCID {link.wcid ?? "UNKNOWN"}<br />{link.freq_mhz ?? "UNKNOWN"} MHz<br />generation {link.scope.link_lifetime ?? "UNKNOWN"}</td>
      {dimensions.map(key => { const dim = link[key]; return <td key={key} className="p-2 align-top"><details><summary className="cursor-pointer">{dim.value.toUpperCase()}{historical || dim.historical ? " · historical" : ""}</summary><Raw value={dim.evidence} /></details><p className="mt-1 text-[11px]">{dim.basis}</p>{dim.limits && <p className="text-warn text-[11px]">{dim.limits}</p>}</td>; })}
    </tr>)}</tbody></table>
    {!state.links.length && <Empty>No scoped link state observed; all dimensions remain UNKNOWN.</Empty>}
    {state.links.flatMap(link => link.conflicts.map((conflict, i) => <p className="text-warn text-xs" key={`${link.link_id}-${i}`}>link {link.link_id}: {conflict}</p>))}
    {state.notes.map(text => <p className="text-dim text-xs" key={text}>{text}</p>)}
    {state.perturbations.map(text => <p className="text-warn" key={text}>{text}</p>)}</div>;
}

export function EvidenceView({ report }: { report: EvidenceReport }) {
  const mlo = report.protocol === "mlo";
  const [link, setLink] = useState("");
  const linkIds = [...new Set(report.packets.map(path => path.scope.link_id).filter(id => id !== null && id !== undefined))];
  const packets = report.packets.filter(path => !mlo || !link || String(path.scope.link_id) === link);
  const readingLabels: Record<string, string> = { interface: "Interface", phy: "PHY", boot_id: "Boot", connected: "Associated", station_authorized: "Station authorization (MLD)", station_peer: "Station peer", helper_available: "Privileged collector available", packed_link_mask: "Packed link mask", wdev: "Interface lifetime (wdev)", frequency_mhz: "Frequency (MHz)", read_at: "Reading time", source: "Source" };
  const readings = Object.entries(report.current_observations ?? {}).filter(([name, value]) => value !== null && value !== undefined && name !== "skipped_reads");
  const unassigned = report.unassigned_observations ?? [];
  return <div className="space-y-3" data-testid="mlo-evidence">
    <div className="flex flex-wrap items-center gap-2"><Badge tone="warn">{report.capture_id ? "HISTORICAL CAPTURE" : "CURRENT READINGS + HISTORICAL OBSERVATIONS"}</Badge><span>{report.mode}</span><span className="mono">{report.device_id}</span></div>
    {readings.length > 0 && <Panel title="Collected current observations"><p className="text-xs text-dim">Direct readings; station authorization applies to the MLD, not firmware programming or authenticated delivery on every link.</p><dl className="grid gap-1 text-xs sm:grid-cols-2">{readings.map(([name, value]) => <div key={name}><dt className="text-dim">{readingLabels[name] ?? name}</dt><dd className="mono">{typeof value === "boolean" ? value ? "YES" : "NO" : name === "packed_link_mask" && typeof value === "number" ? `0x${value.toString(16)}` : String(value)}</dd></div>)}</dl></Panel>}
    {unassigned.length > 0 && <Panel title={`Unassigned driver observations (${unassigned.length})`}><p className="text-warn text-xs">Collected observations with no proven device identity: not used as proof for the selected adapter. They remain available here instead of being discarded.</p>{unassigned.slice(-100).map((obs, i) => <details key={`${obs.id}-${i}`}><summary className="cursor-pointer text-xs">{String(obs.data?.tag || obs.kind)} · observation {obs.id ?? "unpersisted"} · {obs.ts_boottime_ns} ns · {observationFields(obs.data)}</summary><Raw value={obs.raw} /><Raw value={{ boot: obs.data?.boot_id ?? "UNKNOWN", source: obs.source, device_id: obs.device_id, data: obs.data }} /></details>)}{unassigned.length > 100 && <p className="text-xs">Showing the last 100 observations; download evidence JSON for all returned records.</p>}</Panel>}
    {mlo && <Panel title="Per-link evidence states">{report.current_state && <LinkStates state={report.current_state} historical={false} />}
      {(report.snapshot_states ?? []).map((state, i) => <div key={i}><b className="text-xs">Historical capture snapshot {i + 1}</b><LinkStates state={state} historical /></div>)}
      {report.windows.filter(window => window.state).map((window, i) => <details key={i} className="mt-2"><summary className="cursor-pointer">Historical state · boot {window.scope.boot_id} · epoch {window.scope.association_epoch ?? "UNKNOWN"} · generation {window.scope.link_lifetime ?? "UNKNOWN"} · interface {window.scope.interface ?? "UNKNOWN"} · interface lifetime {window.scope.interface_lifetime ?? "UNKNOWN"}</summary><LinkStates state={window.state!} historical /></details>)}
      <p className="text-xs text-dim">YES, NO, UNKNOWN and DRIVER_ONLY describe evidence. A listed link and a rising raw RX counter do not prove delivery.</p></Panel>}
    <Panel title="Packet paths and first missing stage">
      {!mlo && <p className="text-xs text-dim">Authenticated delivery is unknown without correlated security evidence. Stack RX and packet counters alone do not establish it.</p>}
      {mlo && <label>Per-link view <select className={field} aria-label="packet link" value={link} onChange={e => setLink(e.target.value)}><option value="">All / unresolved</option>{linkIds.map(id => <option key={id} value={String(id)}>link {id}</option>)}</select></label>}
      {!packets.length && <Empty>No packet stages collected. Start a capture with available tracepoints; absence of records does not prove no transmission.</Empty>}
      {packets.slice(0, 200).map(path => <div key={path.id} className="my-2 rounded border border-line p-2">
        <div className="text-xs"><b>{path.id}</b> {mlo && <>· link {path.scope.link_id ?? "UNKNOWN"} </>}· boot {path.scope.boot_id} · epoch {path.scope.association_epoch ?? "UNKNOWN"}</div>
        <p className="text-warn text-xs">First missing stage: {path.first_missing ?? "none observed missing"}</p><p className="text-dim text-xs">Direction: {path.direction ?? "unknown"} observations</p><p className="text-dim text-xs">{path.correlation} · ACK reported {path.acked == null ? "UNKNOWN" : String(path.acked)} · stack delivery {path.delivered == null ? "UNKNOWN" : String(path.delivered)} · authenticated delivery {path.authenticated_delivery ? "YES" : "UNKNOWN"}</p>
        {path.observations.map((obs, i) => <details key={i}><summary className="cursor-pointer text-xs">{obs.stage} · {obs.stage_class} · {obs.ts_boottime_ns} ns · +{obs.elapsed_ns ?? "?"} ns</summary><Raw value={obs.raw} /><Raw value={{ identifiers: obs.identifiers, decoded: obs.decoded, observations: obs.evidence }} /></details>)}
        <details><summary className="cursor-pointer text-xs">Evidence gaps and limits</summary><Raw value={{ gaps: path.gaps, limits: path.limits }} /></details></div>)}
      {packets.length > 200 && <p>Showing 200 of {packets.length} paths; download JSON for every observation.</p>}</Panel>
    <Panel title="Firmware identity and lifecycle"><p className="text-warn text-xs">Source-layout matches are distinct from loaded module Build ID equivalence. Missing command bytes and partner fields remain explicit gaps; key material is never displayed.</p>
      {(report.mcu_transport ?? []).map((message, i) => <details key={`transport-${i}`}><summary>MCU partner transport observation {i + 1}</summary><Raw value={message} /></details>)}
      {(report.mcu_payloads ?? []).map((payload, i) => <details key={i}><summary>Observed MCU payload {i + 1}</summary><Raw value={payload} /></details>)}
      {report.windows.map((window, i) => <div key={i} className="my-2 border-t border-line pt-2"><p className="mono text-xs">boot {window.scope.boot_id} · epoch {window.scope.association_epoch ?? "UNKNOWN"}</p>
        {mlo && <div className="overflow-x-auto"><table className="w-full text-xs"><thead><tr><th>Link</th><th>Observed identity (MAC/MLD, DEV/OMAC, BSS, WCID, channel/band)</th></tr></thead><tbody>{window.firmware.links.map(identity => <tr key={identity.link_id}><td>{identity.link_id}</td><td><Raw value={identity.current} /></td></tr>)}</tbody></table></div>}
        {window.firmware.ops.map(op => <details key={op.seq}><summary className="cursor-pointer text-xs">{op.cmd_name ?? `command ${op.cmd}`} {mlo && <>· link {op.link ?? "UNKNOWN"} </>}· {op.status} · ret {op.ret ?? "UNKNOWN"} · {op.duration_us ?? "?"} μs</summary><Raw value={op} /></details>)}
        {window.firmware.flags.map((flag, j) => <p key={j} className="text-warn text-xs">{flag}</p>)}<details><summary>Instrumentation gaps</summary><Raw value={window.firmware.gaps} /></details></div>)}</Panel>
    <Panel title="RX ownership, resolution and security">{report.windows.map((window, i) => <div key={i}><p className="text-xs">boot {window.scope.boot_id} · {window.rx_summary.frames} RX observations</p>
      {window.rx_frames.slice(0, 100).map((frame, j) => <details key={j}><summary className="cursor-pointer text-xs">descriptor band {frame.desc_band ?? "UNKNOWN"} → WCID {frame.resolved_wcid ?? "UNKNOWN"} {mlo && <>/ link {frame.resolved_link ?? "UNKNOWN"} </>}· channel {frame.chfreq ?? "UNKNOWN"} vs intended {frame.expected_channel ?? "UNKNOWN"} · {frame.verdict}</summary><Raw value={frame} /></details>)}<Raw value={window.rx_summary} /></div>)}
      <details><summary>Counter increment locations and limitations</summary><Raw value={report.counter_semantics} /></details></Panel>
    <Panel title={mlo ? "Association and steering timeline" : "Association and EAPOL timeline"}>{report.epochs.map(epoch => <div key={epoch.id} className="my-2 border-t border-line pt-2"><b>{epoch.id} · {epoch.outcome}</b><p className="text-warn text-xs">First missing stage: {epoch.first_missing ?? "none observed missing"}</p>
      {epoch.stages.map((stage, i) => <details key={i}><summary className="cursor-pointer text-xs">{stage.ts_boottime_ns} ns · {stage.stage} · {stage.stage_class} · {stage.result} · cookie {stage.token ?? "UNKNOWN"}</summary><Raw value={stage.evidence} /><p>{stage.note}</p></details>)}{epoch.gaps.map((gap, i) => <p key={i} className="text-warn text-xs">{gap.what}: {gap.kind === "not_applicable" ? "NOT APPLICABLE" : "UNKNOWN"} · {gap.detail ?? gap.kind}</p>)}<Raw value={{ flags: epoch.flags, gaps: epoch.gaps }} /></div>)}</Panel>
    {report.limits.length > 0 && <Panel title="Report limits">{report.limits.map((limit, i) => <p key={i} className="text-warn text-xs">{limit}</p>)}</Panel>}
    <Panel title="Underlying observations"><p className="text-xs">{report.observations.length} attributed observations; {report.unattributed_events} unattributed observations excluded from claims.{report.truncated && " Query limit reached; older observations may be omitted."}</p>
      {report.observations.slice(-200).map((obs, i) => <details key={`${obs.id}-${i}`}><summary className="cursor-pointer text-xs">observation {obs.id ?? i} · {obs.kind} · {obs.ts_boottime_ns} ns</summary><Raw value={obs.raw} /><Raw value={obs.data} /></details>)}
      <details><summary>Report limits and decoder provenance</summary><Raw value={{ limits: report.limits, decoder_source: report.decoder_source }} /></details></Panel>
  </div>;
}

function ExperimentControls({ d }: { d: Device }) {
  const [iface, setIface] = useState(d.netdevs[0] ?? ""); const [target, setTarget] = useState(""); const [tool, setTool] = useState("ping"); const [condition, setCondition] = useState("observation"); const [group, setGroup] = useState("");
  const [trace, setTrace] = useState(false);
  const comparison = useQuery({ queryKey: ["mlo-comparison", group, d.id], queryFn: () => api<{ comparable: boolean; runs: ExperimentResult[]; limits: string[] }>(`/mlo/comparisons?group=${encodeURIComponent(group)}`), enabled: !!group, refetchInterval: group ? 5000 : false });
  const instrumentation = useQuery({ queryKey: ["mlo-instrumentation", d.id], queryFn: () => api<Mt76Instrumentation>(`/devices/${encodeURIComponent(d.id)}/mt76/instrumentation`), enabled: !!d.extensions?.mt76 });
  const traceEvents = (instrumentation.data?.tracepoints ?? []).filter(tp => tp.name.startsWith("whd_") || (tp.group === "net" && ["net_dev_queue", "net_dev_start_xmit", "netif_receive_skb", "netif_receive_skb_entry"].includes(tp.name))).map(tp => `${tp.group}/${tp.name}`);
  const run = useMutation({ mutationFn: () => post<ExperimentResult>("/mlo/experiments", { device_id: d.id, interface: iface, target, tool, condition, comparison_group: group || null, trace_events: trace ? traceEvents : [], wake_counters: false }) });
  return <Panel title="Controlled experiment"><p className="text-xs text-dim">Generates traffic on the selected Wi-Fi interface. Labels record your externally applied control/fix/control conditions. Failed and incomplete runs stay in Captures.</p>
    <div className="flex flex-wrap gap-2 py-2"><select aria-label="experiment interface" className={field} value={iface} onChange={e => setIface(e.target.value)}>{d.netdevs.map(name => <option key={name}>{name}</option>)}</select><input className={field} aria-label="experiment target IP" placeholder="Target IP" value={target} onChange={e => setTarget(e.target.value)} />
      <select className={field} aria-label="experiment tool" value={tool} onChange={e => setTool(e.target.value)}><option>ping</option><option>iperf3</option></select><select className={field} aria-label="experiment condition" value={condition} onChange={e => setCondition(e.target.value)}>{["observation", "control", "fix", "control_after"].map(x => <option key={x}>{x}</option>)}</select><input className={field} aria-label="comparison group" placeholder="Comparison group" value={group} onChange={e => setGroup(e.target.value)} />
      <label><input type="checkbox" checked={trace} onChange={e => setTrace(e.target.checked)} /> Trace available packet stages ({traceEvents.length})</label>
      <Button onClick={() => run.mutate()} disabled={run.isPending || !iface || !target}>Run bound measurement</Button></div>{run.isPending && <Loading />}{run.error && <ErrorBox error={run.error} />}{run.data && <div><Link to={`/mlo?capture=${run.data.capture_id}&device=${encodeURIComponent(d.id)}`}>Open recorded experiment {run.data.capture_id}</Link><Raw value={run.data} /></div>}
    {comparison.data && <div><b>Control / fix / control comparison · {comparison.data.comparable ? "same boot and measurement identity" : "provenance differs or unknown"}</b><table className="text-xs"><thead><tr><th>Condition</th><th>Run / status</th><th>Interface deltas</th></tr></thead><tbody>{comparison.data.runs.map(result => <tr key={result.capture_id}><td>{result.request.condition}</td><td><Link to={`/mlo?capture=${result.capture_id}`}>{result.capture_id} · {result.status}</Link></td><td><Raw value={result.deltas} /></td></tr>)}</tbody></table><Raw value={comparison.data.limits} /></div>}
  </Panel>;
}

type ObservedAirFrame = AirReport["frames"][number] & { eapol?: Record<string, number | string | null> | null };

function AirEapol({ report }: { report: AirReport }) {
  const frames = (report.frames as ObservedAirFrame[]).filter(frame => frame.eapol);
  if (!frames.length) return <p className="text-xs text-dim">No EAPOL key frames decoded in this air import; this does not establish absence of a handshake.</p>;
  const counts = [1, 2, 3, 4].map(message => `M${message} (${frames.filter(frame => frame.eapol?.message === message).length})`);
  return <div className="space-y-2">
    <p className="text-xs">Observed EAPOL: {counts.join(", ")}</p>
    <p className="text-warn text-xs">Clock and association-epoch join: UNKNOWN. These are monitor observations; message labels do not establish handshake completion, key installation, port authorization or authenticated delivery.</p>
    {report.limits.map((limit, i) => <p key={i} className="text-warn text-xs">{limit}</p>)}
    <div className="overflow-x-auto"><table className="w-full text-xs"><thead><tr><th>Observed message</th><th>Recorded time</th><th>Recorded frequency</th><th>Transmitter (addr2)</th><th>Receiver (addr1)</th><th>Key-info / replay counter</th><th>Decoder basis</th></tr></thead><tbody>
      {frames.slice(0, 200).map((frame, i) => <tr key={i}><td>{[1, 2, 3, 4].includes(Number(frame.eapol?.message)) ? `M${frame.eapol?.message}` : "UNKNOWN"}</td><td>{frame.timestamp}</td><td>{frame.freq_mhz == null ? "UNKNOWN" : `${frame.freq_mhz} MHz`}</td><td>{frame.addr2 ?? "UNKNOWN"}</td><td>{frame.addr1 ?? "UNKNOWN"}</td><td>{frame.eapol?.key_info ?? "UNKNOWN"} / {frame.eapol?.replay_counter ?? "UNKNOWN"}</td><td>{frame.eapol?.basis ?? "UNKNOWN"}</td></tr>)}
    </tbody></table></div>
    {frames.length > 200 && <p className="text-xs">Showing 200 of {frames.length} EAPOL observations; download the report for all observations.</p>}
  </div>;
}

function AirControls({ captureId }: { captureId: string }) {
  const [file, setFile] = useState<File | null>(null); const [origin, setOrigin] = useState("independent");
  const imports = useQuery({ queryKey: ["mlo-air", captureId], queryFn: () => api<AirReport[]>(`/captures/${captureId}/mlo/air`) });
  const upload = useMutation({ mutationFn: () => api<AirReport>(`/captures/${captureId}/mlo/air?origin=${origin}&filename=${encodeURIComponent(file!.name)}`, { method: "POST", body: file!, headers: { "content-type": "application/vnd.tcpdump.pcap" } }), onSuccess: () => { void imports.refetch(); } });
  return <Panel title="Air capture"><p className="text-xs">Classic PCAP with 802.11/radiotap frames. A co-located monitor shares the device PHY and is not an independent observer. Unsupported formats, timestamp gaps and unknown receiver health stay visible; AP-local captures have different visibility.</p><input type="file" aria-label="air PCAP" accept=".pcap,.cap" onChange={e => setFile(e.target.files?.[0] ?? null)} /><select aria-label="air capture origin" className={field} value={origin} onChange={e => setOrigin(e.target.value)}><option value="independent">Independent adapter</option><option value="same_phy">Co-located monitor (same PHY)</option><option value="ap_local">AP-local</option></select><Button disabled={!file || upload.isPending} onClick={() => upload.mutate()}>Import air evidence</Button>
    {upload.error && <ErrorBox error={upload.error} />}{imports.error && <ErrorBox error={imports.error} />}{imports.data?.map(saved => <div key={saved.import_id} className="my-2 border-t border-line"><b>{saved.filename ?? saved.import_id}</b> · {saved.origin}<AirEapol report={saved} /><details><summary>Air observations and visibility limits</summary><Raw value={saved} /></details>{saved.pcap_artifact ? <a download href={`/api/v1/captures/${captureId}/artifacts/${saved.pcap_artifact}`}>Download original PCAP</a> : <p>Original bytes omitted from this imported bundle.</p>}</div>)}</Panel>;
}

type StackCapture = components["schemas"]["StackCapture"];

function StackControls({ captureId, deviceId, d }: { captureId: string; deviceId: string; d?: Device }) {
  const qc = useQueryClient();
  const [file, setFile] = useState<File | null>(null);
  const [iface, setIface] = useState("");
  const [direction, setDirection] = useState("");
  const [offset, setOffset] = useState("");
  const [bootId, setBootId] = useState("");
  const boot = bootId.trim();
  const validBoot = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(boot);
  const owner = d?.id === deviceId ? d : undefined;
  const valid = !!file && !!owner && owner.netdevs.includes(iface) && (direction === "tx" || direction === "rx") && /^[+-]?\d+$/.test(offset) && validBoot;
  const path = `/captures/${encodeURIComponent(captureId)}/wifi/stack`;
  const imports = useQuery({ queryKey: ["wifi-stack", captureId], queryFn: () => api<StackCapture[]>(path) });
  const upload = useMutation({
    mutationFn: () => {
      if (!valid) throw new Error("Select a capture owner, interface, direction, boot UUID, integer clock offset and PCAP.");
      const query = new URLSearchParams({ direction, interface: iface, wall_minus_boot_ns: offset, boot_id: boot });
      return api<StackCapture>(`${path}?${query}`, { method: "POST", body: file!, headers: { "content-type": "application/vnd.tcpdump.pcap" } });
    },
    onSuccess: () => Promise.all([
      qc.invalidateQueries({ queryKey: ["wifi-stack", captureId] }),
      qc.invalidateQueries({ queryKey: ["mlo-evidence", deviceId, captureId] }),
    ]),
  });
  return <Panel title="Ethernet stack capture">
    <p className="text-xs">Import an Ethernet PCAP recorded on the captured interface. Supply its direction, boot UUID and wall-clock minus boot-clock offset in nanoseconds. Find boot and clock provenance in the downloaded capture bundle. The interface, boot and packet timestamps must match the recorded capture bounds; validation errors explain mismatches. Stack packets alone do not prove radio reception or authenticated delivery.</p>
    <p className="mono text-xs">Capture owner: {owner?.id ?? "UNKNOWN — uploads disabled"}</p>
    <div className="flex flex-wrap gap-2 py-2">
      <input type="file" aria-label="stack PCAP" accept=".pcap,.cap" onChange={e => setFile(e.target.files?.[0] ?? null)} />
      <label className="text-xs">Captured interface <select aria-label="captured interface" className={field} value={iface} onChange={e => setIface(e.target.value)}><option value="">Select captured interface</option>{owner?.netdevs.map(name => <option key={name} value={name}>{name}</option>)}</select></label>
      <label className="text-xs">Direction <select aria-label="stack direction" className={field} value={direction} onChange={e => setDirection(e.target.value)}><option value="">Select direction</option><option value="tx">TX from interface</option><option value="rx">RX into interface</option></select></label>
      <label className="text-xs">Boot UUID <input aria-label="capture boot UUID" placeholder="Boot UUID from capture provenance" className={field} value={bootId} aria-invalid={!!bootId && !validBoot} onChange={e => setBootId(e.target.value)} /></label>
      <label className="text-xs">Clock offset (ns) <input aria-label="wall minus boot offset (ns)" placeholder="Wall minus boot offset (ns)" className={field} value={offset} onChange={e => setOffset(e.target.value)} /></label>
      <Button disabled={!valid || upload.isPending} onClick={() => upload.mutate()}>Import stack evidence</Button>
    </div>
    {upload.error && <ErrorBox error={upload.error} />}{imports.error && <ErrorBox error={imports.error} />}
    {imports.data?.map(saved => <div key={saved.import_id} className="my-2 border-t border-line pt-2">
      <b>{saved.import_id}</b><p className="mono text-xs">SHA-256 {saved.sha256} · original {saved.original_retained ? "retained" : "not retained"}</p>
      {saved.limits.map((limit, i) => <p key={i} className="text-warn text-xs">{limit}</p>)}
      <details><summary>Stack observations and provenance</summary><Raw value={saved} /></details>
      <div className="flex gap-3">{saved.pcap_artifact && <a download href={`/api/v1/captures/${encodeURIComponent(captureId)}/artifacts/${encodeURIComponent(saved.pcap_artifact)}`}>Download stack PCAP</a>}{saved.report_artifact && <a download href={`/api/v1/captures/${encodeURIComponent(captureId)}/artifacts/${encodeURIComponent(saved.report_artifact)}`}>Download stack report</a>}</div>
    </div>)}
  </Panel>;
}

export function MloEvidencePanel({ deviceId, captureId, d }: { deviceId: string; captureId?: string; d?: Device }) {
  const [iface, setIface] = useState(d?.netdevs.length === 1 ? d.netdevs[0] : "");
  const allowed = !!captureId || !!d && (d.present || d.demo);
  const path = captureId ? `/captures/${captureId}/mlo/evidence?device_id=${encodeURIComponent(deviceId)}` : `/devices/${encodeURIComponent(deviceId)}/mlo/evidence?limit=3000${iface ? `&interface=${encodeURIComponent(iface)}` : ""}`;
  const q = useQuery({ queryKey: ["mlo-evidence", deviceId, captureId, iface], queryFn: () => api<EvidenceReport>(path), enabled: allowed, refetchInterval: captureId ? false : 5000 });
  const monitors = useQuery({ queryKey: ["mlo-monitors"], queryFn: () => api<unknown>("/mlo/monitors"), enabled: !captureId && allowed });
  if (!allowed) return <Empty>Device not present. Open a recorded capture for passive evidence.</Empty>;
  return <div className="space-y-3">{!captureId && d && <label>Evidence interface <select aria-label="state interface" className={field} value={iface} onChange={e => setIface(e.target.value)}><option value="">Select an interface / unknown</option>{d.netdevs.map(name => <option key={name}>{name}</option>)}</select></label>}<div className="flex gap-3"><a download href={`/api/v1${path}`}>Download evidence JSON</a>{captureId && <><a download href={`/api/v1/captures/${captureId}/bundle`}>Download MAC-masked bundle</a><a download href={`/api/v1/captures/${captureId}/bundle?redact_macs=false`}>Download original evidence bundle</a></>}</div>{q.isLoading ? <Loading /> : q.error ? <ErrorBox error={q.error} /> : q.data && <EvidenceView report={q.data} />}
    {d && !captureId && isLiveEvidenceDevice(d) && <ExperimentControls d={d} />}{captureId && (q.data?.protocol === "ordinary" || q.data?.protocol === "unknown") && <StackControls captureId={captureId} deviceId={deviceId} d={d} />}{captureId && <AirControls captureId={captureId} />}{!captureId && <Panel title="Discovered monitor capabilities and tools">{monitors.error && <ErrorBox error={monitors.error} />}<Raw value={monitors.data ?? "UNKNOWN"} /></Panel>}</div>;
}

export function MloEvidenceTab({ d }: { d: Device }) { return <MloEvidencePanel deviceId={d.id} d={d} />; }
