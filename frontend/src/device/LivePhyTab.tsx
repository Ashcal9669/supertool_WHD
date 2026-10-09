import { useQuery } from "@tanstack/react-query";
import { useMemo } from "react";
import { api } from "../api/client";
import type { Device, EventPage, Station, TelemetrySample, WhdEvent, WirelessLive } from "../api/types";
import { TimeChart, type SeriesDef } from "../components/TimeChart";
import { Badge, Empty, ErrorBox, KV, Loading, Panel } from "../components/ui";
import { useEventStream } from "../hooks/useEventStream";
import { ConnStateMachine } from "../viz/ConnStateMachine";
import { MloLinks } from "../viz/MloLinks";

const SIGNAL: SeriesDef[] = [
  { key: "signal_dbm", label: "signal", color: "#22d3ee" }, { key: "signal_avg_dbm", label: "avg", color: "#64748b" },
  { key: "chain0_dbm", label: "chain0", color: "#a78bfa" }, { key: "chain1_dbm", label: "chain1", color: "#f472b6" },
];
const RATE: SeriesDef[] = [
  { key: "tx_bitrate_mbps", label: "tx bitrate", color: "#34d399" }, { key: "rx_bitrate_mbps", label: "rx bitrate", color: "#38bdf8" },
];
const RETRY: SeriesDef[] = [
  { key: "tx_retries_per_s", label: "retries/s", color: "#fbbf24" }, { key: "tx_failed_per_s", label: "failed/s", color: "#f87171" },
  { key: "rx_drop_misc_per_s", label: "rx drop/s", color: "#a78bfa" },
];
const THRU: SeriesDef[] = [
  { key: "rx_bytes_per_s", label: "rx B/s", color: "#38bdf8" }, { key: "tx_bytes_per_s", label: "tx B/s", color: "#34d399" },
];
const SURVEY: SeriesDef[] = [{ key: "busy_pct", label: "busy %", color: "#fbbf24" }, { key: "noise_dbm", label: "noise dBm", color: "#64748b" }];

function rateStr(r: Station["tx_rate"]) {
  if (!r) return null;
  return `${r.bitrate_mbps ?? "?"} Mb/s · ${r.mode}${r.mcs !== null && r.mcs !== undefined ? ` MCS${r.mcs}` : ""}${r.nss ? ` NSS${r.nss}` : ""}${r.width_mhz ? ` ${r.width_mhz}MHz` : ""}${r.gi ? ` GI ${r.gi}` : ""}`;
}

export function LivePhyTab({ d }: { d: Device }) {
  const stream = useEventStream();
  const live = useQuery({ queryKey: ["wlive", d.id], queryFn: () => api<WirelessLive>(`/devices/${encodeURIComponent(d.id)}/wireless/live`), refetchInterval: 2000 });
  const initialTel = useQuery({ queryKey: ["tel", d.id], queryFn: () => api<TelemetrySample[]>(`/telemetry?device_id=${encodeURIComponent(d.id)}&limit=6000`), staleTime: Infinity });
  const hist = useQuery({ queryKey: ["assoc-hist", d.id], queryFn: () => api<EventPage>(`/events?device_id=${encodeURIComponent(d.id)}&categories=association,mlo,scan&limit=500&min_severity=debug`) });
  const streamEvents = stream.events;
  const events = useMemo(() => {
    const m = new Map<number, WhdEvent>();
    for (const e of hist.data?.events ?? []) if (e.id) m.set(e.id, e);
    for (const e of streamEvents) if (e.id && e.device_id === d.id) m.set(e.id, e);
    return [...m.values()].sort((a, b) => a.ts_boottime_ns - b.ts_boottime_ns);
  }, [hist.data, streamEvents, d.id]);
  const init = useMemo(() => initialTel.data ?? [], [initialTel.data]);
  if (live.isLoading) return <Loading what="Querying nl80211" />;
  if (live.error) return <ErrorBox error={live.error} />;
  const L = live.data!;
  if (L.interfaces.length === 0) return <Empty>No wireless interfaces registered for this device.</Empty>;
  return (
    <div className="space-y-4">
      {L.notes.map((n) => <p key={n} className="text-[11px] text-dim">{n}</p>)}
      {L.interfaces.map((li) => {
        const i = li.interface;
        const sta = li.stations[0];
        const staSeries = sta ? `station:${i.name}:${sta.mac}` : null;
        return (
          <div key={i.ifindex} className="space-y-3">
            <div className="flex flex-wrap items-center gap-2">
              <h3 className="text-[14px] font-semibold">{i.name}</h3>
              <Badge tone="accent">{i.iftype}</Badge>
              <Badge tone={li.connected ? "ok" : "warn"}>{li.connected ? "associated" : "not associated"}</Badge>
              {li.association_summary && <span className="mono text-[12px]">{li.association_summary}</span>}
              {Object.keys(li.errors).length > 0 && <Badge tone="warn" title={JSON.stringify(li.errors)}>{Object.keys(li.errors).length} query errors</Badge>}
            </div>
            <div className="grid gap-3 xl:grid-cols-2">
              <Panel title="Connection state machine (event-driven)">
                <ConnStateMachine events={events.filter((e) => !e.data || !("ifname" in e.data) || e.data.ifname === i.name)} snapshotConnected={li.connected} />
              </Panel>
              <Panel title="Operating parameters (nl80211 GET_INTERFACE)">
                <KV rows={[
                  ["SSID", i.ssid], ["Frequency", i.freq_mhz ? `${i.freq_mhz} MHz (ch ${i.channel})` : null],
                  ["Width", i.width], ["Center freq 1/2", i.center_freq1 ? `${i.center_freq1}${i.center_freq2 ? `/${i.center_freq2}` : ""}` : null],
                  ["TX power", i.txpower_dbm !== null && i.txpower_dbm !== undefined ? `${i.txpower_dbm} dBm` : null],
                  ["Power save", i.power_save], ["MLO links", i.mlo_links.length ? String(i.mlo_links.length) : null],
                ]} />
              </Panel>
            </div>
            <Panel title="MLO links (activation / deactivation)">
              <MloLinks iface={li} events={events} />
            </Panel>
            {staSeries ? (
              <div className="grid gap-3 xl:grid-cols-2">
                <TimeChart title="Signal (dBm)" series={staSeries} defs={SIGNAL} initial={init} unit="dBm" />
                <TimeChart title="PHY bitrate (Mb/s)" series={staSeries} defs={RATE} initial={init} unit="Mb/s" />
                <TimeChart title="Retries / failures" series={staSeries} defs={RETRY} initial={init} unit="/s" />
                <TimeChart title="Throughput (station counters)" series={staSeries} defs={THRU} initial={init} unit="B/s" />
                <TimeChart title="Channel survey (in-use channel)" series={`survey:${i.name}`} defs={SURVEY} initial={init} />
              </div>
            ) : (
              <div className="grid gap-3 xl:grid-cols-2">
                <Empty>No station entry: per-station signal/bitrate/retry telemetry starts when the interface associates.</Empty>
                <TimeChart title={`Netdev throughput (${i.name})`} series={`netdev:${i.name}`} defs={[{ key: "rx_bytes_per_s", label: "rx B/s", color: "#38bdf8" }, { key: "tx_bytes_per_s", label: "tx B/s", color: "#34d399" }]} initial={init} unit="B/s" />
              </div>
            )}
            {li.stations.map((s) => (
              <Panel key={s.mac} title={`Station ${s.mac}`}>
                <KV cols={2} rows={[
                  ["signal / avg", `${s.signal_dbm ?? "?"} / ${s.signal_avg_dbm ?? "?"} dBm`], ["chains", s.chain_signal_dbm.join(", ")],
                  ["TX rate", rateStr(s.tx_rate)], ["RX rate", rateStr(s.rx_rate)],
                  ["tx retries / failed", `${s.tx_retries ?? "?"} / ${s.tx_failed ?? "?"}`], ["beacon loss / rx", `${s.beacon_loss ?? "?"} / ${s.beacon_rx ?? "?"}`],
                  ["connected", s.connected_s !== null && s.connected_s !== undefined ? `${s.connected_s} s` : null], ["inactive", s.inactive_ms !== null && s.inactive_ms !== undefined ? `${s.inactive_ms} ms` : null],
                  ["flags", Object.entries(s.flags).filter(([, v]) => v).map(([k]) => k).join(" ")], ["FCS errors", s.fcs_errors],
                ]} />
                {s.links.length > 0 && (
                  <table className="mono mt-2 w-full text-[11px]"><thead className="text-dim"><tr><th>link</th><th>signal</th><th>tx</th><th>rx</th><th>retries</th><th>failed</th></tr></thead>
                    <tbody>{s.links.map((l) => <tr key={l.link_id}><td>{l.link_id}</td><td>{l.signal_dbm}</td><td>{rateStr(l.tx_rate)}</td><td>{rateStr(l.rx_rate)}</td><td>{l.tx_retries}</td><td>{l.tx_failed}</td></tr>)}</tbody></table>
                )}
              </Panel>
            ))}
            <div className="grid gap-3 xl:grid-cols-2">
              <Panel title={`Channel survey (${li.survey.length})`}>
                {li.survey.length === 0 ? <Empty>no survey data</Empty> : (
                  <div className="max-h-64 overflow-auto"><table className="mono w-full text-[11px]"><thead className="sticky top-0 bg-panel text-dim"><tr><th>MHz</th><th>noise</th><th>busy %</th><th>in use</th></tr></thead>
                    <tbody>{li.survey.map((x) => <tr key={x.freq_mhz} className={x.in_use ? "text-accent" : ""}><td>{x.freq_mhz}</td><td>{x.noise_dbm ?? ""}</td><td>{x.busy_ms !== null && x.busy_ms !== undefined && x.time_ms ? ((x.busy_ms / x.time_ms) * 100).toFixed(1) : ""}</td><td>{x.in_use ? "yes" : ""}</td></tr>)}</tbody></table></div>
                )}
              </Panel>
              <Panel title={`Cached scan results (${li.scan.length})`}>
                {li.scan.length === 0 ? <Empty>kernel BSS cache is empty</Empty> : (
                  <div className="max-h-64 overflow-auto"><table className="mono w-full text-[11px]"><thead className="sticky top-0 bg-panel text-dim"><tr><th>SSID</th><th>BSSID</th><th>MHz</th><th>dBm</th><th>age</th><th>status</th><th>MLO</th></tr></thead>
                    <tbody>{li.scan.map((b) => <tr key={b.bssid + b.freq_mhz}><td>{b.ssid}</td><td>{b.bssid}</td><td>{b.freq_mhz}</td><td>{b.signal_dbm}</td><td>{b.seen_ms_ago}ms</td><td>{b.status}</td><td>{b.mld_addr ? `link ${b.mlo_link_id} of ${b.mld_addr}` : ""}</td></tr>)}</tbody></table></div>
                )}
              </Panel>
            </div>
          </div>
        );
      })}
      <div className="grid gap-3 xl:grid-cols-2">
        <Panel title="Regulatory (nl80211 GET_REG)">
          {L.regulatory.map((r, n) => (
            <div key={n} className="mb-2">
              <p className="mono">{r.alpha2} · DFS {r.dfs_region ?? "?"} {r.wiphy !== null && r.wiphy !== undefined ? `· wiphy ${r.wiphy} (self-managed)` : "· global"}</p>
              <table className="mono w-full text-[11px]"><thead className="text-dim"><tr><th>range MHz</th><th>max BW</th><th>EIRP</th><th>flags</th></tr></thead>
                <tbody>{r.rules.map((x, i) => <tr key={i}><td>{x.start_khz / 1000}–{x.end_khz / 1000}</td><td>{x.max_bw_khz ? x.max_bw_khz / 1000 : ""}</td><td>{x.max_eirp_dbm} dBm</td><td>{x.flags.join(" ")}</td></tr>)}</tbody></table>
            </div>
          ))}
        </Panel>
        <Panel title="Capability summary (advertised by the driver)">
          <pre className="mono text-[11px]">{JSON.stringify(L.capability_summary, null, 1)}</pre>
          {L.other_interfaces_on_wiphy.length > 0 && <p className="mt-2 text-[11px]">Other interfaces on this wiphy: {L.other_interfaces_on_wiphy.map((o) => `${o.name} (${o.iftype})`).join(", ")}</p>}
        </Panel>
      </div>
    </div>
  );
}
