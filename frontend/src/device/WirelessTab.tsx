import { useState } from "react";
import type { Band, Device, Wiphy } from "../api/types";
import { Badge, Empty, KV, Panel, Tabs } from "../components/ui";

function Flags({ title, f }: { title: string; f: { raw_hex: string; flags: string[]; definitions: string } }) {
  return (
    <div className="mb-2">
      <p className="kv-key">{title} <span className="mono text-text">{f.raw_hex}</span> <span className="text-[10px]">({f.definitions})</span></p>
      <div className="mt-1 flex flex-wrap gap-1">{f.flags.map((x) => <Badge key={x}>{x}</Badge>)}{f.flags.length === 0 && <span className="text-dim">no named bits set</span>}</div>
    </div>
  );
}

function BandView({ b }: { b: Band }) {
  return (
    <div className="space-y-3">
      <div className="flex flex-wrap items-center gap-2">
        <span className="kv-key">Channel widths:</span>
        {b.widths.map((w) => <Badge key={w.width} tone="accent" title={w.rule}>{w.width} MHz</Badge>)}
        <span className="text-[11px] text-dim">(hover for the capability bit each width is derived from)</span>
      </div>
      <div className="grid gap-3 xl:grid-cols-2">
        <div className="max-h-96 overflow-auto">
          <table className="mono w-full text-[11px]">
            <thead className="sticky top-0 bg-panel text-dim"><tr><th className="text-left">ch</th><th className="text-left">MHz</th><th className="text-right">max dBm</th><th className="text-left">flags</th></tr></thead>
            <tbody>{b.channels.map((c) => (
              <tr key={`${c.freq_mhz}-${c.freq_offset_khz}`} className={c.disabled ? "text-dim line-through" : ""}>
                <td>{c.channel}</td><td>{c.freq_mhz}</td><td className="text-right">{c.max_tx_power_dbm}</td>
                <td className="text-[10px]">{c.flags.join(" ")}{c.dfs_state ? ` DFS:${c.dfs_state}` : ""}</td>
              </tr>
            ))}</tbody>
          </table>
        </div>
        <div>
          {b.ht && <><Flags title="HT capabilities" f={b.ht.cap} /><KV rows={[["HT max RX NSS", b.ht.max_rx_nss], ["A-MPDU factor/density", `${b.ht.ampdu_factor ?? "?"} / ${b.ht.ampdu_density ?? "?"}`]]} /></>}
          {b.vht && <><Flags title="VHT capabilities" f={b.vht.cap} /><KV rows={[["VHT NSS rx/tx", `${b.vht.max_rx_nss}/${b.vht.max_tx_nss}`]]} /></>}
          {b.he.map((h, i) => (
            <div key={i} className="mt-2 border-t border-line pt-2">
              <p className="mb-1 text-[12px]">HE (Wi-Fi 6) for {h.iftypes.join(", ")} {h.max_rx_nss_80 ? `· ${h.max_rx_nss_80} SS ≤80MHz` : ""}</p>
              <Flags title="HE MAC" f={h.mac} /><Flags title="HE PHY" f={h.phy} />
              {h.he_6ghz_capa_hex && <KV rows={[["HE 6 GHz capa", h.he_6ghz_capa_hex]]} />}
            </div>
          ))}
          {b.eht.map((h, i) => (
            <div key={i} className="mt-2 border-t border-line pt-2">
              <p className="mb-1 text-[12px]">EHT (Wi-Fi 7) for {h.iftypes.join(", ")}</p>
              <Flags title="EHT MAC" f={h.mac} /><Flags title="EHT PHY" f={h.phy} />
            </div>
          ))}
          {!b.ht && !b.vht && b.he.length === 0 && b.eht.length === 0 && <Empty>No HT/VHT/HE/EHT capabilities advertised</Empty>}
        </div>
      </div>
    </div>
  );
}

function WiphyView({ w }: { w: Wiphy }) {
  const [band, setBand] = useState(w.bands[0]?.name ?? "");
  const b = w.bands.find((x) => x.name === band);
  const wifiGen = w.bands.some((x) => x.eht.length) ? "Wi-Fi 7 (EHT)" : w.bands.some((x) => x.he.length) ? (w.bands.some((x) => x.name === "6GHZ" && x.he.length) ? "Wi-Fi 6E (HE)" : "Wi-Fi 6 (HE)") : w.bands.some((x) => x.vht) ? "Wi-Fi 5 (VHT)" : "legacy/HT";
  return (
    <div className="space-y-3">
      <div className="grid gap-3 lg:grid-cols-2">
        <Panel title={`${w.name} (wiphy ${w.index})`} meta={w.meta}>
          <KV rows={[
            ["Highest PHY advertised", wifiGen, "From advertised capability elements, not from model names"],
            ["Permanent address", w.perm_addr],
            ["Bands", w.bands.map((x) => x.name).join(", ")],
            ["Antennas avail tx/rx", w.antenna_avail_tx !== null && w.antenna_avail_tx !== undefined ? `0x${w.antenna_avail_tx.toString(16)} / 0x${(w.antenna_avail_rx ?? 0).toString(16)}` : null],
            ["Max scan SSIDs", w.max_scan_ssids],
            ["Retry short/long", w.retry_short !== null && w.retry_short !== undefined ? `${w.retry_short}/${w.retry_long}` : null],
            ["MLO support", w.mlo_support ? "yes (NL80211_ATTR_MLO_SUPPORT)" : "no"],
            ["Self-managed regulatory", w.self_managed_reg ? "yes" : "no"],
          ]} />
        </Panel>
        <Panel title="Interface modes & security">
          <p className="kv-key mb-1">Supported iftypes</p>
          <div className="mb-2 flex flex-wrap gap-1">{w.supported_iftypes.map((t) => <Badge key={t}>{t}</Badge>)}</div>
          <p className="kv-key mb-1">Cipher suites</p>
          <div className="mb-2 flex flex-wrap gap-1">{w.cipher_suites.map((t) => <Badge key={t}>{t}</Badge>)}</div>
          {w.mld.length > 0 && (<>
            <p className="kv-key mb-1">MLD / EML capabilities (per iftype)</p>
            <table className="mono w-full text-[11px]"><tbody>{w.mld.map((m) => (
              <tr key={m.iftype}><td>{m.iftype}</td><td>EML {m.eml_capability_hex}</td><td>MLD ops {m.mld_capa_and_ops_hex}</td></tr>
            ))}</tbody></table>
          </>)}
        </Panel>
      </div>
      <Panel title="Bands">
        <Tabs tabs={w.bands.map((x) => ({ id: x.name, label: `${x.name} (${x.channels.length})` }))} value={band} onChange={setBand} />
        <div className="pt-3">{b ? <BandView b={b} /> : <Empty>No bands</Empty>}</div>
      </Panel>
      <div className="grid gap-3 lg:grid-cols-2">
        <Panel title={`Extended features (${w.ext_features.length})`}>
          <div className="flex flex-wrap gap-1">{w.ext_features.map((t) => <Badge key={t}>{t}</Badge>)}</div>
        </Panel>
        <Panel title={`Feature flags / commands`}>
          <div className="mb-2 flex flex-wrap gap-1">{w.feature_flags.map((t) => <Badge key={t}>{t}</Badge>)}</div>
          <details><summary className="cursor-pointer text-dim">Supported commands ({w.supported_commands.length})</summary>
            <div className="mt-1 flex flex-wrap gap-1">{w.supported_commands.map((t) => <Badge key={t}>{t}</Badge>)}</div></details>
          <details className="mt-1"><summary className="cursor-pointer text-dim">Attributes not decoded by WHD ({w.undecoded_attrs.length})</summary>
            <p className="mono mt-1 text-[11px] text-dim">{w.undecoded_attrs.join(" ")}</p></details>
        </Panel>
      </div>
    </div>
  );
}

export function WirelessTab({ d }: { d: Device }) {
  if (d.wiphys.length === 0)
    return <Empty>No wiphy data. {d.phys.length ? "nl80211 did not return data for this PHY (see System → integrations)." : "No PHY is registered for this device (driver not bound or probe failed)."}</Empty>;
  return <div className="space-y-4">{d.wiphys.map((w) => <WiphyView key={w.index} w={w} />)}</div>;
}
