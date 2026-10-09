import type { Device } from "../api/types";
import { Badge, Empty, KV, Panel } from "../components/ui";
import { bytes } from "../lib/format";

export function InterfacesTab({ d }: { d: Device }) {
  if (d.netdev_info.length === 0) return <Empty>No network interfaces registered for this device</Empty>;
  return (
    <div className="space-y-3">
      {d.netdev_info.map((n) => (
        <div key={n.name} className="grid gap-3 lg:grid-cols-2">
          <Panel title={`netdev ${n.name}`} meta={n.meta}>
            <KV rows={[
              ["ifindex", n.ifindex],
              ["MAC", n.mac],
              ["operstate", n.operstate],
              ["admin up", n.up === null || n.up === undefined ? null : String(n.up)],
              ["carrier", n.carrier === null || n.carrier === undefined ? null : String(n.carrier)],
              ["flags", n.flags_hex],
              ["MTU", n.mtu],
              ["phy", n.phy],
              ["previous names", n.name_history.join(", ")],
              ["rx", `${bytes(n.stats.rx_bytes)} · ${n.stats.rx_packets} pkts · err ${n.stats.rx_errors} · drop ${n.stats.rx_dropped}`],
              ["tx", `${bytes(n.stats.tx_bytes)} · ${n.stats.tx_packets} pkts · err ${n.stats.tx_errors} · drop ${n.stats.tx_dropped}`],
            ]} />
          </Panel>
          <Panel title="nl80211 interface">
            {n.wifi ? (
              <>
                <KV rows={[
                  ["type", n.wifi.iftype],
                  ["SSID", n.wifi.ssid],
                  ["frequency", n.wifi.freq_mhz ? `${n.wifi.freq_mhz} MHz (ch ${n.wifi.channel})` : null],
                  ["width", n.wifi.width],
                  ["center freq1/2", n.wifi.center_freq1 ? `${n.wifi.center_freq1}${n.wifi.center_freq2 ? " / " + n.wifi.center_freq2 : ""}` : null],
                  ["tx power", n.wifi.txpower_dbm !== null && n.wifi.txpower_dbm !== undefined ? `${n.wifi.txpower_dbm} dBm` : null],
                  ["power save", n.wifi.power_save],
                  ["wdev", n.wifi.wdev],
                  ["4addr", n.wifi.use_4addr === null || n.wifi.use_4addr === undefined ? null : String(n.wifi.use_4addr)],
                ]} />
                {n.wifi.mlo_links.length > 0 && (
                  <>
                    <p className="kv-key mt-2">MLO links</p>
                    <table className="mono w-full text-[11px]"><thead className="text-dim"><tr><th>link</th><th>MHz</th><th>width</th><th>addr</th></tr></thead>
                      <tbody>{n.wifi.mlo_links.map((l) => <tr key={l.link_id}><td>{l.link_id}</td><td>{l.freq_mhz}</td><td>{l.width}</td><td>{l.mac}</td></tr>)}</tbody></table>
                  </>
                )}
              </>
            ) : <Empty>nl80211 did not report this interface</Empty>}
          </Panel>
        </div>
      ))}
      {d.rfkill.length > 0 && (
        <Panel title="rfkill">
          {d.rfkill.map((r) => (
            <p key={r.name} className="mono">{r.name} ({r.type}) soft={String(r.soft)} hard={String(r.hard)} {r.soft || r.hard ? <Badge tone="err">blocked</Badge> : <Badge tone="ok">unblocked</Badge>}</p>
          ))}
        </Panel>
      )}
    </div>
  );
}
