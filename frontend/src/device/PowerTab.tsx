import type { Device } from "../api/types";
import { Empty, KV, Panel } from "../components/ui";
import { ms } from "../lib/format";

export function PowerTab({ d }: { d: Device }) {
  const p = d.power;
  return (
    <div className="grid gap-3 lg:grid-cols-2">
      <Panel title="Runtime PM" meta={p.meta}>
        <KV rows={[
          ["control", p.runtime_control],
          ["runtime_status", p.runtime_status],
          ["active time", ms(p.runtime_active_ms)],
          ["suspended time", ms(p.runtime_suspended_ms)],
          ["autosuspend delay", p.autosuspend_delay_ms !== null && p.autosuspend_delay_ms !== undefined ? `${p.autosuspend_delay_ms} ms` : null],
          ["wakeup", p.wakeup],
          ["PCI D-state", p.pci_power_state],
          ["d3cold allowed", p.d3cold_allowed === null || p.d3cold_allowed === undefined ? null : String(p.d3cold_allowed)],
        ]} />
      </Panel>
      <Panel title="ASPM" meta={p.aspm_meta}>
        {Object.keys(p.aspm).length ? <KV rows={Object.entries(p.aspm).map(([k, v]) => [k, String(v)])} /> : <Empty>{p.aspm_meta.note ?? "not exposed"}</Empty>}
      </Panel>
      <Panel title="Wi-Fi power save (NL80211_CMD_GET_POWER_SAVE)">
        {Object.keys(p.wifi_power_save).length ? <KV rows={Object.entries(p.wifi_power_save).map(([k, v]) => [k, v])} /> : <Empty>no wireless interfaces</Empty>}
      </Panel>
    </div>
  );
}
