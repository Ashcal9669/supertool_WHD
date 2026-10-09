import type { Device } from "../api/types";
import { Badge, Empty, KV, Panel } from "../components/ui";

export function DriverTab({ d }: { d: Device }) {
  const di = d.driver_info;
  const mi = di.module_info as Record<string, string[]>;
  return (
    <div className="grid gap-3 lg:grid-cols-2">
      <Panel title="Driver binding" meta={di.meta}>
        <KV rows={[
          ["Bound driver", di.driver ?? <span className="text-err">none</span>],
          ["Module", di.module],
          ["Module version", mi.version?.[0] ?? di.module_sysfs.version],
          ["srcversion", mi.srcversion?.[0] ?? di.module_sysfs.srcversion],
          ["vermagic", mi.vermagic?.[0]],
          ["Module file", mi.filename?.[0]],
          ["Description", mi.description?.[0]],
          ["Taint", di.module_sysfs.taint, "O = out-of-tree, E = unsigned"],
          ["Refcount", di.module_sysfs.refcnt],
          ["Kernel (ethtool)", (di.ethtool as Record<string, string>).version],
        ]} />
      </Panel>
      <Panel title="Firmware" meta={d.firmware.meta}>
        <KV rows={[["Running version", d.firmware.version]]} />
        <p className="kv-key mb-1 mt-2">Firmware files declared by module (modinfo firmware=)</p>
        {d.firmware.declared_files.length ? (
          <ul className="mono text-[12px]">{d.firmware.declared_files.map((f) => <li key={f}>{f}</li>)}</ul>
        ) : <Empty>none declared</Empty>}
        <p className="mt-2 text-[11px] text-dim">Declared files are candidates the module may request; which one loaded is chip-dependent and not inferred.</p>
      </Panel>
      <Panel title="Candidate modules (modules.alias match)">
        {di.candidate_modules.length === 0 ? <Empty>No module alias matches this device's modalias</Empty> : (
          <table className="mono w-full text-[12px]">
            <thead className="text-dim"><tr><th className="text-left">module</th><th>wireless</th><th>loaded</th><th className="text-left">path</th></tr></thead>
            <tbody>{di.candidate_modules.map((m) => (
              <tr key={m.module}><td>{m.module}</td><td className="text-center">{m.wireless ? "yes" : "no"}</td>
                <td className="text-center">{m.loaded ? <Badge tone="ok">loaded</Badge> : "—"}</td><td className="break-all text-dim">{m.path}</td></tr>
            ))}</tbody>
          </table>
        )}
        {di.candidate_modules.filter((m) => m.wireless).length > 1 && (
          <p className="mt-2 text-[11px] text-warn">Multiple wireless modules alias this device; the one that binds depends on load order and blacklists.</p>
        )}
      </Panel>
      <Panel title="Module parameters">
        {Object.keys(di.module_params).length ? <KV rows={Object.entries(di.module_params).map(([k, v]) => [k, v])} /> : <Empty>none readable</Empty>}
      </Panel>
      <Panel title="ethtool driver info (ETHTOOL_GDRVINFO)">
        {Object.keys(di.ethtool).length ? <KV rows={Object.entries(di.ethtool).map(([k, v]) => [k, String(v)])} /> : <Empty>not available</Empty>}
      </Panel>
      <Panel title="Module dependency closure">
        <div className="mono flex flex-wrap gap-1 text-[12px]">{di.module_dependencies.map((m) => <Badge key={m}>{m}</Badge>)}</div>
      </Panel>
    </div>
  );
}
