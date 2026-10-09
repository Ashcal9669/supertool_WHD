import type { Device } from "../api/types";
import { Badge, Empty, KV, Panel } from "../components/ui";
import { bytes, hex } from "../lib/format";
import { PciConfigPanel } from "./PciConfigPanel";

function Pci({ d }: { d: Device }) {
  const p = d.pci!;
  return (
    <div className="grid gap-3 lg:grid-cols-2">
      <Panel title="PCI function" meta={p.meta}>
        <KV rows={[
          ["BDF", p.bdf],
          ["Vendor:Device", `${hex(p.vendor_id)}:${hex(p.device_id)}`],
          ["Subsystem", `${hex(p.subsystem_vendor_id)}:${hex(p.subsystem_device_id)}${p.subsystem_name ? " " + p.subsystem_name : ""}`],
          ["Class", p.class_code !== null && p.class_code !== undefined ? `${hex(p.class_code, 6)} ${p.class_name ?? ""}` : null],
          ["Revision", hex(p.revision, 2)],
          ["Names source", p.names_source],
          ["modalias", p.modalias],
          ["IRQ", p.irq],
          ["MSI/MSI-X vectors", p.msi_irqs.length ? `${p.msi_irqs.length}: ${p.msi_irqs.join(", ")}` : null],
          ["NUMA node", p.numa_node],
          ["IOMMU group", p.iommu_group],
          ["Enabled", p.enabled === null || p.enabled === undefined ? null : String(p.enabled)],
          ["Power state", p.power_state],
          ["Reset methods", p.reset_methods.join(", ")],
          ["Config bytes readable", p.config_bytes_readable === 64 ? "64 (unprivileged: header only)" : p.config_bytes_readable],
        ]} />
      </Panel>
      <div className="space-y-3">
        <Panel title="Link (sysfs)">
          {p.link ? (
            <KV rows={[
              ["Current", `${p.link.current_speed ?? "?"} x${p.link.current_width ?? "?"} (Gen${p.link.current_gen ?? "?"})`],
              ["Maximum", `${p.link.max_speed ?? "?"} x${p.link.max_width ?? "?"} (Gen${p.link.max_gen ?? "?"})`],
              ["Degraded", p.link.degraded === null || p.link.degraded === undefined ? null : p.link.degraded ? <Badge tone="warn">below max</Badge> : <Badge tone="ok">at max</Badge>],
            ]} />
          ) : <Empty>No link attributes (not a PCIe function or not exposed)</Empty>}
        </Panel>
        <Panel title="AER counters (sysfs)">
          {Object.keys(p.aer).length === 0 ? <Empty>AER counters not exposed (no AER capability or CONFIG_PCIEAER off)</Empty> : (
            <div className="grid gap-3 md:grid-cols-3">
              {Object.entries(p.aer).map(([k, v]) => (
                <div key={k}>
                  <p className="kv-key mb-1 uppercase">{k}</p>
                  <table className="mono w-full text-[11px]"><tbody>
                    {Object.entries(v).map(([n, c]) => (
                      <tr key={n} className={c ? "text-err" : ""}><td>{n}</td><td className="text-right">{c}</td></tr>
                    ))}
                  </tbody></table>
                </div>
              ))}
            </div>
          )}
        </Panel>
        <Panel title="BAR resources">
          {p.bars.length === 0 ? <Empty>No BARs</Empty> : (
            <table className="mono w-full text-[12px]">
              <thead className="text-dim"><tr><th className="text-left">BAR</th><th className="text-left">range</th><th className="text-right">size</th><th>flags</th></tr></thead>
              <tbody>{p.bars.map((b) => (
                <tr key={b.index}><td>{b.index}</td><td>{b.start}–{b.end}</td><td className="text-right">{bytes(b.size)}</td>
                  <td className="text-center">{b.kind}{b.mem64 ? " 64" : ""}{b.prefetchable ? " pref" : ""}</td></tr>
              ))}</tbody>
            </table>
          )}
        </Panel>
      </div>
      <div className="lg:col-span-2"><PciConfigPanel d={d} /></div>
    </div>
  );
}

function Usb({ d }: { d: Device }) {
  const u = d.usb!;
  return (
    <div className="grid gap-3 lg:grid-cols-2">
      <Panel title="USB device" meta={u.meta}>
        <KV rows={[
          ["Bus / Dev", `${u.busnum ?? "?"} / ${u.devnum ?? "?"}`],
          ["Port path", u.port_path],
          ["VID:PID", `${hex(u.vendor_id)}:${hex(u.product_id)}`],
          ["Names", `${u.vendor_name ?? ""} ${u.product_name ?? ""}`.trim() || null],
          ["Manufacturer / Product", `${u.manufacturer ?? ""} / ${u.product ?? ""}`],
          ["Serial", u.serial],
          ["USB version", u.usb_version],
          ["Negotiated speed", u.speed_mbps ? `${u.speed_mbps} Mb/s ${u.speed_name ?? ""}` : null],
          ["Lanes rx/tx", u.rx_lanes ? `${u.rx_lanes}/${u.tx_lanes}` : null],
          ["bcdDevice", u.bcd_device],
          ["Max power", u.max_power],
          ["Configuration", u.active_config !== null && u.active_config !== undefined ? `${u.active_config} of ${u.num_configurations}` : null],
          ["Removable", u.removable],
          ["Authorized", u.authorized === null || u.authorized === undefined ? null : String(u.authorized)],
          ["Quirks", u.quirks],
          ["LTM capable", u.ltm_capable],
        ]} />
      </Panel>
      <div className="space-y-3">
        <Panel title="Power / autosuspend">
          <KV rows={Object.entries(u.power).map(([k, v]) => [k, v === null ? null : String(v)])} />
        </Panel>
        <Panel title="Hub port state">
          {Object.keys(u.port_state).length ? <KV rows={Object.entries(u.port_state).map(([k, v]) => [k, v === null ? null : String(v)])} /> : <Empty>Port attributes not exposed</Empty>}
        </Panel>
      </div>
      <Panel title="Interfaces & endpoints" className="lg:col-span-2">
        {u.interfaces.map((i) => (
          <div key={i.name} className="mb-3">
            <p className="mb-1">
              <span className="mono">{i.name}</span> · if {i.number} alt {i.alt_setting} · class {hex(i.class_code, 2)}/{hex(i.subclass, 2)}/{hex(i.protocol, 2)} {i.class_name && <span className="text-dim">({i.class_name})</span>}
              {" · "}driver <span className="text-accent">{i.driver ?? "none"}</span>
              {i.wireless_candidate && <Badge tone="accent">wireless</Badge>}
            </p>
            <table className="mono w-full text-[12px]">
              <thead className="text-dim"><tr><th className="text-left">EP</th><th className="text-left">dir</th><th className="text-left">type</th><th className="text-right">maxpkt</th><th className="text-right">interval</th><th>attrs</th></tr></thead>
              <tbody>{i.endpoints.map((e) => (
                <tr key={e.address}><td>{hex(e.address, 2)}</td><td>{e.direction}</td><td>{e.type}</td><td className="text-right">{e.max_packet_size}</td><td className="text-right">{e.interval}</td><td className="text-center">{e.attributes_hex}</td></tr>
              ))}</tbody>
            </table>
          </div>
        ))}
      </Panel>
      <Panel title={`Raw descriptors (${u.descriptors.length})`} className="lg:col-span-2">
        <table className="mono w-full text-[11px]">
          <thead className="text-dim"><tr><th className="text-left">off</th><th className="text-left">type</th><th className="text-left">len</th><th className="text-left">fields</th></tr></thead>
          <tbody>{u.descriptors.map((n) => (
            <tr key={n.offset} className="align-top"><td>{n.offset}</td><td>{n.type_name}</td><td>{n.length}</td>
              <td className="break-all">{Object.keys(n.fields).length ? Object.entries(n.fields).map(([k, v]) => `${k}=${v}`).join(" ") : n.raw_hex}</td></tr>
          ))}</tbody>
        </table>
      </Panel>
    </div>
  );
}

export function BusTab({ d }: { d: Device }) {
  if (d.pci) return <Pci d={d} />;
  if (d.usb) return <Usb d={d} />;
  return <Empty>No bus-specific data for bus type {d.bus}</Empty>;
}
