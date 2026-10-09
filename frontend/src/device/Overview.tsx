import type { Device } from "../api/types";
import { Badge, KV, Panel } from "../components/ui";
import { ago, hex } from "../lib/format";

export function BusPath({ d }: { d: Device }) {
  return (
    <div className="flex flex-wrap items-center gap-1 text-[12px]">
      {d.bus_path.map((n, i) => (
        <span key={n.sysfs_path} className="flex items-center gap-1">
          {i > 0 && <span className="text-dim">→</span>}
          <span className="panel mono px-2 py-0.5" title={n.sysfs_path}>
            <span className="text-dim">{n.kind.replace("_", " ")}</span> {n.name}
            {n.driver && <span className="text-accent"> [{n.driver}]</span>}
          </span>
        </span>
      ))}
      {d.driver && (<><span className="text-dim">→</span><span className="panel mono px-2 py-0.5 text-accent">driver {d.driver}</span></>)}
      {d.firmware_version && (<><span className="text-dim">→</span><span className="panel mono px-2 py-0.5">fw {d.firmware_version}</span></>)}
      {d.phys.map((p) => (<span key={p} className="flex items-center gap-1"><span className="text-dim">→</span><span className="panel mono px-2 py-0.5">{p}</span></span>))}
      {d.netdevs.map((p) => (<span key={p} className="flex items-center gap-1"><span className="text-dim">→</span><span className="panel mono px-2 py-0.5">{p}</span></span>))}
    </div>
  );
}

export function Overview({ d }: { d: Device }) {
  return (
    <div className="grid gap-3 lg:grid-cols-2">
      <Panel title="Identity">
        <KV rows={[
          ["Stable ID", d.id, "Derived from bus location and vendor/device IDs; never from netdev names"],
          ["Bus", d.bus],
          ["Vendor", d.vendor_name ? `${d.vendor_name} (${hex(d.vendor_id)})` : hex(d.vendor_id)],
          ["Product", d.product_name ? `${d.product_name} (${hex(d.product_id)})` : hex(d.product_id)],
          ["sysfs", d.sysfs_path],
          ["First seen", ago(d.first_seen)],
          ["Last seen", ago(d.last_seen)],
          ["Present", d.present ? "yes" : "no (showing last stored snapshot)"],
        ]} />
      </Panel>
      <Panel title="Detection">
        <ul className="space-y-1">
          {d.detection.map((r, i) => (
            <li key={i}>
              <Badge tone={r.strength === "authoritative" ? "ok" : r.strength === "strong" ? "accent" : "warn"}>{r.kind} · {r.strength}</Badge>
              <span className="mono ml-2 break-all text-[12px]">{r.detail}</span>
            </li>
          ))}
        </ul>
      </Panel>
      <Panel title="Bus path (discovered)" className="lg:col-span-2">
        <BusPath d={d} />
      </Panel>
      <Panel title="Summary" className="lg:col-span-2">
        <KV cols={2} rows={[
          ["Driver", d.driver ?? (d.driver_info.candidate_modules.length ? "not bound (candidates exist)" : null)],
          ["Module", d.module],
          ["Firmware", d.firmware_version],
          ["PHYs", d.phys.join(", ")],
          ["Netdevs", d.netdevs.join(", ")],
          ["Operstate", d.operstate],
          ["Link", d.pci?.link ? `${d.pci.link.current_speed} x${d.pci.link.current_width} (max ${d.pci.link.max_speed} x${d.pci.link.max_width})` : d.usb ? `USB ${d.usb.usb_version} ${d.usb.speed_name ?? ""} (${d.usb.speed_mbps} Mb/s)` : null],
          ["Runtime PM", d.power.runtime_status ? `${d.power.runtime_status} (control=${d.power.runtime_control})` : null],
        ]} />
      </Panel>
    </div>
  );
}
