import type { Device } from "../api/types";
import { Badge, Empty, KV, Panel } from "../components/ui";

function Obj({ o }: { o: Record<string, unknown> }) {
  const rows = Object.entries(o).map(([k, v]) => [k, typeof v === "object" && v !== null ? JSON.stringify(v) : String(v)] as [string, string]);
  return rows.length ? <KV rows={rows} /> : <Empty>not present</Empty>;
}

/** Decoded PCI configuration space (privileged helper, read-only). */
export function PciConfigPanel({ d }: { d: Device }) {
  const c = d.pci_config;
  if (!c) {
    return (
      <Panel title="PCI configuration space (decoded)">
        <Empty>
          Full config space (capabilities, ASPM, AER registers, MSI/MSI-X, L1 substates) requires root. Start the
          WHD privileged helper (<code className="mono">make helper</code>) — it only performs read-only config reads.
        </Empty>
      </Panel>
    );
  }
  return (
    <Panel title="PCI configuration space (decoded, read-only)" meta={c.meta}>
      <div className="mb-3 flex flex-wrap gap-1">
        {c.capabilities.map((cap) => (
          <Badge key={`${cap.extended}-${cap.offset}`} tone={cap.extended ? "accent" : "dim"} title={`offset 0x${cap.offset.toString(16)}`}>
            {cap.extended ? "ext " : ""}{cap.name}@{cap.offset.toString(16)}
          </Badge>
        ))}
      </div>
      <div className="grid gap-3 lg:grid-cols-3">
        <div><p className="kv-key mb-1 font-semibold">Link (Link Cap/Ctl/Sta)</p><Obj o={c.link} /></div>
        <div><p className="kv-key mb-1 font-semibold">ASPM</p><Obj o={c.aspm} /></div>
        <div><p className="kv-key mb-1 font-semibold">L1 PM Substates</p><Obj o={c.l1ss} /></div>
        <div><p className="kv-key mb-1 font-semibold">AER registers</p><Obj o={c.aer} /></div>
        <div><p className="kv-key mb-1 font-semibold">MSI</p><Obj o={c.msi} /></div>
        <div><p className="kv-key mb-1 font-semibold">MSI-X</p><Obj o={c.msix} /></div>
        <div><p className="kv-key mb-1 font-semibold">Power Management</p><Obj o={c.pm} /></div>
      </div>
      {c.registers.length > 0 && (
        <details className="mt-3">
          <summary className="cursor-pointer text-dim">Raw decoded registers ({c.registers.length})</summary>
          <table className="mono mt-2 w-full text-[11px]"><tbody>
            {c.registers.map((r) => (
              <tr key={`${r.name}-${r.offset}`} className="align-top"><td className="pr-2">{r.name}</td><td className="pr-2">0x{r.offset.toString(16)}</td><td className="pr-2">{r.raw_hex}</td>
                <td className="break-all text-dim">{Object.entries(r.fields).map(([k, v]) => `${k}=${v}`).join(" ")}</td></tr>
            ))}
          </tbody></table>
        </details>
      )}
    </Panel>
  );
}
