import { Link } from "react-router-dom";
import { useInventory, useRescan, useSystem } from "../api/hooks";
import type { DeviceSummary } from "../api/types";
import { Badge, Button, Empty, ErrorBox, Loading, Panel } from "../components/ui";
import { ago, hex } from "../lib/format";

function DeviceCard({ d }: { d: DeviceSummary }) {
  const ids = d.vendor_id !== null && d.vendor_id !== undefined ? `${hex(d.vendor_id)?.slice(2)}:${hex(d.product_id)?.slice(2)}` : null;
  const opTone = d.operstate === "up" ? "ok" : d.operstate === "down" ? "warn" : "dim";
  return (
    <Link to={`/device/${encodeURIComponent(d.id)}`} className={`panel block p-3 transition hover:border-accent/60 ${d.present ? "" : "opacity-60"}`}>
      <div className="mb-2 flex items-start gap-2">
        <Badge tone="accent">{d.bus === "pci" ? "PCIe" : d.bus.toUpperCase()}</Badge>
        {d.demo && <Badge tone="demo" title="Fixture data, not live hardware">demo</Badge>}
        {!d.present && <Badge tone="warn">absent</Badge>}
        <span className="ml-auto mono text-[11px] text-dim">{d.id}</span>
      </div>
      <h3 className="mb-1 text-[14px] font-semibold leading-tight">{d.title}</h3>
      <p className="mb-2 text-dim">{d.vendor_name ?? "unknown vendor"} {ids && <span className="mono">[{ids}]</span>}</p>
      <div className="mono grid grid-cols-2 gap-x-4 gap-y-0.5 text-[12px]">
        <span className="text-dim">driver</span>
        <span>{d.driver ?? <span className="text-err">not bound</span>}</span>
        <span className="text-dim">module</span>
        <span>{d.module ?? "—"}</span>
        <span className="text-dim">firmware</span>
        <span className="break-all">{d.firmware_version ?? <span className="text-dim italic">not reported</span>}</span>
        <span className="text-dim">phy / netdev</span>
        <span>{d.phys.join(",") || "—"} / {d.netdevs.join(",") || "—"}</span>
        <span className="text-dim">operstate</span>
        <span><Badge tone={opTone}>{d.operstate ?? "n/a"}</Badge></span>
      </div>
      <div className="mt-2 flex flex-wrap gap-1">
        {d.detection.map((r, i) => (
          <Badge key={i} tone={r.strength === "authoritative" ? "ok" : r.strength === "strong" ? "accent" : "warn"} title={r.detail}>
            {r.kind.replace("_", " ")}
          </Badge>
        ))}
      </div>
      {!d.present && <p className="mt-2 text-[11px] text-dim">last seen {ago(d.last_seen)}</p>}
    </Link>
  );
}

export function InventoryPage() {
  const inv = useInventory();
  const sys = useSystem();
  const rescan = useRescan();
  if (inv.isLoading) return <Loading what="Discovering devices" />;
  if (inv.error) return <ErrorBox error={inv.error} />;
  const data = inv.data!;
  const present = data.devices.filter((d) => d.present);
  const absent = data.devices.filter((d) => !d.present);
  return (
    <div className="space-y-4">
      <div className="flex items-center gap-3">
        <h1 className="text-lg font-semibold">Wireless devices</h1>
        <span className="text-dim">
          {present.length} present · scan {data.duration_ms.toFixed(0)} ms · {ago(data.taken_at)}
        </span>
        <div className="ml-auto flex items-center gap-2">
          {rescan.data && (
            <span className="text-[11px] text-dim">
              +{rescan.data.added.length} −{rescan.data.removed.length} ~{Object.keys(rescan.data.changed).length}
            </span>
          )}
          <Button tone="primary" onClick={() => rescan.mutate()} disabled={rescan.isPending}>
            {rescan.isPending ? "Scanning…" : "Rescan"}
          </Button>
        </div>
      </div>
      {data.issues.length > 0 && (
        <Panel title="Discovery issues">
          <ul className="mono text-[12px] text-warn">
            {data.issues.map((i, n) => <li key={n}>{i.kind} · {i.source}: {i.detail}</li>)}
          </ul>
        </Panel>
      )}
      {present.length === 0 ? (
        <Empty>
          No wireless devices found. WHD checks bound PHYs (/sys/class/ieee80211), modalias matches against wireless
          kernel modules, and PCI class 0x0280.
        </Empty>
      ) : (
        <div className="grid gap-3 md:grid-cols-2 xl:grid-cols-3">
          {present.map((d) => <DeviceCard key={d.id} d={d} />)}
        </div>
      )}
      {absent.length > 0 && (
        <>
          <h2 className="pt-2 text-[13px] font-semibold text-dim">Previously seen (not present now)</h2>
          <div className="grid gap-3 md:grid-cols-2 xl:grid-cols-3">
            {absent.map((d) => <DeviceCard key={d.id} d={d} />)}
          </div>
        </>
      )}
      {sys.data && (
        <Panel title="Integrations">
          <div className="flex flex-wrap gap-1.5">
            {sys.data.integrations.map((i) => (
              <Badge key={i.name} tone={i.state === "ok" || i.state === "via_helper" ? "ok" : i.state === "missing" ? "dim" : "warn"}
                title={`${i.enables}${i.detail ? " — " + i.detail : ""}`}>
                {i.name}: {i.state}
              </Badge>
            ))}
          </div>
        </Panel>
      )}
    </div>
  );
}
