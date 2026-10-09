import { useParams, useSearchParams } from "react-router-dom";
import { useDevice } from "../api/hooks";
import { Badge, ErrorBox, Loading, Tabs } from "../components/ui";
import { deviceTabs } from "../device/registry";

export function DeviceDetail() {
  const { id } = useParams();
  const [sp, setSp] = useSearchParams();
  const q = useDevice(id);
  if (q.isLoading) return <Loading />;
  if (q.error) return <ErrorBox error={q.error} />;
  const d = q.data!;
  const tabs = deviceTabs.filter((t) => !t.when || t.when(d));
  const tab = tabs.find((t) => t.id === sp.get("tab")) ?? tabs[0];
  return (
    <div className="space-y-3">
      <div className="flex flex-wrap items-center gap-2">
        <Badge tone="accent">{d.bus === "pci" ? "PCIe" : d.bus.toUpperCase()}</Badge>
        {d.demo && <Badge tone="demo">demo data</Badge>}
        {!d.present && <Badge tone="warn">not present — last snapshot</Badge>}
        <h1 className="text-lg font-semibold">{d.title}</h1>
        <span className="mono text-dim">{d.id}</span>
      </div>
      <Tabs tabs={tabs.map((t) => ({ id: t.id, label: t.label }))} value={tab.id}
        onChange={(t) => setSp((p) => { p.set("tab", t); return p; }, { replace: true })} />
      <tab.Component d={d} />
    </div>
  );
}
