import { useQuery } from "@tanstack/react-query";
import { useSearchParams } from "react-router-dom";
import { api } from "../api/client";
import type { Device, Inventory } from "../api/types";
import { Empty, ErrorBox, Loading } from "../components/ui";
import { MloEvidencePanel } from "../device/MloEvidenceTab";

export function MloPage() {
  const [sp, setSp] = useSearchParams(); const cid = sp.get("capture") ?? undefined;
  const devices = useQuery({ queryKey: ["mlo-devices", cid], queryFn: async () => {
    if (cid) return api<Device[]>(`/captures/${cid}/devices`);
    const inventory = await api<Inventory>("/devices");
    return Promise.all(inventory.devices.filter(d => d.present || d.demo).map(d => api<Device>(`/devices/${encodeURIComponent(d.id)}`)));
  } });
  if (devices.isLoading) return <Loading />; if (devices.error) return <ErrorBox error={devices.error} />;
  const rows = devices.data ?? []; const selected = rows.find(d => d.id === sp.get("device"))?.id ?? rows[0]?.id;
  if (!selected) return <Empty>{cid ? "No device identity in this capture. Attributed observations are needed for claims." : "No wireless devices present. Open a recorded capture for passive evidence."}</Empty>;
  return <div className="space-y-3"><h1 className="text-lg">Wi-Fi evidence</h1><label>Device <select aria-label="Wi-Fi device" value={selected} onChange={e => setSp(p => { p.set("device", e.target.value); return p; })}>{rows.map(d => <option key={d.id} value={d.id}>{d.title} · {d.id}</option>)}</select></label><MloEvidencePanel key={`${selected}-${cid}`} deviceId={selected} captureId={cid} d={rows.find(d => d.id === selected)} /></div>;
}
