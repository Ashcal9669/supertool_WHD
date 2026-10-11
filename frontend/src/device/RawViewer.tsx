import { useQuery } from "@tanstack/react-query";
import { useMemo, useState } from "react";
import { api } from "../api/client";
import type { Device, Mt76RawListing, Mt76RawRead } from "../api/types";
import { Badge, Button, Empty, ErrorBox, Loading, Panel } from "../components/ui";
import { bootSec } from "../lib/format";

const TIER_TONE: Record<string, "ok" | "warn" | "err" | "dim"> = { passive: "ok", wakes_device: "warn", mmio: "err", mcu: "err", never: "err" };
const TIER_NOTE: Record<string, string> = {
  passive: "driver memory only",
  wakes_device: "reading wakes the chip from runtime PM",
  mmio: "touches device registers; not available here",
  mcu: "sends a firmware command; not available here",
  never: "blocked by policy",
};

/** Deep lookup: the unmodified text of any readable driver debugfs file, with when it was read. The file list comes
 * from the running kernel, so it shows whatever this driver or build exposes. */
export function RawViewer({ d, phy }: { d: Device; phy?: string }) {
  const [path, setPath] = useState("");
  const [wake, setWake] = useState(false);
  const [filter, setFilter] = useState("");
  const qs = phy ? `phy=${encodeURIComponent(phy)}` : "";
  const list = useQuery({ queryKey: ["mt76-raw-files", d.id, phy], queryFn: () => api<Mt76RawListing>(`/devices/${encodeURIComponent(d.id)}/mt76/raw-files?${qs}`), staleTime: 30000, retry: false });
  const files = useMemo(() => (list.data?.files ?? []).filter((f) => f.path.toLowerCase().includes(filter.toLowerCase())), [list.data, filter]);
  const sel = list.data?.files.find((f) => f.path === path);
  const readable = sel && (sel.tier === "passive" || (sel.tier === "wakes_device" && wake));
  const read = useQuery({
    queryKey: ["mt76-raw", d.id, phy, path, wake],
    queryFn: () => api<Mt76RawRead>(`/devices/${encodeURIComponent(d.id)}/mt76/raw?path=${encodeURIComponent(path)}&wake=${wake}&${qs}`),
    enabled: !!readable, retry: false, refetchOnWindowFocus: false, staleTime: 0,
  });
  if (list.isLoading) return <Loading what="Listing driver files" />;
  if (list.error) return <ErrorBox error={list.error} />;
  return (
    <div className="grid gap-3 lg:grid-cols-[22rem_1fr]">
      <Panel title={`Driver files on ${list.data!.phy} (${list.data!.files.length}${list.data!.truncated ? "+" : ""})`}>
        <input aria-label="filter files" value={filter} onChange={(e) => setFilter(e.target.value)} placeholder="filter…" className="mb-2 w-full rounded border border-line bg-bg px-1.5 py-1" />
        <ul className="max-h-[32rem] space-y-0.5 overflow-auto text-[12px]">
          {files.map((f) => (
            <li key={f.path}>
              <button type="button" onClick={() => setPath(f.path)} className={`flex w-full items-center gap-2 rounded px-1 py-0.5 text-left hover:bg-panel2 ${f.path === path ? "bg-panel2" : ""}`}>
                <Badge tone={TIER_TONE[f.tier ?? "never"] ?? "dim"} title={f.policy ?? ""}>{f.tier ?? "unclassified"}</Badge>
                <span className="mono break-all">{f.path}</span>
              </button>
            </li>))}
          {files.length === 0 && <li className="text-dim">no file matches</li>}
        </ul>
        <label className="mt-2 flex items-center gap-2 text-[11px]"><input type="checkbox" checked={wake} onChange={(e) => { if (!e.target.checked || window.confirm("Some files take the driver mutex and wake the chip from runtime power save when read. These reads change nothing else, and each one is audited. Allow?")) setWake(e.target.checked); }} />allow reads that wake the chip</label>
      </Panel>
      <Panel title={path || "Select a file"} right={read.data && <Button onClick={() => void navigator.clipboard?.writeText(read.data!.text ?? "")}>Copy</Button>}>
        {!sel ? <Empty>Pick a file on the left. Everything shown is exactly what the kernel returned, not WHD&apos;s interpretation.</Empty> : (
          <div className="space-y-2">
            <div className="flex flex-wrap items-center gap-2 text-[11px] text-dim">
              <Badge tone={TIER_TONE[sel.tier ?? "never"] ?? "dim"}>{sel.tier}</Badge>{TIER_NOTE[sel.tier ?? "never"]}
              {sel.policy && <span>· {sel.policy}</span>}
            </div>
            {!readable ? <Empty>{sel.tier === "wakes_device" ? "Enable “allow reads that wake the chip” to read this file." : "This file cannot be read from here."}</Empty>
              : read.isLoading ? <Loading what="Reading" />
              : read.error ? <ErrorBox error={read.error} />
              : read.data && (
                <>
                  <div className="mono text-[11px] text-dim" data-testid="raw-meta">{read.data.bytes} bytes{read.data.truncated ? " (truncated)" : ""} · read in {read.data.elapsed_ms.toFixed(1)} ms · at {bootSec(read.data.read_at_boottime_ns)}s boottime · {new Date(read.data.read_at_wall * 1000).toLocaleTimeString()}</div>
                  {read.data.binary ? <Empty>Binary content is not shown.</Empty> : <pre className="mono max-h-[30rem] overflow-auto whitespace-pre rounded bg-bg p-2 text-[11px]" data-testid="raw-text">{read.data.text}</pre>}
                  <Button onClick={() => void read.refetch()}>Read again</Button>
                </>)}
          </div>)}
      </Panel>
    </div>
  );
}
