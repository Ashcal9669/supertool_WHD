import { useQuery } from "@tanstack/react-query";
import {
  Background,
  Controls,
  Handle,
  MarkerType,
  MiniMap,
  Position,
  ReactFlow,
  type Edge,
  type Node,
  type NodeProps,
} from "@xyflow/react";
import "@xyflow/react/dist/style.css";
import { motion } from "framer-motion";
import { useMemo, useState } from "react";
import { Link } from "react-router-dom";
import { api } from "../api/client";
import type { TopoNode, Topology } from "../api/types";
import { Badge, Empty, ErrorBox, KV, Loading, Panel } from "../components/ui";
import { useNodePulses, type Pulse } from "../hooks/usePulses";
import { layeredLayout } from "../viz/layout";

const KIND_STYLE: Record<string, { border: string; tag: string }> = {
  pci_root: { border: "#475569", tag: "PCIe root" },
  pci_bridge: { border: "#64748b", tag: "PCIe bridge" },
  pci_device: { border: "#22d3ee", tag: "PCIe function" },
  usb_host: { border: "#64748b", tag: "USB root hub" },
  usb_hub: { border: "#64748b", tag: "USB hub" },
  usb_device: { border: "#22d3ee", tag: "USB device" },
  usb_interface: { border: "#38bdf8", tag: "interface" },
  usb_endpoint: { border: "#334155", tag: "endpoint" },
  driver: { border: "#a78bfa", tag: "driver" },
  driver_candidate: { border: "#f87171", tag: "unbound" },
  firmware: { border: "#f472b6", tag: "firmware" },
  phy: { border: "#34d399", tag: "wiphy" },
  netdev: { border: "#fbbf24", tag: "netdev" },
  platform: { border: "#64748b", tag: "platform" },
  other: { border: "#64748b", tag: "other" },
};

type TopoNodeData = { n: TopoNode; pulse?: Pulse; selected?: boolean };

function stateDot(n: TopoNode): { color: string; title: string } | null {
  const s = n.state as Record<string, unknown>;
  if (n.kind === "netdev") {
    const up = s.operstate === "up";
    return { color: up ? "#34d399" : s.operstate === "down" ? "#fbbf24" : "#7b8aa8", title: `operstate ${String(s.operstate)}` };
  }
  if (n.kind === "pci_device" && s.degraded !== undefined && s.degraded !== null)
    return { color: s.degraded ? "#fbbf24" : "#34d399", title: s.degraded ? "link below maximum" : "link at maximum" };
  if (n.kind === "driver_candidate") return { color: "#f87171", title: "no driver bound" };
  if (n.kind === "driver") return { color: "#34d399", title: "bound" };
  return null;
}

function TopoNodeView({ data }: NodeProps<Node<TopoNodeData>>) {
  const n = data.n;
  const st = KIND_STYLE[n.kind] ?? KIND_STYLE.other;
  const dot = stateDot(n);
  const p = data.pulse;
  const pulseColor = p ? (p.severity === "error" || p.severity === "critical" ? "#f87171" : p.severity === "warning" ? "#fbbf24" : "#22d3ee") : undefined;
  return (
    <motion.div
      key={p?.seq ?? 0}
      initial={p ? { boxShadow: `0 0 0 6px ${pulseColor}aa` } : false}
      animate={{ boxShadow: `0 0 0 0px ${pulseColor ?? "#000"}00` }}
      transition={{ duration: 1.6 }}
      className="rounded-md bg-panel2 px-2.5 py-1.5 text-[11px]"
      style={{ border: `1px ${n.kind === "driver_candidate" ? "dashed" : "solid"} ${data.selected ? "#e2e8f0" : st.border}`, width: 210 }}
      title={n.evidence}
    >
      <Handle type="target" position={Position.Top} style={{ background: st.border }} />
      <div className="flex items-center gap-1.5">
        <span className="text-[9px] uppercase tracking-wider" style={{ color: st.border }}>{st.tag}</span>
        {dot && <span className="ml-auto inline-block h-2 w-2 rounded-full" style={{ background: dot.color }} title={dot.title} />}
      </div>
      <div className="truncate font-semibold text-text" title={n.label}>{n.label}</div>
      {n.sublabel && <div className="mono truncate text-dim" title={n.sublabel}>{n.sublabel}</div>}
      {p && <div className="mono truncate text-[9px]" style={{ color: pulseColor }}>{p.kind}</div>}
      <Handle type="source" position={Position.Bottom} style={{ background: st.border }} />
    </motion.div>
  );
}

const nodeTypes = { topo: TopoNodeView };

export function TopologyPage() {
  const q = useQuery({ queryKey: ["topology"], queryFn: () => api<Topology>("/topology"), refetchInterval: 10000 });
  const [sel, setSel] = useState<string | null>(null);
  const [showEndpoints, setShowEndpoints] = useState(false);
  const pulses = useNodePulses(q.data);
  const { nodes, edges } = useMemo(() => {
    if (!q.data) return { nodes: [] as Node<TopoNodeData>[], edges: [] as Edge[] };
    const tn = q.data.nodes.filter((n) => showEndpoints || n.kind !== "usb_endpoint");
    const ids = new Set(tn.map((n) => n.id));
    const te = q.data.edges.filter((e) => ids.has(e.source) && ids.has(e.target));
    const pos = layeredLayout(tn, te);
    return {
      nodes: tn.map((n) => ({
        id: n.id, type: "topo", position: { x: pos.get(n.id)!.x, y: pos.get(n.id)!.y },
        data: { n, pulse: pulses.get(n.id), selected: sel === n.id },
      })),
      edges: te.map((e) => ({
        id: e.id, source: e.source, target: e.target, label: e.label ?? undefined,
        animated: !!pulses.get(e.target) && Date.now() - (pulses.get(e.target)?.at ?? 0) < 2000,
        style: { stroke: e.kind === "candidate" ? "#f87171" : e.kind === "bus" ? "#475569" : "#64748b", strokeDasharray: e.kind === "candidate" ? "4 3" : undefined },
        labelStyle: { fill: "#94a3b8", fontSize: 10 },
        labelBgStyle: { fill: "#0d1424" },
        markerEnd: { type: MarkerType.ArrowClosed, color: "#475569" },
      })),
    };
  }, [q.data, showEndpoints, pulses, sel]);
  if (q.isLoading) return <Loading what="Building topology" />;
  if (q.error) return <ErrorBox error={q.error} />;
  const selected = q.data!.nodes.find((n) => n.id === sel);
  return (
    <div className="grid h-[calc(100vh-110px)] gap-3 lg:grid-cols-[1fr_360px]">
      <div className="panel relative overflow-hidden">
        <div className="absolute left-3 top-2 z-10 flex items-center gap-3 text-[11px] text-dim">
          <span>{q.data!.nodes.length} nodes · discovered relationships only</span>
          <label className="flex items-center gap-1"><input type="checkbox" checked={showEndpoints} onChange={(e) => setShowEndpoints(e.target.checked)} /> USB endpoints</label>
          <span>node pulses = live events for that device</span>
        </div>
        {nodes.length === 0 ? <div className="p-10"><Empty>No wireless devices to draw</Empty></div> : (
          <ReactFlow nodes={nodes} edges={edges} nodeTypes={nodeTypes} fitView fitViewOptions={{ maxZoom: 1.15, padding: 0.15 }} minZoom={0.2}
            onNodeClick={(_, n) => setSel(n.id)} nodesConnectable={false} nodesDraggable proOptions={{ hideAttribution: true }}
            colorMode="dark">
            <Background color="#1e2a44" gap={20} />
            <Controls showInteractive={false} />
            {nodes.length > 12 && <MiniMap pannable zoomable nodeColor={(n) => KIND_STYLE[(n.data as TopoNodeData).n.kind]?.border ?? "#64748b"} maskColor="#070b14cc" />}
          </ReactFlow>
        )}
      </div>
      <Panel title="Node details">
        {selected ? (
          <div className="space-y-2">
            <p className="font-semibold">{selected.label}</p>
            <Badge tone="accent">{selected.kind}</Badge>
            {selected.device_id && (
              <p><Link className="text-accent hover:underline" to={`/device/${encodeURIComponent(selected.device_id)}`}>open device inspector →</Link></p>
            )}
            <KV rows={[["sysfs", selected.sysfs_path], ["evidence", selected.evidence], ["sublabel", selected.sublabel]]} />
            <p className="kv-key mt-2">State</p>
            <KV rows={Object.entries(selected.state).map(([k, v]) => [k, v === null || v === undefined ? null : typeof v === "object" ? JSON.stringify(v) : String(v)])} />
            <p className="kv-key mt-2">Attributes</p>
            <KV rows={Object.entries(selected.attrs).map(([k, v]) => [k, v === null || v === undefined ? null : typeof v === "object" ? JSON.stringify(v) : String(v)])} />
            {pulses.get(selected.id) && (
              <p className="mono text-[11px] text-accent">last event: {pulses.get(selected.id)!.kind} — {pulses.get(selected.id)!.summary}</p>
            )}
          </div>
        ) : <Empty>Click a node to inspect it</Empty>}
      </Panel>
    </div>
  );
}
