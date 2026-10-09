import { useEffect, useMemo, useState } from "react";
import type { Topology, WhdEvent } from "../api/types";
import { eventStream } from "./eventStream";

export interface Pulse {
  seq: number;
  at: number;
  kind: string;
  severity: string;
  summary: string;
}

/** Which topology node kinds an event category animates (only nodes that exist for that device). */
const CATEGORY_TARGETS: Record<string, string[]> = {
  pci_error: ["pci_device"], pci_link: ["pci_device", "pci_bridge"], power: ["pci_device", "usb_device"],
  usb_error: ["usb_device"], usb_transfer: ["usb_interface", "usb_device"], hotplug: ["pci_device", "usb_device"],
  reset: ["pci_device", "usb_device", "driver"], driver_state: ["driver", "driver_candidate"], firmware: ["firmware"],
  association: ["netdev"], netdev: ["netdev"], phy: ["phy"], scan: ["phy"], regulatory: ["phy"], mlo: ["netdev"],
  trace: ["driver"], kernel_log: ["driver"],
};

/** Map live events to topology node pulses. Events without a device attribution animate nothing. */
export function useNodePulses(topo: Topology | undefined): Map<string, Pulse> {
  const [pulses, setPulses] = useState<Map<string, Pulse>>(new Map());
  const byDevice = useMemo(() => {
    const m = new Map<string, Map<string, string[]>>();
    for (const n of topo?.nodes ?? []) {
      if (!n.device_id) continue;
      if (!m.has(n.device_id)) m.set(n.device_id, new Map());
      const k = m.get(n.device_id)!;
      if (!k.has(n.kind)) k.set(n.kind, []);
      k.get(n.kind)!.push(n.id);
    }
    return m;
  }, [topo]);
  useEffect(() => {
    eventStream.acquire();
    let seq = 0;
    const off = eventStream.onEvent((e: WhdEvent) => {
      if (!e.device_id || e.severity === "debug") return;
      const kinds = byDevice.get(e.device_id);
      if (!kinds) return;
      const targets = (CATEGORY_TARGETS[e.category] ?? []).flatMap((k) => kinds.get(k) ?? []);
      if (!targets.length) return;
      setPulses((prev) => {
        const next = new Map(prev);
        for (const t of targets) next.set(t, { seq: ++seq, at: Date.now(), kind: e.kind, severity: e.severity, summary: e.summary });
        return next;
      });
    });
    return () => {
      off();
      eventStream.release();
    };
  }, [byDevice]);
  return pulses;
}
