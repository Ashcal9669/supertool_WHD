import type { ComponentType } from "react";
import { CapturesPage } from "./Captures";
import { DeviceDetail } from "./DeviceDetail";
import { DiagnosticsPage } from "./Diagnostics";
import { InventoryPage } from "./Inventory";
import { SystemPage } from "./System";
import { TimelinePage } from "./Timeline";
import { TopologyPage } from "./Topology";
import { VizPage } from "./Viz";

export interface PageDef {
  path: string;
  Component: ComponentType;
  nav?: string;
}

export const pages: PageDef[] = [
  { path: "/", Component: InventoryPage, nav: "Inventory" },
  { path: "/device/:id", Component: DeviceDetail },
  { path: "/topology", Component: TopologyPage, nav: "Topology" },
  { path: "/timeline", Component: () => <TimelinePage />, nav: "Timeline" },
  { path: "/viz", Component: VizPage, nav: "Visualizations" },
  { path: "/captures", Component: CapturesPage, nav: "Captures" },
  { path: "/diagnostics", Component: DiagnosticsPage, nav: "Diagnostics" },
  { path: "/system", Component: SystemPage, nav: "System" },
];
