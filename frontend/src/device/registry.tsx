import type { ComponentType } from "react";
import type { Device } from "../api/types";
import { BusTab } from "./BusTab";
import { DriverTab } from "./DriverTab";
import { EvidenceTab } from "./EvidenceTab";
import { InterfacesTab } from "./InterfacesTab";
import { Overview } from "./Overview";
import { PowerTab } from "./PowerTab";
import { WirelessTab } from "./WirelessTab";
import { LivePhyTab } from "./LivePhyTab";
import { Mt76Tab } from "./Mt76Tab";
import { TimelinePage } from "../pages/Timeline";

export interface DeviceTab {
  id: string;
  label: string;
  Component: ComponentType<{ d: Device }>;
  when?: (d: Device) => boolean;
}

export const deviceTabs: DeviceTab[] = [
  { id: "overview", label: "Overview", Component: Overview },
  { id: "bus", label: "Bus", Component: BusTab, when: (d) => !!d.pci || !!d.usb },
  { id: "driver", label: "Driver & firmware", Component: DriverTab },
  { id: "wireless", label: "Wireless PHY", Component: WirelessTab },
  { id: "live", label: "Live PHY", Component: LivePhyTab, when: (d) => d.present && d.netdevs.length > 0 },
  { id: "mt76", label: "mt76", Component: Mt76Tab, when: (d) => d.present && !!(d.extensions as Record<string, unknown>)?.mt76 },
  { id: "interfaces", label: "Interfaces", Component: InterfacesTab },
  { id: "power", label: "Power", Component: PowerTab },
  { id: "events", label: "Events", Component: ({ d }) => <TimelinePage deviceId={d.id} /> },
  { id: "evidence", label: "Evidence", Component: EvidenceTab },
];
