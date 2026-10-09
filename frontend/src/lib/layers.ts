import type { WhdEvent } from "../api/types";

/** Driver-stack layers, bottom (hardware) to top (user-visible). Mirrors backend diagnostics.layers. */
export const LAYERS = ["bus", "driver", "firmware", "mac80211", "netdev"] as const;
export type Layer = (typeof LAYERS)[number];

export const LAYER_LABEL: Record<Layer, string> = {
  bus: "Bus (PCIe / USB)", driver: "Driver", firmware: "Firmware / chip", mac80211: "mac80211 / cfg80211", netdev: "Network interface",
};

const BY_CATEGORY: Record<string, Layer> = {
  pci_error: "bus", pci_link: "bus", usb_error: "bus", usb_transfer: "bus", hotplug: "bus", power: "bus",
  driver_state: "driver", trace: "driver", kernel_log: "driver", telemetry: "driver",
  firmware: "firmware", reset: "firmware",
  association: "mac80211", phy: "mac80211", mlo: "mac80211", scan: "mac80211", regulatory: "mac80211",
  netdev: "netdev", system: "driver", diagnostic: "driver",
};

export const layerOf = (e: WhdEvent): Layer => BY_CATEGORY[e.category] ?? "driver";
