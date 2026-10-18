import type { LiveInterface, WhdEvent } from "../api/types";

/** GET_INTERFACE lists negotiated links, without active/security/delivery state. */
export function MloLinks({ iface }: { iface: LiveInterface; events: WhdEvent[] }) {
  if (!iface.interface.mlo_links.length) return <p className="text-dim">No negotiated MLO links reported.</p>;
  return <div className="space-y-2"><p className="text-xs text-dim">nl80211 membership only. Open MLO evidence for separate dimensions.</p>
    <div className="flex flex-wrap gap-3">{iface.interface.mlo_links.map(link => <div key={link.link_id} className="rounded border border-line p-3">
      <b>link {link.link_id}</b><div>{link.freq_mhz ?? "UNKNOWN"} MHz · channel {link.channel ?? "UNKNOWN"}</div>
      <div>negotiated: {iface.connected === true ? "YES" : iface.connected === false ? "NO (disconnected; retained membership)" : "UNKNOWN"}</div><div>active: UNKNOWN</div><div>firmware-programmed: UNKNOWN</div><div>authorized: UNKNOWN</div><div>authenticated delivery: UNKNOWN</div>
    </div>)}</div></div>;
}
