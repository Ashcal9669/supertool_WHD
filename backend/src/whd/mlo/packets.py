"""Observation-only packet paths. Identifiers establish a bounded correlation, never causation."""

from __future__ import annotations

from typing import Any, Literal

from pydantic import Field

from whd.mlo.kv import fields_of, num, tag_of, trace_name
from whd.mlo.lifetime import event_interface_scope
from whd.mlo.models import EvidenceRef, Gap, Scope, StageClass
from whd.mlo.timeline import Collectors, assign_boots, boot_of, build_epochs, ref
from whd.model.common import Model
from whd.model.events import Event

STAGES = [
    "userspace_submit",
    "stack_tx",
    "mac80211_select",
    "driver_enqueue",
    "txd",
    "tx_free",
    "tx_status",
    "air_frame",
    "ap_receive",
    "reply",
    "raw_rx",
    "wcid_resolve",
    "security",
    "mac80211_rx",
    "stack_rx",
]
NAMES = {
    "net_dev_queue": "stack_tx",
    "net_dev_start_xmit": "driver_enqueue",
    "mlo_tx_select": "mac80211_select",
    "mlo_txwi": "txd",
    "mlo_txfree": "tx_free",
    "mac_txdone": "tx_status",
    "mlo_txs": "tx_status",
    "mlo_rx": "raw_rx",
    "whd_rx_descriptor": "raw_rx",
    "netif_receive_skb": "stack_rx",
    "netif_receive_skb_entry": "stack_rx",
    "napi_gro_receive_entry": "stack_rx",
    "mlo_rx_deliver": "mac80211_rx",
}
TAGS = {
    "MLO_RX_UNICAST_TRACE": "wcid_resolve",
    "MLO_RX_DECRYPT_TRACE": "security",
    "MLO_RX_PN_OK": "security",
    "MLO_RX_PN_DROP": "security",
    "MLO_TX_SELECT": "mac80211_select",
    "MLO_TX_DISPATCH": "driver_enqueue",
}


class PacketObservation(Model):
    stage: str
    stage_class: StageClass = "observation"
    ts_boottime_ns: int
    elapsed_ns: int | None = None
    identifiers: dict[str, str]
    decoded: dict[str, Any]
    raw: str
    evidence: list[EvidenceRef]
    explicit_boot: bool = False
    observed_interface: str | None = None


class PacketPath(Model):
    id: str
    scope: Scope
    correlation: str
    direction: Literal["tx", "rx", "exchange", "unknown"] = "unknown"
    observations: list[PacketObservation] = Field(default_factory=list)
    gaps: list[Gap] = Field(default_factory=list)
    first_missing: str | None = None
    acked: bool | None = None
    delivered: bool | None = None
    authenticated_delivery: bool | None = None
    duration_ns: int | None = None
    limits: list[str] = Field(
        default_factory=lambda: [
            "skb pointers can be reused; joined only within a bounded lifetime",
            "TX-free means buffer release, not ACK or network delivery",
            "stack RX means observed stack ingress, not application/socket consumption",
        ]
    )


def build_paths(events: list[Event], device_id: str) -> list[PacketPath]:
    own = [e for e in events if e.device_id == device_id]
    boots = assign_boots(own)
    epochs = build_epochs(own, device_id, Collectors())
    out: list[PacketPath] = []
    pending: dict[tuple[Any, ...], PacketPath] = {}
    for e, boot in sorted(zip(own, boots, strict=True), key=lambda pair: (pair[1], pair[0].ts_boottime_ns)):
        f = fields_of(e)
        stage = NAMES.get(trace_name(e) or "") or TAGS.get(tag_of(e) or "")
        if trace_name(e) == "whd_tx_descriptor":
            phase = f.get("stage")
            stage = phase if phase in ("txd", "tx_status") else None
        if trace_name(e) in ("whd_packet_boundary", "whd_rx_boundary"):
            phase = f.get("stage")
            stage = "security" if phase in ("pn_ok", "pn_drop") else phase if phase in STAGES else None
        if e.kind.startswith("packet.") and e.kind[7:] in STAGES:
            stage = e.kind[7:]
        if stage is None:
            continue
        if tag_of(e) == "MLO_RX_PN_DROP":
            f["stage"] = "pn_drop"
        interface, interface_lifetime = event_interface_scope(e)
        label = interface_label(e)
        ep = next(
            (
                x.id
                for x in epochs
                if x.boot_id == boot
                and (x.interface, x.interface_lifetime) == (interface, interface_lifetime)
                and x.start_ns <= e.ts_boottime_ns
                and (x.end_ns is None or e.ts_boottime_ns < x.end_ns)
            ),
            None,
        )
        ep = e.data.get("association_epoch") or f.get("association_epoch") or ep
        ids: dict[str, str] = {
            k: f[k]
            for k in ("packet_id", "skbaddr", "skb", "token", "cookie", "id", "seq", "sip", "dip")
            if k in f
        }
        namespace, strong = packet_identity(f)
        lk = num(f, "resolved_link")
        if lk is None:
            lk = num(f, "link")
        if lk is None:
            lk = num(f, "link_id")
        # Descriptor/initial ownership is not final link resolution. Keep it in decoded fields.
        if stage == "raw_rx" or (lk is not None and lk < 0):
            lk = None
        generation = e.data.get("generation", f.get("generation"))
        generation = str(generation) if generation is not None else None
        key = (boot, device_id, interface, interface_lifetime, label, ep, generation, namespace, strong)
        path = pending.get(key) if strong else None
        if path and (
            (lk is not None and path.scope.link_id not in (None, lk))
            or e.ts_boottime_ns - path.observations[-1].ts_boottime_ns > 1_000_000_000
            or (
                stage in ("stack_tx", "userspace_submit") and any(o.stage == stage for o in path.observations)
            )
            or (stage == "raw_rx" and any(o.stage == "raw_rx" for o in path.observations))
            or (
                stage in ("raw_rx", "wcid_resolve", "security", "mac80211_rx", "stack_rx")
                and namespace == "skb"
                and any(o.stage in STAGES[:7] for o in path.observations)
            )
        ):
            path = None
        if path is None:
            path = PacketPath(
                id=f"packet-{len(out) + 1}",
                scope=Scope(
                    boot_id=boot,
                    device_id=device_id,
                    association_epoch=ep,
                    link_id=lk,
                    link_lifetime=generation,
                    interface=interface,
                    interface_lifetime=interface_lifetime,
                ),
                correlation=(
                    f"same packet/buffer identifier {strong}"
                    if strong
                    else "unjoined: no stable packet identifier"
                ),
            )
            out.append(path)
            if strong:
                pending[key] = path
        elif path.scope.link_id is None and lk is not None:
            path.scope.link_id = lk
        elapsed = e.ts_boottime_ns - path.observations[0].ts_boottime_ns if path.observations else 0
        cls: StageClass = (
            "queued_request"
            if stage in ("userspace_submit", "stack_tx", "mac80211_select", "driver_enqueue", "txd")
            else "observation"
        )
        path.observations.append(
            PacketObservation(
                stage=stage,
                stage_class=cls,
                ts_boottime_ns=e.ts_boottime_ns,
                elapsed_ns=elapsed,
                identifiers=ids,
                decoded=f,
                raw=e.raw,
                evidence=[ref(e)],
                explicit_boot=boot_of(e) is not None,
                observed_interface=label,
            )
        )
        ack_supported = trace_name(e) != "whd_tx_descriptor" or (
            f.get("status_supported") == "1" and f.get("layout") == "connac3_txs32_prefix"
        )
        if stage == "tx_status" and ack_supported and f.get("acked") in ("0", "1"):
            path.acked = f["acked"] == "1"
        if trace_name(e) == "whd_tx_descriptor":
            path.limits.append(
                "driver descriptor/TXS observation; no loaded-build equivalence or token/PID-to-packet lineage is established; ACK does not establish AP reception or delivery"
            )
            if (
                num(f, "observed_len") is not None
                and num(f, "captured_len") is not None
                and (num(f, "observed_len") or 0) > (num(f, "captured_len") or 0)
            ):
                path.limits.append("raw TXS prefix is truncated; uncaptured descriptor words remain unknown")
        if stage == "stack_rx":
            path.delivered = True
        if stage == "stack_rx" or (stage == "tx_free" and namespace != "packet_id"):
            pending.pop(key, None)
    for path in out:
        security = [o for o in path.observations if o.stage == "security"]
        raw_rx = [o for o in path.observations if o.stage == "raw_rx"]
        stack_rx = [o for o in path.observations if o.stage == "stack_rx"]
        if (
            path.delivered
            and path.scope.association_epoch is not None
            and path.scope.link_id is not None
            and path.scope.link_lifetime is not None
            and path.scope.interface is not None
            and strong_interface_lifetime(path.scope.interface_lifetime)
            and security
            and raw_rx
            and stack_rx
            and raw_rx[0].ts_boottime_ns < security[0].ts_boottime_ns
            and security[-1].ts_boottime_ns < stack_rx[-1].ts_boottime_ns
            and all(o.explicit_boot for o in path.observations)
            and all(
                all(
                    o.decoded.get(k) == "1"
                    for k in ("decrypted", "integrity_ok", "replay_ok", "channel_matches")
                )
                and o.decoded.get("stage") != "pn_drop"
                for o in security
            )
        ):
            path.authenticated_delivery = True
        if path.scope.interface is None or path.scope.interface_lifetime is None:
            path.limits.append(
                "interface identity/lifetime is incomplete; cannot establish interface-scoped authenticated delivery"
            )
        elif not strong_interface_lifetime(path.scope.interface_lifetime):
            path.limits.append(
                "ifindex can be reused within a boot; interface incarnation is unknown without wdev or explicit lifetime"
            )
        seen = {o.stage for o in path.observations}
        path.gaps = [
            Gap(
                kind="not_traced",
                what=s,
                detail="no correlated observation; collector coverage may be incomplete",
            )
            for s in STAGES
            if s not in seen
        ]
        tx_seen = bool(seen.intersection(STAGES[:7]))
        rx_seen = bool(seen.intersection(STAGES[10:]))
        path.direction = (
            "exchange" if tx_seen and rx_seen else "tx" if tx_seen else "rx" if rx_seen else "unknown"
        )
        required = STAGES[10:] if path.direction == "rx" else STAGES
        path.first_missing = next((stage for stage in required if stage not in seen), None)
        if path.direction == "rx":
            path.limits.append(
                "first missing stage covers the receive leg; upstream TX/air/AP/reply gaps remain separate and no exchange is inferred"
            )
        path.duration_ns = path.observations[-1].ts_boottime_ns - path.observations[0].ts_boottime_ns
    return out


def packet_identity(fields: dict[str, str]) -> tuple[str, str | None]:
    """Never equate a packet ID with an skb pointer, including identical printed values."""
    for key, namespace in (("packet_id", "packet_id"), ("skbaddr", "skb"), ("skb", "skb")):
        value = fields.get(key)
        if value and value not in ("0", "0x0", "(null)", "None"):
            return namespace, value
    return "skb", None


def strong_interface_lifetime(lifetime: str | None) -> bool:
    """An ifindex partitions observations but does not identify a netdev incarnation."""
    return lifetime is not None and lifetime.startswith(("interface_lifetime:", "wdev:"))


def interface_label(event: Event) -> str | None:
    """Keep recorded names as collision barriers even when incarnation is unknown."""
    fields = fields_of(event)
    value = (
        event.data.get("ifname")
        or event.data.get("interface")
        or fields.get("ifname")
        or fields.get("interface")
    )
    return str(value) if value is not None else None
