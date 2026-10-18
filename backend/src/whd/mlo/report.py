"""Reports grouped by boot, device, association and observed peer generation."""

from __future__ import annotations

from collections import defaultdict
from typing import Any, Literal

from pydantic import Field

from whd.mlo import fwid, rx
from whd.mlo.definitions import COUNTER_SEMANTICS, mcu_ids
from whd.mlo.kv import fields_of, num, tag_of
from whd.mlo.lifetime import event_interface_scope
from whd.mlo.mcu import decode_tlv
from whd.mlo.models import Dimension, Epoch, Scope
from whd.mlo.packets import PacketPath, build_paths
from whd.mlo.state import MloState, build_state
from whd.mlo.timeline import Collectors, assign_boots, build_epochs
from whd.mlo.transport import decode_transport
from whd.model.common import Model
from whd.model.device import Device
from whd.model.events import Event


class EvidenceWindow(Model):
    scope: Scope
    firmware: fwid.FwReport
    rx_frames: list[rx.RxFrame]
    rx_summary: rx.RxSummary
    state: MloState


class EvidenceReport(Model):
    device_id: str
    mode: str
    protocol: Literal["ordinary", "mlo", "unknown"] = "unknown"
    historical: bool = True
    capture_id: str | None = None
    current_state: MloState | None = None
    current_observations: dict[str, Any] = Field(default_factory=dict)
    snapshot_states: list[MloState] = Field(default_factory=list)
    windows: list[EvidenceWindow]
    epochs: list[Epoch]
    packets: list[PacketPath]
    observations: list[Event]
    unassigned_observations: list[Event] = Field(
        default_factory=list,
        description="Unattributed input records retained individually; not evidence for the selected device or link.",
    )
    unattributed_events: int
    mcu_payloads: list[dict[str, Any]] = Field(default_factory=list)
    mcu_transport: list[dict[str, Any]] = Field(default_factory=list)
    truncated: bool = False
    counter_semantics: list[dict[str, str]] = Field(default_factory=lambda: COUNTER_SEMANTICS)
    decoder_source: dict[str, Any] | None = None
    limits: list[str] = Field(
        default_factory=lambda: [
            "unattributed events cannot establish per-device claims",
            "adjacent RX tags are provisional; authenticated stack delivery needs stable packet identifiers",
            "MCU names/layouts are source-table interpretations; running source/build match unverified",
            "unknown boot IDs inferred from clocks are provisional, not kernel boot UUIDs",
        ]
    )


def analyze(
    events: list[Event],
    device_id: str,
    mode: str,
    capture_id: str | None = None,
    collectors: Collectors | None = None,
    device: Device | None = None,
) -> EvidenceReport:
    own = [e for e in events if e.device_id == device_id and not (e.session or "").startswith("replay:")]
    col = collectors or Collectors()
    col.traced_kinds.update(e.kind for e in own if e.kind.startswith("trace."))
    col.tracepoints.update(k[6:].replace(".", ":", 1) for k in col.traced_kinds)
    col.kv_tags.update(tag for e in own if (tag := tag_of(e)) is not None)
    col.log_kinds.update(e.kind for e in own if not e.kind.startswith("trace."))
    epochs = build_epochs(own, device_id, col)
    groups: dict[tuple[str, str | None, str | None, str | None, str | None], list[Event]] = defaultdict(list)
    paths = build_paths(own, device_id)
    generations: dict[tuple[str, str | None, int | None, str | None, str | None], str] = {}
    for e, boot in sorted(
        zip(own, assign_boots(own), strict=True), key=lambda pair: (pair[1], pair[0].ts_boottime_ns)
    ):
        interface, interface_lifetime = event_interface_scope(e)
        ep = next(
            (
                x
                for x in epochs
                if x.boot_id == boot
                and x.interface == interface
                and x.interface_lifetime == interface_lifetime
                and x.start_ns <= e.ts_boottime_ns
                and (x.end_ns is None or e.ts_boottime_ns < x.end_ns)
            ),
            None,
        )
        f = fields_of(e)
        gen = f.get("generation")
        eid = (
            str(e.data.get("association_epoch")) if e.data.get("association_epoch") else ep.id if ep else None
        )
        link = num(f, "link_id")
        if link is None:
            link = num(f, "link")
        if link is None:
            link = num(f, "resolved_link")
        lifetime_key = (boot, eid, link, interface, interface_lifetime)
        if gen:
            generations[lifetime_key] = gen
        groups[
            (boot, eid, generations.get(lifetime_key) if eid else gen, interface, interface_lifetime)
        ].append(e)
    windows = []
    for (boot, eid, gen, interface, interface_lifetime), es in groups.items():
        fw = fwid.analyze(es)
        if any(e.kind.endswith("whd_mcu_transport") for e in es):
            fw.gaps = [
                "only audited transport spans are retained; unknown/security/reserved regions are suppressed",
                "transport responses need matching cookie, attempt, sequence and identity lifetime before establishing per-link programming",
                "loaded module/source binding remains unverified; transport envelopes do not supply association or link lifetimes",
            ]
        channel_history = []
        for event in es:
            f = fields_of(event)
            identity_tag = tag_of(event)
            if identity_tag and fwid.IDENTITY_TAGS.get(identity_tag, {}).get("control_channel") == "channel":
                channel_link, channel = fwid._link_of(f), num(f, "control_channel")
                if channel_link is not None and channel is not None:
                    channel_history.append((event.ts_boottime_ns, channel_link, channel))
        frames = rx.build_frames(es, channel_history=channel_history)
        ep = next((x for x in epochs if x.id == eid), None)
        state = build_state(
            device_id=device_id,
            phy=None,
            boot_id=boot,
            epoch=ep,
            epoch_events=es,
            mask_raw=None,
            mask_read_ns=None,
            link_stats=[],
            wcid_dump=[],
            nl_links=[],
            nl_connected=None,
            sta_authorized=None,
            fw=fw,
            rx_frames=frames,
            woke_device=False,
            sources=["historical events"],
        )
        for link_state in state.links:
            link_state.scope.link_lifetime = gen
            link_state.scope.interface = interface
            link_state.scope.interface_lifetime = interface_lifetime
            for dim in [
                link_state.negotiated,
                link_state.active,
                link_state.fw_programmed,
                link_state.authorized,
                link_state.authenticated_delivery,
            ]:
                dim.historical = True
            proven = [
                p
                for p in paths
                if p.authenticated_delivery is True
                and p.scope.boot_id == boot
                and p.scope.association_epoch == eid
                and p.scope.link_id == link_state.link_id
                and p.scope.link_lifetime == gen
                and p.scope.interface == interface
                and p.scope.interface_lifetime == interface_lifetime
            ]
            if proven:
                link_state.authenticated_delivery = Dimension(
                    value="yes",
                    historical=True,
                    basis=f"{len(proven)} scoped packet(s) with explicit decryption/integrity/replay/channel checks and stack delivery",
                    evidence=[ref for path in proven for obs in path.observations for ref in obs.evidence],
                    limits="collector-reported checks and stable packet identifiers; not proof of concurrent radios",
                )
        windows.append(
            EvidenceWindow(
                scope=Scope(
                    boot_id=boot,
                    device_id=device_id,
                    association_epoch=eid,
                    link_lifetime=gen,
                    interface=interface,
                    interface_lifetime=interface_lifetime,
                ),
                firmware=fw,
                rx_frames=frames,
                rx_summary=rx.summarize(frames),
                state=state,
            )
        )
    payloads = []
    for e in own:
        f = fields_of(e)
        if e.kind.endswith("whd_mcu_tlv") and num(f, "cmd") is not None and num(f, "tag") is not None:
            decoded = decode_tlv(
                num(f, "cmd") or 0,
                num(f, "tag") or 0,
                f.get("hex", ""),
                layout_provenance=e.data.get("layout_provenance")
                if isinstance(e.data.get("layout_provenance"), dict)
                else None,
            )
            decoded.update(event_id=e.id, ts_boottime_ns=e.ts_boottime_ns, cookie=f.get("cookie"))
            payloads.append(decoded)
    protocol: Literal["ordinary", "mlo", "unknown"] = "unknown"
    if device is not None:
        if (device.vendor_id, device.product_id) == (0x14C3, 0x0616):
            protocol = "ordinary"
        elif any(w.mlo_support for w in device.wiphys) or (device.vendor_id, device.product_id) == (
            0x14C3,
            0x7927,
        ):
            protocol = "mlo"
        elif device.wiphys:
            protocol = "ordinary"
    result = EvidenceReport(
        device_id=device_id,
        mode=mode,
        protocol=protocol,
        capture_id=capture_id,
        windows=windows,
        epochs=epochs,
        packets=paths,
        observations=own,
        unassigned_observations=[e for e in events if e.device_id is None],
        unattributed_events=sum(e.device_id is None for e in events),
        mcu_payloads=payloads,
        mcu_transport=[decode_transport(e) for e in own if e.kind.endswith("whd_mcu_transport")],
        decoder_source=mcu_ids().get("source"),
    )
    if protocol == "ordinary":
        for window in result.windows:
            window.state.links = []
        for path in result.packets:
            path.scope.link_id = None
            path.scope.link_lifetime = None
            # A decoded shared-driver link number is not a negotiated MLO link.
            path.authenticated_delivery = None
        for epoch in result.epochs:
            epoch.stages = [s for s in epoch.stages if s.stage != "links_activated"]
            for stage in epoch.stages:
                stage.link_id = None
            epoch.missing = [s for s in epoch.missing if s != "links_activated"]
            epoch.gaps = [g for g in epoch.gaps if g.what != "link activation"]
            epoch.first_missing = epoch.missing[0] if epoch.missing else None
        result.limits.append("ordinary Wi-Fi association; MLO link states and activation are not applicable")
    return result
