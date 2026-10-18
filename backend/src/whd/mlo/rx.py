"""RX evidence: what the descriptor said, what the driver resolved, what the security checks reported.

The driver's printk sequence has no packet identifier, so its adjacency joins are provisional,
bounded by JOIN_NS and observed boot/interface/generation/CPU identity. Initial WCID resolution
is kept apart from final remapping. The optional 0002 descriptor/boundary hooks use scoped skb
identity and retain raw words/flags without decoding source-dependent bits. Neither printk
decryption nor a PN/mac80211 hook alone proves authenticated network-stack delivery.
"""

from __future__ import annotations

from collections import Counter

from pydantic import Field

from whd.mlo.kv import fields_of, num, tag_of, trace_name
from whd.mlo.lifetime import event_interface_scope
from whd.mlo.models import EvidenceRef
from whd.mlo.packets import interface_label, packet_identity, strong_interface_lifetime
from whd.mlo.rx_layout import DescriptorDecode, decode_descriptor
from whd.mlo.timeline import assign_boots, boot_of, ref
from whd.model.common import Model
from whd.model.events import Event

JOIN_NS = 2_000_000  # lines of one frame are printed within microseconds; 2 ms is a generous bound

RX_TAGS = (
    "MLO_RX_UNICAST_TRACE",
    "MLO_RX_BAND_REMAP",
    "MLO_RX_DECRYPT_TRACE",
    "MLO_RX_PN_OK",
    "MLO_RX_PN_DROP",
)


class RxFrame(Model):
    ts_boottime_ns: int
    device_id: str | None = None
    boot_id: str | None = None
    explicit_boot: bool = False
    interface: str | None = None
    interface_lifetime: str | None = None
    observed_interface: str | None = None
    skbaddr: str | None = None
    raw_descriptor_words: dict[str, str] = Field(default_factory=dict)
    descriptor_decode: DescriptorDecode | None = None
    boundary_observations: list[dict[str, str]] = Field(default_factory=list)
    freq_mhz: int | None = None  # explicitly emitted status frequency, not decoded from descriptor words
    flags: str | None = None  # raw status flags; meanings require an exact source/build binding
    mac80211_rx_reported: bool = False
    association_epoch: str | None = None
    link_lifetime: str | None = None
    # raw descriptor ownership, as the hardware reported it
    fw_idx: int | None = None
    desc_band: int | None = None
    wcid_band: int | None = None
    initial_wcid: int | None = None
    initial_link: int | None = None
    # what the driver resolved
    resolved_wcid: int | None = None
    resolved_link: int | None = None
    chfreq: int | None = None  # the channel field printed with the frame (a channel number, not a frequency)
    remap_from_link: int | None = None
    remap_to_link: int | None = None  # -1 = no candidate link was found for the descriptor's band
    # security checks the driver reported
    sec_mode: int | None = None
    decrypted: bool | None = None
    icv_err: int | None = None
    fcs_err: int | None = None
    tkip_mic_err: int | None = None
    pn_ok_reported: bool = False
    pn_drop_reported: bool = False
    pn: str | None = None
    # judgement
    expected_channel: int | None = None
    channel_matches: bool | None = None  # None = the link's channel is unknown
    authenticated: bool | None = None  # None = security result not reported
    verdict: str
    packet_id: str | None = None
    delivered: bool = False
    join_ambiguous: bool = False
    notes: list[str] = Field(default_factory=list)
    join_basis: str = "adjacent driver log lines (no packet identifier available)"
    evidence: list[EvidenceRef] = Field(default_factory=list)


class RxSummary(Model):
    frames: int
    by_resolved_link: dict[str, int]
    verdicts: dict[str, int]
    authenticated_by_link: dict[str, int]  # decrypted, no errors, channel not contradicting
    remap_none: int  # descriptor band had no candidate link
    flags: list[str]
    note: str


def build_frames(
    events: list[Event],
    link_channels: dict[int, int] | None = None,
    channel_history: list[tuple[int, int, int]] | None = None,
) -> list[RxFrame]:
    """`link_channels`: channel number per link id, from whatever the caller knows now (nl80211 / firmware tags)."""
    link_channels = link_channels or {}
    boots = assign_boots(events)
    evs = sorted(
        (
            (e, boot)
            for e, boot in zip(events, boots, strict=True)
            if tag_of(e) in RX_TAGS or trace_name(e) in ("whd_rx_descriptor", "whd_rx_boundary")
        ),
        key=lambda pair: (pair[1], pair[0].ts_boottime_ns),
    )
    frames: list[RxFrame] = []
    pending: dict[tuple[str | None, ...], RxFrame] = {}

    def finish(fr: RxFrame) -> RxFrame:
        channels = dict(link_channels)
        if channel_history is not None:
            channels = {}
            for ts, link, channel in sorted(channel_history):
                if ts <= fr.ts_boottime_ns:
                    channels[link] = channel
        # Channel inputs have no scope fields; a caller must partition them with the frame events.
        if len(channel_scopes) > 1:
            channels = {}
        return _finish(fr, channels)

    for e, boot in evs:
        t = tag_of(e) or trace_name(e)
        f = fields_of(e)
        ts = e.ts_boottime_ns
        interface, lifetime = event_interface_scope(e)
        label = interface_label(e)
        epoch = e.data.get("association_epoch", f.get("association_epoch"))
        generation = e.data.get("generation", f.get("generation"))
        epoch = str(epoch) if epoch is not None else None
        generation = str(generation) if generation is not None else None
        namespace, pid = packet_identity(f)
        cpu = e.data.get("cpu", f.get("cpu"))
        scope = (
            e.device_id,
            boot,
            interface,
            lifetime,
            label,
            epoch,
            generation,
            str(cpu) if cpu is not None else None,
            namespace,
            pid,
        )
        cur = pending.get(scope)
        orphan_boundary = t == "whd_rx_boundary" and (
            cur is None or ts - cur.ts_boottime_ns > JOIN_NS or pid is None
        )
        if t in ("MLO_RX_UNICAST_TRACE", "whd_rx_descriptor") or orphan_boundary:
            cur = RxFrame(
                ts_boottime_ns=ts,
                device_id=e.device_id,
                boot_id=boot,
                explicit_boot=boot_of(e) is not None,
                interface=interface,
                interface_lifetime=lifetime,
                observed_interface=label,
                skbaddr=pid if namespace == "skb" else None,
                raw_descriptor_words={k: f[k] for k in ("rxd0", "rxd1", "rxd2", "rxd3", "rxd4") if k in f}
                if t == "whd_rx_descriptor"
                else {},
                association_epoch=epoch,
                link_lifetime=generation,
                fw_idx=num(f, "fw_idx"),
                initial_wcid=num(f, "resolved_wcid"),
                initial_link=num(f, "resolved_link"),
                resolved_wcid=num(f, "resolved_wcid"),
                resolved_link=num(f, "resolved_link"),
                chfreq=num(f, "chfreq"),
                verdict="incomplete",
                evidence=[] if orphan_boundary else [ref(e)],
                packet_id=pid if namespace == "packet_id" else None,
                join_basis=f"same {namespace} identifier within boot/interface/association/generation"
                if pid
                else "adjacent driver log lines (no packet identifier available)",
            )
            frames.append(cur)
            pending[scope] = cur
            if t == "whd_rx_descriptor":
                cur.descriptor_decode = decode_descriptor(
                    cur.raw_descriptor_words, layout_provenance=e.data.get("layout_provenance")
                )
                # Only raw ownership/metadata populate these fields. Security checks stay distinct below.
                df = cur.descriptor_decode.fields
                for name in ("fw_idx", "desc_band", "sec_mode", "chfreq"):
                    value = df.get(name)
                    if isinstance(value, int):
                        setattr(cur, name, value)
            if not orphan_boundary:
                continue
        if cur is None or ts - cur.ts_boottime_ns > JOIN_NS:
            continue  # a continuation line with no frame start inside the join window is not attributed
        if t == "whd_rx_boundary":
            # The 0002 layout emits these values directly. No descriptor/status bit masks are decoded.
            cur.boundary_observations.append(dict(f))
            cur.evidence.append(ref(e))
            wcid, link = num(f, "wcid"), num(f, "link")
            wcid = wcid if wcid is not None and wcid >= 0 else None
            link = link if link is not None and link >= 0 else None
            if (cur.resolved_wcid is not None and wcid != cur.resolved_wcid) or (
                cur.resolved_link is not None and link != cur.resolved_link
            ):
                cur.join_ambiguous = True
            else:
                cur.resolved_wcid, cur.resolved_link = wcid, link
            cur.freq_mhz, cur.flags = num(f, "freq"), f.get("flags")
            phase = f.get("stage")
            cur.pn_ok_reported |= phase == "pn_ok"
            cur.pn_drop_reported |= phase == "pn_drop"
            cur.mac80211_rx_reported |= phase == "mac80211_rx"
            if phase == "mac80211_rx":
                pending.pop(scope, None)  # source hook is before RX conversion; no stack delivery claim
        elif t == "MLO_RX_BAND_REMAP":
            if num(f, "fw_idx") != cur.fw_idx or num(f, "from_link") != cur.initial_link:
                continue
            cur.desc_band, cur.wcid_band = num(f, "desc_band"), num(f, "wcid_band")
            cur.remap_from_link, cur.remap_to_link = num(f, "from_link"), num(f, "to_link")
            if cur.remap_to_link is not None and cur.remap_to_link >= 0:
                cur.resolved_link = cur.remap_to_link
                # The remap line has no final WCID; only a matching decrypt line can provide it.
                cur.resolved_wcid = None
            cur.evidence.append(ref(e))
        elif t == "MLO_RX_DECRYPT_TRACE":
            wcid, link = num(f, "wcid"), num(f, "link")
            if wcid is None or (cur.resolved_wcid is not None and wcid != cur.resolved_wcid):
                continue
            if link is not None and link != cur.resolved_link:
                continue
            if cur.resolved_wcid is None and (link is None or cur.remap_to_link != link):
                continue
            if cur.decrypted is not None:
                cur.join_ambiguous = True
                cur.evidence.append(ref(e))
                continue  # duplicate lines may describe another frame; never overwrite an error
            cur.resolved_wcid = wcid
            cur.sec_mode = num(f, "sec_mode")
            cur.icv_err, cur.fcs_err, cur.tkip_mic_err = (
                num(f, "icv_err"),
                num(f, "fcs_err"),
                num(f, "tkip_mic_err"),
            )
            d = num(f, "decrypted")
            cur.decrypted = bool(d) if d in (0, 1) else None
            cur.evidence.append(ref(e))
        elif t in ("MLO_RX_PN_OK", "MLO_RX_PN_DROP"):
            if t == "MLO_RX_PN_OK" and cur.decrypted is None:
                continue  # replay acceptance before the decrypt observation is not the source sequence
            if cur.resolved_wcid is None or num(f, "wcid") != cur.resolved_wcid:
                continue
            link = num(f, "link")
            if link is not None and link != cur.resolved_link:
                continue
            cur.pn_ok_reported |= t == "MLO_RX_PN_OK"
            cur.pn_drop_reported |= t == "MLO_RX_PN_DROP"
            cur.pn = f.get("pn")
            cur.evidence.append(ref(e))
            if pid is None:
                pending.pop(scope, None)  # a second PN result cannot belong to the same id-less frame
    channel_scopes = {
        (
            fr.device_id,
            fr.boot_id,
            fr.interface,
            fr.interface_lifetime,
            fr.observed_interface,
            fr.association_epoch,
            fr.link_lifetime,
        )
        for fr in frames
    }
    return [finish(fr) for fr in frames]


def _finish(fr: RxFrame, link_channels: dict[int, int]) -> RxFrame:
    notes: list[str] = []
    if fr.raw_descriptor_words or fr.boundary_observations:
        notes.append(
            "0002 hook layout: descriptor bit decoding requires matching explicit archived layout provenance; "
            "status flags remain raw; running source/build match unverified"
        )
        if fr.descriptor_decode is not None:
            notes.extend(fr.descriptor_decode.limits)
        if not fr.raw_descriptor_words:
            notes.append("partial RX boundary without a correlated descriptor inside the lifetime/window")
        if fr.mac80211_rx_reported:
            notes.append(
                "mac80211_rx hook precedes RX conversion/ieee80211_rx_list; it does not prove stack delivery"
            )
    if fr.resolved_link is not None and fr.resolved_link in link_channels:
        fr.expected_channel = link_channels[fr.resolved_link]
        if fr.chfreq is not None:
            fr.channel_matches = fr.chfreq == fr.expected_channel
    errs = [x for x in (fr.icv_err, fr.fcs_err, fr.tkip_mic_err) if x]
    complete_errors = all(x is not None for x in (fr.icv_err, fr.fcs_err, fr.tkip_mic_err))
    if fr.pn_drop_reported:
        fr.authenticated = False
        notes.append("driver rejected the replay/PN check; decryption does not establish authentication")
    elif fr.decrypted is False or errs:
        fr.authenticated = False
    elif fr.decrypted is None or not complete_errors:
        fr.authenticated = None
    else:
        fr.authenticated = fr.decrypted and not errs
    if fr.remap_to_link == -1:
        notes.append(
            f"driver's band remap found no candidate link for descriptor band {fr.desc_band} "
            f"(station entry band {fr.wcid_band}); the frame stayed on link {fr.remap_from_link}"
        )
    elif fr.remap_to_link is not None and fr.remap_from_link not in (None, fr.remap_to_link):
        notes.append(
            f"driver moved the frame from link {fr.remap_from_link} to link {fr.remap_to_link} by band"
        )
    if fr.desc_band is not None and fr.wcid_band is not None and fr.desc_band != fr.wcid_band:
        notes.append("the descriptor's band differs from the band of the station entry it was attributed to")
    if fr.channel_matches is False:
        notes.append(
            f"frame channel {fr.chfreq} is not link {fr.resolved_link}'s channel {fr.expected_channel}: it cannot "
            "show that link works"
        )
    if fr.channel_matches is None and fr.expected_channel is None:
        notes.append("the intended link's channel is unknown, so the channel could not be compared")
    if errs:
        notes.append(f"security errors reported (icv={fr.icv_err} fcs={fr.fcs_err} mic={fr.tkip_mic_err})")
    if fr.decrypted is False and fr.sec_mode not in (None, 0):
        notes.append("security mode is set but the frame was not decrypted")
    if not strong_interface_lifetime(fr.interface_lifetime):
        notes.append("interface incarnation is unknown; ifindex alone can be reused within a boot")
    if fr.pn_drop_reported:
        fr.verdict = "replay_drop"
    elif fr.join_ambiguous:
        fr.verdict = "ambiguous_join"
        notes.append("multiple decrypt observations cannot establish a unique frame lineage")
    elif fr.channel_matches is False:
        fr.verdict = "wrong_channel_for_link"
    elif errs:
        fr.verdict = "security_error"
    elif (
        fr.authenticated is True
        and fr.channel_matches is True
        and fr.pn_ok_reported
        and fr.packet_id
        and fr.explicit_boot
        and fr.device_id is not None
        and fr.interface is not None
        and strong_interface_lifetime(fr.interface_lifetime)
        and fr.association_epoch is not None
        and fr.link_lifetime is not None
        and fr.resolved_link is not None
        and fr.resolved_link >= 0
        and fr.remap_to_link != -1
        and all(x == 0 for x in (fr.icv_err, fr.fcs_err, fr.tkip_mic_err))
    ):
        fr.verdict = "authenticated"
    elif fr.authenticated is True:
        fr.verdict = "security_checked_adjacent"
        notes.append(
            "adjacent lines lack a stable packet identifier or complete channel/security/replay evidence"
        )
    elif fr.authenticated is False:
        fr.verdict = "not_decrypted" if fr.decrypted is False else "security_error"
    else:
        fr.verdict = "unverified"
    fr.notes = notes
    return fr


def summarize(frames: list[RxFrame]) -> RxSummary:
    by_link: Counter[str] = Counter()
    auth: Counter[str] = Counter()
    verdicts: Counter[str] = Counter()
    none = 0
    for fr in frames:
        key = str(fr.resolved_link) if fr.resolved_link is not None else "unresolved"
        by_link[key] += 1
        verdicts[fr.verdict] += 1
        if fr.verdict == "authenticated":
            auth[key] += 1
        if fr.remap_to_link == -1:
            none += 1
    flags: list[str] = []
    if frames and none == len(frames):
        flags.append(
            "every frame's band remap found no candidate link: the link attribution comes only from the station "
            "entry the hardware matched, not from a band check"
        )
    wrong = verdicts.get("wrong_channel_for_link", 0)
    if wrong:
        flags.append(f"{wrong} frame(s) arrived on a channel that is not their resolved link's channel")
    if frames and not auth:
        flags.append(
            "no frame has complete packet-scoped channel/security/replay evidence; counters alone do not prove delivery"
        )
    return RxSummary(
        frames=len(frames),
        by_resolved_link=dict(by_link),
        verdicts=dict(verdicts),
        authenticated_by_link=dict(auth),
        remap_none=none,
        flags=flags,
        note="Frames use an identifier when present, otherwise bounded log adjacency. 'authenticated' requires "
        "packet-scoped boot/interface/association/generation, matching channel, decryption, zero ICV/FCS/MIC errors "
        "and replay success. Delivery to the network stack is a separate stage and is not inferred here.",
    )
