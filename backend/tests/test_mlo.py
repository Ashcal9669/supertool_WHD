"""MLO evidence parsers against REAL events captured from a live system (scrubbed; tools/extract_mlo_fixture.py) plus
the hand-built edge cases a live system does not conveniently produce. Real-fixture tests are marked as such."""

from __future__ import annotations

from pathlib import Path

from whd.mlo import fwid, rx
from whd.mlo.mask import decode_active_links
from whd.mlo.models import Epoch
from whd.mlo.state import build_state
from whd.mlo.timeline import Collectors, assign_boots, build_epochs
from whd.model.events import Event

FX = Path(__file__).parent / "fixtures" / "mlo"
DEV = "pci:0000:07:00.0:14c3:7927"


def load(name: str) -> list[Event]:
    return [
        Event.model_validate_json(x) for x in (FX / f"{name}.jsonl").read_text().splitlines() if x.strip()
    ]


def collectors(evs: list[Event]) -> Collectors:
    return Collectors(
        kv_tags={str(e.data["tag"]) for e in evs if e.kind == "driver.kv_trace" and e.data.get("tag")},
        log_kinds={e.kind for e in evs},
        tracepoints={"mt76:mlo_rx", "mt76:mlo_txwi", "mt76:mlo_tx_select"},
        traced_kinds=set(),
    )


# ------------------------------------------------------------------------------------------ packed mask


def test_packed_mask_real_value_0x70006() -> None:
    """REAL value read from a live adapter: active = bits 15:0, valid = bits 31:16 (link 0 valid but NOT active)."""
    d = decode_active_links(0x70006)
    assert (
        d.layout == "packed_active_valid"
        and d.active == [1, 2]
        and d.valid == [0, 1, 2]
        and d.consistent is True
    )


def test_mask_edge_cases_are_unknown_not_guessed() -> None:
    assert decode_active_links(None).active is None
    z = decode_active_links(0)
    assert z.layout == "zero" and z.active is None and z.valid is None
    old = decode_active_links(0x6)  # no upper half: cannot be the packed layout
    assert old.layout == "active_only_unverified" and old.active is None
    bad = decode_active_links(0x20004)  # active link 2 not in valid {1}
    assert bad.consistent is False and any("inconsistent" in n for n in bad.notes)


# ------------------------------------------------------------------------------------------ epochs (real)


def test_real_rejected_then_successful_association_are_separate_epochs() -> None:
    evs = load("assoc_reject_timeout_then_ok")
    eps = build_epochs(evs, DEV, collectors(evs), include_unattributed=True)
    assert [e.outcome for e in eps] == ["timed_out", "associated"]
    first, second = eps
    # every association attempt used a fresh local address: distinct epochs, never merged
    assert first.local_address != second.local_address
    resp = [s.result for s in first.stages if s.stage == "assoc_response"]
    assert resp == ["status=30"] * 3 and any("rejected 3x" in f for f in first.flags)
    # after a rejection later stages are "not reached", not "missing"
    assert first.missing == [] and first.first_missing is None
    # the successful one is missing handshake stages that nothing in this window observed
    assert second.first_missing == "connect_notified" and "port_authorized" in second.missing
    assert all(g.kind in ("no_collector", "not_traced", "absent_while_collected") for g in second.gaps)
    assert {e.boot_id for e in eps} == {eps[0].boot_id} and len(set(assign_boots(evs))) == 1


def test_real_epoch_has_key_install_firmware_results_and_roc_tokens() -> None:
    evs = load("assoc_ok_keys_eapol_links")
    (ep,) = build_epochs(evs, DEV, collectors(evs), include_unattributed=True)
    st = {s.stage for s in ep.stages}
    assert {"key_install_request", "key_install_fw", "roc_request", "roc_grant", "activation_deferred"} <= st
    fwres = [s for s in ep.stages if s.stage == "key_install_fw" and s.stage_class == "firmware_result"]
    assert fwres and all(s.result and s.result.startswith("ret=0") for s in fwres)
    assert {"roc:9", "roc:10"} <= set(ep.request_tokens)
    # request / core completion / firmware result are kept apart
    classes = {s.stage_class for s in ep.stages}
    assert {"queued_request", "core_complete", "firmware_result"} <= classes
    # key material and its fingerprint never appear in stage evidence
    blob = " ".join(x.text for s in ep.stages for x in s.evidence)
    assert "keyfp=0" not in blob.replace("keyfp=<redacted>", "")


def test_stale_association_in_progress_when_watching_began() -> None:
    evs = [
        e
        for e in load("assoc_reject_timeout_then_ok")
        if e.kind not in ("assoc.authenticate", "assoc.auth_tx")
    ]
    eps = build_epochs(evs, DEV, collectors(evs))
    assert any(not e.started_observed and any("already in progress" in f for f in e.flags) for e in eps)


def test_boots_are_never_merged() -> None:
    a = load("assoc_reject_timeout_then_ok")[:40]
    b = []
    for e in load("assoc_reject_timeout_then_ok")[:40]:
        e2 = e.model_copy(deep=True)
        e2.ts_wall += 36000.0  # same boot-relative times, wall clock 10 h later: a different boot
        e2.ts_raw = None
        b.append(e2)
    ids = assign_boots(a + b)
    assert len(set(ids[:40])) == 1 and len(set(ids[40:])) == 1 and ids[0] != ids[-1]


def test_unattributed_lines_are_flagged_when_included() -> None:
    evs = load("assoc_ok_keys_eapol_links")
    (ep,) = build_epochs(evs, DEV, collectors(evs), include_unattributed=True)
    assert any("unattributed" in f for f in ep.flags)
    (ep2,) = build_epochs(evs, DEV, collectors(evs), include_unattributed=False)
    assert not any("unattributed" in f for f in ep2.flags)


def test_delayed_association_notification_is_flagged() -> None:
    evs = load("assoc_ok_keys_eapol_links")
    resp = next(e for e in evs if e.kind == "assoc.assoc_resp")
    done = next(e for e in evs if e.kind == "assoc.associated")
    done.ts_boottime_ns = resp.ts_boottime_ns + 900_000_000
    (ep,) = build_epochs(evs, DEV, collectors(evs))
    assert any("delayed association notification" in f for f in ep.flags)


# ------------------------------------------------------------------------------------------ firmware identity (real)


def test_real_firmware_ops_are_decoded_from_the_header_tables() -> None:
    rep = fwid.analyze(load("assoc_ok_keys_eapol_links"))
    names = {o.cmd_name for o in rep.ops}
    assert {"BSS_INFO_UPDATE", "DEV_INFO_UPDATE"} <= names
    assert all(o.status == "ok" and o.duration_us and o.token.startswith("0x2000") for o in rep.ops)
    assert all(o.bytes_available is False for o in rep.ops) and any("command bytes" in g for g in rep.gaps)
    ident = {lk.link_id: lk.current for lk in rep.links}
    assert ident[1]["channel"] == 40 and ident[1]["freq_mhz"] == 5200 and ident[1]["sta_state"] == 2
    # the broadcast station entry is not mistaken for the peer changing identity
    assert not any("wcid changed" in f for f in rep.flags)


def test_real_peer_lifecycle_generation_and_missing_member() -> None:
    rep = fwid.analyze(load("rx_remap_peer_lifecycle"))
    assert rep.generations and set(rep.generations) == {2}
    assert any("missing member" in f for f in rep.flags)


def test_stale_and_recreated_peer_and_incomplete_command() -> None:
    evs = []
    for i, (tag, fields) in enumerate(
        [
            ("MLO_MCU_SEND_START", "cmd=0x20003 link=1 t=100"),
            ("MLO_FW_PEER_LIFECYCLE", "generation=3 stage=a link_id=1 wcid=1 ret=0"),
            ("MLO_FW_PEER_LIFECYCLE", "generation=2 stage=b link_id=1 wcid=1 ret=0"),
            ("MLO_FW_PEER_LIFECYCLE", "generation=4 stage=c link_id=1 wcid=1 ret=0"),
            ("MLO_WCID_LIFE", "stage=add_alloc link=1"),
            ("MLO_WCID_LIFE", "stage=add_alloc link=1"),
        ]
    ):
        kv = dict(p.split("=") for p in fields.split())
        evs.append(
            Event(
                id=i + 1,
                ts_boottime_ns=1000 + i,
                ts_source="recorded",
                ts_wall=1.0,
                source="t",
                category="mlo",
                kind="driver.kv_trace",
                summary=tag,
                explanation="x",
                raw=tag,
                data={"tag": tag, "fields": kv},
            )
        )
    flags = " | ".join(fwid.analyze(evs).flags)
    assert "stale peer-lifecycle event: generation 2 after 3" in flags
    assert "peer recreated: generation 3 -> 4" in flags or "peer recreated: generation 2 -> 4" in flags
    assert "allocated 2x" in flags and "never completed" in flags


# ------------------------------------------------------------------------------------------ RX evidence (real)


def test_real_rx_frames_separate_descriptor_from_resolved_link() -> None:
    frames = rx.build_frames(load("rx_remap_peer_lifecycle"), {1: 40, 2: 69})
    assert len(frames) == 36
    f = frames[0]
    assert (f.desc_band, f.wcid_band, f.resolved_link, f.remap_to_link) == (1, 0, 1, -1)
    assert f.verdict == "security_checked_adjacent" and f.channel_matches is True and f.pn_ok_reported
    s = rx.summarize(frames)
    assert s.remap_none == 36 and any("no candidate link" in x for x in s.flags)


def test_frame_on_another_links_channel_does_not_prove_the_link_works() -> None:
    """False link attribution: the same real frames, but the intended link is on a different channel."""
    frames = rx.build_frames(load("rx_remap_peer_lifecycle"), {1: 69})
    assert {f.verdict for f in frames} == {"wrong_channel_for_link"}
    assert rx.summarize(frames).authenticated_by_link == {}
    assert all(any("cannot show that link works" in n for n in f.notes) for f in frames)


def test_unknown_link_channel_is_reported_not_assumed() -> None:
    frames = rx.build_frames(load("rx_remap_peer_lifecycle"), {})
    assert frames[0].channel_matches is None and any("channel is unknown" in n for n in frames[0].notes)


# ------------------------------------------------------------------------------------------ per-link state


def _epoch(evs: list[Event]) -> Epoch:
    return build_epochs(evs, DEV, collectors(evs))[-1]


def test_state_keeps_five_dimensions_apart_and_never_marks_active_from_iw() -> None:
    evs = load("rx_remap_peer_lifecycle")
    st = build_state(
        device_id=DEV,
        phy="phyX",
        boot_id="b",
        epoch=None,
        epoch_events=evs,
        mask_raw=0x70006,
        mask_read_ns=5,
        link_stats=[
            {"wcid": 1, "link": 2, "valid": True, "rx_pkts": 9671, "tx_pkts": 7, "rx_bytes": 1, "tx_bytes": 1}
        ],
        wcid_dump=[],
        nl_links=[{"link_id": i, "freq_mhz": f} for i, f in ((0, None), (1, 5200), (2, 6295))],
        nl_connected=True,
        sta_authorized=None,
        fw=fwid.analyze(evs),
        rx_frames=rx.build_frames(evs, {1: 40, 2: 69}),
        woke_device=True,
        sources=["debugfs", "nl80211"],
    )
    by = {ln.link_id: ln for ln in st.links}
    assert (
        by[0].negotiated.value == "yes" and by[0].active.value == "no"
    )  # valid, listed by nl80211, not active
    assert by[0].conflicts and "not active" in by[0].conflicts[0]
    assert by[1].active.value == "yes" and by[2].active.value == "yes"
    # link 2 only has a pre-security counter: DRIVER_ONLY, never YES
    assert by[2].authenticated_delivery.value == "driver_only"
    assert by[2].conflicts and "no authenticated frame" in by[2].conflicts[-1]
    # link 1 has traced, decrypted frames on its own channel
    assert by[1].authenticated_delivery.value == "driver_only" and by[1].authenticated_delivery.historical
    assert st.perturbations and "wakes the chip" in st.perturbations[0]
    assert all(ln.scope.device_id == DEV and ln.scope.boot_id == "b" for ln in st.links)


def test_state_without_readable_mask_shows_unknown_and_marks_logged_values_historical() -> None:
    evs = load("assoc_ok_keys_eapol_links")
    ep = _epoch(evs)
    st = build_state(
        device_id=DEV,
        phy=None,
        boot_id="b",
        epoch=ep,
        epoch_events=evs,
        mask_raw=None,
        mask_read_ns=None,
        link_stats=[],
        wcid_dump=[],
        nl_links=[{"link_id": 0}, {"link_id": 1}, {"link_id": 2}],
        nl_connected=True,
        sta_authorized=None,
        fw=fwid.analyze(evs),
        rx_frames=[],
        woke_device=False,
        sources=["nl80211"],
    )
    by = {ln.link_id: ln for ln in st.links}
    assert st.mask.layout == "unreadable" and st.mask.active is None
    # the logged active_links=0x2 is shown, flagged historical, and link 0/2 are not claimed active
    assert by[1].active.value == "yes" and by[1].active.historical
    assert by[2].active.value == "no" and by[2].active.historical
    assert by[1].authenticated_delivery.value == "unknown"


def test_fresh_disconnect_overrides_old_authorized_epoch_and_retained_mask() -> None:
    evs = load("assoc_ok_keys_eapol_links")
    st = build_state(
        device_id=DEV,
        phy="phyX",
        boot_id="b",
        epoch=_epoch(evs),
        epoch_events=evs,
        mask_raw=0x70006,
        mask_read_ns=5,
        link_stats=[],
        wcid_dump=[],
        nl_links=[{"link_id": 1}],
        nl_connected=False,
        sta_authorized=None,
        fw=fwid.analyze(evs),
        rx_frames=[],
        woke_device=False,
        sources=["nl80211"],
    )
    assert st.mac80211_authorized is False
    assert all(
        link.active.value == "no" and link.negotiated.value == "no" and link.authorized.value == "no"
        for link in st.links
    )
    assert all(link.fw_programmed.value == "unknown" for link in st.links)


def test_interface_lifetimes_split_association_epochs() -> None:
    evs = load("assoc_reject_timeout_then_ok")
    first = evs[0].model_copy(deep=True)
    first.kind = "assoc.associated"
    first.data = {"boot_id": "boot-a", "ifname": "wifi-a", "wdev": 1}
    second = first.model_copy(deep=True)
    second.ts_boottime_ns += 1
    second.data = {"boot_id": "boot-a", "ifname": "wifi-a", "wdev": 2}
    epochs = build_epochs([first, second], DEV, collectors([first, second]), include_unattributed=True)
    assert len(epochs) == 2
    assert epochs[0].id != epochs[1].id
    assert {e.interface_lifetime for e in epochs} == {"wdev:1", "wdev:2"}
