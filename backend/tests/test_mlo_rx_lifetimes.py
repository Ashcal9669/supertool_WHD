"""Recorded MT7927 observations plus edge cases matched to mt7925/mac.c log ordering."""

from pathlib import Path

import pytest

from test_mlo_safety import event
from whd.mlo.rx import build_frames, summarize
from whd.model.events import Event


def lines():
    es = [
        event(
            1,
            tag="MLO_RX_UNICAST_TRACE",
            fw_idx="1",
            resolved_wcid="1",
            resolved_link="1",
            chfreq="40",
            packet_id="p",
        ),
        event(
            2,
            tag="MLO_RX_BAND_REMAP",
            fw_idx="1",
            desc_band="1",
            wcid_band="0",
            from_link="1",
            to_link="2",
            packet_id="p",
        ),
        event(
            3,
            tag="MLO_RX_DECRYPT_TRACE",
            wcid="9",
            link="2",
            decrypted="1",
            sec_mode="4",
            icv_err="0",
            fcs_err="0",
            tkip_mic_err="0",
            packet_id="p",
        ),
        event(4, tag="MLO_RX_PN_OK", wcid="9", link="2", packet_id="p", pn="000000000001"),
    ]
    for e in es:
        e.data.update(boot_id="boot-a", association_epoch="assoc-a", ifname="wlan0", wdev="0x1")
        e.data["fields"]["generation"] = "7"
    return es


def test_successful_remap_preserves_initial_owner_and_final_resolution():
    fr = build_frames(lines(), {1: 69, 2: 40})[0]
    assert (fr.fw_idx, fr.desc_band, fr.wcid_band) == (1, 1, 0)
    assert (fr.initial_wcid, fr.initial_link, fr.resolved_wcid, fr.resolved_link) == (1, 1, 9, 2)
    assert fr.channel_matches is True and fr.pn_ok_reported
    assert fr.verdict == "authenticated" and fr.delivered is False


@pytest.mark.parametrize("change", ["ifname", "wdev", "generation", "association_epoch", "boot_id"])
def test_security_continuations_never_cross_lifetime(change):
    es = lines()
    es[1].data["fields"]["to_link"] = "-1"
    for e in es[2:]:
        e.data["fields"].update(wcid="1", link="1")
        (e.data["fields"] if change == "generation" else e.data)[change] = "other"
    fr = build_frames(es, {1: 40})[0]
    assert fr.decrypted is None and not fr.pn_ok_reported


def test_boot_in_ts_raw_is_a_real_boundary():
    es = lines()
    for e in es:
        e.data.pop("boot_id")
        e.ts_raw = "(boot aaaaaaaa)"
    es[2].ts_raw = "(boot bbbbbbbb)"
    assert build_frames(es, {2: 40})[0].decrypted is None


@pytest.mark.parametrize("identity", ["packet_id", "skbaddr"])
def test_identifier_must_be_present_on_both_sides_in_same_namespace(identity):
    es = lines()
    for e in es:
        e.data["fields"].pop("packet_id")
    es[2].data["fields"][identity] = "p"
    assert build_frames(es, {2: 40})[0].decrypted is None


def test_missing_error_bits_are_unknown_not_security_success():
    es = lines()
    es[2].data["fields"].pop("icv_err")
    fr = build_frames(es, {2: 40})[0]
    assert fr.authenticated is None
    assert summarize([fr]).authenticated_by_link == {}


def test_pn_drop_is_retained_and_overrides_decryption():
    es = lines()
    es[3].data["tag"] = "MLO_RX_PN_DROP"
    fr = build_frames(es, {2: 40})[0]
    assert fr.verdict == "replay_drop" and fr.pn_drop_reported
    assert summarize([fr]).authenticated_by_link == {}
    assert [r.event_id for r in fr.evidence] == [1, 2, 3, 4]


def test_remap_with_other_raw_index_is_not_attributed():
    es = lines()
    es[1].data["fields"]["fw_idx"] = "88"
    fr = build_frames(es, {1: 40})[0]
    assert fr.desc_band is None and fr.decrypted is None


def test_real_mt7927_fixture_never_promotes_adjacency_to_delivery():
    path = Path(__file__).parent / "fixtures/mlo/rx_remap_peer_lifecycle.jsonl"
    es = [Event.model_validate_json(line) for line in path.read_text().splitlines()]
    frames = build_frames(es, {1: 40, 2: 69})
    assert len(frames) == 36
    assert all(
        (fr.fw_idx, fr.desc_band, fr.wcid_band, fr.resolved_link, fr.remap_to_link) == (1, 1, 0, 1, -1)
        for fr in frames
    )
    assert all(fr.verdict == "security_checked_adjacent" and not fr.delivered for fr in frames)
    summary = summarize(frames)
    assert summary.authenticated_by_link == {}
    assert "complete packet-scoped" in " ".join(summary.flags)


def test_ifindex_is_not_authenticated_interface_lifetime_proof():
    es = lines()
    for e in es:
        e.data.pop("wdev")
        e.data["ifindex"] = 3
    fr = build_frames(es, {2: 40})[0]
    assert fr.verdict != "authenticated"
    assert any("incarnation" in note for note in fr.notes)


def test_replay_line_before_decryption_cannot_prove_completion():
    es = lines()
    es.pop(1)
    es[0].data["fields"].update(resolved_link="2", resolved_wcid="9")
    es[2].ts_boottime_ns = es[1].ts_boottime_ns - 1
    assert build_frames(es, {2: 40})[0].verdict != "authenticated"


def test_conflicting_duplicate_decrypt_line_cannot_be_silently_discarded():
    es = lines()
    second = es[2].model_copy(deep=True)
    second.id = 5
    second.ts_boottime_ns += 1
    second.data["fields"]["icv_err"] = "1"
    fr = build_frames([*es, second], {2: 40})[0]
    assert fr.verdict != "authenticated"


def test_interleaved_interfaces_do_not_lose_or_mix_frame_security():
    a, b = lines(), lines()
    for e in b:
        e.id += 10
        e.ts_boottime_ns += 1
        e.data.update(ifname="wlan1", wdev="0x2")
    frames = build_frames([*a, *b])
    assert [[r.event_id for r in fr.evidence] for fr in frames] == [[1, 2, 3, 4], [11, 12, 13, 14]]


def test_unscoped_channel_map_cannot_authenticate_multiple_interfaces():
    a, b = lines(), lines()
    for e in b:
        e.id += 10
        e.ts_boottime_ns += 1
        e.data.update(ifname="wlan1", wdev="0x2")
    assert summarize(build_frames([*a, *b], {2: 40})).authenticated_by_link == {}


def test_unknown_incarnations_do_not_erase_observed_interface_separation():
    es = lines()
    for e in es:
        e.data.pop("wdev")
    es[2].data["ifname"] = "wlan1"
    assert build_frames(es, {2: 40})[0].decrypted is None
