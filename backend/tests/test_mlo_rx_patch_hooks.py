"""Synthetic layout-source fixtures shaped like docs/patches/0002; NOT hardware captures.

The patch records rxd0..4 before validation and emits PN/mac80211 boundaries with
status WCID/link/frequency/flags. It has no interface lifetime or security-bit decoder.
"""

import pytest

from test_mlo_safety import event
from whd.mlo.packets import build_paths
from whd.mlo.rx import JOIN_NS, build_frames, summarize


def descriptor(n=1):
    return event(
        n,
        kind="trace.mt76.whd_rx_descriptor",
        skbaddr="0x123",
        rxd0="0xdeadbeef",
        rxd1="0x12345678",
        rxd2="0x90abcdef",
        rxd3="0x40000000",
        rxd4="0xffffffff",
    )


def boundary(n, stage, **fields):
    return event(
        n,
        kind="trace.mt76.whd_rx_boundary",
        skbaddr="0x123",
        stage=stage,
        wcid="9",
        link="2",
        freq="5975",
        flags="0x12340000",
        **fields,
    )


def test_patch_descriptor_and_boundaries_produce_visible_partial_raw_frame():
    es = [descriptor(), boundary(2, "pn_ok"), boundary(3, "mac80211_rx")]
    # Synthetic collector envelope, not fields emitted by the patch or a live build assertion.
    for e in es:
        e.data.update(ifname="wlan0", wdev="0x1", generation="7", boot_id="a", association_epoch="epoch")
    frames = build_frames(es)
    assert len(frames) == 1
    fr = frames[0]
    assert fr.raw_descriptor_words == {
        "rxd0": "0xdeadbeef",
        "rxd1": "0x12345678",
        "rxd2": "0x90abcdef",
        "rxd3": "0x40000000",
        "rxd4": "0xffffffff",
    }
    assert (fr.skbaddr, fr.resolved_wcid, fr.resolved_link, fr.freq_mhz, fr.flags) == (
        "0x123",
        9,
        2,
        5975,
        "0x12340000",
    )
    assert fr.fw_idx is None and fr.desc_band is None and fr.chfreq is None
    assert fr.decrypted is None and fr.authenticated is None and not fr.delivered
    assert fr.pn_ok_reported and fr.mac80211_rx_reported
    assert [r.event_id for r in fr.evidence] == [1, 2, 3]
    assert len(fr.boundary_observations) == 2
    assert "unverified" in " ".join(fr.notes)
    assert summarize(frames).authenticated_by_link == {}
    assert not any(p.authenticated_delivery for p in build_paths(es, "device-a"))


def test_patch_pn_drop_does_not_turn_following_mac80211_call_into_delivery():
    fr = build_frames([descriptor(), boundary(2, "pn_drop"), boundary(3, "mac80211_rx")])[0]
    assert fr.pn_drop_reported and fr.mac80211_rx_reported
    assert fr.verdict == "replay_drop" and fr.delivered is False
    assert fr.boundary_observations[0]["flags"] == "0x12340000"


@pytest.mark.parametrize("identity", ["ifname", "wdev", "generation", "boot_id", "association_epoch"])
def test_patch_boundary_must_not_enrich_another_interface_or_generation(identity):
    a, b = descriptor(), boundary(2, "pn_ok")
    for e in (a, b):
        e.data.update(ifname="wlan0", wdev="0x1", generation="7", boot_id="a", association_epoch="epoch")
    b.data[identity] = "other"
    frames = build_frames([a, b])
    assert len(frames) == 2
    assert frames[0].resolved_wcid is None and not frames[0].pn_ok_reported
    assert frames[1].raw_descriptor_words == {}


def test_reused_patch_skb_and_expired_join_window_start_partial_frames():
    es = [descriptor(), boundary(2, "pn_ok"), descriptor(3), boundary(4, "pn_drop")]
    frames = build_frames(es)
    assert len(frames) == 2
    assert frames[0].pn_ok_reported and not frames[0].pn_drop_reported
    assert frames[1].pn_drop_reported and not frames[1].pn_ok_reported
    es = [descriptor(), boundary(2, "mac80211_rx")]
    es[1].ts_boottime_ns = es[0].ts_boottime_ns + JOIN_NS + 1
    assert len(build_frames(es)) == 2


def test_patch_unresolved_and_malformed_words_stay_raw_not_fabricated_ownership():
    a, b = descriptor(), boundary(2, "mac80211_rx")
    a.data["fields"]["rxd1"] = "malformed-word"
    b.data["fields"].update(wcid="-1", link="-1", freq="0", flags="0x0")
    fr = build_frames([a, b])[0]
    assert fr.raw_descriptor_words["rxd1"] == "malformed-word"
    assert fr.resolved_wcid is None and fr.resolved_link is None
    assert fr.flags == "0x0" and fr.decrypted is None and fr.channel_matches is None


def test_unknown_patch_boundary_stage_is_retained_without_security_claim():
    fr = build_frames([descriptor(), boundary(2, "future_phase")])[0]
    assert fr.boundary_observations[0]["stage"] == "future_phase"
    assert not fr.pn_ok_reported and not fr.mac80211_rx_reported
