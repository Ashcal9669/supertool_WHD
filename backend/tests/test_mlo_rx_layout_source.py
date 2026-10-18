"""Synthetic source-layout fixtures, not hardware/build validation or packet-delivery proof."""

import hashlib
import json
import re
from pathlib import Path

import pytest

from test_mlo_rx_patch_hooks import boundary
from test_mlo_safety import event
from whd.mlo.rx import build_frames, summarize

FX = Path(__file__).parent / "fixtures/mlo/rx_layout_source"


def fixture():
    return json.loads((FX / "layout.json").read_text())


def raw_event(n=1, *, provenance=True, words=None):
    layout = fixture()
    e = event(
        n,
        kind="trace.mt76.whd_rx_descriptor",
        skbaddr="0x123",
        **(layout["cases"][0]["words"] if words is None else words),
    )
    e.data.update(boot_id="boot-a", ifname="wlan0", wdev="0x1", association_epoch="assoc-a", generation="7")
    if provenance:
        e.data["layout_provenance"] = layout["layout_provenance"]
    return e


def decoded(e):
    fr = build_frames([e])[0]
    assert hasattr(fr, "descriptor_decode"), "raw RX words need a provenance-gated descriptor decoder"
    return fr, fr.descriptor_decode


def test_actual_full_archived_header_and_consumer_bytes_match_pinned_fixture_hashes():
    from whd.mlo.rx_layout import SOURCE_SHA256

    layout = fixture()
    assert layout["evidence_class"] == "synthetic source layout; NOT hardware evidence"
    for name, expected in layout["source_sha256"].items():
        assert hashlib.sha256((FX / name).read_bytes()).hexdigest() == expected == SOURCE_SHA256[name]
    archive = Path(layout["archive"])
    if archive.exists():
        for name in layout["source_sha256"]:
            assert (FX / name).read_bytes() == (archive / name).read_bytes()


def test_matching_source_layout_decodes_ownership_without_resolved_or_security_claims():
    e = raw_event()
    fr, result = decoded(e)
    assert result.layout_match == "matched" and result.consumer_match == "matched"
    expected = fixture()["cases"][0]["expected"]
    assert all(result.fields[k] == value for k, value in expected.items())
    assert (fr.fw_idx, fr.desc_band, fr.sec_mode, fr.chfreq) == (9, 1, 4, 69)
    assert fr.initial_wcid is None and fr.resolved_wcid is None and fr.resolved_link is None
    assert fr.decrypted is None and fr.authenticated is None
    assert not fr.pn_ok_reported and not fr.delivered
    assert summarize([fr]).authenticated_by_link == {}
    assert result.matches_loaded_build is None
    assert result.raw_words == fixture()["cases"][0]["words"]


@pytest.mark.parametrize(
    "bad",
    [
        None,
        {},
        {"source_matched": True},
        {"file": "mt76_connac2_mac.h"},
        {"file": "mt76_connac3_mac.h", "file_sha256": "0" * 64},
        "matched",
    ],
)
def test_missing_or_wrong_provenance_keeps_every_word_raw_and_uninterpreted(bad):
    e = raw_event(provenance=False)
    e.data["layout_provenance"] = bad
    fr, result = decoded(e)
    assert result.layout_match == "unverified" and result.fields == {}
    assert result.raw_words == fixture()["cases"][0]["words"]
    assert fr.fw_idx is None and fr.desc_band is None and fr.sec_mode is None and fr.chfreq is None


def test_header_hash_only_allows_masks_but_not_consumer_decryption_rule():
    e = raw_event()
    e.data["layout_provenance"].pop("consumer_file_sha256")
    _, result = decoded(e)
    assert result.layout_match == "matched" and result.consumer_match == "unverified"
    assert result.fields["fw_idx"] == 9
    assert result.fields["decrypted_candidate"] is None


@pytest.mark.parametrize(
    "value", ["oops", "-1", "0x100000000", "4294967296", "0x", "1.0", "True", "0x123456789"]
)
def test_invalid_words_do_not_zero_fill_security_or_ownership(value):
    words = fixture()["cases"][0]["words"]
    words["rxd1"] = value
    fr, result = decoded(raw_event(words=words))
    assert result.raw_words["rxd1"] == value and "rxd1" in result.invalid_words
    assert not result.complete
    assert result.fields["fw_idx"] is None and result.fields["desc_band"] is None
    assert result.fields["icv_err"] is None and result.fields["integrity_ok"] is None
    assert result.fields["decrypted_candidate"] is None
    assert result.fields["sec_mode"] == 4 and result.fields["chfreq"] == 69
    assert fr.decrypted is None and fr.authenticated is None


def test_missing_word_does_not_hide_other_valid_word_or_manufacture_integrity():
    words = fixture()["cases"][0]["words"]
    words.pop("rxd3")
    _, result = decoded(raw_event(words=words))
    assert result.fields["fw_idx"] == 9 and result.fields["fcs_err"] is None
    assert result.fields["integrity_ok"] is None and not result.complete


@pytest.mark.parametrize("bit,field", [(23, "cm"), (24, "clm"), (25, "icv_err"), (26, "tkip_mic_err")])
def test_each_rxd1_error_bit_is_independent_of_decryption_candidate(bit, field):
    words = fixture()["cases"][0]["words"]
    words["rxd1"] = hex(int(words["rxd1"], 16) | (1 << bit))
    _, result = decoded(raw_event(words=words))
    assert result.fields[field] is True
    assert result.fields["decrypted_candidate"] is (field not in ("cm", "clm"))
    assert result.fields["integrity_ok"] is (field not in ("icv_err", "tkip_mic_err"))


def test_no_security_mode_is_not_a_decryption_candidate_and_fcs_error_is_retained():
    words = fixture()["cases"][0]["words"]
    words["rxd2"] = "0x0"
    words["rxd3"] = "0x01014500"
    _, result = decoded(raw_event(words=words))
    assert result.fields["sec_mode"] == 0 and result.fields["decrypted_candidate"] is False
    assert result.fields["fcs_err"] is True and result.fields["integrity_ok"] is False


def test_decoded_fields_use_masks_from_actual_full_header_bytes():
    header = (FX / "mt76_connac3_mac.h").read_text()
    mappings = [
        ("rxd1", "MT_RXD1_NORMAL_WLAN_IDX", "fw_idx"),
        ("rxd1", "MT_RXD1_NORMAL_BAND_IDX", "desc_band"),
        ("rxd1", "MT_RXD1_NORMAL_KEY_ID", "key_id"),
        ("rxd2", "MT_RXD2_NORMAL_SEC_MODE", "sec_mode"),
        ("rxd3", "MT_RXD3_NORMAL_CH_FREQ", "chfreq"),
        ("rxd3", "MT_RXD3_NORMAL_ADDR_TYPE", "addr_type"),
    ]
    for word, macro, field in mappings:
        match = re.search(rf"^#define\s+{macro}\s+GENMASK\((\d+), (\d+)\)", header, re.M)
        assert match is not None
        high, low = map(int, match.groups())
        # Independent source-header oracle: single bits on both sides of each documented range.
        for bit in range(32):
            words = {f"rxd{n}": "0x0" for n in range(5)}
            words[word] = hex(1 << bit)
            _, result = decoded(raw_event(words=words))
            assert result.fields[field] == (1 << (bit - low) if low <= bit <= high else 0)


def test_decode_does_not_cross_interface_lifetime_with_pn_boundary():
    start = raw_event()
    other = boundary(2, "pn_ok")
    other.data.update(start.data)
    other.data["fields"] = {
        "skbaddr": "0x123",
        "stage": "pn_ok",
        "wcid": "1",
        "link": "1",
        "freq": "5180",
        "flags": "0x0",
    }
    other.data["wdev"] = "0x2"
    frames = build_frames([start, other])
    assert len(frames) == 2 and frames[0].fw_idx == 9
    assert frames[0].resolved_link is None and not frames[0].pn_ok_reported
    assert frames[1].fw_idx is None and frames[1].raw_descriptor_words == {}


def test_successful_raw_bits_plus_pn_ok_do_not_fabricate_authenticated_delivery():
    start = raw_event()
    cont = boundary(2, "pn_ok")
    for key in ("boot_id", "ifname", "wdev", "association_epoch", "generation"):
        cont.data[key] = start.data[key]
    fr = build_frames([start, cont], {2: 69})[0]
    assert fr.descriptor_decode.fields["decrypted_candidate"] is True
    assert fr.pn_ok_reported and fr.resolved_link == 2
    assert fr.authenticated is None and fr.decrypted is None and not fr.delivered
    assert summarize([fr]).authenticated_by_link == {}
