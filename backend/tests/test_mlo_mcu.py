import struct

import pytest

from conftest import fixture_host
from whd.discovery import Discovery
from whd.mlo.mcu import decode_tlv
from whd.mlo.provenance import snapshot


def test_source_layout_match_required_and_mld_members_are_decoded():
    payload = struct.pack("<HH6sHHHB3xHBxHBx", 32, 28, bytes.fromhex("02005e200001"), 1, 2, 3, 2, 1, 4, 2, 5)
    unknown = decode_tlv(0x20003, 32, payload.hex(), source_matched=False)
    assert not unknown["fields"] and unknown["layout_match"] == "unverified"
    matched = decode_tlv(0x20003, 32, payload.hex(), source_matched=True)
    assert matched["fields"]["mld_mac"] == "02:00:5e:20:00:01"
    assert matched["fields"]["members"] == [{"wcid": 1, "bss_idx": 4}, {"wcid": 2, "bss_idx": 5}]


def test_incomplete_mcu_and_key_tlvs_never_decode_or_expose_key_bytes():
    assert not decode_tlv(0x20003, 32, "20001c000200", source_matched=True)["complete"]
    key = decode_tlv(0x20003, 12, "deadbeef", source_matched=True)
    assert key["raw_hex"] is None and key["redacted"]


@pytest.mark.parametrize("payload", ["00000c00" + "ab" * 8, "20001c00" + "ab" * 25])
def test_wrong_identity_header_or_size_withholds_all_payload_bytes(payload):
    result = decode_tlv(0x20003, 32, payload, source_matched=True)
    assert result["raw_hex"] is None and result["redacted"]
    assert not result["fields"] and not result["complete"]


def test_bss_mld_layout_and_reserved_bytes_have_exact_source_provenance():
    # Synthetic byte fixture from saved bss_mld_tlv; no recorded raw dump is available.
    raw = "1a001400ff0202005e200001ff01020203aabbcc"
    result = decode_tlv(0x20002, 26, raw, source_matched=True)
    assert result["fields"] == {
        "group_mld": 255,
        "own_mld": 2,
        "mac": "02:00:5e:20:00:01",
        "remap_idx": 255,
        "link_id": 1,
        "eml_enable": 2,
        "max_link_num": 2,
        "hybrid_mode": 3,
    }
    assert result["unknown_fields"] == [{"offset": 17, "length": 3, "raw_hex": "aabbcc"}]
    assert result["layout_source"]["struct"] == "bss_mld_tlv"
    assert result["layout_source"]["file"] == "mt7925/mcu.h"
    assert (
        result["layout_source"]["file_sha256"]
        == "7fa7577d38e080df816d9e32524c930443cb36030b4208fefdf912790bd198fd"
    )
    assert result["matches_loaded_build"] is None


def test_bss_rlm_decodes_channels_without_inventing_frequencies():
    raw = "02001000282a00030202010401000000"
    result = decode_tlv(0x20002, 2, raw, source_matched=True)
    assert result["fields"] == {
        "channel": 40,
        "center_channel": 42,
        "center_channel2": 0,
        "width_code": 3,
        "tx_streams": 2,
        "rx_streams": 2,
        "ht_op_info": 1,
        "sco": 4,
        "band": 1,
    }
    assert result["layout_source"]["struct"] == "bss_rlm_tlv"
    unverified = decode_tlv(0x20002, 2, raw)
    assert unverified["complete"] and not unverified["fields"]
    assert unverified["matches_loaded_build"] is None


def test_mld_count_larger_than_source_array_is_explicitly_inconsistent():
    payload = struct.pack("<HH6sHHHB3xHBxHBx", 32, 28, bytes.fromhex("02005e200001"), 1, 2, 3, 3, 1, 4, 2, 5)
    result = decode_tlv(0x20003, 32, payload.hex(), source_matched=True)
    assert result["fields"]["link_num"] == 3
    assert len(result["fields"]["members"]) == 2
    assert result["consistent"] is False and "2" in result["limit"]


def test_capture_provenance_includes_dependency_build_ids_and_untracked_source():
    host = fixture_host("mt7927-pcie-host")
    dev = Discovery(host).run().devices[0]
    result = snapshot(host, [dev])
    assert set(dev.driver_info.module_dependencies) <= set(result["modules"])
    assert "backend/src/whd/mlo/privacy.py" in result["collector"]["source_sha256"]
