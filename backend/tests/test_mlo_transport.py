"""Synthetic 0003 source-layout spans; not bytes observed on hardware."""

from test_mlo_safety import event
from whd.mlo.privacy import scrub
from whd.mlo.report import analyze
from whd.mlo.transport import LAYOUT_SHA256, ROC_LAYOUT_SHA256, decode_transport


def message(**fields):
    return event(
        1,
        kind="trace.mt76.whd_mcu_transport",
        phase="response",
        cmd="0x20003",
        eid="1",
        reason="safe_result_status",
        offset="48",
        region_len="4",
        captured_len="4",
        **fields,
    )


def test_status_bytes_require_layout_binding_and_never_prove_loaded_match():
    e = message(hex="05000000")
    out = decode_transport(e)
    assert out["raw_hex"] == "05000000" and not out["decoded"]
    e.data["layout_provenance"] = {"file": "mt7925/mcu.h", "file_sha256": LAYOUT_SHA256}
    out = analyze([e], "device-a", "fixture").mcu_transport[0]
    assert out["decoded"] == {"firmware_status": 5}
    assert out["matches_loaded_build"] is None
    e.data["layout_provenance"]["file_sha256"] = "0" * 64
    assert not decode_transport(e)["decoded"]


def test_unknown_security_or_incomplete_spans_are_withheld_before_storage():
    for change in (
        {"cmd": "0x20005"},
        {"reason": "unknown_tail"},
        {"captured_len": "5"},
        {"eid": "4"},
        {"hex": "malformed"},
    ):
        e = message(hex="aabbccdd")
        e.data["fields"].update(change)
        e.raw = "hex=" + e.data["fields"]["hex"]
        assert decode_transport(e)["raw_hex"] is None
        redacted = scrub(e.model_dump())
        assert redacted["data"]["fields"]["hex"] == "<redacted>"
        assert "aabbccdd" not in str(redacted)


def test_transport_envelopes_retain_mismatches_suppression_and_exact_errors():
    e = message(hex="")
    e.data["fields"].update(
        phase="parse",
        captured_len="0",
        reason="metadata_only",
        expected_seq="1",
        actual_seq="2",
        ret="-11",
        cookie="7",
        attempt="2",
    )
    result = decode_transport(e)
    assert result["envelope"]["ret"] == "-11"
    assert result["envelope"]["actual_seq"] == "2"
    assert result["raw_hex"] is None and not result["decoded"]
    assert "unmatched responses" in " ".join(result["limits"])


def test_roc_grant_uses_its_own_struct_with_rfsco_before_band():
    e = event(
        1,
        kind="trace.mt76.whd_mcu_transport",
        phase="async",
        reason="safe_roc_grant",
        eid="0x27",
        offset="48",
        region_len="15",
        captured_len="15",
        hex="000014000109002801030250510201",
    )
    e.data["layout_provenance"] = {"file": "mt7925/mt7925.h", "file_sha256": ROC_LAYOUT_SHA256}
    decoded = decode_transport(e)["decoded"]
    assert decoded["rf_sco"] == 1 and decoded["rf_band"] == 3
    assert decoded["width_code"] == 2 and decoded["center_channel"] == 80
    assert decoded["request_type"] == 2 and decoded["dbdcband"] == 1
    e.data["layout_provenance"] = {"file": "mt7925/mcu.h", "file_sha256": LAYOUT_SHA256}
    assert not decode_transport(e)["decoded"]


def test_extended_identity_envelope_is_withheld_before_persistence():
    e = event(1, kind="trace.mt76.whd_mcu_tlv", cmd="0x20001", hex="00000c00010002005e010203aabbccdd")
    e.data["fields"]["tag"] = "0"
    e.raw = "hex=" + e.data["fields"]["hex"]
    cleaned = scrub(e.model_dump())
    assert cleaned["data"]["fields"]["hex"] == "<redacted>"
    assert "aabbccdd" not in str(cleaned)


def test_malformed_transport_field_container_is_redacted_not_a_collector_crash():
    for invalid in (None, "bad", ["bad"]):
        e = message(hex="aabbccdd")
        e.data["fields"] = invalid
        e.raw = "hex=aabbccdd"
        cleaned = scrub(e.model_dump())
        assert cleaned["data"]["fields"]["hex"] == "<redacted>"
        assert "aabbccdd" not in str(cleaned)
