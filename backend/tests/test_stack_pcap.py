import struct

from whd.mlo import stack_pcap


def pcap(payload):
    return (
        bytes.fromhex("d4c3b2a1")
        + struct.pack("<HHIIII", 2, 4, 0, 0, 256, 1)
        + struct.pack("<IIII", 100, 0, len(payload), len(payload))
        + payload
    )


def test_ethernet_capture_exposes_stack_boundary_without_security_or_mlo_claims():
    frame = bytes.fromhex("00112233445566778899aabb0800") + bytes.fromhex(
        "4500001c00000000400100000a0000010a0000020000000000070003"
    )
    result = stack_pcap.decode(
        pcap(frame),
        direction="rx",
        device_id="device",
        interface="renamed",
        boot_id="boot",
        wall_minus_boot_ns=50_000_000_000,
    )
    obs = result.events[0]
    assert obs.kind == "packet.stack_rx"
    assert obs.ts_boottime_ns == 50_000_000_000
    assert obs.data["fields"]["seq"] == "3"
    assert "link" not in obs.data["fields"]
    assert "decrypted" not in obs.data["fields"]
    assert result.original_retained is True


def test_eapol_keeps_key_info_and_replay_counter_but_discards_key_data():
    frame = (
        bytes.fromhex("00112233445566778899aabb888e0203006002008a00100000000000000007")
        + b"secret-key-payload"
    )
    result = stack_pcap.decode(
        pcap(frame),
        direction="rx",
        device_id="device",
        interface="renamed",
        boot_id="boot",
        wall_minus_boot_ns=0,
    )
    assert result.events[0].data["fields"]["key_info"] == "138"
    assert result.events[0].data["fields"]["replay_counter"] == "7"
    assert "secret" not in result.model_dump_json()
    assert result.original_retained is False
    assert result.events[0].kind == "packet.eapol_rx"
    from whd.mlo.timeline import eapol_frames

    assert eapol_frames(result.events)[0][0] == "rx"


def test_recorded_mt7922_monitor_decodes_four_eapol_messages_without_key_data():
    import json
    from pathlib import Path

    from whd.mlo.air import parse_pcap

    saved = json.loads(
        (Path(__file__).parent / "fixtures/wifi/mt7922-20261012/monitor-headers.json").read_text()
    )
    records = []
    for frame in saved["frames"]:
        payload = bytes.fromhex(frame["raw_hex"])
        records.append(
            struct.pack("<IIII", int(frame["timestamp"]), 0, len(payload), frame["original_bytes"]) + payload
        )
    data = bytes.fromhex("d4c3b2a1") + struct.pack("<HHIIII", 2, 4, 0, 0, 128, 127) + b"".join(records)
    result = parse_pcap(data, "same_phy")
    messages = [frame.eapol["message"] for frame in result.frames if frame.eapol]
    assert messages == [1, 2, 3, 4]
    assert result.unsupported_frames == 0 and not result.can_establish_absence


def test_air_import_discards_eapol_key_data_and_withholds_unsafe_original():
    from whd.mlo.air import parse_pcap

    body = bytes.fromhex("0800000000112233445566778899aabb0011223344550000aaaa03000000888e")
    eapol = bytes.fromhex("0203008002008a00100000000000000007") + b"\0" * 82 + b"secret-key-material"
    frame = body + eapol
    data = (
        bytes.fromhex("d4c3b2a1")
        + struct.pack("<HHIIII", 2, 4, 0, 0, 256, 105)
        + struct.pack("<IIII", 100, 0, len(frame), len(frame))
        + frame
    )
    report = parse_pcap(data, "same_phy")
    assert not report.original_retained
    assert b"secret-key-material".hex() not in report.model_dump_json()


def test_unknown_eapol_key_descriptor_cannot_retain_raw_key_payload():
    from whd.mlo.air import parse_pcap

    frame = (
        bytes.fromhex("0800000000112233445566778899aabb0011223344550000aaaa03000000888e0203003001")
        + b"\0" * 30
        + b"wep-secret"
    )
    data = (
        bytes.fromhex("d4c3b2a1")
        + struct.pack("<HHIIII", 2, 4, 0, 0, 128, 105)
        + struct.pack("<IIII", 100, 0, len(frame), len(frame))
        + frame
    )
    assert parse_pcap(data, "same_phy").original_retained is False
