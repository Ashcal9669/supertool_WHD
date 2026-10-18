import struct

from test_mlo_safety import event
from whd.mlo import air, packets


def test_packet_path_has_only_observed_stages_and_rejects_other_boot():
    es = [
        event(1, kind="trace.net.net_dev_queue", skbaddr="0x123"),
        event(2, kind="trace.mt76.mlo_txfree", skbaddr="0x123"),
        event(3, kind="trace.net.netif_receive_skb", skbaddr="0x123"),
    ]
    for e in es:
        e.data.update(boot_id="boot-a", association_epoch="assoc-a")
    es[-1].data["boot_id"] = "boot-b"
    paths = packets.build_paths(es, "device-a")
    a = next(p for p in paths if p.scope.boot_id == "boot-a")
    assert [o.stage for o in a.observations] == ["stack_tx", "tx_free"]
    assert "stack_rx" in [g.what for g in a.gaps]
    assert a.delivered is None and a.acked is None
    assert a.observations[1].stage_class == "observation"
    assert a.first_missing == "userspace_submit"


def test_reused_skb_after_receive_begins_new_lifetime():
    es = [
        event(1, kind="trace.net.net_dev_queue", skbaddr="0x123"),
        event(2, kind="trace.net.netif_receive_skb", skbaddr="0x123"),
        event(3, kind="trace.net.net_dev_queue", skbaddr="0x123"),
    ]
    # TX and RX buffer observations are separate; reception cannot close a TX lifetime.
    assert len(packets.build_paths(es, "device-a")) == 3


def test_unidentified_events_are_separate_not_a_fake_packet():
    es = [event(1, kind="trace.mt76.mlo_txwi"), event(2, kind="trace.mt76.mlo_rx")]
    paths = packets.build_paths(es, "device-a")
    assert len(paths) == 2 and all(len(p.observations) == 1 for p in paths)
    assert all(p.correlation == "unjoined: no stable packet identifier" for p in paths)


def test_link_resolution_enriches_same_skb_without_cross_link_join():
    es = [
        event(1, kind="trace.net.net_dev_queue", skbaddr="0x123"),
        event(2, kind="trace.mt76.whd_packet_boundary", skbaddr="0x123", stage="txd", link="4", token="5"),
        event(
            3, kind="trace.mt76.whd_packet_boundary", skbaddr="0x123", stage="tx_free", link="4", token="5"
        ),
        event(4, kind="trace.mt76.whd_packet_boundary", skbaddr="0x123", stage="txd", link="8", token="6"),
    ]
    paths = packets.build_paths(es, "device-a")
    assert len(paths) == 2
    assert paths[0].scope.link_id == 4 and len(paths[0].observations) == 3
    assert paths[1].scope.link_id == 8


def test_authenticated_delivery_requires_scoped_security_channel_and_stack_evidence():
    es = [
        event(1, kind="packet.raw_rx", packet_id="frame-a", link="4"),
        event(
            2,
            kind="packet.security",
            packet_id="frame-a",
            link="4",
            decrypted="1",
            integrity_ok="1",
            replay_ok="1",
            channel_matches="1",
        ),
        event(3, kind="packet.stack_rx", packet_id="frame-a", link="4"),
    ]
    for e in es:
        e.data.update(boot_id="boot-a", association_epoch="epoch-a", ifname="wifi-fixture", wdev=7)
        e.data["fields"]["generation"] = "3"
    assert packets.build_paths(es, "device-a")[0].authenticated_delivery is True
    es[1].data["fields"]["channel_matches"] = "0"
    assert packets.build_paths(es, "device-a")[0].authenticated_delivery is None
    del es[1].data["fields"]["channel_matches"]
    assert packets.build_paths(es, "device-a")[0].authenticated_delivery is None


def pcap(payload: bytes, linktype: int = 105) -> bytes:
    return (
        struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, linktype)
        + struct.pack("<IIII", 100, 50, len(payload), len(payload))
        + payload
    )


def test_air_capture_addresses_raw_bytes_and_visibility_limits():
    payload = bytes.fromhex("0800000002005e20000102005e20000202005e2000030000")
    report = air.parse_pcap(pcap(payload), "independent")
    assert report.frames[0].addr2 == "02:00:5e:20:00:02"
    assert report.frames[0].raw_hex == payload.hex()
    assert report.frames[0].freq_mhz is None
    assert report.health == "unknown" and not report.can_establish_absence


def test_unsupported_or_truncated_capture_does_not_establish_absence():
    report = air.parse_pcap(pcap(b"abc", 999), "ap_local")
    assert report.origin == "ap_local" and report.unsupported_frames == 1
    assert not report.can_establish_absence
    assert air.parse_pcap(pcap(b"abc")[:-1], "independent").truncated
