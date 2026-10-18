import struct

from conftest import fixture_host
from test_mlo_packets import pcap
from whd.discovery import Discovery
from whd.drivers.mt76 import read_snapshot
from whd.mlo import air


def test_snapshot_active_ids_do_not_include_upper_valid_mask_bits():
    host = fixture_host("mt7927-pcie-host")
    for key, result in host.helper.data["calls"].items():
        if key.startswith("debugfs_read:") and "mlo_active_links" in key:
            result["text"] = "0x70006\n"
    dev = Discovery(host).run().devices[0]
    assert read_snapshot(host, dev, False).mlo_active_link_ids == [1, 2]


def test_air_channel_changes_and_timestamp_gaps_remain_qualified():
    frame = bytes.fromhex("0800000002005e20000102005e20000202005e2000030000")

    def packet(freq):
        return struct.pack("<BBHIHH", 0, 0, 12, 8, freq, 0) + frame

    data = pcap(packet(5180), 127)
    b = packet(5200)
    data += struct.pack("<IIII", 110, 50, len(b), len(b)) + b
    report = air.parse_pcap(data, "independent")
    assert report.channel_changes == [{"timestamp": 110.00005, "from_mhz": 5180, "to_mhz": 5200}]
    assert report.stalls == [10.0] and not report.can_establish_absence
