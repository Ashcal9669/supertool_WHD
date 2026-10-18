"""Offline Ethernet capture boundaries. Stack capture is neither RF nor RX security proof."""

import hashlib
import ipaddress
import struct
from typing import Literal

from pydantic import Field

from whd.model.common import Model
from whd.model.events import Event


class StackCapture(Model):
    import_id: str | None = None
    pcap_artifact: str | None = None
    report_artifact: str | None = None
    events: list[Event] = Field(default_factory=list)
    sha256: str
    direction: Literal["tx", "rx"]
    interface: str
    boot_id: str
    wall_minus_boot_ns: int
    original_retained: bool = True
    unsupported: int = 0
    truncated: bool = False
    limits: list[str] = Field(
        default_factory=lambda: [
            "direction/interface/boot and clock offset supplied by capture owner; timestamps require calibration",
            "Ethernet capture is a stack boundary, not independent air reception, ACK or security/PN evidence",
            "each frame remains unjoined to driver descriptors without a shared packet identifier",
        ]
    )


def decode(
    data: bytes,
    *,
    direction: Literal["tx", "rx"],
    device_id: str,
    interface: str,
    boot_id: str,
    wall_minus_boot_ns: int,
) -> StackCapture:
    magic = data[:4]
    if len(data) < 24 or magic not in (
        bytes.fromhex("d4c3b2a1"),
        bytes.fromhex("a1b2c3d4"),
        bytes.fromhex("4d3cb2a1"),
        bytes.fromhex("a1b23c4d"),
    ):
        raise ValueError("classic Ethernet PCAP required")
    endian = "<" if magic in (bytes.fromhex("d4c3b2a1"), bytes.fromhex("4d3cb2a1")) else ">"
    if struct.unpack_from(endian + "I", data, 20)[0] != 1:
        raise ValueError("Ethernet link type required; monitor PCAP belongs in air capture")
    result = StackCapture(
        sha256=hashlib.sha256(data).hexdigest(),
        direction=direction,
        interface=interface,
        boot_id=boot_id,
        wall_minus_boot_ns=wall_minus_boot_ns,
    )
    at, sequence = 24, 0
    while at < len(data) and sequence < 10000:
        if at + 16 > len(data):
            result.truncated = True
            break
        sec, frac, cap, original = struct.unpack_from(endian + "IIII", data, at)
        at += 16
        if cap > 65535 or at + cap > len(data):
            result.truncated = True
            break
        payload = data[at : at + cap]
        at += cap
        sequence += 1
        result.truncated |= cap < original
        if len(payload) < 14:
            result.unsupported += 1
            result.original_retained = False
            continue
        ether = int.from_bytes(payload[12:14], "big")
        fields = {
            "interface": interface,
            "ethertype": str(ether),
            "capture_frame": str(sequence),
            "capture_sha256": result.sha256,
            "direction": direction,
            "dst": ":".join(f"{b:02x}" for b in payload[:6]),
            "src": ":".join(f"{b:02x}" for b in payload[6:12]),
        }
        kind = f"packet.stack_{direction}"
        raw = payload.hex()
        if ether == 0x888E:
            kind = f"packet.eapol_{direction}"
            result.original_retained = False
            # Ethernet + EAPOL + descriptor type, key-info, key-length, replay counter ONLY.
            raw = payload[:31].hex()
            if len(payload) >= 31 and payload[15] == 3 and payload[18] == 2:
                fields["key_info"] = str(int.from_bytes(payload[19:21], "big"))
                fields["replay_counter"] = str(int.from_bytes(payload[23:31], "big"))
        elif ether == 0x0800 and len(payload) >= 34:
            body = payload[14:]
            ihl = (body[0] & 15) * 4
            if body[0] >> 4 != 4 or ihl < 20 or len(body) < ihl + 8 or body[9] != 1:
                result.unsupported += 1
                result.original_retained = False
                continue
            fields.update(
                l4p="1",
                sip=str(ipaddress.ip_address(body[12:16])),
                dip=str(ipaddress.ip_address(body[16:20])),
                icmp_type=str(body[ihl]),
                id=str(int.from_bytes(body[ihl + 4 : ihl + 6], "big")),
                seq=str(int.from_bytes(body[ihl + 6 : ihl + 8], "big")),
            )
            fields["icmp"] = f"{body[ihl]}/{body[ihl + 1]}"
        else:
            result.unsupported += 1
            result.original_retained = False
            continue
        timestamp_ns = sec * 1_000_000_000 + frac * (
            1 if magic in (bytes.fromhex("4d3cb2a1"), bytes.fromhex("a1b23c4d")) else 1000
        )
        result.events.append(
            Event(
                ts_boottime_ns=max(0, timestamp_ns - wall_minus_boot_ns),
                ts_wall=timestamp_ns / 1e9,
                ts_source="receive_boottime",
                source="pcap:ethernet",
                device_id=device_id,
                category="association" if ether == 0x888E else "netdev",
                kind=kind,
                summary=f"{direction} Ethernet capture on {interface}",
                explanation="capture-owner attributed stack observation; no RF/security inference",
                raw=raw,
                data={"boot_id": boot_id, "fields": fields},
            )
        )
    return result
