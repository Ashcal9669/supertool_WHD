"""Bounded classic PCAP ingestion. Offline captures do not prove current monitor health or RF absence."""

from __future__ import annotations

import struct
from typing import Any, Literal

from pydantic import Field

from whd.model.common import Model


class AirFrame(Model):
    timestamp: float
    raw_hex: str
    captured_bytes: int
    original_bytes: int
    freq_mhz: int | None = None
    addr1: str | None = None
    addr2: str | None = None
    addr3: str | None = None
    sequence: int | None = None
    frame_type: int | None = None
    subtype: int | None = None
    protected: bool | None = None
    eapol: dict[str, int | str | None] | None = None


class AirReport(Model):
    origin: Literal["independent", "ap_local", "same_phy"]
    import_id: str | None = None
    filename: str | None = None
    sha256: str | None = None
    pcap_artifact: str | None = None
    original_retained: bool = True
    report_artifact: str | None = None
    linktype: int | None = None
    frames: list[AirFrame] = Field(default_factory=list)
    unsupported_frames: int = 0
    truncated: bool = False
    health: str = "unknown"
    stalls: list[float] = Field(default_factory=list)
    channel_changes: list[dict[str, Any]] = Field(default_factory=list)
    dropped_packets: int | None = None
    can_establish_absence: bool = False
    limits: list[str] = Field(
        default_factory=lambda: [
            "offline capture: ongoing receiver health/drops unknown",
            "channel coverage is known only where radiotap supplies a frequency",
            "capture timestamps need external clock calibration to join host events",
        ]
    )


def _radiotap(payload: bytes) -> tuple[int, int | None]:
    if len(payload) < 8 or payload[0] != 0:
        raise ValueError("invalid radiotap")
    size, present = struct.unpack_from("<HI", payload, 2)
    if size < 8 or size > len(payload):
        raise ValueError("short radiotap")
    at = 8
    more = present
    while more & (1 << 31):
        if at + 4 > size:
            raise ValueError("short radiotap bitmap")
        more = struct.unpack_from("<I", payload, at)[0]
        at += 4
    for bit, align, width in [(0, 8, 8), (1, 1, 1), (2, 1, 1)]:
        if present & (1 << bit):
            at = (at + align - 1) // align * align + width
    freq = None
    if present & 8:
        at = (at + 1) // 2 * 2
        if at + 4 <= size:
            freq = struct.unpack_from("<H", payload, at)[0]
    return size, freq


def parse_pcap(data: bytes, origin: Literal["independent", "ap_local", "same_phy"]) -> AirReport:
    report = AirReport(origin=origin)
    if origin == "same_phy":
        report.limits.append(
            "co-located monitor shares the transmitting PHY; not independent RF/AP reception proof"
        )
    magic = data[:4]
    endian = "<" if magic in (b"\xd4\xc3\xb2\xa1", b"\x4d\x3c\xb2\xa1") else ">"
    if (
        magic not in (b"\xd4\xc3\xb2\xa1", b"\xa1\xb2\xc3\xd4", b"\x4d\x3c\xb2\xa1", b"\xa1\xb2\x3c\x4d")
        or len(data) < 24
    ):
        report.limits.append(
            "unsupported container: classic PCAP required; pcapng must be converted externally"
        )
        report.unsupported_frames = 1
        return report
    ns = magic in (b"\x4d\x3c\xb2\xa1", b"\xa1\xb2\x3c\x4d")
    report.linktype = struct.unpack_from(endian + "I", data, 20)[0] & 0xFFFF
    at = 24
    while at < len(data) and len(report.frames) < 10000:
        if at + 16 > len(data):
            report.truncated = True
            break
        sec, frac, cap, orig = struct.unpack_from(endian + "IIII", data, at)
        at += 16
        if cap > 65535 or at + cap > len(data):
            report.truncated = True
            break
        payload = data[at : at + cap]
        at += cap
        ts = sec + frac / (1e9 if ns else 1e6)
        frame = AirFrame(timestamp=ts, raw_hex=payload.hex(), captured_bytes=cap, original_bytes=orig)
        report.truncated |= cap < orig
        start = 0
        try:
            if report.linktype == 127:
                start, frame.freq_mhz = _radiotap(payload)
            elif report.linktype != 105:
                raise ValueError("unsupported frame format")
            body = payload[start:]
            if len(body) < 24:
                raise ValueError("short 802.11 header")
            fc = int.from_bytes(body[:2], "little")
            frame.frame_type, frame.subtype, frame.protected = (
                (fc >> 2) & 3,
                (fc >> 4) & 15,
                bool(fc & 0x4000),
            )
            frame.addr1, frame.addr2, frame.addr3 = (
                ":".join(f"{x:02x}" for x in body[i : i + 6]) for i in (4, 10, 16)
            )
            frame.sequence = int.from_bytes(body[22:24], "little") >> 4
            if frame.frame_type == 2 and not frame.protected:
                header = 24 + (6 if fc & 0x300 == 0x300 else 0)
                if (frame.subtype or 0) & 8:
                    header += 2 + (4 if fc & 0x8000 else 0)
                if body[header : header + 8] == bytes.fromhex("aaaa03000000888e"):
                    eapol = body[header + 8 :]
                    # Retain metadata through Replay Counter only. Never expose EAPOL Key Data.
                    frame.raw_hex = payload[: start + header + 8 + 17].hex()
                    if len(eapol) > 99 or (len(eapol) > 17 and (eapol[1] != 3 or eapol[4] != 2)):
                        report.original_retained = False
                        report.limits.append(
                            "original PCAP withheld: EAPOL key-data present; safe header metadata retained"
                        )
                    if len(eapol) >= 17 and eapol[1] == 3 and eapol[4] == 2:
                        info = int.from_bytes(eapol[5:7], "big")
                        ack, mic, install, secure = (bool(info & b) for b in (128, 256, 64, 512))
                        message = None
                        if info & 8:
                            if ack and not mic and not install:
                                message = 1
                            elif not ack and mic and not secure:
                                message = 2
                            elif ack and mic and install:
                                message = 3
                            elif not ack and mic and secure:
                                message = 4
                        frame.eapol = {
                            "message": message,
                            "key_info": info,
                            "replay_counter": int.from_bytes(eapol[9:17], "big"),
                            "basis": "pairwise key-info; transmitter/receiver retained; no key data decoded",
                        }
        except ValueError:
            report.unsupported_frames += 1
        if report.frames:
            previous_freq = report.frames[-1].freq_mhz
            if previous_freq is not None and frame.freq_mhz is not None and previous_freq != frame.freq_mhz:
                report.channel_changes.append(
                    {"timestamp": ts, "from_mhz": previous_freq, "to_mhz": frame.freq_mhz}
                )
                report.limits.append(
                    "radiotap frequency changed; a retune or merged receivers require capture-owner attribution"
                )
            delay = ts - report.frames[-1].timestamp
            if delay > 5:
                report.stalls.append(delay)
                report.limits.append(
                    "packet timestamp gap: monitor stall or quiet channel; cannot distinguish"
                )
        report.frames.append(frame)
    if at < len(data):
        report.truncated = True
    return report
