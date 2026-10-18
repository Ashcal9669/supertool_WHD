"""Audited identity layouts, independent of running-module equivalence.

source_matched is a caller assertion about the layout only (legacy API). New callers
can supply layout_provenance: file + file_sha256 must match the pinned source below.
Neither path establishes a loaded BuildID binding; matches_loaded_build stays None.
Unknown/security TLVs and malformed identity envelopes never expose payload bytes.
"""

from __future__ import annotations

import struct
from typing import Any

# Layouts read from decoder_source's mt76_connac_mcu.h / mt7925/mcu.h.
# Keys and unknown TLVs are withheld: a future TLV may contain secret material.
SAFE_LENGTHS = {(1, 0): 12, (2, 0): 32, (2, 2): 16, (2, 26): 20, (3, 0): 20, (3, 32): 28, (0x27, 0): 24}
_ARTIFACT = "archived-mt76-source-snapshot"
_SOURCES = {
    "mt76_connac_mcu.h": "be1b99744a442b30f419d0a214490c7f2189f59695252efa6c52deec87c25107",
    "mt7925/mcu.h": "7fa7577d38e080df816d9e32524c930443cb36030b4208fefdf912790bd198fd",
    "mt76_connac_mcu.c": "8a947b7bdcc04853060a63603dfbe95e99313a0cdaab2c8666771e891aa16300",
}
_LAYOUTS = {
    (1, 0): ("mt76_connac_mcu.c", "mt76_connac_mcu_uni_add_dev::req_tlv"),
    (2, 0): ("mt76_connac_mcu.h", "mt76_connac_bss_basic_tlv"),
    (2, 2): ("mt7925/mcu.h", "bss_rlm_tlv"),
    (2, 26): ("mt7925/mcu.h", "bss_mld_tlv"),
    (3, 0): ("mt76_connac_mcu.h", "sta_rec_basic"),
    (3, 32): ("mt7925/mcu.h", "sta_rec_mld"),
    (0x27, 0): ("mt7925/mcu.h", "roc_acquire_tlv"),
}
# Only uninterpreted ranges inside exact audited non-key structures are retained.
_RESERVED = {
    (2, 2): [(13, 3)],
    (2, 26): [(17, 3)],
    (3, 32): [(17, 3), (23, 1), (27, 1)],
    (0x27, 0): [(21, 3)],
}


def decode_tlv(
    cmd: int,
    tag: int,
    raw_hex: str,
    *,
    source_matched: bool = False,
    layout_provenance: dict[str, Any] | None = None,
) -> dict[str, Any]:
    key = (cmd & 0xFFFF, tag)
    out: dict[str, Any] = {
        "cmd": cmd,
        "tag": tag,
        "raw_hex": None,
        "fields": {},
        "complete": False,
        "layout_match": "matched" if source_matched else "unverified",
        "redacted": False,
        "matches_loaded_build": None,
        "layout_source": None,
        "unknown_fields": [],
        "consistent": None,
    }
    if not cmd & 0x20000 or key not in SAFE_LENGTHS:
        out["redacted"] = True
        out["limit"] = "key/unknown TLV payload withheld; header metadata only"
        return out
    file, declaration = _LAYOUTS[key]
    out["layout_source"] = {
        "artifact": f"{_ARTIFACT}/{file}",
        "file": file,
        "file_sha256": _SOURCES[file],
        "struct": declaration,
        "byte_order": "little",
        "packed": True,
    }
    if layout_provenance is not None:
        source_matched = (
            layout_provenance.get("file") == file and layout_provenance.get("file_sha256") == _SOURCES[file]
        )
    out["layout_match"] = "matched" if source_matched else "unverified"
    try:
        raw = bytes.fromhex(raw_hex)
    except ValueError:
        out["limit"] = "malformed hex"
        return out
    size = SAFE_LENGTHS[key]
    out["complete"] = (
        len(raw) == size and len(raw) >= 4 and struct.unpack_from("<HH", raw)[0:2] == (tag, size)
    )
    if not out["complete"]:
        out["redacted"] = True
        out["limit"] = "identity TLV size/header mismatch; payload withheld"
        return out
    out["raw_hex"] = raw.hex()
    if not source_matched:
        out["limit"] = (
            "incomplete dump or source/build equivalence unverified; bytes retained without interpretation"
        )
        return out
    out["unknown_fields"] = [
        {"offset": at, "length": length, "raw_hex": raw[at : at + length].hex()}
        for at, length in _RESERVED.get(key, [])
    ]
    out["consistent"] = True
    f: dict[str, Any] = {}

    def mac(at: int) -> str:
        return ":".join(f"{b:02x}" for b in raw[at : at + 6])

    def u16(at: int) -> int:
        return int(struct.unpack_from("<H", raw, at)[0])

    if key == (3, 32):
        f = {
            "mld_mac": mac(4),
            "primary_wcid": u16(10),
            "secondary_wcid": u16(12),
            "wlan_id": u16(14),
            "link_num": raw[16],
            "members": [{"wcid": u16(at), "bss_idx": raw[at + 2]} for at in (20, 24)][: min(raw[16], 2)],
        }
        if raw[16] > 2:
            out["consistent"] = False
            out["limit"] = (
                "link_num exceeds the source layout's 2 member slots; no additional members inferred"
            )
    elif key == (3, 0):
        f = {
            "connection_type": struct.unpack_from("<I", raw, 4)[0],
            "state": raw[8],
            "qos": raw[9],
            "aid": u16(10),
            "peer_mac": mac(12),
            "extra_info": u16(18),
        }
    elif key == (2, 0):
        f = {
            "active": raw[4],
            "omac": raw[5],
            "hw_bss_idx": raw[6],
            "band": raw[7],
            "connection_type": struct.unpack_from("<I", raw, 8)[0],
            "connection_state": raw[12],
            "wmm": raw[13],
            "bssid": mac(14),
            "bmc_wcid": u16(20),
            "station_wcid": u16(26),
            "link_idx": raw[31],
        }
    elif key == (1, 0):
        f = {"active": raw[4], "dev_link_idx": raw[5], "mac": mac(6)}
    elif key == (2, 26):
        f = {
            "group_mld": raw[4],
            "own_mld": raw[5],
            "mac": mac(6),
            "remap_idx": raw[12],
            "link_id": raw[13],
            "eml_enable": raw[14],
            "max_link_num": raw[15],
            "hybrid_mode": raw[16],
        }
    elif key == (2, 2):
        f = {
            "channel": raw[4],
            "center_channel": raw[5],
            "center_channel2": raw[6],
            "width_code": raw[7],
            "tx_streams": raw[8],
            "rx_streams": raw[9],
            "ht_op_info": raw[10],
            "sco": raw[11],
            "band": raw[12],
        }
    elif key == (0x27, 0):
        f = {
            "bss_idx": raw[4],
            "token": raw[5],
            "channel": raw[6],
            "band": raw[8],
            "width_code": raw[9],
            "center_channel": raw[10],
            "request_type": raw[15],
            "duration_ms": struct.unpack_from("<I", raw, 16)[0],
            "dbdcband": raw[20],
        }
    out["fields"] = f
    return out
