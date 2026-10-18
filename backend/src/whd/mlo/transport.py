"""Bounded nonsecret MCU transport spans emitted by the separate 0003 proposal.

A layout match never proves a loaded-build match. Suppressed or unrecognized
regions retain their envelope and suppression reason, never guessed contents.
"""

import struct
from typing import Any

from whd.mlo.kv import fields_of, num
from whd.model.events import Event

ROC_LAYOUT_SHA256 = "a1f2132f81ddad454090ad501a8dbcaad61e927fc3d66128eb9aa80c6be56553"
LAYOUT_SHA256 = "7fa7577d38e080df816d9e32524c930443cb36030b4208fefdf912790bd198fd"


def safe_transport_hex(fields: dict[str, str]) -> str | None:
    try:
        raw = bytes.fromhex(fields.get("hex", ""))
    except ValueError:
        return None
    n = num(fields, "captured_len")
    size = num(fields, "region_len")
    offset = num(fields, "offset")
    if not n or n != len(raw) or n != size or offset is None:
        return None
    phase, reason = fields.get("phase"), fields.get("reason")
    cmd, eid = num(fields, "cmd"), num(fields, "eid")
    if phase == "response" and cmd in (0x20001, 0x20002, 0x20003) and eid == 1:
        if reason == "safe_result_cid" and offset == 44 and n == 1 and raw[0] == (cmd & 0xFFFF):
            return raw.hex()
        if reason == "safe_result_status" and offset == 48 and n == 4:
            return raw.hex()
    if phase == "async" and eid == 0x27:
        if reason == "safe_roc_grant" and offset >= 48 and (offset - 48) % 20 == 0 and n == 15:
            if struct.unpack_from("<HH", raw) in ((0, 20), (4, 20)):
                return raw.hex()
        if reason == "safe_roc_interval" and offset >= 64 and (offset - 64) % 20 == 0 and n == 4:
            return raw.hex()
    return None


def decode_transport(event: Event) -> dict[str, Any]:
    f = fields_of(event)
    raw_hex = safe_transport_hex(f)
    provenance = event.data.get("layout_provenance")
    source_file, source_hash = (
        ("mt7925/mt7925.h", ROC_LAYOUT_SHA256)
        if f.get("phase") == "async"
        else ("mt7925/mcu.h", LAYOUT_SHA256)
    )
    matched = (
        isinstance(provenance, dict)
        and provenance.get("file") == source_file
        and provenance.get("file_sha256") == source_hash
    )
    out: dict[str, Any] = {
        "event_id": event.id,
        "ts_boottime_ns": event.ts_boottime_ns,
        "envelope": {k: v for k, v in f.items() if k != "hex"},
        "raw_hex": raw_hex,
        "decoded": {},
        "layout_match": "matched" if matched else "unverified",
        "matches_loaded_build": None,
        "layout_source": {"file": source_file, "file_sha256": source_hash, "byte_order": "little"},
        "limits": [
            "transport sequence/cookie is not association or link lifetime",
            "parse return is distinct from firmware status; unmatched responses are not command completion",
        ],
    }
    if f.get("hex") and raw_hex is None:
        out["limits"].append("unaudited, malformed or inconsistent byte span withheld")
    if raw_hex and matched:
        raw = bytes.fromhex(raw_hex)
        reason = f.get("reason")
        if reason == "safe_result_cid":
            out["decoded"] = {"cid": raw[0]}
        elif reason == "safe_result_status":
            out["decoded"] = {"firmware_status": struct.unpack("<I", raw)[0]}
        elif reason == "safe_roc_interval":
            out["decoded"] = {"interval_ms": struct.unpack("<I", raw)[0]}
        elif reason == "safe_roc_grant":
            out["decoded"] = {
                "tag": struct.unpack_from("<H", raw)[0],
                "bss_idx": raw[4],
                "token": raw[5],
                "status": raw[6],
                "primary_channel": raw[7],
                "rf_sco": raw[8],
                "rf_band": raw[9],
                "width_code": raw[10],
                "center_channel": raw[11],
                "center_channel2": raw[12],
                "request_type": raw[13],
                "dbdcband": raw[14],
            }
    return out
