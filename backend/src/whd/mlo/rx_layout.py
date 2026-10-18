"""Pinned archived MT7925/MT7927 RXD layout; never a loaded-module/BuildID assertion.

0002 emits CPU-order u32 words after le32_to_cpu(), before fill_rx validation.
Only explicit file/hash provenance enables masks. The decryption-flag candidate
also needs the exact archived consumer hash; it is not an executed security check.
Status flags from whd_rx_boundary use a different layout and are NOT decoded here.
"""

from __future__ import annotations

import re
from typing import Literal

from pydantic import Field

from whd.model.common import Model

SOURCE_SHA256 = {
    "mt76_connac3_mac.h": "65f970c7a5cd1868b047ce536710f0b103ea31d5f7dd7c9456b109fda204ecd2",
    "mt7925/mac.h": "df86c480aae92400e8b9aab55997d6643ec9b118a07387230ed0b5c6901484eb",
    "mt7925/mac.c": "095a0e32d1f9bf426660833391431b979ceb7599143ccdd0f2532efa3f64c483",
}
ARTIFACT = "archived-mt76-source-snapshot"
WORDS = tuple(f"rxd{n}" for n in range(5))
# Full-header definitions: (word, mask, shift, boolean), no masks borrowed from other chips.
MASKS = {
    "fw_idx": ("rxd1", 0x00000FFF, 0, False),  # MT_RXD1_NORMAL_WLAN_IDX
    "key_id": ("rxd1", 0x00600000, 21, False),
    "cm": ("rxd1", 0x00800000, 23, True),
    "clm": ("rxd1", 0x01000000, 24, True),
    "icv_err": ("rxd1", 0x02000000, 25, True),
    "tkip_mic_err": ("rxd1", 0x04000000, 26, True),
    "desc_band": ("rxd1", 0x18000000, 27, False),
    "sec_done": ("rxd1", 0x80000000, 31, True),
    "hdr_trans": ("rxd2", 0x00000080, 7, True),
    "sec_mode": ("rxd2", 0x001F0000, 16, False),
    "amsdu_err": ("rxd2", 0x00800000, 23, True),
    "max_len_error": ("rxd2", 0x01000000, 24, True),
    "chfreq": ("rxd3", 0x0000FF00, 8, False),  # channel number, NOT MHz
    "addr_type": ("rxd3", 0x00030000, 16, False),
    "fcs_err": ("rxd3", 0x01000000, 24, True),
}
_U32 = re.compile(r"(?:0[xX][0-9a-fA-F]{1,8}|[0-9]{1,10})\Z")


class DescriptorDecode(Model):
    raw_words: dict[str, str]
    fields: dict[str, int | bool | None] = Field(default_factory=dict)
    layout_match: Literal["matched", "unverified"] = "unverified"
    consumer_match: Literal["matched", "unverified"] = "unverified"
    complete: bool = False
    invalid_words: list[str] = Field(default_factory=list)
    missing_words: list[str] = Field(default_factory=list)
    matches_loaded_build: None = None
    layout_source: dict[str, str] = Field(
        default_factory=lambda: {
            "artifact": ARTIFACT,
            "file": "mt76_connac3_mac.h",
            "file_sha256": SOURCE_SHA256["mt76_connac3_mac.h"],
            "consumer_file": "mt7925/mac.c",
            "consumer_file_sha256": SOURCE_SHA256["mt7925/mac.c"],
            "hook": "whd_rx_descriptor at mt7925_mac_fill_rx entry",
            "word_order": "CPU-order u32 emitted after le32_to_cpu",
        }
    )
    limits: list[str] = Field(
        default_factory=lambda: [
            "explicit layout provenance selects archived source semantics; running source/build match unverified",
            "descriptor WLAN index/band do not identify a resolved host WCID, MLO link or interface incarnation",
            "decrypted_candidate/integrity_ok describe raw bits only; PN/replay, executed validation and delivery remain separate",
            "SEC_DONE is raw metadata, not replay acceptance; status flags from boundary hooks remain uninterpreted",
        ]
    )


def decode_descriptor(words: dict[str, str], *, layout_provenance: object = None) -> DescriptorDecode:
    """Fail closed per word, preserving malformed/missing data and every undecoded raw word."""
    raw = {word: words[word] for word in WORDS if word in words}
    out = DescriptorDecode(raw_words=raw)
    parsed: dict[str, int] = {}
    for word in WORDS:
        value = raw.get(word)
        if value is None:
            out.missing_words.append(word)
        elif not _U32.fullmatch(value):
            out.invalid_words.append(word)
        else:
            number = int(value, 16 if value.lower().startswith("0x") else 10)
            if number > 0xFFFFFFFF:
                out.invalid_words.append(word)
            else:
                parsed[word] = number
    out.complete = len(parsed) == len(WORDS)
    if not isinstance(layout_provenance, dict) or (
        layout_provenance.get("file") != "mt76_connac3_mac.h"
        or layout_provenance.get("file_sha256") != SOURCE_SHA256["mt76_connac3_mac.h"]
    ):
        return out
    out.layout_match = "matched"
    if (
        layout_provenance.get("consumer_file") == "mt7925/mac.c"
        and layout_provenance.get("consumer_file_sha256") == SOURCE_SHA256["mt7925/mac.c"]
    ):
        out.consumer_match = "matched"
    for field, (word, mask, shift, boolean) in MASKS.items():
        word_value = parsed.get(word)
        extracted = (word_value & mask) >> shift if word_value is not None else None
        out.fields[field] = bool(extracted) if boolean and extracted is not None else extracted
    f = out.fields
    # MT_RXD3_NORMAL_U2M is BIT(0) of the extracted address-type field.
    f["unicast"] = f["addr_type"] == 1 if f["addr_type"] is not None else None
    errors = [f[name] for name in ("icv_err", "tkip_mic_err", "fcs_err")]
    f["integrity_ok"] = not any(errors) if all(v is not None for v in errors) else None
    f["decrypted_candidate"] = None
    if out.consumer_match == "matched" and all(f[k] is not None for k in ("sec_mode", "clm", "cm")):
        f["decrypted_candidate"] = f["sec_mode"] != 0 and not (f["clm"] or f["cm"])
    return out
