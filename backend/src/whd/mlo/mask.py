"""Decode the driver's packed MLO link mask.

Source basis (read-only, matched to the build that exposes a readable `mlo_active_links` debugfs file): the getter
packs `vif->active_links | vif->valid_links << 16` (mt7925/debugfs.c, mt7925_get_links_iter): bits 15:0 are mac80211's
active links, bits 31:16 are the links valid (negotiated) for the MLD. Stock drivers expose no readable file at all.

The layout cannot be verified against the running binary, so it is inferred from the value and reported with its basis:
a non-zero upper half is the packed form; a non-zero lower half with an empty upper half is not decodable as packed
(an MLD cannot have active links without valid links) and is reported as an active-only mask of unknown layout.
"""

from __future__ import annotations

from typing import Literal

from whd.model.common import Model

Layout = Literal["packed_active_valid", "active_only_unverified", "zero", "unreadable"]

BASIS = (
    "bits 15:0 = mac80211 active_links, bits 31:16 = valid_links "
    "(driver getter packs active_links | valid_links << 16; not verifiable against the running binary)"
)


class MaskDecode(Model):
    raw: int | None
    layout: Layout
    active: list[int] | None  # None = UNKNOWN
    valid: list[int] | None
    consistent: bool | None  # active ⊆ valid; None when it cannot be judged
    basis: str
    notes: list[str]


def bits(mask: int) -> list[int]:
    return [i for i in range(32) if mask & (1 << i)]


def decode_active_links(raw: int | None) -> MaskDecode:
    if raw is None:
        return MaskDecode(
            raw=None,
            layout="unreadable",
            active=None,
            valid=None,
            consistent=None,
            basis=BASIS,
            notes=["the file could not be read, so active and valid links are UNKNOWN"],
        )
    if raw < 0 or raw > 0xFFFFFFFF:
        return MaskDecode(
            raw=raw,
            layout="unreadable",
            active=None,
            valid=None,
            consistent=None,
            basis=BASIS,
            notes=["value does not fit 32 bits; not decoded"],
        )
    lo, hi = raw & 0xFFFF, (raw >> 16) & 0xFFFF
    if raw == 0:
        return MaskDecode(
            raw=0,
            layout="zero",
            active=None,
            valid=None,
            consistent=None,
            basis=BASIS,
            notes=[
                "zero: the getter returns 0 when no station MLD interface exists, which is indistinguishable "
                "from an MLD with nothing active; both are UNKNOWN here"
            ],
        )
    if hi:
        act, val = bits(lo), bits(hi)
        ok = (lo & ~hi) == 0
        notes = [] if ok else [f"active links {bits(lo & ~hi)} are not in the valid set {val}: inconsistent"]
        return MaskDecode(
            raw=raw,
            layout="packed_active_valid",
            active=act,
            valid=val,
            consistent=ok,
            basis=BASIS,
            notes=notes,
        )
    return MaskDecode(
        raw=raw,
        layout="active_only_unverified",
        active=None,
        valid=None,
        consistent=None,
        basis=BASIS,
        notes=[
            f"0x{raw:x} has no upper half, so it does not match the packed layout; it may be an older active-only "
            "mask but that cannot be verified, so active and valid links are UNKNOWN"
        ],
    )
