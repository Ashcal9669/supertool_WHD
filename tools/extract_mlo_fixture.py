#!/usr/bin/env python3
"""Extract a bounded, scrubbed slice of REAL events from a WHD event database into a test fixture.

    tools/extract_mlo_fixture.py --db ~/.local/state/whd/whd.db --ids 14440202:14440420 --out backend/tests/fixtures/mlo/x.jsonl

The database is opened read-only. Every MAC address becomes a stable synthetic one, IPv4/IPv6 addresses and hashed
kernel pointers are masked, and the output records which id range it came from. Nothing else is altered, so parsers are
tested against what the driver and kernel really printed.
"""

from __future__ import annotations

import argparse
import json
import re
import sqlite3
from pathlib import Path

MAC = re.compile(r"(?i)\b[0-9a-f]{2}(?::[0-9a-f]{2}){5}\b")
IP4 = re.compile(r"\b\d{1,3}(?:\.\d{1,3}){3}\b")
IP6 = re.compile(r"(?i)\b(?:[0-9a-f]{1,4}:){7}[0-9a-f]{1,4}\b|(?<![0-9a-z])(?:[0-9a-f]{1,4}:){1,6}:(?:[0-9a-f]{1,4}(?::[0-9a-f]{1,4}){0,5})?")
KEYFP = re.compile(r"keyfp=\w+")  # derived from key material: never copied
PTR = re.compile(r"\b(?:ffff[0-9a-f]{12}|0{8}[0-9a-f]{8})\b")


def scrub(text: str, macs: dict[str, str]) -> str:
    def m(mo: re.Match[str]) -> str:
        k = mo.group(0).lower()
        if k in ("ff:ff:ff:ff:ff:ff", "00:00:00:00:00:00"):
            return k
        if k not in macs:
            n = len(macs) + 1
            macs[k] = f"02:00:5e:20:{(n >> 8) & 0xFF:02x}:{n & 0xFF:02x}"
        return macs[k]

    text = MAC.sub(m, text)
    text = IP6.sub("<ip6>", text)
    text = IP4.sub("<ip4>", text)
    text = KEYFP.sub("keyfp=<redacted>", text)
    return PTR.sub("<ptr>", text)


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--db", required=True)
    ap.add_argument("--ids", action="append", required=True, help="first:last event id (repeatable)")
    ap.add_argument("--out", required=True)
    ap.add_argument("--max", type=int, default=3000)
    a = ap.parse_args()
    con = sqlite3.connect(f"file:{a.db}?mode=ro", uri=True)
    macs: dict[str, str] = {}
    rows: list[str] = []
    for rng in a.ids:
        lo, hi = (int(x) for x in rng.split(":"))
        for (js,) in con.execute("SELECT json FROM events WHERE id BETWEEN ? AND ? ORDER BY id", (lo, hi)):
            rows.append(scrub(js, macs))
            if len(rows) >= a.max:
                break
    out = Path(a.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text("\n".join(rows) + "\n")
    meta = {"source": "real events from a WHD database (read-only)", "id_ranges": a.ids, "events": len(rows),
            "macs_masked": len(macs)}
    out.with_suffix(".meta.json").write_text(json.dumps(meta, indent=1) + "\n")
    print(json.dumps(meta))


if __name__ == "__main__":
    main()
