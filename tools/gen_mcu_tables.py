#!/usr/bin/env python3
"""Generate WHD's MCU command/TLV name tables from a driver source tree (read-only).

    tools/gen_mcu_tables.py --src /path/to/mt76 --out backend/src/whd/mlo/definitions/mcu_ids.json

Names and numbers come from the enums in mt76_connac_mcu.h of the tree you point at; the output records the file's git
blob hash and the tree's commit so a decode can be tied to the source it was generated from. The tree is never written.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import subprocess
from pathlib import Path

ENUMS = {
    "uni_cmd": r"MCU_UNI_CMD_DEV_INFO_UPDATE",
    "uni_bss_info_tag": r"UNI_BSS_INFO_BASIC",
    "sta_rec_tag": r"STA_REC_BASIC",
    "uni_dev_info_tag": r"UNI_DEV_INFO_ACTIVE",
}
FLAG_UNI = 0x20000  # __MCU_CMD_FIELD_UNI: BIT(17), set in every unified command word the driver prints


def parse_enum(text: str, first: str) -> dict[str, int]:
    m = re.search(r"enum\s*(?:\w+\s*)?\{[^{}]*?\b" + first + r"\b[^{}]*\}", text, re.S)
    if not m:
        return {}
    body = re.sub(r"/\*.*?\*/|//[^\n]*", "", m.group(0), flags=re.S)
    body = body[body.index("{") + 1 : body.rindex("}")]
    out: dict[str, int] = {}
    cur: int | None = -1
    for item in body.split(","):
        item = item.strip()
        if not item:
            continue
        name, _, val = item.partition("=")
        name = name.strip()
        if not re.fullmatch(r"[A-Za-z_]\w*", name):
            continue
        val = val.strip()
        if val:
            try:
                cur = int(val, 0)
            except ValueError:
                cur = None
                continue  # an expression we do not evaluate; skipped, never guessed
        else:
            if cur is None:
                continue
            cur += 1
        out[name] = cur
    return out


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--src", required=True)
    ap.add_argument("--out", required=True)
    a = ap.parse_args()
    src = Path(a.src)
    hdr = src / "mt76_connac_mcu.h"
    text = hdr.read_text()

    def git(*args: str) -> str:
        return subprocess.run(["git", "-C", str(src), *args], capture_output=True, text=True, check=False).stdout.strip()

    tables = {k: parse_enum(text, v) for k, v in ENUMS.items()}
    doc = {
        "source": {
            "file": "mt76_connac_mcu.h",
            "git_commit": git("rev-parse", "--short=12", "HEAD"),
            "blob_sha1": git("hash-object", str(hdr)),
            "tree_dirty": bool(git("status", "--porcelain", "--untracked-files=no")),
            "tree_diff_sha256": hashlib.sha256(git("diff", "HEAD").encode()).hexdigest(),
            "note": "decode tables for the tree this was generated from; the running binary's build is recorded "
            "separately (module build id) and a match is not asserted",
        },
        "uni_cmd_flag": FLAG_UNI,
        "tables": {k: {n: v for n, v in t.items()} for k, t in tables.items()},
    }
    Path(a.out).parent.mkdir(parents=True, exist_ok=True)
    Path(a.out).write_text(json.dumps(doc, indent=1, sort_keys=True) + "\n")
    print({k: len(v) for k, v in tables.items()}, doc["source"]["git_commit"])


if __name__ == "__main__":
    main()
