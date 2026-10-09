#!/usr/bin/env python3
"""Generate Python constant modules from Linux kernel headers.

WHD never hand-types protocol constants: nl80211 attribute IDs, IEEE 802.11
capability bits and PCI register offsets are extracted from the kernel headers
by this script and written to backend/src/whd/platform/kconsts/.

Usage:
    tools/gen_kernel_consts.py [--headers /usr/src/linux-headers-$(uname -r)]

The header tree path and kernel release are recorded in each generated file.
"""

from __future__ import annotations

import argparse
import ast
import operator
import os
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
OUT = ROOT / "backend" / "src" / "whd" / "platform" / "kconsts"

_OPS = {
    ast.Add: operator.add,
    ast.Sub: operator.sub,
    ast.Mult: operator.mul,
    ast.LShift: operator.lshift,
    ast.RShift: operator.rshift,
    ast.BitOr: operator.or_,
    ast.BitAnd: operator.and_,
    ast.BitXor: operator.xor,
}


def _eval(expr: str, names: dict[str, int]) -> int | None:
    expr = expr.strip()
    expr = re.sub(r"\b(0[xX][0-9a-fA-F]+|\d+)[uUlL]+\b", r"\1", expr)
    expr = re.sub(r"\(\s*(?:u8|u16|u32|u64|__u8|__u16|__u32|__u64|unsigned\s+\w*|int)\s*\)", "", expr)
    expr = re.sub(r"\bSUITE\(([^(),]+),([^(),]+)\)", r"(((\1) << 8) | (\2))", expr)
    expr = re.sub(r"\bBIT\(([^()]+)\)", r"(1 << (\1))", expr)
    expr = re.sub(r"\bBIT_ULL\(([^()]+)\)", r"(1 << (\1))", expr)
    try:
        tree = ast.parse(expr, mode="eval")
    except SyntaxError:
        return None

    def ev(node: ast.AST) -> int:
        if isinstance(node, ast.Expression):
            return ev(node.body)
        if isinstance(node, ast.Constant) and isinstance(node.value, int):
            return node.value
        if isinstance(node, ast.Name):
            if node.id in names:
                return names[node.id]
            raise KeyError(node.id)
        if isinstance(node, ast.BinOp) and type(node.op) in _OPS:
            return int(_OPS[type(node.op)](ev(node.left), ev(node.right)))
        if isinstance(node, ast.UnaryOp) and isinstance(node.op, ast.USub):
            return -ev(node.operand)
        if isinstance(node, ast.UnaryOp) and isinstance(node.op, ast.Invert):
            return ~ev(node.operand)
        raise ValueError(ast.dump(node))

    try:
        return ev(tree)
    except (KeyError, ValueError, ZeroDivisionError):
        return None


def _strip_comments(text: str) -> str:
    text = re.sub(r"/\*.*?\*/", " ", text, flags=re.S)
    return re.sub(r"//[^\n]*", " ", text)


def parse_header(path: Path, names: dict[str, int]) -> tuple[dict[str, dict[str, int]], dict[str, int], dict[str, str]]:
    """Return (enums, numeric defines, string defines). `names` is updated in place."""
    raw = path.read_text(errors="replace")
    text = _strip_comments(raw)
    # Join continued lines for #define.
    text = re.sub(r"\\\n", " ", text)
    enums: dict[str, dict[str, int]] = {}
    num_defs: dict[str, int] = {}
    str_defs: dict[str, str] = {}

    # Defines first pass (in order), enums are interleaved; do a combined scan by position.
    tokens: list[tuple[int, str, re.Match[str]]] = []
    for m in re.finditer(r"^[ \t]*#[ \t]*define[ \t]+(\w+)(\([^)]*\))?[ \t]+(.+)$", text, flags=re.M):
        tokens.append((m.start(), "define", m))
    for m in re.finditer(r"\benum\s*(\w*)\s*\{(.*?)\}\s*;", text, flags=re.S):
        tokens.append((m.start(), "enum", m))
    tokens.sort(key=lambda t: t[0])

    pending_defines: list[tuple[str, str]] = []
    for _, kind, m in tokens:
        if kind == "define":
            name, params, value = m.group(1), m.group(2), m.group(3).strip()
            if params:
                continue
            sm = re.fullmatch(r'"([^"]*)"', value)
            if sm:
                str_defs[name] = sm.group(1)
                continue
            v = _eval(value, names)
            if v is None:
                pending_defines.append((name, value))
            else:
                num_defs[name] = v
                names[name] = v
        else:
            ename, body = m.group(1) or f"_anon_{m.start()}", m.group(2)
            body = re.sub(r"^[ \t]*#.*$", "", body, flags=re.M)
            members: dict[str, int] = {}
            nxt = 0
            for part in body.split(","):
                part = part.strip()
                if not part:
                    continue
                if "=" in part:
                    k, expr = part.split("=", 1)
                    k = k.strip()
                    v = _eval(expr, names)
                    if v is None:
                        continue
                else:
                    k, v = part, nxt
                if not re.fullmatch(r"\w+", k):
                    continue
                members[k] = v
                names[k] = v
                nxt = v + 1
            enums[ename] = members
    # Resolve defines that referenced later enum members.
    for _ in range(3):
        still: list[tuple[str, str]] = []
        for name, value in pending_defines:
            v = _eval(value, names)
            if v is None:
                still.append((name, value))
            else:
                num_defs[name] = v
                names[name] = v
        pending_defines = still
    return enums, num_defs, str_defs


def emit(out: Path, header_desc: str, enums: dict[str, dict[str, int]], defs: dict[str, int],
         sdefs: dict[str, str], define_filter: re.Pattern[str] | None) -> None:
    lines = [
        '"""GENERATED by tools/gen_kernel_consts.py -- do not edit.',
        "",
        f"Source: {header_desc}",
        '"""',
        "",
        "# ruff: noqa: E501",
        "from __future__ import annotations",
        "",
    ]
    for ename in sorted(enums):
        lines.append(f"# enum {ename}")
        for k, v in enums[ename].items():
            lines.append(f"{k} = {v}")
        lines.append("")
    if defs:
        lines.append("# numeric #defines")
        for k, v in defs.items():
            if define_filter is None or define_filter.search(k):
                lines.append(f"{k} = {v}")
        lines.append("")
    if sdefs:
        lines.append("# string #defines")
        for k, v in sdefs.items():
            if define_filter is None or define_filter.search(k):
                lines.append(f"{k} = {v!r}")
        lines.append("")
    lines.append("ENUMS: dict[str, dict[str, int]] = {")
    for ename in sorted(enums):
        lines.append(f"    {ename!r}: {{")
        for k, v in enums[ename].items():
            lines.append(f"        {k!r}: {v},")
        lines.append("    },")
    lines.append("}")
    lines.append("")
    lines.append("DEFINES: dict[str, int] = {")
    for k, v in defs.items():
        if define_filter is None or define_filter.search(k):
            lines.append(f"    {k!r}: {v},")
    lines.append("}")
    lines.append("")
    out.write_text("\n".join(lines))


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--headers", default=f"/usr/src/linux-headers-{os.uname().release}")
    args = ap.parse_args()
    h = Path(args.headers)
    if not h.is_dir():
        print(f"header tree not found: {h}", file=sys.stderr)
        return 1
    OUT.mkdir(parents=True, exist_ok=True)
    (OUT / "__init__.py").write_text('"""Kernel constants generated from headers by tools/gen_kernel_consts.py."""\n')
    desc = lambda rel: f"{h / rel} (headers for {h.name})"  # noqa: E731

    names: dict[str, int] = {}
    e, d, s = parse_header(h / "include/uapi/linux/nl80211.h", names)
    emit(OUT / "nl80211.py", desc("include/uapi/linux/nl80211.h"), e, d, s, None)

    names = {}
    allenums: dict[str, dict[str, int]] = {}
    alldefs: dict[str, int] = {}
    srcs = []
    for rel in ["include/linux/ieee80211.h", "include/linux/ieee80211-ht.h", "include/linux/ieee80211-vht.h",
                "include/linux/ieee80211-he.h", "include/linux/ieee80211-eht.h"]:
        p = h / rel
        if not p.exists():
            continue
        srcs.append(rel)
        e, d, _ = parse_header(p, names)
        allenums.update(e)
        alldefs.update(d)
    emit(OUT / "ieee80211.py", ", ".join(str(h / r) for r in srcs), allenums, alldefs, {},
         re.compile(r"^(IEEE80211_(HT_CAP|VHT_CAP|HE_PHY_CAP|HE_MAC_CAP|EHT_PHY_CAP|EHT_MAC_CAP|HT_MCS|VHT_MCS)|WLAN_CIPHER_SUITE_)"))

    base_names: dict[str, int] = {}
    for mod, rel, flt in [
        ("pci_regs", "include/uapi/linux/pci_regs.h", None),
        ("netlink", "include/uapi/linux/netlink.h", None),
        ("genetlink", "include/uapi/linux/genetlink.h", None),
        ("rtnetlink", "include/uapi/linux/rtnetlink.h", None),
        ("if_link", "include/uapi/linux/if_link.h", None),
        ("sockios", "include/uapi/linux/sockios.h", None),
        ("if_flags", "include/uapi/linux/if.h", re.compile(r"^IFF_|^IF_OPER_")),
        ("ethtool", "include/uapi/linux/ethtool.h", re.compile(r"^(ETHTOOL_G|ETHTOOL_FW|ETHTOOL_BUSINFO)")),
        ("ioport", "include/linux/ioport.h", re.compile(r"^IORESOURCE_(IO|MEM|PREFETCH|MEM_64|DISABLED|UNSET|READONLY|BUSY)$")),
        ("usb_ch9", "include/uapi/linux/usb/ch9.h", re.compile(r"^USB_(DT|CLASS|ENDPOINT|DIR|SPEED|REQ)_")),
    ]:
        names = dict(base_names) if mod in ("genetlink", "rtnetlink") else {}
        p = h / rel
        if not p.exists():
            print(f"skip missing {p}", file=sys.stderr)
            continue
        e, d, s = parse_header(p, names)
        if mod == "netlink":
            base_names = dict(names)
        emit(OUT / f"{mod}.py", desc(rel), e, d, s, flt)
    print(f"wrote constants to {OUT}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
