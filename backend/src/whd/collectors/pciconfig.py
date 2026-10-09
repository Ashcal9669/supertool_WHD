"""Decode PCI/PCIe configuration space bytes (read-only) using pci_regs.h constants.

Input is the raw `config` contents as read by whd-helper (up to 4096 bytes). With
only 64 bytes (unprivileged), just the standard header is decoded.
"""

from __future__ import annotations

import struct
from typing import Any

from whd.model.device import DecodedRegister, PciCapability, PciConfig
from whd.platform.kconsts import pci_regs as R

CAP_NAMES = {
    v: k.removeprefix("PCI_CAP_ID_")
    for k, v in R.DEFINES.items()
    if k.startswith("PCI_CAP_ID_") and k != "PCI_CAP_ID_MAX"
}
EXT_CAP_NAMES = {
    v: k.removeprefix("PCI_EXT_CAP_ID_")
    for k, v in R.DEFINES.items()
    if k.startswith("PCI_EXT_CAP_ID_") and k != "PCI_EXT_CAP_ID_MAX"
}
# PCIe base spec link speed encoding (Link Status Current Link Speed / Link Capabilities SLS)
SPEED = {1: "2.5 GT/s", 2: "5.0 GT/s", 3: "8.0 GT/s", 4: "16.0 GT/s", 5: "32.0 GT/s", 6: "64.0 GT/s"}
PORT_TYPES = {
    v: k.removeprefix("PCI_EXP_TYPE_") for k, v in R.DEFINES.items() if k.startswith("PCI_EXP_TYPE_")
}
DSTATE = {0: "D0", 1: "D1", 2: "D2", 3: "D3hot"}


def _u8(d: bytes, o: int) -> int:
    return d[o] if o < len(d) else 0


def _u16(d: bytes, o: int) -> int | None:
    return struct.unpack_from("<H", d, o)[0] if o + 2 <= len(d) else None


def _u32(d: bytes, o: int) -> int | None:
    return struct.unpack_from("<I", d, o)[0] if o + 4 <= len(d) else None


def _bits(value: int, prefix: str, exclude: tuple[str, ...] = ()) -> list[str]:
    """Names of single-bit defines with the given prefix set in value."""
    out = []
    for k, v in R.DEFINES.items():
        if not k.startswith(prefix) or any(k.endswith(x) for x in exclude):
            continue
        if v and (v & (v - 1)) == 0 and value & v:
            out.append(k.removeprefix(prefix))
    return out


def _field(value: int, mask: int) -> int:
    if not mask:
        return 0
    shift = (mask & -mask).bit_length() - 1
    return (value & mask) >> shift


def walk_capabilities(d: bytes) -> list[PciCapability]:
    caps: list[PciCapability] = []
    status = _u16(d, R.PCI_STATUS) or 0
    if status & R.PCI_STATUS_CAP_LIST and len(d) > R.PCI_CAPABILITY_LIST:
        ptr = _u8(d, R.PCI_CAPABILITY_LIST) & ~3
        seen: set[int] = set()
        while 0x40 <= ptr < min(len(d), 256) and ptr not in seen:
            seen.add(ptr)
            cid = _u8(d, ptr)
            caps.append(PciCapability(id=cid, name=CAP_NAMES.get(cid, f"0x{cid:02x}"), offset=ptr))
            ptr = _u8(d, ptr + 1) & ~3
    if len(d) > R.PCI_CFG_SPACE_SIZE:
        off = R.PCI_CFG_SPACE_SIZE
        seen = set()
        while off and off + 4 <= len(d) and off not in seen:
            seen.add(off)
            h = _u32(d, off) or 0
            if h in (0, 0xFFFFFFFF):
                break
            cid, ver, nxt = h & 0xFFFF, (h >> 16) & 0xF, (h >> 20) & 0xFFC
            caps.append(
                PciCapability(
                    id=cid,
                    name=EXT_CAP_NAMES.get(cid, f"0x{cid:04x}"),
                    offset=off,
                    extended=True,
                    version=ver,
                )
            )
            off = nxt if nxt >= R.PCI_CFG_SPACE_SIZE else 0
    return caps


def _reg(
    regs: list[DecodedRegister], name: str, off: int, val: int | None, width: int, fields: dict[str, Any]
) -> None:
    if val is not None:
        regs.append(DecodedRegister(name=name, offset=off, raw_hex=f"0x{val:0{width * 2}x}", fields=fields))


def decode_config(d: bytes) -> PciConfig:
    cfg = PciConfig(length=len(d), raw_hex=d.hex())
    regs: list[DecodedRegister] = []
    cmd, sts = _u16(d, R.PCI_COMMAND), _u16(d, R.PCI_STATUS)
    _reg(regs, "COMMAND", R.PCI_COMMAND, cmd, 2, {"set": " ".join(_bits(cmd or 0, "PCI_COMMAND_"))})
    _reg(regs, "STATUS", R.PCI_STATUS, sts, 2, {"set": " ".join(_bits(sts or 0, "PCI_STATUS_"))})
    caps = walk_capabilities(d)
    cfg.capabilities = caps
    for c in caps:
        o = c.offset
        if not c.extended and c.id == R.PCI_CAP_ID_EXP:
            flags = _u16(d, o + R.PCI_EXP_FLAGS) or 0
            ptype = _field(flags, R.PCI_EXP_FLAGS_TYPE)
            devcap = _u32(d, o + R.PCI_EXP_DEVCAP)
            devctl = _u16(d, o + R.PCI_EXP_DEVCTL)
            devsta = _u16(d, o + R.PCI_EXP_DEVSTA)
            lnkcap = _u32(d, o + R.PCI_EXP_LNKCAP)
            lnkctl = _u16(d, o + R.PCI_EXP_LNKCTL)
            lnksta = _u16(d, o + R.PCI_EXP_LNKSTA)
            lnkcap2 = _u32(d, o + R.PCI_EXP_LNKCAP2)
            lnkctl2 = _u16(d, o + R.PCI_EXP_LNKCTL2)
            devctl2 = _u16(d, o + R.PCI_EXP_DEVCTL2)
            _reg(
                regs, "EXP_FLAGS", o + R.PCI_EXP_FLAGS, flags, 2, {"port_type": PORT_TYPES.get(ptype, ptype)}
            )
            if devcap is not None:
                _reg(
                    regs,
                    "EXP_DEVCAP",
                    o + R.PCI_EXP_DEVCAP,
                    devcap,
                    4,
                    {
                        "max_payload": 128 << _field(devcap, R.PCI_EXP_DEVCAP_PAYLOAD),
                        "flr": bool(devcap & R.PCI_EXP_DEVCAP_FLR),
                    },
                )
            if devctl is not None:
                _reg(
                    regs,
                    "EXP_DEVCTL",
                    o + R.PCI_EXP_DEVCTL,
                    devctl,
                    2,
                    {
                        "max_payload": 128 << _field(devctl, R.PCI_EXP_DEVCTL_PAYLOAD),
                        "max_read_req": 128 << _field(devctl, R.PCI_EXP_DEVCTL_READRQ),
                        "set": " ".join(_bits(devctl, "PCI_EXP_DEVCTL_", ("_PAYLOAD", "_READRQ"))),
                    },
                )
            if devsta is not None:
                _reg(
                    regs,
                    "EXP_DEVSTA",
                    o + R.PCI_EXP_DEVSTA,
                    devsta,
                    2,
                    {"set": " ".join(_bits(devsta, "PCI_EXP_DEVSTA_"))},
                )
            if lnkcap is not None:
                aspms = _field(lnkcap, R.PCI_EXP_LNKCAP_ASPMS)
                cfg.link.update(
                    {
                        "port_type": PORT_TYPES.get(ptype, ptype),
                        "cap_max_speed": SPEED.get(lnkcap & R.PCI_EXP_LNKCAP_SLS, f"code {lnkcap & 15}"),
                        "cap_max_width": _field(lnkcap, R.PCI_EXP_LNKCAP_MLW),
                        "cap_port_number": lnkcap >> 24,
                        "cap_clock_pm": bool(lnkcap & R.PCI_EXP_LNKCAP_CLKPM),
                        "cap_dll_active_reporting": bool(lnkcap & R.PCI_EXP_LNKCAP_DLLLARC),
                    }
                )
                cfg.aspm.update(
                    {
                        "l0s_supported": bool(lnkcap & R.PCI_EXP_LNKCAP_ASPM_L0S),
                        "l1_supported": bool(lnkcap & R.PCI_EXP_LNKCAP_ASPM_L1),
                        "l0s_exit_latency_code": _field(lnkcap, R.PCI_EXP_LNKCAP_L0SEL),
                        "l1_exit_latency_code": _field(lnkcap, R.PCI_EXP_LNKCAP_L1EL),
                    }
                )
                _reg(regs, "EXP_LNKCAP", o + R.PCI_EXP_LNKCAP, lnkcap, 4, {"aspm_support": aspms})
            if lnkctl is not None:
                cfg.aspm.update(
                    {
                        "l0s_enabled": bool(lnkctl & R.PCI_EXP_LNKCTL_ASPM_L0S),
                        "l1_enabled": bool(lnkctl & R.PCI_EXP_LNKCTL_ASPM_L1),
                        "clkreq_enabled": bool(lnkctl & R.PCI_EXP_LNKCTL_CLKREQ_EN),
                    }
                )
                cfg.link.update(
                    {
                        "ctl_link_disabled": bool(lnkctl & R.PCI_EXP_LNKCTL_LD),
                        "ctl_common_clock": bool(lnkctl & R.PCI_EXP_LNKCTL_CCC),
                    }
                )
                _reg(
                    regs,
                    "EXP_LNKCTL",
                    o + R.PCI_EXP_LNKCTL,
                    lnkctl,
                    2,
                    {"set": " ".join(_bits(lnkctl, "PCI_EXP_LNKCTL_", ("_ASPMC",)))},
                )
            if lnksta is not None:
                cfg.link.update(
                    {
                        "sta_speed": SPEED.get(lnksta & R.PCI_EXP_LNKSTA_CLS, f"code {lnksta & 15}"),
                        "sta_width": _field(lnksta, R.PCI_EXP_LNKSTA_NLW),
                        "sta_training": bool(lnksta & R.PCI_EXP_LNKSTA_LT),
                        "sta_dll_link_active": bool(lnksta & R.PCI_EXP_LNKSTA_DLLLA),
                        "sta_bandwidth_mgmt": bool(lnksta & R.PCI_EXP_LNKSTA_LBMS),
                        "sta_autonomous_bw": bool(lnksta & R.PCI_EXP_LNKSTA_LABS),
                    }
                )
                _reg(
                    regs,
                    "EXP_LNKSTA",
                    o + R.PCI_EXP_LNKSTA,
                    lnksta,
                    2,
                    {"set": " ".join(_bits(lnksta, "PCI_EXP_LNKSTA_", ("_CLS", "_NLW")))},
                )
            if lnkcap2:
                vec = _field(lnkcap2, R.PCI_EXP_LNKCAP2_SLS)
                cfg.link["cap2_supported_speeds"] = [
                    SPEED[i + 1] for i in range(7) if vec & (1 << i) and i + 1 in SPEED
                ]
                _reg(regs, "EXP_LNKCAP2", o + R.PCI_EXP_LNKCAP2, lnkcap2, 4, {})
            if lnkctl2 is not None and lnkcap2:
                cfg.link["ctl2_target_speed"] = SPEED.get(lnkctl2 & 0xF, f"code {lnkctl2 & 15}")
                _reg(regs, "EXP_LNKCTL2", o + R.PCI_EXP_LNKCTL2, lnkctl2, 2, {})
            if devctl2 is not None:
                cfg.link["ltr_enabled"] = bool(devctl2 & R.PCI_EXP_DEVCTL2_LTR_EN)
        elif not c.extended and c.id == R.PCI_CAP_ID_MSI:
            fl = _u16(d, o + R.PCI_MSI_FLAGS) or 0
            cfg.msi = {
                "enabled": bool(fl & R.PCI_MSI_FLAGS_ENABLE),
                "vectors_capable": 1 << _field(fl, R.PCI_MSI_FLAGS_QMASK),
                "vectors_enabled": 1 << _field(fl, R.PCI_MSI_FLAGS_QSIZE),
                "64bit": bool(fl & R.PCI_MSI_FLAGS_64BIT),
                "per_vector_masking": bool(fl & R.PCI_MSI_FLAGS_MASKBIT),
            }
            _reg(regs, "MSI_FLAGS", o + R.PCI_MSI_FLAGS, fl, 2, dict(cfg.msi))
        elif not c.extended and c.id == R.PCI_CAP_ID_MSIX:
            fl = _u16(d, o + R.PCI_MSIX_FLAGS) or 0
            tbl = _u32(d, o + R.PCI_MSIX_TABLE) or 0
            pba = _u32(d, o + R.PCI_MSIX_PBA) or 0
            cfg.msix = {
                "enabled": bool(fl & R.PCI_MSIX_FLAGS_ENABLE),
                "function_masked": bool(fl & R.PCI_MSIX_FLAGS_MASKALL),
                "table_size": _field(fl, R.PCI_MSIX_FLAGS_QSIZE) + 1,
                "table_bir": tbl & R.PCI_MSIX_TABLE_BIR,
                "table_offset": f"0x{tbl & ~7:x}",
                "pba_bir": pba & 7,
                "pba_offset": f"0x{pba & ~7:x}",
            }
            _reg(regs, "MSIX_FLAGS", o + R.PCI_MSIX_FLAGS, fl, 2, dict(cfg.msix))
        elif not c.extended and c.id == R.PCI_CAP_ID_PM:
            pmc = _u16(d, o + R.PCI_PM_PMC) or 0
            ctl = _u16(d, o + R.PCI_PM_CTRL) or 0
            cfg.pm = {
                "version": pmc & R.PCI_PM_CAP_VER_MASK,
                "d1_support": bool(pmc & R.PCI_PM_CAP_D1),
                "d2_support": bool(pmc & R.PCI_PM_CAP_D2),
                "pme_support_mask": f"0x{_field(pmc, R.PCI_PM_CAP_PME_MASK):x}",
                "power_state": DSTATE[ctl & R.PCI_PM_CTRL_STATE_MASK],
                "no_soft_reset": bool(ctl & R.PCI_PM_CTRL_NO_SOFT_RESET),
                "pme_enabled": bool(ctl & R.PCI_PM_CTRL_PME_ENABLE),
                "pme_status": bool(ctl & R.PCI_PM_CTRL_PME_STATUS),
            }
            _reg(regs, "PM_CTRL", o + R.PCI_PM_CTRL, ctl, 2, dict(cfg.pm))
        elif c.extended and c.id == R.PCI_EXT_CAP_ID_ERR:
            us, um, usv = (
                _u32(d, o + x) for x in (R.PCI_ERR_UNCOR_STATUS, R.PCI_ERR_UNCOR_MASK, R.PCI_ERR_UNCOR_SEVER)
            )
            cs, cm, cap = (_u32(d, o + x) for x in (R.PCI_ERR_COR_STATUS, R.PCI_ERR_COR_MASK, R.PCI_ERR_CAP))
            hdr = d[o + R.PCI_ERR_HEADER_LOG : o + R.PCI_ERR_HEADER_LOG + 16]
            cfg.aer = {
                "uncorrectable_status": _bits(us or 0, "PCI_ERR_UNC_"),
                "uncorrectable_mask": _bits(um or 0, "PCI_ERR_UNC_"),
                "uncorrectable_fatal_severity": _bits(usv or 0, "PCI_ERR_UNC_"),
                "correctable_status": _bits(cs or 0, "PCI_ERR_COR_", ("_STATUS", "_MASK")),
                "correctable_mask": _bits(cm or 0, "PCI_ERR_COR_", ("_STATUS", "_MASK")),
                "first_error_pointer": (cap or 0) & 0x1F,
                "header_log": hdr.hex() if any(hdr) else None,
            }
            _reg(regs, "AER_UNCOR_STATUS", o + R.PCI_ERR_UNCOR_STATUS, us, 4, {})
            _reg(regs, "AER_COR_STATUS", o + R.PCI_ERR_COR_STATUS, cs, 4, {})
        elif c.extended and c.id == R.PCI_EXT_CAP_ID_L1SS:
            l1cap = _u32(d, o + R.PCI_L1SS_CAP) or 0
            ctl1 = _u32(d, o + R.PCI_L1SS_CTL1) or 0
            cfg.l1ss = {
                "cap_aspm_l1_1": bool(l1cap & R.PCI_L1SS_CAP_ASPM_L1_1),
                "cap_aspm_l1_2": bool(l1cap & R.PCI_L1SS_CAP_ASPM_L1_2),
                "cap_pcipm_l1_1": bool(l1cap & R.PCI_L1SS_CAP_PCIPM_L1_1),
                "cap_pcipm_l1_2": bool(l1cap & R.PCI_L1SS_CAP_PCIPM_L1_2),
                "aspm_l1_1_enabled": bool(ctl1 & R.PCI_L1SS_CTL1_ASPM_L1_1),
                "aspm_l1_2_enabled": bool(ctl1 & R.PCI_L1SS_CTL1_ASPM_L1_2),
                "pcipm_l1_1_enabled": bool(ctl1 & R.PCI_L1SS_CTL1_PCIPM_L1_1),
                "pcipm_l1_2_enabled": bool(ctl1 & R.PCI_L1SS_CTL1_PCIPM_L1_2),
            }
            _reg(regs, "L1SS_CTL1", o + R.PCI_L1SS_CTL1, ctl1, 4, dict(cfg.l1ss))
    cfg.registers = regs
    if len(d) <= 64:
        cfg.meta.availability = "partial"
        cfg.meta.note = "Only the 64-byte standard header was readable (unprivileged)"
    return cfg
