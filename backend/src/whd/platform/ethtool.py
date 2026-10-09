"""ETHTOOL_GDRVINFO via the SIOCETHTOOL ioctl (unprivileged, read-only)."""

from __future__ import annotations

import ctypes
import fcntl
import socket
import struct

from whd.platform.kconsts import ethtool as E
from whd.platform.kconsts import sockios

# struct ethtool_drvinfo: cmd, driver[32], version[32], fw_version[FWVERS_LEN], bus_info[BUSINFO_LEN],
#                         erom_version[32], reserved2[12], n_priv_flags, n_stats, testinfo_len,
#                         eedump_len, regdump_len
_DRVINFO = struct.Struct(f"=I32s32s{E.ETHTOOL_FWVERS_LEN}s{E.ETHTOOL_BUSINFO_LEN}s32s12sIIIII")
IFNAMSIZ = 16


def _cstr(b: bytes) -> str:
    return b.split(b"\0", 1)[0].decode(errors="replace")


def get_drvinfo(ifname: str) -> dict[str, str | int]:
    """Raises OSError on failure (e.g. EOPNOTSUPP, ENODEV)."""
    buf = ctypes.create_string_buffer(_DRVINFO.pack(E.ETHTOOL_GDRVINFO, *([b""] * 6), 0, 0, 0, 0, 0))
    ifr = struct.pack(f"{IFNAMSIZ}sP", ifname.encode()[: IFNAMSIZ - 1], ctypes.addressof(buf))
    ifr += b"\0" * (40 - len(ifr))
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        fcntl.ioctl(s.fileno(), sockios.SIOCETHTOOL, ifr)
    (_, drv, ver, fw, bus, erom, _, npriv, nstats, testlen, eelen, reglen) = _DRVINFO.unpack(
        buf.raw[: _DRVINFO.size]
    )
    return {
        "driver": _cstr(drv),
        "version": _cstr(ver),
        "fw_version": _cstr(fw),
        "bus_info": _cstr(bus),
        "erom_version": _cstr(erom),
        "n_stats": nstats,
        "n_priv_flags": npriv,
        "regdump_len": reglen,
        "eedump_len": eelen,
        "testinfo_len": testlen,
    }
