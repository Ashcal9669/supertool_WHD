"""Minimal netlink / generic-netlink client and attribute codec.

Implemented on raw AF_NETLINK sockets so that WHD controls every byte that is
sent: only GET/dump requests and multicast subscriptions are ever issued.
Constants come from kconsts (generated from kernel headers).
"""

from __future__ import annotations

import os
import socket
import struct
from collections.abc import Iterator
from dataclasses import dataclass, field

from whd.platform.kconsts import genetlink as G
from whd.platform.kconsts import netlink as N

NLMSG_HDR = struct.Struct("=IHHII")  # len, type, flags, seq, pid
GENL_HDR = struct.Struct("=BBH")  # cmd, version, reserved
NLA_HDR = struct.Struct("=HH")
NLA_TYPE_MASK = ~(N.NLA_F_NESTED | N.NLA_F_NET_BYTEORDER) & 0xFFFF


def _align(n: int) -> int:
    return (n + 3) & ~3


# ---------------------------------------------------------------------------
# Attribute encoding / decoding
# ---------------------------------------------------------------------------


def nla(atype: int, payload: bytes) -> bytes:
    ln = NLA_HDR.size + len(payload)
    return NLA_HDR.pack(ln, atype) + payload + b"\0" * (_align(ln) - ln)


def nla_u32(atype: int, v: int) -> bytes:
    return nla(atype, struct.pack("=I", v))


def nla_u64(atype: int, v: int) -> bytes:
    return nla(atype, struct.pack("=Q", v))


def nla_str(atype: int, s: str) -> bytes:
    return nla(atype, s.encode() + b"\0")


def nla_flag(atype: int) -> bytes:
    return nla(atype, b"")


def iter_attrs(data: bytes) -> Iterator[tuple[int, bytes]]:
    off = 0
    end = len(data)
    while off + NLA_HDR.size <= end:
        ln, at = NLA_HDR.unpack_from(data, off)
        if ln < NLA_HDR.size or off + ln > end:
            break
        yield at & NLA_TYPE_MASK, data[off + NLA_HDR.size : off + ln]
        off += _align(ln)


@dataclass
class Attrs:
    """Parsed attribute set: type -> payload (last one wins), plus ordered list."""

    items: list[tuple[int, bytes]] = field(default_factory=list)

    @classmethod
    def parse(cls, data: bytes) -> Attrs:
        return cls(list(iter_attrs(data)))

    def get(self, t: int) -> bytes | None:
        v: bytes | None = None
        for at, p in self.items:
            if at == t:
                v = p
        return v

    def has(self, t: int) -> bool:
        return any(at == t for at, _ in self.items)

    def u8(self, t: int) -> int | None:
        p = self.get(t)
        return p[0] if p is not None and len(p) >= 1 else None

    def u16(self, t: int) -> int | None:
        p = self.get(t)
        return int(struct.unpack_from("=H", p)[0]) if p is not None and len(p) >= 2 else None

    def u32(self, t: int) -> int | None:
        p = self.get(t)
        return int(struct.unpack_from("=I", p)[0]) if p is not None and len(p) >= 4 else None

    def s32(self, t: int) -> int | None:
        p = self.get(t)
        return int(struct.unpack_from("=i", p)[0]) if p is not None and len(p) >= 4 else None

    def s8(self, t: int) -> int | None:
        p = self.get(t)
        return int(struct.unpack_from("=b", p)[0]) if p is not None and len(p) >= 1 else None

    def u64(self, t: int) -> int | None:
        p = self.get(t)
        return int(struct.unpack_from("=Q", p)[0]) if p is not None and len(p) >= 8 else None

    def str(self, t: int) -> str | None:
        p = self.get(t)
        return p.split(b"\0", 1)[0].decode(errors="replace") if p is not None else None

    def nested(self, t: int) -> Attrs | None:
        p = self.get(t)
        return Attrs.parse(p) if p is not None else None

    def nested_list(self, t: int) -> list[tuple[int, Attrs]]:
        """For array-of-nested attributes: returns (index, Attrs) per element."""
        p = self.get(t)
        if p is None:
            return []
        return [(i, Attrs.parse(sub)) for i, sub in iter_attrs(p)]

    def types(self) -> list[int]:
        return [t for t, _ in self.items]


# ---------------------------------------------------------------------------
# Messages
# ---------------------------------------------------------------------------


@dataclass
class NlMsg:
    type: int
    flags: int
    seq: int
    pid: int
    payload: bytes


def iter_msgs(buf: bytes) -> Iterator[NlMsg]:
    off = 0
    while off + NLMSG_HDR.size <= len(buf):
        ln, mtype, flags, seq, pid = NLMSG_HDR.unpack_from(buf, off)
        if ln < NLMSG_HDR.size or off + ln > len(buf):
            break
        yield NlMsg(mtype, flags, seq, pid, buf[off + NLMSG_HDR.size : off + ln])
        off += _align(ln)


@dataclass
class GenlMsg:
    cmd: int
    version: int
    attrs: Attrs
    raw: bytes  # genl header + attributes (as recorded in fixtures)

    @classmethod
    def from_payload(cls, payload: bytes) -> GenlMsg:
        cmd, ver, _ = GENL_HDR.unpack_from(payload, 0)
        return cls(cmd, ver, Attrs.parse(payload[GENL_HDR.size :]), payload)


class NetlinkError(Exception):
    def __init__(self, err: int, context: str = "") -> None:
        self.errno = err
        msg = os.strerror(err) if err else "unknown"
        super().__init__(f"netlink error {err} ({msg}) {context}".strip())


# ---------------------------------------------------------------------------
# Sockets
# ---------------------------------------------------------------------------


class GenlSocket:
    """Blocking generic netlink socket for request/dump transactions."""

    def __init__(self, timeout: float = 3.0) -> None:
        self.sock = socket.socket(socket.AF_NETLINK, socket.SOCK_RAW | socket.SOCK_CLOEXEC, N.NETLINK_GENERIC)
        self.sock.settimeout(timeout)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 1 << 20)
        self.sock.bind((0, 0))
        self.seq = 1

    def close(self) -> None:
        self.sock.close()

    def __enter__(self) -> GenlSocket:
        return self

    def __exit__(self, *a: object) -> None:
        self.close()

    def request(
        self, family: int, cmd: int, attrs: bytes = b"", dump: bool = False, version: int = 1
    ) -> list[bytes]:
        """Send a request and collect all reply payloads (genl header + attrs)."""
        self.seq += 1
        seq = self.seq
        flags = N.NLM_F_REQUEST | N.NLM_F_ACK
        if dump:
            flags |= N.NLM_F_DUMP
        body = GENL_HDR.pack(cmd, version, 0) + attrs
        msg = NLMSG_HDR.pack(NLMSG_HDR.size + len(body), family, flags, seq, 0) + body
        self.sock.send(msg)
        out: list[bytes] = []
        while True:
            buf = self.sock.recv(1 << 20)
            for m in iter_msgs(buf):
                if m.seq != seq:
                    continue
                if m.type == N.NLMSG_ERROR:
                    (err,) = struct.unpack_from("=i", m.payload, 0)
                    if err == 0:
                        if not dump:
                            return out
                        continue
                    raise NetlinkError(-err, f"family={family} cmd={cmd}")
                if m.type == N.NLMSG_DONE:
                    return out
                out.append(m.payload)
                if not dump and not (m.flags & N.NLM_F_MULTI):
                    # wait for ACK
                    continue

    def resolve_family(self, name: str) -> tuple[int, dict[str, int]]:
        """Return (family id, multicast group name -> id)."""
        replies = self.request(G.GENL_ID_CTRL, G.CTRL_CMD_GETFAMILY, nla_str(G.CTRL_ATTR_FAMILY_NAME, name))
        if not replies:
            raise NetlinkError(2, f"genl family {name} not found")
        m = GenlMsg.from_payload(replies[0])
        fid = m.attrs.u16(G.CTRL_ATTR_FAMILY_ID)
        if fid is None:
            raise NetlinkError(2, f"genl family {name} has no id")
        groups: dict[str, int] = {}
        for _, g in m.attrs.nested_list(G.CTRL_ATTR_MCAST_GROUPS):
            gname = g.str(G.CTRL_ATTR_MCAST_GRP_NAME)
            gid = g.u32(G.CTRL_ATTR_MCAST_GRP_ID)
            if gname is not None and gid is not None:
                groups[gname] = gid
        return fid, groups


SOL_NETLINK = 270
NETLINK_ADD_MEMBERSHIP = 1


def open_multicast(protocol: int, groups: list[int] | None = None, bind_groups: int = 0) -> socket.socket:
    """Open a non-blocking netlink socket subscribed to the given multicast groups."""
    s = socket.socket(
        socket.AF_NETLINK, socket.SOCK_RAW | socket.SOCK_CLOEXEC | socket.SOCK_NONBLOCK, protocol
    )
    s.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 4 << 20)
    s.bind((0, bind_groups))
    for g in groups or []:
        s.setsockopt(SOL_NETLINK, NETLINK_ADD_MEMBERSHIP, g)
    return s
