from whd.platform.kconsts import netlink as N
from whd.platform.netlink import NLMSG_HDR, Attrs, iter_attrs, iter_msgs, nla, nla_str, nla_u32


def test_nla_roundtrip_and_alignment() -> None:
    buf = nla_u32(1, 0xDEADBEEF) + nla_str(2, "phy0") + nla(3 | N.NLA_F_NESTED, nla_u32(1, 7))
    assert len(buf) % 4 == 0
    a = Attrs.parse(buf)
    assert a.u32(1) == 0xDEADBEEF
    assert a.str(2) == "phy0"
    inner = a.nested(3)
    assert inner is not None and inner.u32(1) == 7  # NESTED flag masked off the type


def test_iter_attrs_stops_on_truncation() -> None:
    good = nla_u32(1, 1)
    bad = good + b"\x08\x00\x02\x00\x01"  # declares 8 bytes, has 5
    assert [t for t, _ in iter_attrs(bad)] == [1]


def test_iter_msgs() -> None:
    body = b"\x01\x02\x00\x00"
    m = NLMSG_HDR.pack(NLMSG_HDR.size + len(body), 0x1F, 0, 7, 0) + body
    msgs = list(iter_msgs(m + m))
    assert len(msgs) == 2 and msgs[0].seq == 7 and msgs[0].payload == body
