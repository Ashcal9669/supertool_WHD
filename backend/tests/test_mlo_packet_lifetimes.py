"""Offline correlation regressions; synthetic identities are not hardware evidence."""

import pytest

from test_mlo_safety import event
from whd.mlo.packets import build_paths


def scoped(n, boundary, **fields):
    e = event(n, kind=f"packet.{boundary}", packet_id="reused", generation="7", **fields)
    e.data.update(boot_id="boot-a", association_epoch="assoc-a", ifname="wlan0", wdev="0x1")
    return e


@pytest.mark.parametrize("identity", ["packet_id", "skbaddr"])
@pytest.mark.parametrize(
    "change",
    ["ifname", "wdev", "interface_lifetime", "ifindex", "boot_id", "association_epoch", "generation"],
)
def test_reused_identifiers_do_not_cross_scope(identity, change):
    a, b = scoped(1, "raw_rx"), scoped(2, "stack_rx")
    for e in (a, b):
        e.data["fields"].pop("packet_id")
        e.data["fields"][identity] = "0x123"
    if change == "generation":
        b.data["fields"][change] = "8"
    elif change == "ifindex":
        for e in (a, b):
            e.data.pop("wdev")
            e.data["ifindex"] = 3
        b.data[change] = 4
    else:
        b.data[change] = "different"
    paths = build_paths([a, b], "device-a")
    assert len(paths) == 2
    assert paths[0].delivered is None


@pytest.mark.parametrize("missing", ["ifname", "wdev", "generation"])
def test_unknown_scope_does_not_borrow_known_scope(missing):
    a, b = scoped(1, "raw_rx"), scoped(2, "stack_rx")
    (b.data["fields"] if missing == "generation" else b.data).pop(missing)
    assert len(build_paths([a, b], "device-a")) == 2


def test_interleaved_interfaces_keep_independent_pending_buffers():
    es = [scoped(1, "raw_rx"), scoped(2, "raw_rx"), scoped(3, "stack_rx"), scoped(4, "stack_rx")]
    for e in (es[1], es[3]):
        e.data.update(ifname="wlan1", wdev="0x2")
    paths = build_paths(es, "device-a")
    assert [[r.event_id for o in p.observations for r in o.evidence] for p in paths] == [[1, 3], [2, 4]]
    assert [(p.scope.interface, p.scope.interface_lifetime) for p in paths] == [
        ("wlan0", "wdev:0x1"),
        ("wlan1", "wdev:0x2"),
    ]


def test_complete_security_lineage_is_ordered_and_interface_scoped():
    raw = scoped(1, "raw_rx", link="2")
    security = scoped(
        2, "security", link="2", decrypted="1", integrity_ok="1", replay_ok="1", channel_matches="1"
    )
    stack = scoped(3, "stack_rx", link="2")
    assert build_paths([raw, security, stack], "device-a")[0].authenticated_delivery is True
    raw.ts_boottime_ns = security.ts_boottime_ns + 1
    assert not any(p.authenticated_delivery for p in build_paths([raw, security, stack], "device-a"))


def test_pn_drop_never_authenticates_despite_optimistic_fields():
    raw = scoped(1, "raw_rx", link="2")
    drop = scoped(
        2,
        "security",
        link="2",
        decrypted="1",
        integrity_ok="1",
        replay_ok="1",
        channel_matches="1",
        stage="pn_drop",
    )
    drop.kind = "trace.mt76.whd_rx_boundary"
    stack = scoped(3, "stack_rx", link="2")
    assert not any(p.authenticated_delivery for p in build_paths([raw, drop, stack], "device-a"))


def test_raw_descriptor_link_is_not_a_resolved_link():
    raw = scoped(1, "raw_rx", link="1", desc_band="1")
    resolve = scoped(2, "wcid_resolve", resolved_link="2", resolved_wcid="9")
    paths = build_paths([raw, resolve], "device-a")
    assert len(paths) == 1
    assert paths[0].scope.link_id == 2
    assert paths[0].observations[0].decoded["link"] == "1"


def test_null_packet_id_does_not_hide_valid_skb():
    a, b = scoped(1, "raw_rx", skbaddr="0x123"), scoped(2, "stack_rx", skbaddr="0x123")
    for e in (a, b):
        e.data["fields"]["packet_id"] = "(null)"
    assert len(build_paths([a, b], "device-a")) == 1


def test_reused_ifindex_correlates_but_cannot_prove_interface_incarnation():
    es = [
        scoped(1, "raw_rx", link="2"),
        scoped(2, "security", link="2", decrypted="1", integrity_ok="1", replay_ok="1", channel_matches="1"),
        scoped(3, "stack_rx", link="2"),
    ]
    for e in es:
        e.data.pop("wdev")
        e.data["ifindex"] = 3
    path = build_paths(es, "device-a")[0]
    assert len(path.observations) == 3 and path.scope.interface_lifetime == "ifindex:3"
    assert path.authenticated_delivery is None
    assert any("incarnation" in limit for limit in path.limits)


def test_buffer_and_packet_id_namespaces_cannot_alias():
    a, b = scoped(1, "raw_rx"), scoped(2, "stack_rx")
    b.data["fields"]["skbaddr"] = b.data["fields"].pop("packet_id")
    assert len(build_paths([a, b], "device-a")) == 2


def test_automatic_epoch_is_selected_only_from_same_interface_lifetime():
    start = scoped(1, "raw_rx")
    start.kind = "assoc.authenticate"
    start.data.pop("association_epoch")
    other = scoped(2, "raw_rx")
    other.data.pop("association_epoch")
    other.data.update(ifname="wlan1", wdev="0x2")
    assert build_paths([start, other], "device-a")[0].scope.association_epoch is None


def test_names_without_lifetimes_cannot_cross_correlate():
    a, b = scoped(1, "raw_rx"), scoped(2, "stack_rx")
    for e in (a, b):
        e.data.pop("wdev")
    b.data["ifname"] = "wlan1"
    assert len(build_paths([a, b], "device-a")) == 2


def test_printk_pn_drop_remains_a_negative_security_observation():
    es = [
        scoped(1, "raw_rx", link="2"),
        scoped(2, "security", link="2", decrypted="1", integrity_ok="1", replay_ok="1", channel_matches="1"),
        scoped(4, "stack_rx", link="2"),
    ]
    drop = scoped(3, "security", link="2")
    drop.kind = "driver.kv_trace"
    drop.data["tag"] = "MLO_RX_PN_DROP"
    path = build_paths([*es, drop], "device-a")[0]
    assert len(path.observations) == 4
    assert path.authenticated_delivery is None


def test_explicit_packet_id_keeps_late_txs_separate_from_buffer_release_semantics():
    es = [scoped(1, "txd"), scoped(2, "tx_free"), scoped(3, "tx_status", acked="1")]
    paths = build_paths(es, "device-a")
    assert len(paths) == 1
    assert paths[0].acked is True and paths[0].delivered is None
    assert [o.stage for o in paths[0].observations] == ["txd", "tx_free", "tx_status"]


def test_rx_first_missing_stage_does_not_require_an_unrelated_userspace_tx():
    path = build_paths([scoped(1, "raw_rx"), scoped(2, "stack_rx")], "device-a")[0]
    assert path.direction == "rx"
    assert path.first_missing == "wcid_resolve"
    assert any(g.what == "userspace_submit" for g in path.gaps)
