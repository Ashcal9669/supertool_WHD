"""Synthetic 0004 trace contracts; not activated driver or hardware evidence."""

from test_mlo_safety import event
from whd.mlo.packets import build_paths
from whd.mlo.privacy import scrub


def descriptor(n, stage, **fields):
    e = event(n, kind="trace.mt76.whd_tx_descriptor", stage=stage, **fields)
    e.data.update(boot_id="boot-a")
    return e


def test_raw_txd_and_txs_with_only_token_pid_are_visible_but_never_joined():
    es = [
        descriptor(1, "txd", token="7", pid="9", wcid="2", layout="connac3_txd32"),
        descriptor(
            2, "tx_status", token="7", pid="9", status_supported="1", acked="1", layout="connac3_txs32_prefix"
        ),
    ]
    paths = build_paths(es, "device-a")
    assert len(paths) == 2
    assert paths[0].observations[0].stage == "txd" and paths[0].acked is None
    assert paths[1].observations[0].stage == "tx_status" and paths[1].acked is True
    assert all(p.delivered is None and p.authenticated_delivery is None for p in paths)


def test_unsupported_txs_format_never_becomes_an_ack_success():
    e = descriptor(
        1, "tx_status", status_supported="0", acked="1", txs_format="7", layout="connac3_txs32_prefix"
    )
    paths = build_paths([e], "device-a")
    assert len(paths) == 1 and paths[0].acked is None
    assert paths[0].observations[0].decoded["txs_format"] == "7"


def test_extended_descriptor_bytes_are_withheld_before_storage():
    e = descriptor(1, "txd", hex="aa" * 40, observed_len="40", captured_len="40", layout="connac3_txd32")
    assert e.data["fields"]["hex"] == "<redacted>"
    assert "aa" * 40 not in str(scrub(e.model_dump()))
