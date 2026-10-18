from whd.mlo import fwid, rx
from whd.mlo.timeline import Collectors, assign_boots, build_epochs
from whd.model.events import Event


def event(n: int, kind: str = "driver.kv_trace", tag: str = "", **fields: str) -> Event:
    return Event(
        id=n,
        ts_boottime_ns=n * 1000,
        ts_wall=1000 + n / 1e6,
        ts_source="tracefs_boot",
        source="test",
        device_id="device-a",
        category="mlo",
        kind=kind,
        summary=tag,
        explanation="test observation",
        raw=tag,
        data={"tag": tag, "fields": fields},
    )


def test_explicit_boots_with_equal_clock_offsets_never_merge():
    a, b = event(1), event(2)
    a.ts_raw, b.ts_raw = "(boot aaaaaaaa)", "(boot bbbbbbbb)"
    assert assign_boots([a, b]) == ["aaaaaaaa", "bbbbbbbb"]


def test_unknown_channel_and_missing_replay_result_cannot_prove_delivery():
    es = [
        event(1, tag="MLO_RX_UNICAST_TRACE", resolved_wcid="9", resolved_link="4", chfreq="40"),
        event(
            2, tag="MLO_RX_DECRYPT_TRACE", wcid="9", decrypted="1", icv_err="0", fcs_err="0", tkip_mic_err="0"
        ),
    ]
    frames = rx.build_frames(es, {})
    assert rx.summarize(frames).authenticated_by_link == {}
    assert frames[0].verdict != "authenticated"


def test_unattributed_trace_does_not_supply_epoch_key_evidence_by_default():
    start = event(1, kind="assoc.authenticate")
    key = event(2, tag="MLO_KEY_INSTALL", cipher="4", key_link_id="4")
    key.device_id = None
    ep = build_epochs([start, key], "device-a", Collectors())[0]
    assert "key_install_request" not in {s.stage for s in ep.stages}


def test_ethertype_and_position_do_not_decode_four_way_messages():
    es = [event(1, kind="assoc.authenticate")]
    for i, name in enumerate(["mlo_rx", "mlo_tx_select", "mlo_rx", "mlo_tx_select"], 2):
        es.append(event(i, kind=f"trace.mt76.{name}", proto="0x888e"))
    ep = build_epochs(es, "device-a", Collectors())[0]
    assert not any(s.stage.startswith("eapol_m") for s in ep.stages)
    assert len([s for s in ep.stages if s.stage == "eapol_unclassified"]) == 4


def test_rx_continuation_from_other_device_cannot_authenticate_frame():
    es = [
        event(1, tag="MLO_RX_UNICAST_TRACE", resolved_wcid="9", resolved_link="4", chfreq="40"),
        event(
            2, tag="MLO_RX_DECRYPT_TRACE", wcid="9", decrypted="1", icv_err="0", fcs_err="0", tkip_mic_err="0"
        ),
    ]
    es[1].device_id = "device-b"
    assert rx.build_frames(es, {4: 40})[0].decrypted is None


def test_overlapping_mcu_commands_cannot_silently_overwrite_pending():
    es = [
        event(1, tag="MLO_MCU_SEND_START", cmd="0x20002", link="4", t="100"),
        event(2, tag="MLO_MCU_SEND_START", cmd="0x20002", link="4", t="200"),
        event(3, tag="MLO_MCU_SEND_DONE", cmd="0x20002", link="4", ret="0"),
    ]
    rep = fwid.analyze(es)
    assert all(o.status == "incomplete" for o in rep.ops)
    assert any("ambiguous" in f for f in rep.flags)
