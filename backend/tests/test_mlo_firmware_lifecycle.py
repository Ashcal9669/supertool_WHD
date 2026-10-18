"""Synthetic firmware-lifetime edge cases; recorded-fixture regressions remain separate."""

from test_mlo_safety import event
from whd.mlo import fwid


def station(n, tag="MLO_FW_STA_RET", **fields):
    return event(n, tag=tag, link="4", wcid="9", bss_idx="2", enable="1", state="2", **fields)


def test_new_generation_cannot_inherit_completed_station_identity():
    report = fwid.analyze(
        [
            event(1, tag="MLO_FW_PEER_LIFECYCLE", link="4", generation="3"),
            station(2, ret="0"),
            event(3, tag="MLO_FW_PEER_LIFECYCLE", link="4", generation="4"),
        ]
    )
    row = report.links[0]
    assert "sta_ret" not in row.current and "wcid" not in row.current
    assert not row.completed_evidence


def test_success_count_does_not_survive_a_new_request_or_failed_update():
    for last in (station(2, tag="MLO_FW_STA_RAW"), station(2, ret="-5")):
        report = fwid.analyze(
            [
                station(1, ret="0"),
                last,
                event(3, tag="MLO_FW_STA_MLD", update_link="4", link_num="1"),
            ]
        )
        assert any("missing member" in flag for flag in report.flags)


def test_confirmed_wcid_removal_allows_reallocation_without_identity_conflict():
    report = fwid.analyze(
        [
            event(1, tag="MLO_WCID_LIFE", link="4", stage="add_alloc"),
            station(2, ret="0"),
            event(3, tag="MLO_WCID_LIFE", link="4", stage="remove_after", old_idx="9"),
            event(4, tag="MLO_WCID_LIFE", link="4", stage="add_alloc"),
            event(5, tag="MLO_FW_STA_RAW", link="4", wcid="10", enable="1", state="2"),
        ]
    )
    assert report.links[0].current["wcid"] == 10
    assert not report.links[0].completed_evidence
    assert not any("allocated 2x" in flag or "wcid changed" in flag for flag in report.flags)


def test_stale_generation_does_not_move_high_watermark_backwards():
    report = fwid.analyze(
        [
            event(1, tag="MLO_FW_PEER_LIFECYCLE", link="4", generation="5"),
            station(2, ret="0"),
            event(3, tag="MLO_FW_PEER_LIFECYCLE", link="4", generation="3"),
            event(4, tag="MLO_FW_PEER_LIFECYCLE", link="4", generation="4"),
        ]
    )
    assert not any("peer recreated" in flag for flag in report.flags)
    assert report.links[0].current["sta_ret"] == 0


def test_other_link_start_does_not_erase_unsubmitted_requested_identity():
    report = fwid.analyze(
        [
            event(1, tag="MLO_FW_BSS_BASIC", link="4", bss_idx="2", active="1"),
            event(2, tag="MLO_MCU_SEND_START", link="5", cmd="0x20002", t="10"),
            event(3, tag="MLO_MCU_SEND_START", link="4", cmd="0x20002", t="20"),
        ]
    )
    assert report.ops[1].requested["bss_idx"] == 2


def test_raw_length_is_scoped_to_command_and_link_and_consumed_once():
    report = fwid.analyze(
        [
            event(1, tag="MLO_FW_BSS_RAW", link="4", cmd="0x20002", len="32"),
            event(2, tag="MLO_MCU_SEND_START", link="5", cmd="0x20002", t="10"),
            event(3, tag="MLO_MCU_SEND_START", link="4", cmd="0x20002", t="20"),
            event(4, tag="MLO_MCU_SEND_START", link="4", cmd="0x20002", t="30"),
        ]
    )
    assert [op.raw_len for op in report.ops] == [None, 32, None]


def test_late_station_completion_after_removal_cannot_revive_identity():
    report = fwid.analyze(
        [
            station(1, ret="0"),
            event(2, tag="MLO_WCID_LIFE", link="4", stage="remove_after", old_idx="9"),
            station(3, ret="0"),
        ]
    )
    assert "wcid" not in report.links[0].current
    assert not report.links[0].completed_evidence
    assert any("stale" in flag for flag in report.flags)


def test_programming_contract_requires_partner_responses_not_driver_returns():
    events = [
        event(1, tag="MLO_DEVINFO_TX", link="4", bss="2", omac="1", active="1"),
        event(2, tag="MLO_MCU_SEND_START", link="4", cmd="0x20001", t="10"),
        event(3, tag="MLO_MCU_SEND_DONE", link="4", cmd="0x20001", ret="0"),
        event(4, tag="MLO_FW_BSS_BASIC", link="4", bss_idx="2", omac="1", active="1"),
        event(5, tag="MLO_MCU_SEND_START", link="4", cmd="0x20002", t="20"),
        event(6, tag="MLO_MCU_SEND_DONE", link="4", cmd="0x20002", ret="0"),
        station(7, ret="0"),
    ]
    for e in events:
        e.data.update(boot_id="boot-a", association_epoch="epoch-a", interface="wifi-a")
        e.data["fields"]["generation"] = "3"
    contract = fwid.analyze(events).links[0].current["fw_programming"]
    assert contract["value"] == "unknown"
    assert contract["identity_scope"]["device_id"] == "device-a"
    assert contract["identity_scope"]["bss_idx"] == 2
    assert contract["identity_scope"]["wcid"] == 9
    assert set(contract["components"]) == {"dev", "bss", "sta"}
    for component in contract["components"].values():
        assert component["driver_return"] == 0
        assert component["response_matched"] is False
    assert contract["evidence"] == []
