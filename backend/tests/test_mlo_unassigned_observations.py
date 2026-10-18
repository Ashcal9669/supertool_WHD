"""Unassigned recorded facts remain visible without becoming device evidence."""

from pathlib import Path

from whd.mlo.report import EvidenceReport, analyze
from whd.model.events import Event

FX = Path(__file__).parent / "fixtures/mlo/assoc_ok_keys_eapol_links.jsonl"
DEVICE = "pci:0000:07:00.0:14c3:7927"


def recorded_events() -> list[Event]:
    return [Event.model_validate_json(line) for line in FX.read_text().splitlines() if line.strip()]


def test_real_unassigned_completions_are_visible_without_owned_firmware_or_rx_claims():
    events = recorded_events()
    before = [event.model_dump() for event in events]
    own = [event for event in events if event.device_id == DEVICE]
    unassigned = [event for event in events if event.device_id is None]
    assert len(own) == 25 and len(unassigned) == 375

    result = analyze(events, DEVICE, "recorded")
    assert result.unassigned_observations == unassigned
    assert result.observations == own
    assert result.unattributed_events == 375
    completions = [
        event for event in result.unassigned_observations if event.data.get("tag") == "MLO_MCU_SEND_DONE"
    ]
    assert len(completions) == 4
    assert all(event.device_id is None for event in completions)
    assert all(event.raw and event.data["fields"]["ret"] == "0" for event in completions)
    assert all(not window.firmware.ops and not window.rx_frames for window in result.windows)
    assert not result.packets and not result.mcu_payloads and not result.mcu_transport
    assert all(
        link.fw_programmed.value == link.authenticated_delivery.value == "unknown"
        for window in result.windows
        for link in window.state.links
    )
    restored = EvidenceReport.model_validate_json(result.model_dump_json())
    assert [event.model_dump() for event in restored.unassigned_observations] == [
        event.model_dump() for event in unassigned
    ]
    assert [event.model_dump() for event in events] == before


def test_unassigned_records_keep_separate_boots_and_replay_labels_without_joining():
    completion = next(event for event in recorded_events() if event.data.get("tag") == "MLO_MCU_SEND_DONE")
    first = completion.model_copy(deep=True)
    second = completion.model_copy(deep=True)
    assert first.device_id is None and second.device_id is None
    first.data["boot_id"] = "recorded-boot-a"
    second.data["boot_id"] = "recorded-boot-b"
    second.session = "replay:other-recording"
    result = analyze([first, second], DEVICE, "recorded")

    assert [event.model_dump() for event in result.unassigned_observations] == [
        first.model_dump(),
        second.model_dump(),
    ]
    assert result.unattributed_events == 2
    assert not result.observations and not result.windows and not result.epochs and not result.packets
    assert not result.mcu_payloads and not result.mcu_transport
    assert result.current_state is None
