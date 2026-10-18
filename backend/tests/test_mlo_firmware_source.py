"""Report integration using a hashed saved header, never an assumed live build."""

import hashlib
import json
from pathlib import Path

from test_mlo_safety import event
from whd.mlo import report
from whd.model.events import Event

FX = Path(__file__).parent / "fixtures" / "mlo" / "firmware_source"


def test_report_decodes_only_explicit_source_bound_fixture():
    fixture = json.loads((FX / "bss_layout.json").read_text())
    provenance = fixture["layout_provenance"]
    # Verify the actual archived bytes, not just two asserted metadata strings.
    assert hashlib.sha256((FX / "mt7925_mcu.h").read_bytes()).hexdigest() == provenance["file_sha256"]
    events = []
    for n, payload in enumerate(fixture["payloads"], 1):
        seed = event(n, kind="trace.mt76.whd_mcu_tlv").model_dump()
        seed["data"] = {"fields": {"cookie": "10", **payload}, "layout_provenance": provenance}
        e = Event.model_validate(seed)
        events.append(e)
    result = report.analyze(events, "device-a", "fixture")
    assert result.mcu_payloads[0]["fields"]["own_mld"] == 2
    assert result.mcu_payloads[1]["fields"]["channel"] == 40
    assert all(p["matches_loaded_build"] is None for p in result.mcu_payloads)
    events[0].data["layout_provenance"] = {**provenance, "file_sha256": "0" * 64}
    mismatch = report.analyze(events, "device-a", "fixture").mcu_payloads[0]
    assert not mismatch["fields"] and mismatch["layout_match"] == "unverified"
    assert mismatch["raw_hex"] == fixture["payloads"][0]["hex"]
    assert not mismatch["unknown_fields"] and mismatch["matches_loaded_build"] is None
