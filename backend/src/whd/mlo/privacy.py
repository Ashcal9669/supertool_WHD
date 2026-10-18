"""Remove wireless key bytes/fingerprints before event storage or export."""

from __future__ import annotations

import re
from typing import Any

SECRET = re.compile(r"(?i)\b(keyfp|key_bytes|key_material|key_data|ptk|gtk|igtk|bigtk|key)\s*[=:]\s*[^\s,;]+")
KEYS = {"keyfp", "key_bytes", "key_material", "key_data", "ptk", "gtk", "igtk", "bigtk", "key"}


def scrub(value: Any) -> Any:
    if isinstance(value, dict):
        if str(value.get("kind", "")).endswith("whd_tx_descriptor"):
            from whd.mlo.tx_observation import safe_descriptor_hex

            data = value.get("data", {})
            data = data if isinstance(data, dict) else {}
            candidate = data.get("fields", {})
            fields = dict(candidate) if isinstance(candidate, dict) else {}
            safe_hex = safe_descriptor_hex({str(k): str(v) for k, v in fields.items()})
            if "hex" in fields:
                fields["hex"] = safe_hex if safe_hex is not None else "<redacted>"
            value = dict(value, data=dict(data, fields=fields))
            if safe_hex is None:
                for key in ("raw", "summary"):
                    value[key] = re.sub(r"\bhex=\S+", "hex=<redacted>", str(value.get(key, "")))
        if str(value.get("kind", "")).endswith("whd_mcu_transport"):
            from whd.mlo.transport import safe_transport_hex

            data = value.get("data", {})
            data = data if isinstance(data, dict) else {}
            candidate = data.get("fields", {})
            fields = dict(candidate) if isinstance(candidate, dict) else {}
            safe_hex = safe_transport_hex({str(k): str(v) for k, v in fields.items()})
            fields["hex"] = safe_hex if safe_hex is not None else "<redacted>"
            value = dict(value, data=dict(data, fields=fields))
            for key in ("raw", "summary"):
                value[key] = re.sub(r"\bhex=\S+", "hex=" + fields["hex"], str(value.get(key, "")))
        if str(value.get("kind", "")).endswith("whd_mcu_tlv"):
            from whd.mlo.mcu import decode_tlv

            data = value.get("data", {})
            data = data if isinstance(data, dict) else {}
            candidate = data.get("fields", {})
            fields = dict(candidate) if isinstance(candidate, dict) else {}
            try:
                cmd, tag = int(str(fields.get("cmd", "0")), 0), int(str(fields.get("tag", "-1")), 0)
                decoded = decode_tlv(cmd, tag, str(fields.get("hex", "")))
                safe = decoded["complete"] and decoded["raw_hex"] is not None
            except ValueError:
                safe = False
            if not safe:
                for key in ("hex", "bytes", "payload", "raw_bytes"):
                    if key in fields:
                        fields[key] = "<redacted>"
                value = dict(value, data=dict(data, fields=fields))
                for key in ("raw", "summary"):
                    value[key] = re.sub(
                        r"\b(hex|bytes|payload|raw_bytes)=\S+", r"\1=<redacted>", str(value.get(key, ""))
                    )
        return {k: ("<redacted>" if str(k).lower() in KEYS else scrub(v)) for k, v in value.items()}
    if isinstance(value, list):
        return [scrub(v) for v in value]
    if isinstance(value, str):
        return SECRET.sub(lambda m: m.group(1) + "=<redacted>", value)
    return value
