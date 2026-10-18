"""Safe descriptor prefixes, never packet payload or secret key material."""

from whd.mlo.kv import num


def safe_descriptor_hex(fields: dict[str, str]) -> str | None:
    expected = {"txd": "connac3_txd32", "tx_status": "connac3_txs32_prefix"}
    stage = fields.get("stage")
    if expected.get(stage or "") != fields.get("layout"):
        return None
    captured, observed = num(fields, "captured_len"), num(fields, "observed_len")
    if captured != 32 or observed is None or observed < captured or observed > 48:
        return None
    if stage == "txd" and observed != 32:
        return None
    try:
        raw = bytes.fromhex(fields.get("hex", ""))
    except ValueError:
        return None
    return raw.hex() if len(raw) == 32 else None
