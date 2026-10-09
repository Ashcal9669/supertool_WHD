from pathlib import Path

from conftest import fixture_host
from whd.discovery import Discovery
from whd.store.db import SCHEMA, Store


def test_migrations_and_name_history(tmp_path: Path) -> None:
    s = Store(tmp_path / "w.db")
    assert s.schema_version == len(SCHEMA)
    a = Discovery(fixture_host("mt7927-pcie-host")).run().devices
    b = Discovery(fixture_host("renamed-netdev")).run().devices
    s.upsert_devices(a, now=100.0)
    meta = s.upsert_devices(b, now=200.0)
    m = meta[a[0].id]
    assert m["first_seen"] == 100.0 and m["last_seen"] == 200.0
    assert m["names"]["netdev"] == ["wlp7s0", "wlx_renamed"]
    assert m["names"]["phy"] == ["phy1", "phy3"]
    s.close()
    # reopen: idempotent migration, data persisted
    s2 = Store(tmp_path / "w.db")
    assert s2.schema_version == len(SCHEMA)
    assert s2.device_snapshot(a[0].id)["netdevs"] == ["wlx_renamed"]  # type: ignore[index]
