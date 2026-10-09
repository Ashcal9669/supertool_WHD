from __future__ import annotations

import shutil
from collections.abc import Iterator
from pathlib import Path

import pytest

from whd.config import Settings
from whd.platform.host import FixtureHost

SYSROOTS = Path(__file__).parent / "fixtures" / "sysroots"
BASE = SYSROOTS / "mt7927-pcie-host"


def fixture_host(name: str) -> FixtureHost:
    return FixtureHost(SYSROOTS / name)


@pytest.fixture
def settings(tmp_path: Path) -> Settings:
    s = Settings()
    s.config_dir = tmp_path / "config"
    s.state_dir = tmp_path / "state"
    s.fixtures_dir = SYSROOTS
    s.demo_scenario = "mt7927-pcie-host"
    s.enable_event_sources = False
    s.helper_socket = tmp_path / "no-helper.sock"
    s.static_dir = tmp_path / "no-static"
    return s


@pytest.fixture
def copied_fixture(tmp_path: Path) -> Iterator[Path]:
    d = tmp_path / "fx"
    shutil.copytree(BASE, d, symlinks=True)
    yield d
    for p in d.rglob("*"):
        try:
            if not p.is_symlink():
                p.chmod(0o755 if p.is_dir() else 0o644)
        except OSError:
            pass
