"""`whd serve` starts the privileged helper itself (no second terminal): launch, reuse, degrade, stop."""

from __future__ import annotations

import os
import subprocess
from pathlib import Path

import pytest

from whd.helper import launcher as L
from whd.helper.launcher import HelperLauncher


def make(tmp_path: Path, **kw: object) -> HelperLauncher:
    return HelperLauncher(
        tmp_path / "run" / "helper.sock",
        elevate=kw.pop("elevate", []),  # type: ignore[arg-type]
        extra_args=["--allow-non-root"],
        log_path=tmp_path / "helper.log",
        interactive=False,
        say=lambda _m: None,
        **kw,  # type: ignore[arg-type]
    )


def test_starts_reuses_and_stops_the_helper(tmp_path: Path) -> None:
    a = make(tmp_path)
    r = a.start()
    try:
        assert r.outcome == "started" and r.pid and (tmp_path / "run" / "helper.sock").exists()
        b = make(tmp_path)  # a second `whd serve` reuses the running helper instead of starting another
        assert b.start().outcome == "already_running" and b.proc is None
    finally:
        a.stop()
    assert not (tmp_path / "run" / "helper.sock").exists()  # no stale socket left looking "available"
    assert make(tmp_path)._ping() == "absent"


def test_unavailable_without_sudo(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    if os.geteuid() == 0:
        pytest.skip("already root")
    h = make(tmp_path, elevate=None)
    monkeypatch.setattr(h, "_sudo", lambda: None)
    r = h.start()
    assert r.outcome == "unavailable" and "sudo is not installed" in r.detail and h.proc is None


def test_no_terminal_and_sudo_wants_a_password(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    if os.geteuid() == 0:
        pytest.skip("already root")
    h = make(tmp_path, elevate=None)
    monkeypatch.setattr(h, "_sudo", lambda: "/usr/bin/sudo")
    monkeypatch.setattr(L.subprocess, "run", lambda *a, **k: subprocess.CompletedProcess(a, 1, b"", b""))
    r = h.start()
    assert r.outcome == "unavailable" and "no terminal" in r.detail and h.proc is None


def test_helper_that_dies_is_reported_with_its_log(tmp_path: Path) -> None:
    h = make(tmp_path, python="/bin/false", ready_timeout=3)
    r = h.start()
    assert r.outcome == "unavailable" and "exited with status" in r.detail and "helper.log" in r.detail
    assert h.proc is None
