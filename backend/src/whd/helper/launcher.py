"""Start the privileged whd-helper from `whd serve`, so enabling it needs no second terminal.

The web server stays an unprivileged process. This launcher (run by the CLI before the web server starts) asks
for sudo once, inline in the terminal the user is already in, starts the root helper as a child process, then
drops the cached sudo credential again so nothing in the web process keeps a usable root ticket. The helper is
stopped when the server exits. If sudo is unavailable the server still starts, with the helper features marked
"cannot check" rather than absent.
"""

from __future__ import annotations

import contextlib
import os
import shutil
import signal
import subprocess
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from typing import IO, Any

from whd.helper.client import HelperClient, HelperUnavailable
from whd.helper.protocol import HelperError

Outcome = str  # "off" | "already_running" | "started" | "unavailable"


@dataclass
class LaunchResult:
    outcome: Outcome
    detail: str = ""
    pid: int | None = None

    @property
    def ok(self) -> bool:
        return self.outcome in ("already_running", "started")


class HelperLauncher:
    def __init__(
        self,
        socket_path: Path,
        uid: int | None = None,
        *,
        python: str | None = None,
        elevate: list[str] | None = None,
        extra_args: list[str] | None = None,
        log_path: Path | None = None,
        interactive: bool | None = None,
        ready_timeout: float = 8.0,
        say: Any = None,
    ) -> None:
        self.socket = Path(socket_path)
        self.uid = os.getuid() if uid is None else uid
        self.python = python or sys.executable
        self.elevate = elevate  # None: find sudo; []: no elevation (tests / already root)
        self.extra_args = extra_args or []
        self.log_path = log_path
        self.interactive = sys.stdin.isatty() if interactive is None else interactive
        self.ready_timeout = ready_timeout
        self.say = say or (lambda m: print(m, file=sys.stderr, flush=True))
        self.proc: subprocess.Popen[bytes] | None = None
        self._log: IO[bytes] | None = None

    # ------------------------------------------------------------------ probing
    def _ping(self) -> str:
        """'ok' | 'absent' | 'denied' | 'error'"""
        try:
            HelperClient(self.socket).call("ping", 2.0)
            return "ok"
        except HelperUnavailable as e:
            msg = str(e)
            if "no permission" in msg:
                return "denied"
            return "absent"
        except HelperError:
            return "ok"  # a reply came back (even an error one): a helper is there and accepted our uid

    def _sudo(self) -> str | None:
        return shutil.which("sudo")

    # ------------------------------------------------------------------ start / stop
    def start(self) -> LaunchResult:
        state = self._ping()
        if state == "ok":
            return LaunchResult("already_running", f"using the helper at {self.socket}")
        if state == "denied":
            return LaunchResult(
                "unavailable", f"a helper is running at {self.socket} but this user may not use it"
            )
        elevate = self.elevate
        if elevate is None:
            if os.geteuid() == 0:
                elevate = []
            else:
                sudo = self._sudo()
                if sudo is None:
                    return LaunchResult("unavailable", "sudo is not installed")
                elevate = [sudo, "-n"]
                if self.interactive:
                    self.say(
                        "WHD: starting the privileged helper (read-only debugfs/tracefs/PCI-config access). "
                        "sudo will ask for your password once."
                    )
                    if subprocess.run([sudo, "-v"], check=False).returncode != 0:
                        return LaunchResult("unavailable", "sudo authentication failed or was cancelled")
                elif subprocess.run([sudo, "-n", "true"], check=False, capture_output=True).returncode != 0:
                    return LaunchResult(
                        "unavailable", "sudo needs a password and there is no terminal to ask"
                    )
        cmd = [
            *elevate,
            self.python,
            "-B",  # never write root-owned .pyc files into the user's tree
            "-m",
            "whd.helper.server",
            "--socket",
            str(self.socket),
            "--allow-uid",
            str(self.uid),
            *self.extra_args,
        ]
        out: Any = subprocess.DEVNULL
        if self.log_path is not None:
            self.log_path.parent.mkdir(parents=True, exist_ok=True)
            self._log = open(self.log_path, "ab")  # noqa: SIM115 - closed in stop()
            out = self._log
        self.proc = subprocess.Popen(cmd, stdin=subprocess.DEVNULL, stdout=out, stderr=out)
        deadline = time.monotonic() + self.ready_timeout
        while time.monotonic() < deadline:
            if self.proc.poll() is not None:
                break
            if self._ping() == "ok":
                self._forget_sudo(elevate)
                return LaunchResult("started", f"helper running as root (pid {self.proc.pid})", self.proc.pid)
            time.sleep(0.1)
        rc = self.proc.poll()
        self.stop()
        self._forget_sudo(elevate)
        why = (
            f"the helper exited with status {rc}" if rc is not None else "the helper did not come up in time"
        )
        if self.log_path is not None:
            why += f" (see {self.log_path})"
        return LaunchResult("unavailable", why)

    def _forget_sudo(self, elevate: list[str]) -> None:
        """Drop the cached sudo credential: the running helper does not need it and the web process must not
        be left able to sudo without a password."""
        if elevate and Path(elevate[0]).name == "sudo":
            with contextlib.suppress(OSError):
                subprocess.run([elevate[0], "-k"], check=False, capture_output=True)

    def stop(self) -> None:
        p, self.proc = self.proc, None
        if p is not None and p.poll() is None:
            with contextlib.suppress(OSError):
                p.send_signal(signal.SIGTERM)  # sudo relays it to the helper, which removes its socket
            try:
                p.wait(timeout=5)
            except subprocess.TimeoutExpired:
                with contextlib.suppress(OSError):
                    p.kill()
        if self._log is not None:
            self._log.close()
            self._log = None
