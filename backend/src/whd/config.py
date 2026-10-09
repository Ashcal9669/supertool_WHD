"""Runtime configuration from environment (WHD_*) and CLI flags."""

from __future__ import annotations

import ipaddress
import os
from dataclasses import dataclass, field
from pathlib import Path


def _xdg(var: str, default: str) -> Path:
    return Path(os.environ.get(var) or Path.home() / default)


def _bool(v: str | None) -> bool:
    return (v or "").strip().lower() in ("1", "true", "yes", "on")


@dataclass
class Settings:
    host: str = "127.0.0.1"
    port: int = 8787
    allow_remote: bool = False
    demo_scenario: str | None = None
    fixtures_dir: Path = field(
        default_factory=lambda: Path(__file__).resolve().parents[2] / "tests" / "fixtures" / "sysroots"
    )
    config_dir: Path = field(default_factory=lambda: _xdg("XDG_CONFIG_HOME", ".config") / "whd")
    state_dir: Path = field(default_factory=lambda: _xdg("XDG_STATE_HOME", ".local/state") / "whd")
    static_dir: Path | None = None
    cache_ttl_s: float = 5.0
    helper_socket: Path = Path("/run/whd/helper.sock")
    telemetry_interval_s: float = 1.0
    event_ring_size: int = 20000
    event_retention: int = 500_000
    ws_queue_size: int = 2000
    ollama_url: str = "http://127.0.0.1:11434"
    ollama_model: str | None = None
    enable_event_sources: bool = True
    demo_speed: float = 1.0
    enable_docs: bool = False
    cookie_secure: bool = False

    @classmethod
    def from_env(cls) -> Settings:
        s = cls()
        e = os.environ
        s.host = e.get("WHD_HOST", s.host)
        s.port = int(e.get("WHD_PORT", s.port))
        s.allow_remote = _bool(e.get("WHD_ALLOW_REMOTE"))
        s.demo_scenario = e.get("WHD_DEMO") or None
        if e.get("WHD_FIXTURES_DIR"):
            s.fixtures_dir = Path(e["WHD_FIXTURES_DIR"])
        if e.get("WHD_CONFIG_DIR"):
            s.config_dir = Path(e["WHD_CONFIG_DIR"])
        if e.get("WHD_STATE_DIR"):
            s.state_dir = Path(e["WHD_STATE_DIR"])
        if e.get("WHD_STATIC_DIR"):
            s.static_dir = Path(e["WHD_STATIC_DIR"])
        s.cache_ttl_s = float(e.get("WHD_CACHE_TTL", s.cache_ttl_s))
        if e.get("WHD_HELPER_SOCKET"):
            s.helper_socket = Path(e["WHD_HELPER_SOCKET"])
        s.telemetry_interval_s = float(e.get("WHD_TELEMETRY_INTERVAL", s.telemetry_interval_s))
        s.ollama_url = e.get("WHD_OLLAMA_URL", s.ollama_url)
        s.ollama_model = e.get("WHD_OLLAMA_MODEL") or None
        s.enable_event_sources = not _bool(e.get("WHD_NO_EVENT_SOURCES"))
        s.cookie_secure = _bool(e.get("WHD_COOKIE_SECURE"))
        s.enable_docs = _bool(e.get("WHD_ENABLE_DOCS"))
        s.demo_speed = max(0.1, min(60.0, float(e.get("WHD_DEMO_SPEED", s.demo_speed))))
        return s

    @property
    def mode(self) -> str:
        return "demo" if self.demo_scenario else "live"

    @property
    def db_path(self) -> Path:
        name = f"whd-demo-{self.demo_scenario}.db" if self.demo_scenario else "whd.db"
        return self.state_dir / name

    def check_bind(self) -> None:
        """Refuse non-loopback binds unless WHD_ALLOW_REMOTE=1 (spec 4.6)."""
        try:
            loopback = ipaddress.ip_address(self.host).is_loopback
        except ValueError:
            loopback = self.host == "localhost"
        if not loopback and not self.allow_remote:
            raise SystemExit(
                f"refusing to bind {self.host}: non-loopback bind requires WHD_ALLOW_REMOTE=1. "
                "Prefer an SSH tunnel: ssh -L 8787:127.0.0.1:8787 <host>"
            )
