"""Registry of driver extensions. Each runs during discovery for every device (must be cheap, no privileged calls)."""

from __future__ import annotations

from whd.discovery import Extension
from whd.drivers import mt76


def extensions() -> list[Extension]:
    return [mt76.discovery_extension]
