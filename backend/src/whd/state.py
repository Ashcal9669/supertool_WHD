"""Application state container shared by API routers."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

from whd.auth import Auth
from whd.config import Settings
from whd.events.bus import EventBus
from whd.platform.host import Host
from whd.services.inventory import Inventory
from whd.store.db import Store

if TYPE_CHECKING:
    from whd.capture.manager import CaptureManager
    from whd.events.runtime import EventRuntime
    from whd.helper.client import HelperLike


@dataclass
class AppState:
    settings: Settings
    host: Host
    store: Store
    auth: Auth
    bus: EventBus
    inventory: Inventory
    helper: HelperLike | None = None
    events: EventRuntime | None = None
    captures: CaptureManager | None = None
    extra: dict[str, Any] = field(default_factory=dict)
