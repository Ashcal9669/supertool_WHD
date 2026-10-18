"""Observed interface identity; missing lifetime must never be filled from a current interface."""

from whd.mlo.kv import fields_of
from whd.model.events import Event


def event_interface_scope(event: Event) -> tuple[str | None, str | None]:
    fields = fields_of(event)
    name = event.data.get("ifname") or event.data.get("interface") or fields.get("ifname")
    lifetime = None
    for key in ("interface_lifetime", "wdev", "ifindex"):
        value = event.data.get(key)
        if value is None:
            value = fields.get(key)
        if value is not None:
            lifetime = f"{key}:{value}"
            break
    return str(name) if name is not None and lifetime is not None else None, lifetime
