"""pci.ids / usb.ids name lookup (the hwdata text format)."""

from __future__ import annotations

from dataclasses import dataclass, field

from whd.platform.sysfs import SysfsError, SysRoot

PCI_IDS = ["/usr/share/misc/pci.ids", "/usr/share/hwdata/pci.ids"]
USB_IDS = ["/usr/share/misc/usb.ids", "/var/lib/usbutils/usb.ids", "/usr/share/hwdata/usb.ids"]


@dataclass
class IdsDb:
    path: str | None = None
    vendors: dict[int, str] = field(default_factory=dict)
    devices: dict[tuple[int, int], str] = field(default_factory=dict)
    subsys: dict[tuple[int, int, int, int], str] = field(default_factory=dict)

    @classmethod
    def load(cls, root: SysRoot, candidates: list[str]) -> IdsDb:
        for p in candidates:
            try:
                text = root.read_bytes(p, limit=16 << 20).decode("utf-8", errors="replace")
            except SysfsError:
                continue
            return cls._parse(p, text)
        return cls()

    @classmethod
    def _parse(cls, path: str, text: str) -> IdsDb:
        db = cls(path=path)
        ven: int | None = None
        dev: int | None = None
        for line in text.splitlines():
            if not line or line.startswith("#"):
                continue
            if line.startswith("C "):  # class section begins: stop
                break
            try:
                if not line.startswith("\t"):
                    ven = int(line[:4], 16)
                    dev = None
                    db.vendors[ven] = line[4:].strip()
                elif line.startswith("\t\t"):
                    if ven is None or dev is None:
                        continue
                    sv, sd = line[2:].split()[:2]
                    db.subsys[(ven, dev, int(sv, 16), int(sd, 16))] = line[2:].split(None, 2)[2].strip()
                else:
                    if ven is None:
                        continue
                    dev = int(line[1:5], 16)
                    db.devices[(ven, dev)] = line[5:].strip()
            except (ValueError, IndexError):
                continue
        return db

    def vendor(self, v: int | None) -> str | None:
        return self.vendors.get(v) if v is not None else None

    def device(self, v: int | None, d: int | None) -> str | None:
        return self.devices.get((v, d)) if v is not None and d is not None else None

    def subsystem(self, v: int | None, d: int | None, sv: int | None, sd: int | None) -> str | None:
        if None in (v, d, sv, sd):
            return None
        return self.subsys.get((v, d, sv, sd))  # type: ignore[arg-type]
