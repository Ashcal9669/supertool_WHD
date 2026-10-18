"""Bounded interface-bound measurements; failures and interrupted runs remain capture artifacts."""

from __future__ import annotations

import asyncio
import ipaddress
import json
import secrets
import time
from typing import Any, Literal

from pydantic import Field, field_validator

from whd.capture.manager import CaptureConfig
from whd.clock import boottime_ns
from whd.drivers import mt76
from whd.helper.protocol import HelperError
from whd.mlo.provenance import snapshot
from whd.mlo.selection import interface_phy, verify_live_adapter
from whd.model.common import Model
from whd.model.events import Event
from whd.platform.sysfs import SysfsError
from whd.state import AppState


class ExperimentRequest(Model):
    device_id: str
    interface: str
    target: str
    tool: Literal["ping", "iperf3"] = "ping"
    seconds: int = Field(5, ge=1, le=30)
    count: int = Field(3, ge=1, le=10)
    port: int = Field(5201, ge=1, le=65535)
    trace_events: list[str] = Field(default_factory=list, max_length=64)
    wake_counters: bool = False
    comparison_group: str | None = Field(None, max_length=80)
    condition: Literal["control", "fix", "control_after", "observation"] = "observation"

    @field_validator("target")
    @classmethod
    def ip_target(cls, value: str) -> str:
        return str(ipaddress.ip_address(value))


class ExperimentResult(Model):
    capture_id: str
    status: str
    request: ExperimentRequest
    before: dict[str, Any] = Field(default_factory=dict)
    after: dict[str, Any] = Field(default_factory=dict)
    deltas: dict[str, int | None] = Field(default_factory=dict)
    per_link_deltas: dict[str, dict[str, int | None]] = Field(default_factory=dict)
    command: list[str] = Field(default_factory=list)
    exit_code: int | None = None
    output: str = ""
    error: str | None = None
    limits: list[str] = Field(
        default_factory=lambda: [
            "bound process and counters are an aggregate witness, not per-link RF proof",
            "counter resets give unknown deltas",
            "traffic generation perturbs/wakes the selected device",
        ]
    )


def counter_delta(before: dict[str, int], after: dict[str, int]) -> dict[str, int | None]:
    return {k: after[k] - v if k in after and after[k] >= v else None for k, v in before.items()}


def per_link_delta(before: dict[str, Any], after: dict[str, Any]) -> dict[str, dict[str, int | None]]:
    """A WCID number is reusable; subtraction requires an observed association and peer generation."""
    out: dict[str, dict[str, int | None]] = {}
    later = {(r["link"], r["wcid"]): r for r in after.get("per_link", [])}
    boot = before.get("provenance", {}).get("boot_id")
    epoch = before.get("association_epoch")
    same_scope = bool(
        boot
        and epoch
        and boot == after.get("provenance", {}).get("boot_id")
        and epoch == after.get("association_epoch")
    )
    for row in before.get("per_link", []):
        other = later.get((row["link"], row["wcid"]), {})
        generation = row.get("generation")
        same_peer = (
            generation is not None
            and generation == other.get("generation")
            and row.get("mac") == other.get("mac")
        )
        keys = ("rx_pkts", "rx_bytes", "tx_pkts", "tx_bytes")
        first = {k: row[k] for k in keys if k in row}
        out[f"link={row['link']} wcid={row['wcid']}"] = (
            counter_delta(first, {k: other[k] for k in keys if k in other})
            if same_scope and same_peer
            else {k: None for k in first}
        )
    return out


class CommandTimeout(TimeoutError):
    def __init__(self, output: str):
        super().__init__("measurement timed out; partial output retained")
        self.output = output


def recorded_analysis(saved: dict[str, Any]) -> dict[str, Any]:
    """Recheck historical derived values without rewriting the original recording."""
    result = dict(saved)
    result["per_link_deltas"] = per_link_delta(saved.get("before", {}), saved.get("after", {}))
    result["limits"] = [
        *saved.get("limits", []),
        "per-link deltas rechecked against recorded lifetime evidence; original experiment artifact retained",
    ]
    return result


class CommandCancelled(asyncio.CancelledError):
    def __init__(self, output: str):
        super().__init__("measurement interrupted; partial output retained")
        self.output = output


async def run_command(argv: list[str], budget_s: float) -> tuple[int, str]:
    proc = await asyncio.create_subprocess_exec(
        *argv, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.STDOUT
    )
    chunks: list[bytes] = []
    size = 0

    async def consume() -> None:
        nonlocal size
        assert proc.stdout
        while data := await proc.stdout.read(4096):
            size += len(data)
            if size <= 512 * 1024:
                chunks.append(data)

    try:
        await asyncio.wait_for(asyncio.gather(consume(), proc.wait()), budget_s)
    except (TimeoutError, asyncio.CancelledError) as exc:
        if proc.returncode is None:
            proc.kill()
            await proc.wait()
        output = b"".join(chunks).decode(errors="replace")
        if isinstance(exc, asyncio.CancelledError):
            raise CommandCancelled(output) from exc
        raise CommandTimeout(output) from exc
    return proc.returncode or 0, b"".join(chunks).decode(errors="replace")


async def measurement(
    st: AppState, dev: Any, interface: str, target: str, wake_counters: bool = False
) -> dict[str, Any]:
    def counters() -> dict[str, int]:
        out = {}
        for name in ("rx_bytes", "tx_bytes", "rx_packets", "tx_packets", "rx_dropped", "tx_dropped"):
            try:
                out[name] = int(st.host.root.read_text(f"/sys/class/net/{interface}/statistics/{name}"))
            except (SysfsError, ValueError):
                pass
        return out

    out: dict[str, Any] = {
        "ts_boottime_ns": boottime_ns(),
        "interface": interface,
        "counters": await asyncio.to_thread(counters),
        "per_link": [],
        "route": None,
        "provenance": await asyncio.to_thread(snapshot, st.host, [dev]),
    }
    phy = next((n.phy for n in dev.netdev_info if n.name == interface and n.phy), None)
    nl = st.host.nl80211()
    shared_phy = False
    if nl:
        try:
            ifaces = await asyncio.to_thread(nl.interfaces)
            current = next((i for i in ifaces if i.name == interface), None)
            phy = interface_phy(dev, current) if current is not None else None
            shared_phy = bool(
                phy
                and sum(
                    i.name in dev.netdevs and i.iftype == "STATION" and interface_phy(dev, i) == phy
                    for i in ifaces
                )
                > 1
            )
            out["query_perturbations"] = [
                "nl80211 GET queries performed; firmware-read or device-wake effects unmeasured"
            ]
        except (OSError, ValueError) as exc:
            phy = None
            out["configuration_gap"] = f"current interface PHY could not be verified: {exc}"
    if not nl and phy is None and len(dev.phys) == 1:
        phy = dev.phys[0]
    out["phy"] = phy
    ip = st.host.tool_path("ip")
    if ip and st.host.root.is_live:
        try:
            out["route"] = (await run_command([ip, "-j", "route", "get", target, "oif", interface], 3))[1]
            out["addresses"] = (await run_command([ip, "-j", "addr", "show", "dev", interface], 3))[1]
        except (OSError, TimeoutError) as exc:
            out["route_error"] = str(exc)
    if mt76.is_mt76(dev):
        if shared_phy:
            out["configuration_gap"] = (
                "multiple station interfaces share this PHY; per-association counters cannot be established"
            )
            return out
        if phy is None:
            out["configuration_gap"] = "selected interface PHY is unknown; no default-PHY counters collected"
            return out
        try:
            snap = await asyncio.to_thread(mt76.read_snapshot, st.host, dev, wake_counters, phy)
            out["per_link"], out["configuration"] = snap.link_stats, snap.model_dump(mode="json")
            out["perturbations"] = ["per-link counter reads may wake the device"] if wake_counters else []
        except HelperError as exc:
            out["configuration_gap"] = str(exc)
    return out


async def marker(st: AppState, cid: str, label: str, device_id: str | None) -> None:
    st.bus.publish(
        Event(
            ts_boottime_ns=boottime_ns(),
            ts_wall=time.time(),
            ts_source="receive_boottime",
            source="experiment",
            device_id=device_id,
            category="diagnostic",
            kind="experiment.marker",
            summary=label,
            explanation="experiment marker; no driver operation implied",
            raw=label,
            data={"capture_id": cid, "cookie": secrets.token_hex(8)},
        )
    )


async def run(st: AppState, req: ExperimentRequest) -> ExperimentResult:
    dev = await st.inventory.device(req.device_id)
    if dev is None or req.interface not in dev.netdevs or not dev.present:
        raise ValueError("select an existing interface belonging to this discovered device")
    if st.host.root.is_live:
        await asyncio.to_thread(verify_live_adapter, st.host, req.interface)
    if st.captures is None:
        raise ValueError("capture manager unavailable")
    info = await st.captures.create(
        CaptureConfig(name=f"Wi-Fi {req.condition} {req.tool}", device_id=dev.id, max_seconds=60)
    )
    result = ExperimentResult(capture_id=info.id, status="running", request=req)

    async def persist() -> None:
        await asyncio.to_thread(
            st.store.capture_put_artifact,
            info.id,
            "experiment.json",
            "application/json",
            result.model_dump_json().encode(),
        )

    await persist()
    trace_owned = False
    try:
        result.before = await measurement(st, dev, req.interface, req.target, req.wake_counters)
        await persist()
        await marker(st, info.id, "before", dev.id)
        if not st.host.root.is_live:
            raise ValueError("fixture mode: real network tests are disabled")
        if req.trace_events:
            if st.events is None:
                raise ValueError("trace runtime unavailable")
            if st.helper:
                formats = await asyncio.to_thread(
                    st.helper.call,
                    "tracefs_events",
                    15.0,
                    groups=sorted({spec.split("/")[0] for spec in req.trace_events}),
                    with_format=True,
                )
                await asyncio.to_thread(
                    st.store.capture_put_artifact,
                    info.id,
                    "trace-formats.json",
                    "application/json",
                    json.dumps(formats).encode(),
                )
            await st.events.start_trace(req.trace_events, 4096, 55, interface=req.interface)
            trace_owned = True
        executable = st.host.tool_path(req.tool)
        if not executable:
            raise ValueError(f"{req.tool} unavailable")
        if req.tool == "ping":
            result.command = [
                executable,
                "-n",
                "-I",
                req.interface,
                "-c",
                str(req.count),
                "-W",
                "2",
                req.target,
            ]
        else:
            _, help_text = await run_command([executable, "--help"], 3)
            if "--bind-dev" not in help_text:
                raise ValueError("installed iperf3 lacks --bind-dev; refusing unbound measurement")
            result.command = [
                executable,
                "-c",
                req.target,
                "--bind-dev",
                req.interface,
                "-t",
                str(req.seconds),
                "-p",
                str(req.port),
                "--json",
            ]
        st.bus.publish(
            Event(
                ts_boottime_ns=boottime_ns(),
                ts_wall=time.time(),
                ts_source="receive_boottime",
                source="experiment",
                device_id=dev.id,
                category="diagnostic",
                kind="packet.userspace_submit",
                summary=f"launch {req.tool} bound to {req.interface}",
                explanation="process launch; individual packet IDs not exposed",
                raw=json.dumps(result.command),
                data={"fields": {"cookie": info.id, "interface": req.interface}},
            )
        )
        await persist()
        await asyncio.to_thread(verify_live_adapter, st.host, req.interface)
        result.exit_code, result.output = await run_command(
            result.command, min(45, req.seconds + req.count * 2 + 5)
        )
        result.status = "completed" if result.exit_code == 0 else "failed"
    except asyncio.CancelledError as exc:
        result.status, result.error = "incomplete", "measurement interrupted"
        result.output = getattr(exc, "output", result.output)
        raise
    except (ValueError, RuntimeError, OSError, TimeoutError, HelperError) as exc:
        result.status, result.error = "error", str(exc)
        result.output = getattr(exc, "output", result.output)
    finally:
        try:
            if trace_owned and st.events:
                result.after["trace_status"] = st.events.trace_status()
                await st.events.stop_trace()
            result.after.update(await measurement(st, dev, req.interface, req.target, req.wake_counters))
            result.deltas = counter_delta(result.before.get("counters", {}), result.after.get("counters", {}))
            result.per_link_deltas = per_link_delta(result.before, result.after)
            await marker(st, info.id, "after", dev.id)
        finally:
            await persist()
            await st.captures.stop_capture(info.id, f"experiment {result.status}")
    return result
