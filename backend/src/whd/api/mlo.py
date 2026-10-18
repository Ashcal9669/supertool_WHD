"""Scoped MLO evidence and capture artifacts; reads never trigger scans or link steering."""

from __future__ import annotations

import asyncio
import hashlib
import secrets
import time
from typing import Any, Literal

from fastapi import APIRouter, Depends, HTTPException, Query, Request, Response

from whd.api.deps import get_state, require_auth
from whd.drivers import mt76
from whd.helper.protocol import HelperError
from whd.mlo import air, experiments, fwid, report, stack_pcap
from whd.mlo.selection import interface_phy, verify_live_adapter
from whd.mlo.state import build_state
from whd.mlo.timeline import Collectors
from whd.model.device import Device
from whd.model.events import EventFilter
from whd.platform.sysfs import SysfsError
from whd.state import AppState

router = APIRouter(prefix="/api/v1")
Auth = Depends(require_auth)
State = Depends(get_state)


@router.get("/captures/{cid}/wifi/stack", response_model=list[stack_pcap.StackCapture])
async def stack_imports(cid: str, _: str = Auth, st: AppState = State) -> list[stack_pcap.StackCapture]:
    if st.captures is None:
        raise HTTPException(503, "capture manager unavailable")
    try:
        await st.captures.info(cid)
    except KeyError:
        raise HTTPException(404, "unknown capture") from None
    results = []
    for meta in await asyncio.to_thread(st.store.capture_artifacts, cid):
        if meta["name"].startswith("stack-") and meta["name"].endswith(".json"):
            saved = await st.captures.artifact_json(cid, meta["name"])
            if saved:
                results.append(stack_pcap.StackCapture.model_validate(saved))
    return results


@router.post("/captures/{cid}/wifi/stack", response_model=stack_pcap.StackCapture)
async def stack_upload(
    cid: str,
    request: Request,
    direction: Literal["tx", "rx"],
    interface: str,
    boot_id: str,
    wall_minus_boot_ns: int,
    actor: str = Auth,
    st: AppState = State,
) -> stack_pcap.StackCapture:
    if st.captures is None:
        raise HTTPException(503, "capture manager unavailable")
    try:
        info = await st.captures.info(cid)
    except KeyError:
        raise HTTPException(404, "unknown capture") from None
    if info.state == "running":
        raise HTTPException(409, "stop this capture before importing stack observations")
    provenance = await st.captures.artifact_json(cid, "provenance_start.json") or {}
    devices = (await st.captures.artifact_json(cid, "devices_start.json") or {}).get("devices", [])
    device = next(
        (d for d in devices if interface in d.get("netdevs", []) and d.get("id") == info.config.device_id),
        None,
    )
    if not device or boot_id != provenance.get("boot_id"):
        raise HTTPException(422, "interface or boot does not match this capture's recorded provenance")
    from whd.api.captures import _read_limited

    data = await _read_limited(request, 16 * 1024 * 1024)
    try:
        decoded = await asyncio.to_thread(
            stack_pcap.decode,
            data,
            direction=direction,
            device_id=device["id"],
            interface=interface,
            boot_id=boot_id,
            wall_minus_boot_ns=wall_minus_boot_ns,
        )
    except ValueError as exc:
        raise HTTPException(422, str(exc)) from exc
    # Never merge a different run merely by assigning its boot UUID.
    if info.started_ns is None:
        raise HTTPException(422, "capture start time unavailable; run scope cannot be verified")
    if any(
        e.ts_boottime_ns < info.started_ns - 2_000_000_000
        or (info.stopped_ns is not None and e.ts_boottime_ns > info.stopped_ns + 2_000_000_000)
        for e in decoded.events
    ):
        raise HTTPException(
            422, "packet timestamps fall outside this capture; check run and clock calibration"
        )
    decoded.import_id = "stack-" + secrets.token_hex(12)
    decoded.report_artifact = decoded.import_id + ".json"
    if decoded.original_retained:
        decoded.pcap_artifact = decoded.import_id + ".pcap"
        await asyncio.to_thread(
            st.store.capture_put_artifact, cid, decoded.pcap_artifact, "application/vnd.tcpdump.pcap", data
        )
    else:
        decoded.limits.append(
            "original PCAP withheld: EAPOL key-data or unsupported payloads; only safe decoded observations retained"
        )
    await asyncio.to_thread(
        st.store.capture_put_artifact,
        cid,
        decoded.report_artifact,
        "application/json",
        decoded.model_dump_json().encode(),
    )
    st.store.audit(
        actor,
        "stack_capture_import",
        {
            "capture": cid,
            "direction": direction,
            "interface": interface,
            "sha256": decoded.sha256,
            "original_retained": decoded.original_retained,
        },
    )
    return decoded


@router.get("/mlo/comparisons")
async def comparisons(
    group: str = Query(min_length=1, max_length=80), _: str = Auth, st: AppState = State
) -> dict[str, Any]:
    runs = []
    if st.captures:
        for capture in reversed(await st.captures.list_all()):
            run = await st.captures.artifact_json(capture.id, "experiment.json")
            if run and run.get("request", {}).get("comparison_group") == group:
                runs.append(experiments.recorded_analysis(run))
    identities = {
        (
            r["request"]["device_id"],
            r["request"]["interface"],
            r["request"]["target"],
            r["request"]["tool"],
            r["request"].get("count", 3),
            r["request"].get("seconds", 5),
            r["request"].get("port", 5201),
            r["request"].get("wake_counters", False),
            tuple(sorted(r["request"].get("trace_events", []))),
        )
        for r in runs
    }
    boots = {r.get("before", {}).get("provenance", {}).get("boot_id") for r in runs}
    comparable = len(identities) == 1 and len(boots) == 1 and None not in boots
    return {
        "group": group,
        "runs": runs,
        "comparable": comparable,
        "limits": [
            "runs retain separate observations; labels describe externally applied conditions",
            "different boots, devices, interfaces, targets, tools or measurement settings prevent a single comparison",
            "aggregate counter deltas do not prove per-link RF or authenticated delivery",
        ],
    }


@router.post("/mlo/experiments", response_model=experiments.ExperimentResult)
async def experiment(
    req: experiments.ExperimentRequest, actor: str = Auth, st: AppState = State
) -> experiments.ExperimentResult:
    st.store.audit(actor, "mlo_experiment_request", req.model_dump())
    try:
        return await experiments.run(st, req)
    except ValueError as exc:
        raise HTTPException(422, str(exc)) from exc


@router.get("/mlo/monitors")
async def monitors(_: str = Auth, st: AppState = State) -> dict[str, Any]:
    inv = await st.inventory.get()
    return {
        "devices": [
            {
                "id": d.id,
                "phys": d.phys,
                "interfaces": [n.model_dump() for n in d.netdev_info],
                "monitor_capability": [
                    {"phy": w.name, "interface_types": w.supported_iftypes} for w in d.wiphys
                ],
            }
            for d in inv.devices
        ],
        "tools": {n: st.host.tool_path(n) for n in ("tcpdump", "dumpcap", "tshark", "ping", "iperf3")},
        "limits": [
            "advertised monitor capability does not prove RF coverage",
            "no monitor configured or retuned; upload selected evidence",
        ],
    }


@router.post("/captures/{cid}/mlo/air", response_model=air.AirReport)
async def air_upload(
    cid: str,
    request: Request,
    origin: str = Query("independent", pattern="^(independent|ap_local|same_phy)$"),
    filename: str = Query("capture.pcap", max_length=200),
    actor: str = Auth,
    st: AppState = State,
) -> air.AirReport:
    if not st.captures:
        raise HTTPException(503, "capture manager unavailable")
    try:
        await st.captures.info(cid)
    except KeyError:
        raise HTTPException(404, "unknown capture") from None
    from whd.api.captures import _read_limited

    data = await _read_limited(request, 16 * 1024 * 1024)
    decoded = await asyncio.to_thread(air.parse_pcap, data, origin)  # type: ignore[arg-type]
    decoded.import_id = "air-" + secrets.token_hex(12)
    decoded.filename = filename.rsplit("/", 1)[-1].rsplit("\\", 1)[-1]
    decoded.sha256 = hashlib.sha256(data).hexdigest()
    decoded.pcap_artifact = f"{decoded.import_id}.pcap" if decoded.original_retained else None
    decoded.report_artifact = f"{decoded.import_id}.json"
    for name, mime, payload in [
        (decoded.pcap_artifact, "application/vnd.tcpdump.pcap", data),
        (decoded.report_artifact, "application/json", decoded.model_dump_json().encode()),
    ]:
        if name is not None:
            await asyncio.to_thread(st.store.capture_put_artifact, cid, name, mime, payload)
    st.store.audit(actor, "air_capture_import", {"capture": cid, "origin": origin, "bytes": len(data)})
    return decoded


@router.get("/captures/{cid}/mlo/air", response_model=list[air.AirReport])
async def air_imports(cid: str, _: str = Auth, st: AppState = State) -> list[air.AirReport]:
    if not st.captures:
        raise HTTPException(503, "capture manager unavailable")
    try:
        await st.captures.info(cid)
    except KeyError:
        raise HTTPException(404, "unknown capture") from None
    imports = []
    for meta in await asyncio.to_thread(st.store.capture_artifacts, cid):
        if meta["name"].startswith("air-") and meta["name"].endswith(".json"):
            saved = await st.captures.artifact_json(cid, meta["name"])
            if saved and "origin" in saved and "frames" in saved:
                decoded = air.AirReport.model_validate(saved)
                # Retain legacy artifacts; earlier overwritten imports cannot be reconstructed.
                decoded.import_id = decoded.import_id or meta["name"][:-5]
                decoded.report_artifact = decoded.report_artifact or meta["name"]
                decoded.pcap_artifact = decoded.pcap_artifact or meta["name"][:-5] + ".pcap"
                if not await asyncio.to_thread(st.store.capture_artifact, cid, decoded.pcap_artifact):
                    decoded.pcap_artifact = None
                    decoded.limits.append("original bytes absent from this imported bundle")
                imports.append(decoded)
    return imports


@router.get("/devices/{device_id}/mlo/evidence", response_model=report.EvidenceReport)
async def device_evidence(
    device_id: str,
    wake: bool = False,
    phy: str | None = None,
    interface: str | None = None,
    limit: int = Query(10000, ge=1, le=20000),
    actor: str = Auth,
    st: AppState = State,
) -> report.EvidenceReport:
    dev = await st.inventory.device(device_id)
    if dev is None:
        raise HTTPException(404, "unknown device")
    recent = list(st.bus.ring)
    live_ring = st.settings.mode == "live" and st.settings.enable_event_sources and bool(recent)
    if live_ring:
        events = [e for e in recent if e.device_id == device_id][-limit:]
        unassigned = [e for e in recent if e.device_id is None][-1000:]
    else:
        events = await asyncio.to_thread(
            st.store.query_events, EventFilter(device_id=device_id), None, limit, "desc"
        )
        unassigned = await asyncio.to_thread(
            st.store.query_unattributed_context, max((e.id or 0 for e in events), default=0)
        )
    rep = await asyncio.to_thread(
        report.analyze, events + unassigned, device_id, st.settings.mode, device=dev
    )
    rep.limits.append(
        "History is the bounded live collector ring; open a recorded capture for complete run evidence. Unassigned observations do not establish device ownership."
        if live_ring
        else "Unassigned context is limited to 1000 records within the preceding 20000 global event IDs; proximity does not establish device ownership."
    )
    rep.current_observations = {
        "source": "fresh nl80211 GET and passive debugfs",
        "read_at": time.time(),
        "helper_available": bool(st.helper and st.helper.available),
    }
    rep.truncated = len(events) == limit
    if not dev.present:
        return rep
    if st.host.root.is_live and wake:
        if not interface:
            raise HTTPException(422, "select a verified MT7922 interface for wake measurements")
        try:
            await asyncio.to_thread(verify_live_adapter, st.host, interface)
        except ValueError as exc:
            raise HTTPException(422, str(exc)) from exc
    if interface and interface not in dev.netdevs:
        raise HTTPException(422, "interface does not belong to this discovered device")
    if phy and phy not in dev.phys:
        raise HTTPException(422, "PHY does not belong to this discovered device")
    nl = st.host.nl80211()
    nl_links: list[dict[str, Any]] = []
    authorized, connected = None, None
    shared_phy = False
    interface_lifetime = None
    if nl:
        try:
            ifaces = await asyncio.to_thread(nl.interfaces)
            selected_iface = next((i for i in ifaces if i.name == interface), None) if interface else None
            if interface and selected_iface is None:
                rep.limits.append(
                    "selected interface absent from current nl80211 inventory; readings withheld"
                )
                return rep
            if phy and selected_iface is not None and interface_phy(dev, selected_iface) != phy:
                raise HTTPException(422, "selected interface currently belongs to a different or unknown PHY")
            mine = [
                i
                for i in ifaces
                if i.name in dev.netdevs
                and (interface is None or i.name == interface)
                and (phy is None or interface_phy(dev, i) == phy)
            ]
            if len(mine) > 1:
                rep.limits.append(
                    "select one interface; multiple associations/PHYs cannot share a link-state table"
                )
                return rep
            for iface in mine:
                interface = iface.name
                rep.current_observations.update(
                    interface=interface,
                    wdev=getattr(iface, "wdev", None),
                    frequency_mhz=getattr(iface, "freq_mhz", None),
                )
                current_wdev = getattr(iface, "wdev", None)
                interface_lifetime = f"wdev:{current_wdev}" if current_wdev is not None else None
                selected_phy = interface_phy(dev, iface)
                phy = phy or selected_phy
                if phy is None:
                    rep.limits.append("current interface PHY identity is unknown; readings withheld")
                    return rep
                shared_phy = (
                    sum(
                        i.name in dev.netdevs and i.iftype == "STATION" and interface_phy(dev, i) == phy
                        for i in ifaces
                    )
                    > 1
                )
                nl_links.extend(link.model_dump() for link in iface.mlo_links)
                stations = await asyncio.to_thread(nl.stations, iface.ifindex)
                if iface.iftype == "STATION":
                    connected = bool(stations)
                    if stations:
                        authorized = stations[0].flags.get("AUTHORIZED", stations[0].flags.get("authorized"))
                        rep.current_observations["station_peer"] = getattr(stations[0], "mac", None)
                    rep.current_observations.update(connected=connected, station_authorized=authorized)
        except (OSError, ValueError) as exc:
            rep.limits.append(f"nl80211 query failed: {exc}")
    if interface is None:
        candidates = [
            n.name for n in dev.netdev_info if n.name in dev.netdevs and (phy is None or n.phy == phy)
        ]
        if len(candidates) != 1:
            rep.limits.append("select one interface; association identity is ambiguous")
            return rep
        interface = candidates[0]
    phy = phy or next((n.phy for n in dev.netdev_info if n.name == interface), None)
    if phy is None and len(dev.phys) == 1:
        phy = dev.phys[0]
    snap = None
    if shared_phy:
        rep.limits.append(
            "multiple station interfaces share this PHY; per-PHY debugfs cannot establish per-association masks or counters"
        )
    if rep.protocol != "ordinary" and mt76.is_mt76(dev) and phy and not shared_phy:
        try:
            snap = await asyncio.to_thread(mt76.read_snapshot, st.host, dev, wake, phy)
        except HelperError as exc:
            rep.limits.append(f"debugfs unavailable: {exc}")
    try:
        boot = await asyncio.to_thread(st.host.root.read_text, "/proc/sys/kernel/random/boot_id")
    except SysfsError:
        boot = None
    if not boot:
        boot = "fixture" if st.settings.mode == "demo" else "unknown"
    rep.current_observations.update(boot_id=boot.strip(), interface=interface, phy=phy)
    if snap is not None:
        rep.current_observations.update(
            packed_link_mask=snap.mlo_active_links, skipped_reads=getattr(snap, "skipped", [])
        )
    if rep.protocol == "ordinary":
        rep.limits.append(
            f"current interface {interface}; connected={connected}; station authorized={authorized}; "
            "nl80211 GET queries may wake the device; effect unmeasured; security/PN delivery requires packet evidence"
        )
        return rep
    same_boot = [w for w in rep.windows if w.scope.boot_id == boot.strip()]
    window = same_boot[-1] if same_boot else None
    if wake:
        st.store.audit(actor, "mlo_snapshot_wake", {"device_id": device_id, "phy": phy})
    rep.current_state = build_state(
        interface=interface,
        interface_lifetime=interface_lifetime,
        device_id=device_id,
        phy=snap.phy if snap else phy,
        boot_id=boot.strip(),
        epoch=None,
        epoch_events=[],
        mask_raw=snap.mlo_active_links if snap else None,
        mask_read_ns=snap.boottime_ns if snap else None,
        link_stats=snap.link_stats if snap else [],
        wcid_dump=snap.wcid_dump if snap else [],
        nl_links=nl_links,
        nl_connected=connected,
        sta_authorized=authorized,
        fw=fwid.FwReport(ops=[], links=[], flags=[], generations=[], gaps=[]),
        rx_frames=[],
        woke_device=bool(wake and snap),
        sources=["nl80211", "passive debugfs"],
    )
    if nl:
        rep.current_state.perturbations.append(
            "nl80211 GET queries performed; firmware-read or device-wake effects were not measured"
        )
    if window:
        rep.current_state.notes.append(
            "historical firmware/RX observations are shown separately from current readings"
        )
    return rep


@router.get("/captures/{cid}/mlo/evidence", response_model=report.EvidenceReport)
async def capture_evidence(
    cid: str, device_id: str | None = None, _: str = Auth, st: AppState = State
) -> report.EvidenceReport:
    if st.captures is None:
        raise HTTPException(503, "capture manager unavailable")
    try:
        info = await st.captures.info(cid)
        events = await st.captures.events(cid)
    except KeyError:
        raise HTTPException(404, "unknown capture") from None
    device_id = device_id or info.config.device_id or next((e.device_id for e in events if e.device_id), None)
    if not device_id:
        raise HTTPException(
            422, "select a device identity from this capture; no attributed device was recorded"
        )
    formats = await st.captures.artifact_json(cid, "trace-formats.json")
    recorded_devices = await st.captures.artifact_json(cid, "devices_start.json") or {}
    recorded_device = next((d for d in recorded_devices.get("devices", []) if d.get("id") == device_id), None)
    rep = await asyncio.to_thread(
        report.analyze,
        events,
        device_id,
        info.mode,
        cid,
        Collectors.from_formats(formats),
        Device.model_validate(recorded_device) if recorded_device else None,
    )
    if rep.protocol == "ordinary":
        return rep
    experiment = await st.captures.artifact_json(cid, "experiment.json") or {}
    for phase in ("before", "after"):
        measured = experiment.get(phase) or {}
        provenance = measured.get("provenance") or await st.captures.artifact_json(
            cid, f"provenance_{'start' if phase == 'before' else 'end'}.json"
        )
        if not provenance:
            continue
        device = next((d for d in provenance.get("devices", []) if d.get("id") == device_id), None)
        if not device:
            continue
        interfaces = device.get("netdev_info", [])
        selected_interface = measured.get("interface")
        selected = (
            [n for n in interfaces if n.get("name") == selected_interface]
            if selected_interface
            else interfaces
            if len(interfaces) == 1
            else []
        )
        nl_links = [link for n in selected for link in (n.get("wifi") or {}).get("mlo_links", [])]
        cfg = measured.get("configuration") or {}
        if not selected and len(interfaces) > 1:
            cfg = {}
            rep.limits.append(
                f"historical {phase} interface selection unknown; association readings withheld"
            )
        state = build_state(
            interface=selected_interface or (selected[0].get("name") if selected else None),
            device_id=device_id,
            phy=cfg.get("phy"),
            boot_id=provenance.get("boot_id") or "unknown",
            epoch=None,
            epoch_events=[],
            mask_raw=cfg.get("mlo_active_links"),
            mask_read_ns=cfg.get("boottime_ns"),
            link_stats=cfg.get("link_stats") or [],
            wcid_dump=cfg.get("wcid_dump") or [],
            nl_links=nl_links,
            nl_connected=None,
            sta_authorized=None,
            fw=fwid.FwReport(ops=[], links=[], flags=[], generations=[], gaps=[]),
            rx_frames=[],
            woke_device=bool(cfg.get("include_wake")),
            sources=[f"capture-time {phase} snapshot"],
        )
        state.notes.append(f"historical {phase} snapshot; association lifetime unobserved")
        state.boottime_ns = (
            cfg.get("boottime_ns")
            or measured.get("ts_boottime_ns")
            or provenance.get("clock", {}).get("boottime_before_ns", 0)
        )
        for link in state.links:
            for dim in (
                link.negotiated,
                link.active,
                link.fw_programmed,
                link.authorized,
                link.authenticated_delivery,
            ):
                dim.historical = True
        rep.snapshot_states.append(state)
    return rep


@router.get("/captures/{cid}/artifacts/{name:path}")
async def artifact(cid: str, name: str, _: str = Auth, st: AppState = State) -> Response:
    data = await asyncio.to_thread(st.store.capture_artifact, cid, name)
    if not data:
        raise HTTPException(404, "unknown capture artifact")
    return Response(content=data[1], media_type=data[0], headers={"Content-Disposition": "attachment"})
