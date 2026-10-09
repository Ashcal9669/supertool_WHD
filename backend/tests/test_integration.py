"""Cross-cutting guarantees: persistence across restarts, demo/live isolation, security boundaries."""

from __future__ import annotations

import os
from pathlib import Path

import httpx
import pytest
from fastapi.testclient import TestClient

from whd.app import build_state, create_app
from whd.config import Settings
from whd.events.sources import make_event

DEV = "pci:0000:07:00.0:14c3:7927"


def _ev(i: int, sev: str = "warning"):  # type: ignore[no-untyped-def]
    return make_event(
        ts=1000 + i,
        ts_source="receive_boottime",
        source="t",
        device_id=DEV,
        severity=sev,  # type: ignore[arg-type]
        category="firmware",
        kind="t.k",
        summary=f"persist {i}",
        explanation="e",
        raw="r",
    )


def test_restart_preserves_events_sessions_captures_and_history(settings: Settings) -> None:
    st1 = build_state(settings)
    with TestClient(create_app(settings, state=st1)) as c:
        tok = st1.auth.token
        r = c.post("/api/v1/auth/login", json={"token": tok})
        assert r.status_code == 200
        cookie = c.cookies.get("whd_session")
        cid = c.post("/api/v1/captures", json={"name": "survives"}, headers={"x-whd-request": "1"}).json()[
            "id"
        ]
        for i in range(3):
            st1.bus.publish(_ev(i))
        st1.bus.flush()
        assert c.get("/api/v1/events?min_severity=warning&text=persist").json()["events"]
        # capture left running at shutdown is stopped by lifespan teardown
    # ---- second process lifetime, same dirs (new Auth object reads the same token/key files)
    st2 = build_state(settings)
    assert st2.auth.token == st1.auth.token
    with TestClient(create_app(settings, state=st2)) as c2:
        c2.cookies.set("whd_session", cookie or "")
        assert c2.get("/api/v1/auth/session").status_code == 200, "signed session must survive restart"
        evs = c2.get("/api/v1/events?text=persist&order=asc").json()["events"]
        assert [e["summary"] for e in evs] == ["persist 0", "persist 1", "persist 2"]
        cap = c2.get(f"/api/v1/captures/{cid}").json()
        assert cap["state"] in ("stopped", "expired") and cap["stats"]["stop_reason"]
        runs = c2.get("/api/v1/discovery/runs").json()
        assert len(runs) >= 2, "discovery history accumulates across restarts"
        dev = c2.get(f"/api/v1/devices/{DEV}").json()
        assert dev["first_seen"] is not None


def test_stale_running_capture_is_marked_stopped_on_startup(settings: Settings) -> None:
    st = build_state(settings)
    st.store.capture_upsert(
        {
            "id": "cap-stale",
            "name": "x",
            "state": "running",
            "created_at": 1.0,
            "started_ns": 1,
            "stopped_ns": None,
            "config_json": '{"name":"x"}',
            "stats_json": "{}",
            "mode": "demo",
        }
    )
    with TestClient(create_app(settings, state=st)) as c:
        c.headers["authorization"] = f"Bearer {st.auth.token}"
        cap = c.get("/api/v1/captures/cap-stale").json()
        assert cap["state"] == "stopped" and "restarted" in cap["stats"]["stop_reason"]


def test_demo_and_live_databases_are_separate(tmp_path: Path) -> None:
    live, demo = Settings(), Settings()
    live.state_dir = demo.state_dir = tmp_path
    demo.demo_scenario = "mt7921u-usb"
    assert live.db_path.name == "whd.db" and demo.db_path.name == "whd-demo-mt7921u-usb.db"
    assert live.db_path != demo.db_path and live.mode == "live" and demo.mode == "demo"


def test_events_written_in_demo_mode_are_flagged_demo(settings: Settings) -> None:
    st = build_state(settings)  # settings fixture runs demo scenario mt7927-pcie-host
    st.bus.publish(_ev(1))
    assert st.bus.ring[-1].demo is True


def test_server_refuses_to_run_as_root(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    from whd import __main__ as cli

    monkeypatch.setattr(os, "geteuid", lambda: 0)
    monkeypatch.setenv("WHD_HOST", "127.0.0.1")
    rc = cli.main(["serve", "--demo", "empty"])
    assert rc == 2 and "refusing to run the WHD web server as root" in capsys.readouterr().err


def test_websocket_rejects_cross_origin_and_unauthenticated(settings: Settings) -> None:
    st = build_state(settings)
    with TestClient(create_app(settings, state=st)) as c:
        with pytest.raises(Exception), c.websocket_connect("/api/v1/stream") as ws:
            ws.receive_json()
        with (
            pytest.raises(Exception),
            c.websocket_connect(
                f"/api/v1/stream?token={st.auth.token}", headers={"origin": "http://evil.example"}
            ) as ws,
        ):
            ws.receive_json()
        with c.websocket_connect(f"/api/v1/stream?token={st.auth.token}") as ws:
            assert ws.receive_json()["type"] == "hello"


async def test_static_serving_blocks_path_traversal_and_sets_headers(
    settings: Settings, tmp_path: Path
) -> None:
    static = tmp_path / "dist"
    (static / "assets").mkdir(parents=True)
    (static / "index.html").write_text("<html>spa</html>")
    (static / "assets" / "a.js").write_text("x")
    (tmp_path / "secret.txt").write_text("SECRET")
    settings.static_dir = static
    st = build_state(settings)
    app = create_app(settings, state=st)
    async with app.router.lifespan_context(app):
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://t") as c:
            r = await c.get("/")
            assert r.status_code == 200 and "spa" in r.text
            assert "default-src 'self'" in r.headers["content-security-policy"]
            assert r.headers["x-frame-options"] == "DENY" and r.headers["x-content-type-options"] == "nosniff"
            for evil in (
                "/../secret.txt",
                "/%2e%2e/secret.txt",
                "/..%2fsecret.txt",
                "/assets/../../secret.txt",
            ):
                t = await c.get(evil)
                assert "SECRET" not in t.text, evil
            assert (await c.get("/api/nope")).status_code == 404
            assert (await c.get("/api/docs")).status_code in (200, 404)  # SPA fallback or 404, never swagger
            assert "swagger" not in (await c.get("/api/docs")).text.lower()
            assert "openapi" not in (await c.get("/api/openapi.json")).text[:200].lower()


async def test_login_rate_limit(settings: Settings) -> None:
    st = build_state(settings)
    app = create_app(settings, state=st)
    async with app.router.lifespan_context(app):
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://t") as c:
            codes = [
                (await c.post("/api/v1/auth/login", json={"token": f"bad{i}"})).status_code for i in range(12)
            ]
            assert codes[:10] == [401] * 10 and codes[10] == 429
            assert (await c.post("/api/v1/auth/login", json={"token": st.auth.token})).status_code == 429


@pytest.mark.live
@pytest.mark.skipif(
    os.environ.get("WHD_LIVE") != "1", reason="set WHD_LIVE=1 to run against this host's hardware"
)
def test_live_host_discovery_is_read_only_and_finds_a_phy() -> None:
    from whd.discovery import Discovery
    from whd.platform.host import LiveHost

    res = Discovery(LiveHost()).run()
    assert not [i for i in res.issues if i.kind == "error"]
    with_phy = [d for d in res.devices if d.phys]
    assert with_phy, "expected at least one wireless device with a bound PHY on the dev host"
    d = with_phy[0]
    assert d.wiphys and d.wiphys[0].bands and d.netdev_info and d.driver
    assert d.id.startswith(("pci:", "usb:"))
