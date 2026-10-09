from __future__ import annotations

from collections.abc import AsyncIterator

import httpx
import pytest

from whd.app import build_state, create_app
from whd.config import Settings


@pytest.fixture
async def client(settings: Settings) -> AsyncIterator[httpx.AsyncClient]:
    st = build_state(settings)
    app = create_app(settings, state=st)
    async with app.router.lifespan_context(app):
        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as c:
            c.headers["x-test-token"] = st.auth.token
            yield c


async def login(c: httpx.AsyncClient) -> None:
    r = await c.post("/api/v1/auth/login", json={"token": c.headers["x-test-token"]})
    assert r.status_code == 200, r.text


async def test_health_is_public(client: httpx.AsyncClient) -> None:
    r = await client.get("/api/v1/health")
    assert r.status_code == 200 and r.json()["mode"] == "demo"


async def test_auth_required(client: httpx.AsyncClient) -> None:
    for path in ("/api/v1/devices", "/api/v1/system", "/api/v1/devices/x"):
        assert (await client.get(path)).status_code == 401
    r = await client.post("/api/v1/auth/login", json={"token": "wrong"})
    assert r.status_code == 401


async def test_session_flow_and_inventory(client: httpx.AsyncClient) -> None:
    await login(client)
    r = await client.get("/api/v1/devices")
    assert r.status_code == 200
    inv = r.json()
    assert inv["mode"] == "demo"
    (d,) = [x for x in inv["devices"] if x["present"]]
    assert d["id"] == "pci:0000:07:00.0:14c3:7927" and d["demo"] is True
    r = await client.get(f"/api/v1/devices/{d['id']}")
    assert r.status_code == 200 and r.json()["pci"]["link"]["current_gen"] == 3
    r = await client.get(f"/api/v1/devices/{d['id']}/evidence")
    assert r.status_code == 200
    assert any(k.endswith("/vendor") for k in r.json()["sysfs_attributes"])
    assert (await client.get("/api/v1/devices/nope")).status_code == 404
    s = (await client.get("/api/v1/system")).json()
    assert s["mode"] == "demo" and s["fixture_kind"] == "recorded" and not s["running_as_root"]
    assert any(i["name"] == "nl80211" and i["state"] == "ok" for i in s["integrations"])


async def test_csrf_header_required_for_cookie_mutations(client: httpx.AsyncClient) -> None:
    await login(client)
    assert (await client.post("/api/v1/discovery/rescan")).status_code == 403
    r = await client.post("/api/v1/discovery/rescan", headers={"x-whd-request": "1"})
    assert r.status_code == 200 and r.json()["device_count"] == 1


async def test_bearer_token(client: httpx.AsyncClient) -> None:
    r = await client.get(
        "/api/v1/devices", headers={"authorization": f"Bearer {client.headers['x-test-token']}"}
    )
    assert r.status_code == 200
    r = await client.post(
        "/api/v1/discovery/rescan", headers={"authorization": f"Bearer {client.headers['x-test-token']}"}
    )
    assert r.status_code == 200


async def test_logout_revokes(client: httpx.AsyncClient) -> None:
    await login(client)
    assert (await client.get("/api/v1/auth/session")).status_code == 200
    cookie = client.cookies.get("whd_session")
    await client.post("/api/v1/auth/logout")
    client.cookies.set("whd_session", cookie or "")
    assert (await client.get("/api/v1/auth/session")).status_code == 401


def test_remote_bind_guard() -> None:
    s = Settings()
    s.host = "0.0.0.0"
    with pytest.raises(SystemExit):
        s.check_bind()
    s.allow_remote = True
    s.check_bind()
    s2 = Settings()
    s2.host = "::1"
    s2.check_bind()


def test_token_file_permissions(settings: Settings) -> None:
    from whd.auth import Auth

    a = Auth(settings.config_dir)
    assert (a.token_path.stat().st_mode & 0o777) == 0o600
    assert len(a.token) == 64
    assert Auth(settings.config_dir).token == a.token
