from __future__ import annotations

from collections.abc import AsyncIterator

import httpx
import pytest

from whd.app import build_state, create_app
from whd.config import Settings


@pytest.fixture
async def usb_client(settings: Settings) -> AsyncIterator[httpx.AsyncClient]:
    settings.demo_scenario = "mt7921u-usb"
    st = build_state(settings)
    app = create_app(settings, state=st)
    async with (
        app.router.lifespan_context(app),
        httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app),
            base_url="http://t",
            headers={"authorization": f"Bearer {st.auth.token}"},
        ) as c,
    ):
        yield c


async def test_live_wireless_station(usb_client: httpx.AsyncClient) -> None:
    r = await usb_client.get("/api/v1/devices/usb:000000000:0e8d:7961/wireless/live")
    assert r.status_code == 200, r.text
    d = r.json()
    (li,) = d["interfaces"]
    assert li["connected"] and "HE MCS9 NSS2 80 MHz" in li["association_summary"]
    s = li["stations"][0]
    assert s["signal_dbm"] == -52 and s["tx_retries"] == 811 and s["chain_signal_dbm"] == [-54, -55]
    assert li["survey"][0]["in_use"] and li["scan"][0]["status"] == "ASSOCIATED"
    assert d["regulatory"][0]["alpha2"] == "US" and d["regulatory"][0]["rules"]
    caps = d["capability_summary"]["phy0"]["bands"]
    assert caps["5GHZ"]["highest"].startswith("HE") and "80" in caps["5GHZ"]["widths"]
    assert any("never triggers scans" in n for n in d["notes"])


async def test_live_wireless_errors(usb_client: httpx.AsyncClient) -> None:
    assert (await usb_client.get("/api/v1/devices/nope/wireless/live")).status_code == 404
    r = await usb_client.get("/api/v1/topology")
    assert r.status_code == 200
    kinds = {n["kind"] for n in r.json()["nodes"]}
    assert {"usb_host", "usb_device", "usb_interface", "driver", "phy", "netdev"} <= kinds
