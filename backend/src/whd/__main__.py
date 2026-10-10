"""WHD command line: `whd serve`, `whd discover`, `whd capture-fixture`, `whd token`."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path


def cmd_serve(a: argparse.Namespace) -> int:
    import uvicorn

    from whd.app import create_app
    from whd.config import Settings
    from whd.logging_setup import setup_logging

    s = Settings.from_env()
    if a.host:
        s.host = a.host
    if a.port:
        s.port = a.port
    if a.demo:
        s.demo_scenario = a.demo
    if a.allow_remote:
        s.allow_remote = True
    if a.static_dir:
        s.static_dir = Path(a.static_dir)
    s.check_bind()
    import os

    if os.geteuid() == 0 and not a.i_know_this_is_root:
        print(
            "refusing to run the WHD web server as root; use the whd-helper for privileged reads",
            file=sys.stderr,
        )
        return 2
    setup_logging(a.log_level)
    launcher = None
    mode = a.helper or os.environ.get("WHD_HELPER", "auto")
    if mode != "off" and not s.demo_scenario:
        from whd.helper.launcher import HelperLauncher

        launcher = HelperLauncher(s.helper_socket, log_path=s.state_dir / "helper.log")
        res = launcher.start()
        if res.ok:
            print(f"WHD: helper: {res.detail}", file=sys.stderr, flush=True)
        else:
            print(
                f"WHD: helper not started: {res.detail}. mt76 debugfs, tracing and PCI config stay unavailable "
                "(everything else works). Start WHD from a terminal so sudo can ask for a password, or run "
                "`make helper`, or pass --helper off to silence this.",
                file=sys.stderr,
                flush=True,
            )
    try:
        uvicorn.run(
            create_app(s),
            host=s.host,
            port=s.port,
            log_config=None,
            ws_max_size=1 << 20,
            proxy_headers=False,
            server_header=False,
        )
    finally:
        if launcher is not None:
            launcher.stop()
    return 0


def cmd_discover(a: argparse.Namespace) -> int:
    from whd.config import Settings
    from whd.discovery import Discovery
    from whd.drivers import registry
    from whd.platform.host import FixtureHost, Host, LiveHost

    host: Host = FixtureHost(Path(a.fixture)) if a.fixture else LiveHost(Settings.from_env().helper_socket)
    res = Discovery(host, registry.extensions()).run()
    out = {
        "mode": host.mode,
        "duration_ms": res.duration_ms,
        "issues": [i.model_dump() for i in res.issues],
        "devices": [d.model_dump(mode="json") for d in res.devices],
    }
    json.dump(out, sys.stdout, indent=None if a.compact else 2)
    sys.stdout.write("\n")
    return 0


def cmd_token(a: argparse.Namespace) -> int:
    from whd.auth import Auth
    from whd.config import Settings

    s = Settings.from_env()
    auth = Auth(s.config_dir)
    print(auth.token if a.show else auth.token_path)
    return 0


def cmd_capture_fixture(a: argparse.Namespace) -> int:
    from whd.config import Settings
    from whd.fixtures.capture import capture_fixture

    sock = Path(a.helper_socket) if a.helper_socket else Settings.from_env().helper_socket
    return capture_fixture(
        Path(a.out), a.device, keep_mac=a.keep_mac, description=a.description, helper_socket=sock
    )


def cmd_openapi(a: argparse.Namespace) -> int:
    from whd.app import create_app
    from whd.config import Settings

    spec = create_app(Settings()).openapi()
    text = json.dumps(spec, indent=1, sort_keys=True)
    if a.out:
        Path(a.out).write_text(text + "\n")
    else:
        print(text)
    return 0


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="whd", description="Wireless Hardware Debugger")
    sub = p.add_subparsers(dest="cmd", required=True)
    s = sub.add_parser("serve", help="run the web server")
    s.add_argument("--host")
    s.add_argument("--port", type=int)
    s.add_argument("--demo", metavar="SCENARIO", help="serve a fixture scenario in DEMO mode")
    s.add_argument("--allow-remote", action="store_true")
    s.add_argument(
        "--helper",
        choices=("auto", "off"),
        help="auto (default): start the privileged helper if it is not running, asking for sudo in this "
        "terminal; off: never start it (env WHD_HELPER)",
    )
    s.add_argument("--static-dir")
    s.add_argument("--log-level", default="INFO")
    s.add_argument("--i-know-this-is-root", action="store_true", help=argparse.SUPPRESS)
    s.set_defaults(fn=cmd_serve)
    d = sub.add_parser("discover", help="print the device inventory as JSON")
    d.add_argument("--fixture", help="fixture directory instead of the live host")
    d.add_argument("--compact", action="store_true")
    d.set_defaults(fn=cmd_discover)
    t = sub.add_parser("token", help="print the access token file path (or --show the token)")
    t.add_argument("--show", action="store_true")
    t.set_defaults(fn=cmd_token)
    c = sub.add_parser("capture-fixture", help="record this host's wireless devices into a fixture directory")
    c.add_argument("--out", required=True)
    c.add_argument("--device", action="append", help="device id to include (default: all wireless)")
    c.add_argument("--keep-mac", action="store_true")
    c.add_argument("--description", default="")
    c.add_argument("--helper-socket", help="record privileged data through this whd-helper socket")
    c.set_defaults(fn=cmd_capture_fixture)
    o = sub.add_parser("openapi", help="write the OpenAPI schema (used to generate frontend types)")
    o.add_argument("--out")
    o.set_defaults(fn=cmd_openapi)
    a = p.parse_args(argv)
    return int(a.fn(a))


if __name__ == "__main__":
    raise SystemExit(main())
