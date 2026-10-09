# Wireless Hardware Debugger (WHD): Architecture and Phase 1 Design

Date: 2026-10-09
Status: Draft, awaiting user review
Scope: Overall architecture (all phases) plus a detailed Phase 1. Phases 2 to 7 each get their own spec, plan and implementation cycle that builds on the contracts defined here.

## 1. Goals and non-goals

WHD is a browser-based, Linux-first engineering tool for discovering, inspecting, tracing and troubleshooting PCIe and USB wireless adapters, along with their drivers, firmware and PHYs.

Hard rules that apply to every phase:

- Read-only by default. WHD never resets devices, unbinds drivers, reloads modules, modifies firmware, writes PCI config space, changes regulatory or interface settings, enables injection, or writes to debugfs or tracefs nodes outside its own trace instance.
- No fabricated data. Every value comes from a named source. Anything that cannot be read is reported as unavailable, together with the reason. Synthetic data only ever appears in demo mode, which is visually distinct.
- Nothing is assumed about kernel version, chipset, tracepoints, debugfs nodes or firmware interfaces. All of these are discovered at runtime.
- WHD does not modify existing source trees (`~/mt76`, `~/mt76-mlo-build` or any other repository). Kernel instrumentation that is found to be missing is written up as an optional, separate patch proposal and never applied automatically.
- The web server never runs as root.

## 2. Development host baseline (observed 2026-10-09)

The real-hardware test target is this host. None of these facts are hard-coded; they are listed here because they shape the fixtures and the tests.

- Debian 13, kernel `7.2.0-rc1-mt7927-monitor-v3`, x86_64. Python 3.13.5, Node 24.18, `uv` available.
- MT7927 `14c3:7927` (subsystem `105b:e104`) at `0000:07:00.0`, behind root port `0000:00:02.2`, running PCIe Gen3 x1. Driver `mt7925e_git` (DKMS module in `updates/dkms`), `phy1` -> `wlp7s0`.
- ETHTOOL_GDRVINFO returns `firmware-version: ____000000-20260414134255`. `/sys/module/mt7925e_git/{version,srcversion}` do not exist.
- `/sys/bus/pci/devices/0000:07:00.0/link/` is empty, so ASPM state is not exposed through sysfs. It has to be decoded from PCIe config space, which requires root beyond the first 64 bytes.
- tracefs and debugfs need root. The `mt76` tracepoints include custom `mlo_*` events. debugfs `phy1/mt76` contains state-changing nodes (`chip_reset`, `regidx`/`regval`, `fw_debug`).
- No USB Wi-Fi adapter is attached. USB support is therefore developed against synthetic fixtures (marked as such) until real hardware is available.

## 3. Architecture

### 3.1 Process model

```
 Browser (macOS/Windows/Linux)
     |  HTTP over SSH tunnel or private VPN (WHD binds 127.0.0.1 by default)
     v
 whd-server  (FastAPI + uvicorn, unprivileged user)
     |  REST /api/v1/*, WebSocket /api/v1/stream (Phase 3)
     |  reads: sysfs, nl80211, ETHTOOL ioctl, modules.alias/dep, pci.ids/usb.ids, journal
     |  SQLite state DB
     |
     |  Unix socket /run/whd/helper.sock (SO_PEERCRED, group whd)   [Phase 2+]
     v
 whd-helper  (root, systemd socket-activated, fixed verb set, no shell)
     reads: PCI config space, allowlisted debugfs files, tracefs (own instance), usbmon
```

`whd-helper` is not built in Phase 1. Phase 1 runs entirely unprivileged, and any field that needs root reports `requires_privilege`. The helper's contract is fixed now so that later phases fit into it:

- It exposes a closed set of named verbs, such as `pci_config_read(bdf)`, `debugfs_read(phy, relpath)`, `trace_session_*` and `usbmon_*`. It accepts no arbitrary paths, commands or shell.
- debugfs reads go through an allowlist (an explicit list of known-safe files per driver), never a denylist. A read can still have side effects: `regval` performs an MMIO read of whatever `regidx` points at, and some nodes issue MCU commands. Nodes that are absent from the allowlist cannot be read.
- Tracing uses a dedicated tracefs instance (`instances/whd`), so the global tracer and anyone else's tracing session are left alone.
- Disruptive verbs, if they are ever added, require a separately designed confirmation flow (a server-issued one-time token that the user confirms in the UI), and each one is audit-logged. None are planned before Phase 6.

### 3.2 Repository layout

```
supertool/
  Makefile                      setup / dev / demo / check / test / build / types
  README.md                     setup, run, remote access, implemented-vs-planned matrix
  docs/
    superpowers/specs/          design specs (this file)
    architecture.md             living architecture notes
    clock-domains.md            (Phase 3) timestamp sources and conversions
  backend/
    pyproject.toml              uv-managed, requires-python >=3.12
    src/whd/
      __main__.py               CLI entry: `whd serve`, `whd discover --json`, `whd capture-fixture`
      config.py                 settings (env WHD_*, CLI flags)
      logging.py                structured JSON logging
      app.py                    FastAPI factory, static frontend mount
      auth.py                   token + session cookie
      api/                      routers: system, devices, discovery, auth, health
      model/                    pydantic v2 models = the API contract
      platform/
        sysroot.py              filesystem root abstraction (real "/" or fixture dir)
        sysfs.py                safe attribute reads (allowlisted names, size caps, typed errors)
        ids_db.py               pci.ids / usb.ids parser
        kmod.py                 modules.alias / modules.dep matching, modinfo -0
        ethtool.py              SIOCETHTOOL ETHTOOL_GDRVINFO via ioctl
        nl80211/                genetlink client + attribute decoding
      collectors/
        base.py                 Collector protocol, Section/Availability types
        system.py  pci.py  usb.py  netdev.py  wiphy.py  driver.py  power.py
      discovery.py              orchestration, wireless-device detection, identity
      identity.py               stable device IDs
      store/                    SQLite schema + repository
      fixtures/                 fixture capture tool
    tests/
      fixtures/sysroots/<scenario>/...   fake sysfs trees + nl80211 captures
  frontend/
    package.json  vite.config.ts  tsconfig.json  tailwind
    src/
      api/                      generated OpenAPI types + typed client
      components/  pages/  hooks/
  deploy/
    systemd/whd.service         example unit (User=whd); not installed automatically
```

### 3.3 Extension contracts (fixed now, used by later phases)

**Collector.** `Collector.collect(ctx, device) -> Section`. Each section reports its `availability` (`ok | partial | unavailable | requires_privilege | unsupported | error`), its `sources` (the exact paths, netlink commands or ioctls it read) and its `issues` (a list of typed problems). Driver-specific collectors (mt76 in Phase 5; iwlwifi, ath11k/ath12k and Realtek later) register against a driver-name predicate and add namespaced sections such as `drivers.mt76`.

**Event** (implemented in Phase 3, schema defined now): `id`, `ts_boottime_ns` (canonical), `ts_source` + `ts_raw` (original clock domain), `ts_wall` (derived and labelled as derived), `source`, `device_id | null`, `severity`, `category`, `raw` (verbatim evidence), `explanation` (human-readable, generated from a template, never an LLM), and `demo: bool`.

**Device identity** (Section 4.4) is the join key for every event, capture and diagnosis.

### 3.4 Phase roadmap

| Phase | Deliverable |
|-------|-------------|
| 1 | Repo, backend, frontend shell, discovery, device inventory and detail pages, auth, demo mode, fixtures, tests |
| 2 | `whd-helper` (config-space reads) and PCIe/USB inspectors: ASPM, AER, MSI/MSI-X, BARs, link caps, descriptors/endpoints; React Flow topology |
| 3 | Event sources (kmsg, udev, journal, tracefs instance), WebSocket stream, timeline UI, SQLite event history, clock-domain doc |
| 4 | Live PHY diagnostics: station info, bitrates, signal, retries, scan/regulatory events, mac80211/cfg80211 tracepoints |
| 5 | mt76 module: tracepoint/debugfs discovery, allowlisted debugfs reads, MCU/queue/MLO views, gap report plus optional patch proposals |
| 6 | Animated visualizations, bounded capture sessions, export (JSON/CSV/trace.dat), replay, diagnostic bundles, usbmon |
| 7 | Evidence-based diagnostic engine (observations kept separate from hypotheses), optional Ollama summary |

## 4. Phase 1 detailed design

### 4.1 Scope

Phase 1 covers all of Module 1 (device discovery) and a working inventory UI. It does not include topology graphs, live streaming, tracing, debugfs, the privileged helper or anything mt76-specific.

### 4.2 Wireless device detection

A device counts as wireless if any of the following holds, and the reason is recorded for each match:

1. **Bound PHY:** it is the parent device of `/sys/class/ieee80211/<phy>/device`. This is authoritative.
2. **Driver match, no PHY:** its `modalias` matches a pattern in `modules.alias`, and that module's dependency closure in `modules.dep` includes `cfg80211`. This catches devices whose driver failed to probe or isn't loaded, which is a key debugging case. It also covers out-of-tree and DKMS modules such as `mt7925e_git`, because it does not depend on the module's install path.
3. **Class hint (PCI only):** class `0x0280xx` (network controller, other) with no driver bound. This is labelled as a weak signal.

USB wireless devices are matched by `modalias` against every interface. Bluetooth-only USB devices (interface class `e0/01/01` whose matched module does not depend on cfg80211) are not reported as Wi-Fi.

### 4.3 Data collected per device (Module 1 mapping)

| Field | Source (Phase 1) | Notes |
|-------|------------------|-------|
| PCI vendor/device/subsystem IDs, class, revision | sysfs | names from `pci.ids` |
| USB VID/PID, bcdUSB, speed, serial, interfaces, endpoints | sysfs (`ep_*` dirs) | names from `usb.ids`; descriptor detail is a Phase 2 expansion |
| Bus path (parent chain up to the root complex or host controller) | sysfs `realpath` walk | rendered as a breadcrumb list; graph in Phase 2 |
| PCIe current/max link speed and width | sysfs | shown in Phase 1; full link decode in Phase 2 |
| Driver name, module name | sysfs `driver`, `driver/module` | |
| Module version / srcversion / vermagic / filename | `/sys/module/*` then `modinfo -0` | NUL-separated output, not prose |
| Kernel release, arch, distro | `uname`, `/etc/os-release` | |
| Firmware version | ETHTOOL_GDRVINFO ioctl | unprivileged; empty value means "not exposed" |
| PHY to netdev mapping, wdev, ifindex, MAC | nl80211 `GET_WIPHY`/`GET_INTERFACE`, sysfs | |
| Bands, frequencies, per-channel flags | nl80211 `NL80211_BAND_ATTR_FREQS` | includes `NO_HT40±`, `NO_80MHZ`, `NO_160MHZ`, `NO_320MHZ`, disabled, radar |
| Supported channel widths | derived from HT/VHT/HE/EHT capability fields | derivation rules cite `include/linux/ieee80211.h` bit definitions; raw hex is always shown alongside |
| Advertised capabilities | nl80211 HT/VHT capa, iftype data (HE/EHT), supported iftypes, cipher suites, ext features, MLO flags | only bits defined in uapi/kernel headers get named; unknown bits stay as raw hex |
| Operational state | sysfs `operstate`, `carrier`, `flags`; rfkill soft/hard | |
| Interface type | nl80211 `NL80211_ATTR_IFTYPE` | |
| Power management | PCI `power/control`, `runtime_status`, `power_state`; USB `power/control`, `autosuspend_delay_ms`; Wi-Fi power save via `NL80211_CMD_GET_POWER_SAVE` | ASPM is `requires_privilege` until Phase 2 |

**nl80211 client.** pyroute2 provides the generic-netlink transport and family resolution. WHD decodes the attributes it needs itself, in `platform/nl80211/attrs.py`, using constants taken from `include/uapi/linux/nl80211.h` (each one cited). This guarantees nested band and iftype data is fully decoded. If nl80211 is unavailable, the wiphy section reports `unavailable` and WHD does not fall back to parsing `iw` output.

**Safe sysfs reads.** Collectors read named attributes only and never walk directories blindly. Reads are size-capped (64 KiB). WHD never opens `reset`, `remove`, `rescan`, `rom`, `resource*` (mmap) or `driver_override` for writing. Each failure maps to a typed issue: `ENOENT` becomes `not_exposed`, `EACCES`/`EPERM` becomes `requires_privilege`, `EIO`/`ENODEV` becomes `device_error`.

### 4.4 Stable device identity

- **PCI:** `pci:<domain>:<bus>:<dev>.<fn>:<vendor>:<device>`, for example `pci:0000:07:00.0:14c3:7927`. It stays the same across driver reloads, netdev renames and phy renumbering (`phy0` to `phy1`).
- **USB:** `usb:<serial>:<vid>:<pid>` when the device reports a serial number, so it survives a move to another port. Otherwise it is `usb:<busnum>-<devpath>:<vid>:<pid>`, for example `usb:3-3:0e8d:7961`.
- Netdev names, phy indexes and ifindexes are mutable attributes of a device, never part of its identity. The store keeps `first_seen`, `last_seen` and the name history for each one.

### 4.5 API (Phase 1)

All endpoints sit under `/api/v1`, use JSON, and are described by OpenAPI.

- `GET /health`: liveness. No auth.
- `POST /auth/login {token}` sets an HttpOnly `SameSite=Strict` session cookie. `POST /auth/logout` clears it.
- `GET /system`: host, kernel, arch, distro, WHD version, `mode` (`live`/`demo`), privilege status, and the availability of each integration (`nl80211`, `ethtool`, `modules.alias`, `pci.ids`, `usb.ids`, `tracefs`, `debugfs`, `usbmon`, `perf`, `bpftool`). The probe only checks whether each one exists or can be accessed; it changes nothing.
- `GET /devices`: inventory summaries.
- `GET /devices/{id}`: full detail, with every section, availability and source.
- `GET /devices/{id}/evidence`: the raw attribute values and decoded netlink data that the detail view was built from.
- `POST /discovery/rescan`: reruns discovery and returns a diff (devices added, removed or changed). This is a read-only operation.

Discovery runs once at startup, on rescan, and when a cached result is more than `WHD_CACHE_TTL` old (default 5 s). Udev-driven live updates arrive in Phase 3.

### 4.6 Security

- The server binds `127.0.0.1:8787` by default. Binding a non-loopback address requires `WHD_ALLOW_REMOTE=1`, which logs a warning on startup. The supported remote path is an SSH tunnel (`ssh -L 8787:127.0.0.1:8787 host`) or a private VPN such as Tailscale. The README tells users not to expose WHD to the public internet.
- Auth is always required, including on loopback. On first run WHD generates a 256-bit token, writes it to `$XDG_CONFIG_HOME/whd/token` (mode 0600) and prints the file path, not the token. Login exchanges the token for a session cookie. There's no user database; that is outside the scope of a single-host debugger.
- CSRF: the cookie is `SameSite=Strict`, and mutating endpoints require an `X-WHD-Request: 1` header. CORS is disabled.
- The process runs as the invoking user. The example systemd unit uses `User=whd`, `NoNewPrivileges`, `ProtectSystem=strict` and `StateDirectory=whd`.

### 4.7 Persistence

SQLite (stdlib `sqlite3` called through `asyncio.to_thread`) lives at `$XDG_STATE_HOME/whd/whd.db`, with schema versioning via `PRAGMA user_version`. Phase 1 tables:

- `devices(id PK, bus, first_seen, last_seen, last_snapshot_json)`
- `device_names(device_id, kind {netdev|phy}, name, first_seen, last_seen)`
- `discovery_runs(id, started_at, duration_ms, mode, device_count, issues_json)`

Demo mode writes to a separate DB file so synthetic data never mixes with real history.

### 4.8 Demo mode and fixtures

- `whd serve --demo <scenario>` points the sysroot at `tests/fixtures/sysroots/<scenario>` and replays recorded nl80211 and ethtool responses. `/system` reports `mode: demo`. The UI shows a persistent amber, striped `DEMO — SYNTHETIC/RECORDED DATA` bar, and every device card carries a demo badge.
- Fixture scenarios:
  - `mt7927-pcie-host`: captured from this host and marked as recorded real data.
  - `mt7921u-usb`: synthetic, built to the documented sysfs layout, and marked synthetic.
  - `pci-no-driver`: a wireless-class device with no bound driver.
  - `renamed-netdev`: the same device with a different netdev name and phy index.
  - `permission-denied`: chosen attributes unreadable.
  - `no-nl80211`: the netlink family is missing.
  - `empty`: no wireless devices.
- `whd capture-fixture --device <id> --out <dir>` copies the allowlisted attributes and the decoded netlink and ethtool responses for one device. Users with other hardware (iwlwifi, ath12k, rtw89) can contribute fixtures this way. It is read-only and does not capture MAC addresses unless `--keep-mac` is passed.

### 4.9 Frontend (Phase 1)

React 18, TypeScript (strict), Vite, Tailwind, TanStack Query and React Router, with a dark engineering theme. React Flow, uPlot and Framer Motion are added in the phases that need them, not as unused dependencies now.

- **Login:** a token input that sets the cookie.
- **Inventory:** device cards showing the bus badge (PCIe/USB), IDs and names, driver, firmware, phy/netdev, operstate and detection reason. A system header shows kernel, mode and integration availability.
- **Device detail:** tabbed sections for Identity and Bus, Driver and Firmware, Wireless PHY (bands table, channel list with flags, width matrix, capability flags with raw hex), Interfaces, Power, and Evidence (the raw view). Every section shows an availability badge and a source tooltip. Unavailable fields show the reason, never a dash or a guess.

TypeScript types are generated from the backend's OpenAPI schema (`openapi-typescript`), so frontend and backend cannot drift apart silently.

### 4.10 Error handling

- No collector failure ever fails discovery. Each failure becomes a section issue, and the device is still listed.
- A failure in one device does not affect any other device.
- Integration probes record `missing`, `no_permission` or `ok`. The UI explains what each missing integration disables and how to enable it. For example: "tracefs requires the whd-helper (Phase 3)".
- Structured JSON logs carry `event`, `device_id`, `collector`, `duration_ms` and `error`.

### 4.11 Testing

- **Backend:** pytest, plus mypy `--strict` and ruff. Collectors and discovery run against every fixture scenario, with assertions on detection reasons, identity stability (`renamed-netdev`), typed issues (`permission-denied`, `no-nl80211`), and empty or partial data. The nl80211 decoder is tested on raw netlink message bytes recorded from this host's MT7927. API tests use httpx `ASGITransport` and cover auth enforcement, CSRF header enforcement, and the remote-bind guard.
- **Live smoke test** (opt-in, `make test-live`): runs discovery on the real host and asserts that at least one wireless device has a bound phy. It writes nothing.
- **Frontend:** `tsc --noEmit`, eslint, and vitest with Testing Library (inventory rendering, demo banner, availability badges, unavailable-reason display).
- **`make check`** runs all of the above. Results are reported at the end of the phase.

### 4.12 Setup and run (target UX)

```
make setup        # uv sync (backend), npm ci (frontend)
make dev          # backend --reload on :8787 + vite on :5173 (proxy /api)
make demo         # backend in demo mode, scenario mt7927-pcie-host
make check        # lint, typecheck, tests (backend + frontend)
make build        # frontend build served by backend at /
whd discover --json   # CLI inventory without the web UI
```

### 4.13 Phase 1 done criteria

1. On this host, `make build && whd serve` shows the MT7927 with its PCI IDs and names, `mt7925e_git` driver and module info, firmware `____000000-20260414134255`, `phy1`/`wlp7s0`, bands and widths, and power state, each with its source.
2. Every fixture scenario renders correctly in demo mode with the demo banner.
3. `make check` passes.
4. No WHD process ever writes to sysfs, debugfs, tracefs or netlink in a way that sets state. This is enforced by code review and by a test that runs full discovery with `open`/`os.open` patched to fail on any write flag.
5. The README's implemented-vs-planned matrix is accurate.


## Implementation notes (deviations from this spec, recorded after the build)

- **nl80211 transport:** implemented on raw `AF_NETLINK` sockets (`platform/netlink.py`), not pyroute2; attribute IDs and
  capability bits are generated from the kernel headers (`tools/gen_kernel_consts.py`). Only a GET-command allowlist can be sent.
- **Charts:** uPlot (not Recharts). **Types:** frontend types are generated from the backend OpenAPI schema.
- **Helper socket:** the helper creates its own socket (not systemd socket-activated); example units are in `deploy/systemd/`.
- **Event timeline etc.:** see README for the final module list; `devlink`, `perf` and eBPF were not used.
- **API docs** (`/api/docs`) are off unless `WHD_ENABLE_DOCS=1`.
- Default port is 8787 (8765 collides with another service on the dev host).
- A cold reboot occurred mid-build (kernel 7.2.0-rc1 → 7.3.0-rc5); a second adapter appeared and was handled without changes.
