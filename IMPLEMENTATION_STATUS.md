# WHD implementation status

Last updated: 2026-10-09 (final integration pass complete). This file is maintained while the build is in progress. "Done" means implemented,
tested, and verified as described in the Evidence column.

| Phase | Scope | State | Evidence |
|---|---|---|---|
| 1 | Repo, backend, discovery, inventory UI, auth, demo mode | done | 29 pytest, 3 vitest, Playwright smoke vs live MT7927 |
| 2 | Privileged helper, PCI config decode, USB descriptors, topology | done | helper verified live via sudo (config space, debugfs policy); 6 helper tests; topology e2e |
| 3 | Event sources, WebSocket, timeline | done | journal/uevent/nl80211/rtnl/poll live on MT7927; 9 event tests; timeline e2e |
| 4 | Live PHY diagnostics | done | `/devices/{id}/wireless/live`, Live PHY tab (uPlot charts, state machine, MLO links), 2 API tests |
| 5 | mt76 module | done | coverage report (15 categories) verified live on 2x MT7927; parsers tested on recorded debugfs; trace session e2e; patch 0001 compile-tested in scratch copy |
| 6 | Visualizations, capture, replay, bundles | done | bounded captures + JSON/JSONL/CSV/trace export + redacted zip bundle (6 tests); replay never persisted; 4 animated views + MLO/state machine; demo e2e (2) |
| 7 | Diagnostic engine, Ollama | done | 12 engine/ollama/API tests; analysis + live llama3.2:3b summary verified in browser (demo data) |

## Phase 1 notes
- nl80211 implemented on raw AF_NETLINK (no pyroute2); constants generated from kernel headers (tools/gen_kernel_consts.py).
- Recorded fixture `mt7927-pcie-host` captured from this host; derived scenarios + synthetic USB built by
  tests/fixtures/build_fixtures.py.

## Phase 2 notes
- whd-helper verbs: ping, pci_config_read, debugfs_list, debugfs_read (policy tiers), tracefs_events, tracefs_status,
  trace_stream (own instance `instances/whd`, trace_clock=boot), usbmon_stream (only if usbmon already loaded).
- Real finding on this host: ASPM L0s/L1 and L1 substates disabled on 0000:07:00.0; root port 0000:00:02.2 advertises
  no ASPM support.

## Phase 3 notes
- Kernel log via `journalctl -k -f -o json` (dmesg_restrict=1 prevents /dev/kmsg for uid 1000); cursor persisted.
- Device attribution: journald _KERNEL_DEVICE, ifindex/wiphy index, BDF/netdev/phy names, module in brackets.

## Phase 4/5 notes
- Cold reboot occurred mid-build (kernel now 7.3.0-rc5); a second MT7927 (0000:0b:00.0, phy2/wls1) appeared and discovery handled it unchanged.
- mt76 debugfs reads are tiered by reviewing the read handlers (policy.py); `wakes_device` reads need an explicit `wake=true`
  and are audit-logged; `mmio`/`mcu`/`never` are never offered.
- mt76 `mcu_send/mcu_resp` tracepoints do **not** exist on this kernel; coverage reports them missing and points at
  docs/patches/0001 (compiled `mcu.o`/`trace.o` in a scratch copy only; not loaded on hardware).

## Phase 6 notes
- Demo event streams are SYNTHETIC (tests/fixtures/gen_demo_events.py) but generated through the production handlers; banner
  says "RECORDED DATA + SYNTHETIC EVENT STREAM". `WHD_DEMO_SPEED` accelerates demo replays.
- Capture replay events carry `session=replay:<id>`, are fanned out but never stored or added to the live ring.
- usbmon is parser-tested only: the module is not loaded on this host and WHD never loads kernel modules.
- Custom `MLO_*` printk lines have no device prefix, so they are reported as *unattributed* rather than guessed.
- Trace export is ftrace *text* (not trace.dat); trace-cmd is not used.

## Phase 7 notes
- Report keeps observations (O#), incidents, patterns, correlations, unconfirmed hypotheses (H-*) and missing
  instrumentation (M-*) in separate lists; `cause_confirmed` is always false.
- Incident timing is anchored on warning+/reset events; routine state changes are context only.
- Ollama summary: prompt = report fields only (MACs masked), output labeled AI-generated, ids validated, and cause-asserting
  wording flagged. Nothing feeds back into the analysis; platform works with Ollama absent (tested).

## Final integration pass (2026-10-09)

| Check | Result |
|---|---|
| `make check` (ruff, eslint, mypy --strict, tsc, pytest, vitest) | exit 0; 82 pytest passed (+1 live opt-in), 9 vitest passed |
| `make test-live` (read-only, real hardware) | 1 passed |
| `make build` | frontend production build OK (served by backend at `/`) |
| Final app via `make helper` + `make serve` | web server uid 1000 (not root); helper root; API + assets 200; unauthenticated 401 |
| Browser e2e vs live server (Chromium) | 4 passed (login/inventory/detail tabs, topology, timeline stream, mt76 tab incl. real trace start/stop) |
| Browser e2e vs demo server | 3 passed (banner, visualizations, capture/export/bundle/replay, diagnostics + live Ollama summary) |
| Restart persistence (live) | events retained, signed session valid after restart, discovery history grew |
| Demo/live isolation | live DB 303 events / 0 demo; demo DB 2285 events / all demo |
| Wireless state before/after full test cycle | `iw dev`, `iw reg`, link state, driver debugfs settings, runtime PM: identical (diff empty); tracefs instances empty |
| Driver trees | no driver source tree was modified by WHD or by this build; WHD has no code path that writes to one |

Not verified (hardware-dependent): associated-station telemetry / MLO links on real hardware (no adapter associated), real MCU
timeouts, PCIe error/link-retrain events, all USB behavior and usbmon, TID-to-link from real traffic, macOS/Windows browsers.

Bus safety (GitHub issue #1): `mt76/napi_threaded` oopses the kernel on USB (before 7.3) and SDIO, so it is PCIe-only
(`policy.BUS_ONLY`, fail closed on unknown bus). Every other readable mt76/mt792x/mt7925 debugfs file was then audited
in one mt76 tree (core `debugfs.c`, `mt792x_debugfs.c`, `mt7925/debugfs.c`): each handler only formats fields embedded in the
device structs or skips NULL queues, so none dereferences bus-specific state. That audit covers that tree only; other kernel
versions can differ, and the optional MLO nodes were reviewed separately. Files not on the allowlist are never read.
USB/SDIO reads are still unverified on real hardware.
A device can register several PHYs: the poller samples all of them, and the mt76 tab/API take a `phy` selector.
