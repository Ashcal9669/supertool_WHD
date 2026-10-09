# Optional kernel instrumentation proposals

These patches are **proposals**. WHD never applies, builds, or installs them, and it works without
them. Each one fills a gap that WHD's mt76 instrumentation coverage report (`/api/v1/devices/<id>/mt76/instrumentation`)
marks as *missing* on kernels without it.

## 0001-mt76-trace-mcu-command-lifecycle.diff

**Gap:** mt76 has no tracepoint for MCU (firmware) command submission or completion. The only kernel-visible
signal is the failure path: `"Message %08x (seq %d) timeout"` and `"Retry message %08x (seq %d)"` in `mcu.c`.
Without this patch, command rate, latency, and the command that preceded a timeout cannot be observed.

**Change:** adds two tracepoints to the `mt76` trace system (`trace.h`) and calls them from
`mt76_mcu_skb_send_and_get_msg()` (`mcu.c`):

| tracepoint | fields | emitted |
|---|---|---|
| `mt76:mcu_send` | wiphy, cmd, seq, len, wait_resp, retry | after every `mcu_skb_send_msg()` (including retries) |
| `mt76:mcu_resp` | wiphy, cmd, seq, ret, timeout, latency_us | after `mcu_parse_response()` for commands that wait for a response |

**Base:** `~/mt76` at commit `55b18808` (committed state; the working tree's uncommitted changes were not used).

**Validation performed by WHD's build (2026-10-09):** the patch was applied to a scratch copy of the tree
(`git archive HEAD`) and `mcu.o` and `trace.o` were compiled against
`/usr/src/linux-headers-7.2.0-rc1-mt7927-monitor-v3` with the tree's own flags (`-Werror`). Both objects built and
`__tracepoint_mcu_send` / `__tracepoint_mcu_resp` are present. It was **not** loaded or run on hardware.

**How WHD uses it:** WHD discovers tracepoints at runtime. If `mt76/mcu_send` and `mt76/mcu_resp` exist, the
mt76 coverage report marks *MCU command lifecycle* as available and the firmware sequence diagram draws
command/response pairs with latencies from them. Nothing in WHD assumes they exist.

**Applying it yourself (manual, optional):**

```bash
cd ~/mt76              # your tree; review the diff first
patch -p1 --dry-run < docs/patches/0001-mt76-trace-mcu-command-lifecycle.diff
```
