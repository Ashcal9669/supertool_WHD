# 0004: descriptor-only TXD and TXS observation proposal

Offline, standalone proposal; not installed or loaded. Compiled objects and software fixtures establish static instrumentation behavior only. No hardware test or module link/install was performed.

## Integration schema

Event: **`mt76:whd_tx_descriptor`**. Exact fields, unknown values, source pin and limits are in `0004-mt76-whd-tx-descriptors.schema.json`.

- `stage=txd`, `layout=connac3_txd32`: eight raw TX descriptor words after `mt7925_mac_write_txwi()`, before TXP fill and queue submission. Actual allocated token and PID, selected host WCID, peer link/PHY when available, requested queue enum `qid`, decoded hardware queue `qidx`, raw WLAN/OMAC/TID/TGID/protection/no-ACK/sequence metadata. No packet or TXP DMA-address bytes.
- `stage=tx_status`, `layout=connac3_txs32_prefix`: first eight TXS words at the two MAC dispatch loops, before existing format/PID/WCID filters. Raw WCID/PID/band/format and exact source ACK/error-bit extraction. Available host WCID/link/PHY is an independent read-only RCU snapshot, not a proven peer incarnation.
- `token=-1` and `skbaddr=NULL` for TXS: no borrowed token/skb correlation. Unavailable integer fields use `-1`. `generation_known=0` for every event. Samples are local counters scoped by **stage + boot + device**; equal TXD/TXS sample values are not one packet ID.
- `captured_len=32`; `d0`–`d7` are CPU-endian integers decoded from little-endian words. `hex` is the exact 32 descriptor bytes, compact `%*phN`, preserving original byte order. `observed_len` is 32 for TXD; 32 or 48 for the bounded TXS record. For a 48-byte record its last 16 bytes are intentionally unobserved.

Add this new trace name to the packet adapter deliberately. Source-layout matching is required before interpreting its decoded fields. **Remove `acked` before generic path analysis when it is `-1`, the format is unsupported, or source-layout provenance is unbound**. Otherwise the existing generic `acked == "1"` consumer could misrepresent unknown as false. Do not infer ACK from raw bits on an unbound layout.

Layout pin: `mt76_connac3_mac.h` SHA-256 **`65f970c7a5cd1868b047ce536710f0b103ea31d5f7dd7c9456b109fda204ecd2`**. Do not substitute connac2 masks. Matching this source file permits source-based software interpretation; it does **not** establish equivalence to a loaded module or firmware ABI. That remains unknown.

## Exact ACK interpretation

The observer uses the same source constants as `mt7925_mac_add_txs_skb()`:

| Field | Source definition | Meaning here |
|---|---|---|
| `ack_error` | `MT_TXS0_ACK_ERROR_MASK = GENMASK(18,16)` | Extracted three-bit value 0–7 |
| `ack_timeout` | `MT_TXS0_ACK_TIMEOUT = BIT(16)` | Individual source status bit |
| `rts_timeout` | `MT_TXS0_RTS_TIMEOUT = BIT(17)` | Individual source status bit |
| `queue_timeout` | `MT_TXS0_QUEUE_TIMEOUT = BIT(18)` | Individual source status bit |
| `ba_error` | `MT_TXS0_BA_ERROR = BIT(22)` | Separate bit, **excluded** from ACK mask |
| `acked` | `!(d0 & MT_TXS0_ACK_ERROR_MASK)` | Existing source's ACK interpretation only when `status_supported=1` |

`status_supported=1` requires non-MT7928 connac3 raw TXS format 0 or 1, matching the audited family source. Unsupported formats retain descriptor words and bit extractions, but `acked=-1` and host resolution is withheld. BIP/BA or other bits must not silently be folded into the exact three-bit ACK mask. A BA-only fixture therefore has `ba_error=1`, `ack_error=0`, source `acked=1`; that does not prove complete aggregate acknowledgment or network delivery.

The TXD sequence field is raw configuration bits: check `MT_TXD3_SN_VALID` in raw word 3 before calling it a configured sequence. It is never OTA reception evidence. `no_ack` is descriptor configuration, not an ACK result. A global/non-peer WCID does not acquire a synthetic link or PHY.

## Bounded hooks and unchanged behavior

The TXD hook is inside `mt7925e_tx_prepare_skb()`, after existing descriptor construction. It copies exactly `MT_TXD_SIZE == 32` bytes, guarded by a compile-time assertion. It never accesses `tx_info->skb->data`, frame payload, keys, key fingerprints, DMA-address TXP bytes, or data beyond the descriptor. The audited PCI operations select this callback for MT7927; that is static source coverage, not a loaded-build or live-call claim.

TXS hooks are only inside already bounded dispatch loops:

1. `mt7925_rx_check()`: existing `rxd + 12 <= end`, record length 48 bytes, snapshot prefix 32 bytes.
2. `mt7925_queue_rx_skb()`: existing `rxd + 8 <= end`, record length 32 bytes, snapshot 32 bytes.

They run before the original `mt7925_mac_add_txs()` call, so otherwise rejected formats, untracked PIDs or missing host WCIDs still have raw observations. The read-only lookup does not allocate, refresh or authorize a peer. No descriptor flags, ACK/TXS requests, queue writes, tokens, retries, MCU calls, register accesses, steering, security checks, buffer releases or semaphore state are changed. The pre-existing diagnostic parameter is neither enabled nor modified.

**MCU `UNI_EVENT_TX_DONE_RAW` and MT7928 TX_DONE_MSG are not instrumented by this proposal.** The MCU RAW caller does not provide an independently checked minimum 32-byte record boundary. Adding an unconditional read inside the common TXS parser would introduce new out-of-bounds risk. That path requires separately bounded, source-audited envelope/version work; it must not be represented as covered by these two MAC hooks.

Enabling an observation hook later consumes CPU time/trace bandwidth and samples host state; runtime timing, overhead and trace losses were not measured. No new wake-producing queries or hardware operations are introduced, and no runtime perturbation result is claimed.

## Separate observations, separate missing stages

A TXD snapshot is a queued descriptor, not proven enqueue/DMA completion/RF emission. TXS is source-reported status, not AP reception or stack/application delivery. **Buffer release and semaphore/credit observations are separate boundaries**; `0004` emits neither and never invents them. Existing release evidence remains distinct. Missing TXS cannot prove no transmission because this patch does not request extra status or ensure all packets produce one.

There is no association/link generation or stable token/PID/skb lifetime mapping. Raw descriptor WCID and resolved host WCID are kept separate. Firmware/radio identity, independent air/AP receipt, protected/decrypted replies and RX-to-stack lineage remain missing proof. Do not claim full packet tracing or authenticated network delivery from these records.

## Source and verification artifacts

`0004` is based on the **unpatched** baseline identified by the recorded source manifest. It does not assume `0001`/`0002`/`0003` form an ordered patch series. These proposals overlap source context; integrating/rebasing them needs its own review. Existing files are preserved.

`0004-mt76-whd-tx-descriptors.source.json` records exact original/modified file hashes, patch and object hashes, source revision reference, layout/PCI-definition pins and `matches_loaded_build=null`. Dirty-source file hashes, not revision text alone, identify the audited snapshot. This patch adds a standalone observation structure; it does not change existing driver-operation structure layouts.

Verification performed:

- RED before production helper existed; GREEN under AddressSanitizer/UndefinedBehaviorSanitizer for source-header-based TXD extrema, all eight ACK mask combinations, separate BA/BIP bits, unsupported layout/format ACK unknown, fixed 32-byte copy excluding trailing bytes, and input immutability.
- `trace.o`, `mt7925/mac.o`, `mt7925/pci_mac.o` compiled with the recorded kernel flags and explicit `-Werror`: exit 0, no final compiler diagnostics. Direct compilers read the recorded 7.3.0-rc5 kernel headers; no kernel make/configuration or baseline source write occurred. Full commands and per-object macro profiles are preserved.
- `nm` verifies `__tracepoint_whd_tx_descriptor` and references in both chip objects. `objdump` verifies the TXD observer in `mt7925e_tx_prepare_skb()` and calls to the TXS observer before the existing parser in both dispatch functions. Complete symbol/disassembly records are retained.
- Generated diff dry-runs against the isolated baseline. Four synthetic byte fixtures execute the production helper and validate compact hex against little-endian raw words: TXD, BA-only source ACK, all timeouts, unsupported format with ACK unknown. Fixtures are software evidence, not firmware captures.
This proposal has no parser/privacy/API/UI integration verification. Remaining gaps include loaded-source binding, driver lifetime/generation instrumentation, stable completion mappings, actual enqueue/DMA/release/credit boundaries, bounded MCU TX_DONE variants, RX ownership/security/drop-to-stack lineage, trace-loss/clock evidence and independent air/AP verification. No activation is authorized by this work.
