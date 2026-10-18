# 0003: bounded safe MCU partner transport proposal

Offline proposal only; not installed or loaded. Object compilation and synthetic fixtures do not establish firmware-programmed state, authenticated delivery or a working MT7927 datapath.

## Integration contract

Read `0003-mt76-whd-mcu-partner-transport.schema.json` for exact fields, offsets, reasons and phase semantics. Event: `mt76:whd_mcu_transport`. The print format uses compact `%*phN` hex (no separators), with zero width for suppressed spans. The recorded kernel's `lib/vsprintf.c:hex_string()` supports `N` and returns without dereferencing bytes when width is zero.

Scope samples and cookies by boot/device. One response/async sample groups its header and all safe/suppression spans. The core cookie is an operation counter; it is not `0002`'s timestamp cookie. Attempts count actual send callback invocations. Async has cmd/cookie/attempt zero and expected sequence -1; do not infer a request relationship. Parse and done return codes are host results, not per-link programming/readiness proof. A response candidate may have a mismatched sequence; its parser result remains separately recorded. `parse` has its own sample; pairing with preceding response requires intact serialized order, cookie/attempt/expected-sequence scope, and no collector gap. Do not join arbitrary matching status records.

The observer records receive bytes before destructive parsing, without changing skb data, retry counts, waits, callback arguments, response disposition, or unsolicited dispatch. The optional callback is registered only in this source's MT7925-family **PCI** MCU operations, which the audited source uses for MT7927. No MT7922/USB/SDIO coverage is claimed. `send.actual_seq` is the source-assigned sequence, including no-wait messages; it does not prove a queue operation succeeded or bytes reached firmware. FW_SCATTER has no wire sequence and is explicitly marked. A failed send retains its error separately.

Safe bytes are restricted to:

- Exact unified DEV/BSS/STA result CID and little-endian status, with EID 1 and matching CID. The CID is at original skb offset 44; status at 48. Three padding bytes and any tail are suppressed. No outgoing request payload is copied.
- ROC async EID 0x27, eight TLVs maximum. Tags 0 and 4 must have **exact length 20**. Preserve bytes 0–14 and 16–19 of each grant; suppress reserved byte 15 and the four-byte event prefix. Extended/unknown TLVs are suppressed in full. Layout: tag/length, BSS, token, status, primary channel, rfsco at 8, rfband at 9, width at 10, centers at 11/12, request type at 13, DBDC band at 14, reserved at 15, interval at 16.

All raw RX header bytes, unknown/security command/event payloads, malformed/short/nonlinear content, reserved regions, extra tails and over-budget TLVs remain suppressed with offset/region length and exact reason. Header fields are typed protocol metadata; no key bytes or fingerprints are collected. This is intentionally a narrow safe-span recorder, not a complete raw firmware transport dump. Unknown safe bytes are not reclassified as unsafe bytes merely to satisfy coverage.

Decoder source equivalence can be checked against the recorded layout hashes; it is independent from source-to-loaded-module Build ID equivalence, which remains **unknown**. Validate safe reason, lengths, offsets, sample/header consistency and allowlisted command/EID/tag before exposing decoded fields. Status-only, unjoined results must not produce firmware-programmed YES.

## Baseline, application and compatibility

The diff is **standalone**, based on the unpatched source snapshot identified by the `0002` manifest, reconstructed by reversing that proposal in a new isolated copy. It does not depend on applying `0001` or `0002`, and those files remain unchanged. Do not assume these overlapping standalone proposals form an ordered patch series. Integrating proposals requires a separate review/rebase.

Exact original and modified file SHA-256 values, policy layout hashes, patch hash, object hashes and unknown Build ID equivalence are in `0003-mt76-whd-mcu-partner-transport.source.json`. The source revision is a reference; file hashes identify the dirty source actually audited. The optional `mt76_mcu_ops` member changes an internal cross-module layout: any future activation needs a coordinated compatible rebuild. Never mix it into existing loaded/shared modules. No activation is authorized here.

## Verification actually performed

- Safe-span selector test observed RED before implementation (`production safe-span selector missing`), then GREEN: 17 hand-checked cases under AddressSanitizer/UndefinedBehaviorSanitizer. Cases include result CID/status, padding/extra tail, unknown/security command/event, wrong CID/EID, short headers/results/prefixes, exact tags 0/4, extended/unknown/malformed TLVs, eight-TLV budget and input immutability.
- Direct compiler invocations used the recorded kernel object's command flags and read-only 7.3.0-rc5 kernel headers, with isolated output/dependency files. No kernel `make`/configuration operation or source-tree write was performed.
- `mcu.o`, `trace.o`, `mt7925/mcu.o`, `mt7925/pci_mcu.o` compile with exit 0 and empty diagnostic logs. Commands are saved in `build-commands.json`. Objects are not linked/installable modules and do not carry proof of loaded Build ID equivalence.
- `nm` verifies `__tracepoint_whd_mcu_transport`, MCU observer export/reference and PCI callback registration reference. The core transport disassembly and complete symbol lists are saved.
- Dry-run applies the generated standalone patch to the preserved isolated baseline. Original patch/source manifest checks are retained separately.

This proposal has no runtime/hardware/UI verification. Remaining gaps include source-to-loaded Build ID binding, association/link generations, outgoing identity/key-binding metadata beyond existing proposals, more safe message classes, trace losses/clock joins, TX/TXS lineage, structured RX/security/drop-to-stack tracing, and independent air/AP reception.

## Final macro profile and byte fixtures

`macro-profile.json` records the compiler and exact `-D` flags for every object; `build-commands.json` records complete commands. Explicit `-Werror` was enforced for all four final compiles, which have empty diagnostic logs. Root and subdirectory macro profiles retain their recorded differences; no linked-module or loaded-build equivalence is inferred.

`byte-fixtures.json` is generated by executing the production safe-span selector on synthetic bytes. Response spans retain CID `03` and status `01000000`; ROC tag 4 retains `04001400010700280101022a000100` and interval `e8030000`, with padding/reserved bytes omitted. Unknown/security command bytes and extra tails retain empty hex plus reasons. These are software byte fixtures, not firmware captures. Verification artifact hashes are recorded in the source manifest.

TXD/TXS observation is described separately in [0004](0004-mt76-whd-tx-descriptors.README.md); neither proposal establishes TX/RX lineage or generations.
