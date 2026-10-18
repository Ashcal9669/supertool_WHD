# Wi-Fi and MLO evidence in WHD

Open **Wi-Fi evidence** in the navigation or a device's **Wi-Fi evidence** tab. Select a capture to inspect historical evidence independently of the current device. Device, interface, PHY, link and tracepoint choices come from discovery.

The link table keeps negotiated/valid, active, firmware-programmed, authorized and authenticated delivery separate. A listed nl80211 link establishes negotiated membership, not activity. Missing evidence is UNKNOWN. Every historical observation retains its event ID, boot, device and association scope; incomplete association or link-lifetime identities remain explicit limitations.

Select one interface when a device exposes several. Current kernel interface/PHY metadata overrides stale discovery mappings. If station interfaces share a PHY, per-PHY debugfs masks and counters cannot establish a selected association and are withheld. nl80211 queries are recorded as measurements whose firmware-read or wake effects were not measured.

Packet paths show available submissions, stack/driver boundaries, TXD, buffer release, TX status, air/AP evidence, reply, RX ownership, security and stack ingress. Expand a stage for raw bytes, decoded fields, identifiers and timing. A missing stage remains a gap. Buffer release does not establish ACK success. Authenticated delivery requires explicit security, replay, channel and lifetime evidence joined to stack ingress; aggregate traffic alone cannot establish it.

Firmware tables show observed identities, command lifecycle pairs, ambiguous completions and before/after field changes. MCU definitions retain source provenance; unverified definitions never establish a running-build match. Known identity layouts can be decoded, while unknown fields remain raw when safe. Key material is excluded from event persistence. The observation patch whitelists identity payloads and does not record key command payloads.

Use the experiment controls for a bounded ping or throughput run. Targets are literal IP addresses, ping uses the selected interface, and iperf3 requires support for `--bind-dev`. Runs retain commands, routes, interface traffic, before/after configuration, markers and failures. Optional per-link counter reads are labeled as measurements that may wake the device. A comparison group displays separate control/fix/control-after runs; matching metadata does not itself prove causality.

Existing classic PCAP files can be imported as independent, AP-local or same-PHY observations. Ethernet PCAP imports separately retain stack TX/RX and EAPOL metadata, with explicit capture-owner interface, boot and clock calibration. Key-data-bearing originals are withheld; safe header metadata remains. Unknown boot/run alignment is never borrowed from current hardware. Each import retains an immutable identifier, filename, checksum, origin and original bytes. Saved imports remain available after navigation or reload. WHD records raw frames, observed frequencies, channel changes, truncation and possible stall/quiet intervals. Capability, continuous health, dropped-packet counts and clock alignment remain unknown when the file cannot establish them. Such a capture cannot prove absence of transmission. Monitor discovery reports available interfaces and tools; this implementation does not configure or retune monitors.

Capture exports include events, telemetry, original artifacts and PCAPs, start/end provenance, trace formats, decoding definitions/source, evidence reports, manifest and SHA-256 checksums. Provenance includes kernel, firmware records, module/dependency Build IDs where available, parameters, source revision and dirty-diff hash, collector source hashes and clock calibration. Unavailable loss counts remain unknown. Imported evidence retains its origin.

Choose **Download original evidence bundle** to retain raw binary and hex artifacts. **Download MAC-masked bundle** omits binary artifacts that cannot be safely masked and removes raw hex representations; the manifest lists omissions. Original stored evidence is preserved. Bundle import retains bounded artifacts and original decoding/provenance records, withholding checksum-mismatched or key-bearing artifacts; origin-machine system files are named `imported-*`. Historical per-link deltas are rechecked against saved boot/association/peer lifetimes; absent lifetime evidence produces UNKNOWN. Completed experiment phases persist before traffic starts, partial timeout output survives, and restart recovery marks interrupted runs incomplete.

## Hardware evidence and limits

Active measurements and traffic generation are restricted to dynamically verified **MT7922 PCI 14c3:0616 with mt7921e / mt7921e_git**. Inventory and passive discovery include every present adapter. Physical presence, driver binding, interface state and test eligibility are independent. The experiment guard rechecks sysfs before measurement and launch. Trace collection filters discovered interface/PHY fields in its own instance and preserves existing instances on collision.

MT7922 is ordinary Wi-Fi 6E: it has no negotiated/active MLO states or synthetic link zero. MT7927 evidence is available through passive discovery, recorded captures and labeled fixtures; active MT7927 tests remain forbidden.

Recorded MT7922 evidence includes interface-bound ping replies, stack TX/RX, association and EAPOL M1–M4 metadata. Key-install and authorization callbacks remain requests, not firmware completion proof. The monitor shared the device PHY, changed frequencies during scanning and truncated payloads; independent reception and continuous channel coverage remain unproven. Host/air clock and association alignment remain unverified. These observations establish no authenticated packet delivery.

Remaining gaps include raw RX/security-to-stack lineage, stable WCID/token/PID and association/link lifetimes, firmware identity/key completion binding, independent AP/air reception, verified clock joins and source-to-loaded-module Build ID equivalence. Missing loss counts remain UNKNOWN. PCAPNG import and automatic monitor configuration are unavailable. Software fixtures and offline compilation do not establish hardware behavior.

## Offline observation proposals

The standalone patches in [patches/README.md](patches/README.md) are source-pinned observation proposals, not an ordered patch series. They have not been installed or loaded and supply no new hardware evidence. Source hashes identify audited layouts; `matches_loaded_build` remains unknown until independently established.

- `0002-mt76-whd-observation-boundaries.diff` adds MCU lifecycle/safe identity TLVs, TXD/TX-free and RX descriptor/security/stack boundaries. Its MT7925-specific hooks do not establish MT7922 coverage.
- [0003 MCU transport](patches/0003-mt76-whd-mcu-partner-transport.README.md) records transport attempt/sequence/error envelopes and audited nonsecret result/ROC spans. Unknown/security/reserved bytes are suppressed. Status-only results cannot establish per-link firmware programming without identity and lifetime binding. The shared MCU callback layout requires a coordinated compatible rebuild.
- [0004 TX descriptors](patches/0004-mt76-whd-tx-descriptors.README.md) records bounded TXD and MAC TXS snapshots. Descriptor construction, buffer release, source-reported ACK, RF emission and delivery remain separate boundaries. Unsupported or unbound layouts retain unknown ACK state.

No proposal authorizes activation or mixing incompatible shared modules. Complete TX/RX lineage, authenticated delivery and a working MLO datapath remain unproven.
