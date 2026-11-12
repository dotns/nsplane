# nstun - Task List

> Updated: 2026-11-11

## Usage

Each task is a single line linking to its detail file. All detailed information lives in `docs/task/<timestamp>-<feature-slug>.md`.

### Format

- [ ] [**20260907-1428-add-endpoint Add endpoint**](20260907-1428-add-endpoint.md) `P1`

### Status Markers

| Marker | Meaning |
|--------|---------|
| `[ ]`  | Pending |
| `[-]`  | In progress |
| `[x]`  | Completed |
| `[~]`  | Closed / Won't do |
| `[d]`  | Deleted detail file; index entry retained |

### Priority: P0 (blocking) > P1 (high) > P2 (medium) > P3 (low)

### Rules

- Only update the checkbox marker; never delete the line or change its other content. If the detail file is deleted, mark the entry `[d]`.
- Record change history and deletion reasons in `docs/changelog.md`; update affected dependency and plan references.
- New tasks append to the end.
- See each `<timestamp>-<feature-slug>.md` for full details, except `[d]` entries whose files have been deleted; consult `docs/changelog.md` for their history.

---

## Tasks

- [x] [**20261001-1859-fork-baseline Fork baseline: pma-rust, aws-lc-rs, gotatun-inspired fixes**](20261001-1859-fork-baseline.md) `P1`
- [x] [**20261002-1008-cli-dev-tool Reduce the CLI to a Linux/macOS development tool**](20261002-1008-cli-dev-tool.md) `P2`
- [-] [**20261002-1020-data-plane-core Complete data plane: transport, netstack and ACL inside nstun**](20261002-1020-data-plane-core.md) `P1`
- [-] [**20261002-1509-phase1-followups Phase 1 follow-up fixes (data plane core campaign)**](20261002-1509-phase1-followups.md) `P1`
- [x] [**20261003-1215-traffic-status Engine status snapshot and per-transport traffic counters**](20261003-1215-traffic-status.md) `P2`
- [x] [**20261002-1529-repo-cleanup-layout Remove unused files and move crates under `crates/`**](20261002-1529-repo-cleanup-layout.md) `P2`
- [x] [**20261003-1300-ns-m4-requests Engine hooks requested by ns account mode (M4)**](20261003-1300-ns-m4-requests.md) `P1`
- [-] [**20261003-1500-ns-dataplane-moves Data-plane pieces ns still owns, to move into nsplane**](20261003-1500-ns-dataplane-moves.md) `P1`
- [-] [**20261003-2200-ns-local-side Local-side graph, masquerade, Echo reply, host TUNs and the ACL gate for ns**](20261003-2200-ns-local-side.md) `P1`
- [-] [**20261006-1300-nsgw-requests Data-plane items for the nsgw rebuild, in generic form**](20261006-1300-nsgw-requests.md) `P1`
- [x] [**20261006-1500-business-agnostic-cleanup Remove product concepts from nsplane**](20261006-1500-business-agnostic-cleanup.md) `P1`
- [ ] [**20261006-1700-windows-smoke-for-ns Windows TUN smoke scenario for ns (MT-3 addendum)**](20261006-1700-windows-smoke-for-ns.md) `P1`
- [-] [**20261008-0800-consumer-integration ns and nsgw on nsplane 0.11**](20261008-0800-consumer-integration.md) `P1`
- [x] [**20261011-0101-local-identities Several local identities per engine**](20261011-0101-local-identities.md) `P1`
- [-] [**20261012-1700-peer-keyed-gate Peer-keyed, address-family-agnostic flow gate**](20261012-1700-peer-keyed-gate.md) `P1`
- [x] [**20261012-1830-no-arc-swap No arc-swap in the data path or the public API**](20261012-1830-no-arc-swap.md) `P1`
- [x] [**20261013-1300-lan-prefix-mappings Prefix address mappings for LAN prefixes**](20261013-1300-lan-prefix-mappings.md) `P1`
- [x] [**20261013-1301-per-identity-routing Cryptokey routing per local identity**](20261013-1301-per-identity-routing.md) `P1`
- [x] [**20261013-1600-perf-residuals Performance residuals left after 0.13/0.14**](20261013-1600-perf-residuals.md) `P2`
- [x] [**20261017-1600-flaky-crypto-workers-test Flaky sink count in a crypto-workers e2e test**](20261017-1600-flaky-crypto-workers-test.md) `P3`
- [-] [**20261017-1700-flow-lifecycle-request Per-flow retirement, flow context and delivery gates (request, draft)**](20261017-1700-flow-lifecycle-request.md) `P3`
- [x] [**20261018-1000-doc-system One documentation standard: behavior-only product docs and comments**](20261018-1000-doc-system.md) `P2`
- [x] [**20261020-0854-udp-icmp-isolation Isolate asynchronous errors on shared UDP sockets**](20261020-0854-udp-icmp-isolation.md) `P1`
- [x] [**20261020-1000-macos-quality-gates Make native macOS quality gates executable**](20261020-1000-macos-quality-gates.md) `P2`
- [x] [**20261020-1026-synchronize-regression-fixtures Synchronize concurrent regression fixtures**](20261020-1026-synchronize-regression-fixtures.md) `P1`

- [x] [**20261020-1224-darwin-utun-name Validate Darwin utun descriptors before name queries**](20261020-1224-darwin-utun-name.md) `P1`
- [x] [**20261024-1430-netstack-any-destination Netstack mode that accepts any destination address**](20261024-1430-netstack-any-destination.md) `P2`
- [x] [**20261024-1500-gino-egress-requests Sandboxed agent egress requests from gino-agent**](20261024-1500-gino-egress-requests.md) `P2`
- [x] [**20261024-1304-dns-passthrough DNS transparent forwarding for messages nsplane-dns does not handle**](20261024-1304-dns-passthrough.md) `P2`
- [x] [**20261024-1313-dns-policy DNS policy routing: per-name rules choose the resolver or a local action**](20261024-1313-dns-policy.md) `P2`
- [x] [**20261024-1329-vm-wireguard-example Example: a virtual machine reaching a remote WireGuard peer through nsplane**](20261024-1329-vm-wireguard-example.md) `P2`
- [x] [**20261024-1338-af-packet-transport Ethernet frame transport over an AF_PACKET socket bound to an existing interface**](20261024-1338-af-packet-transport.md) `P2`
- [x] [**20261024-1437-simple-dns-in-tree Keep the simple-dns protocol crate in this repository**](20261024-1437-simple-dns-in-tree.md) `P2`
- [x] [**20261024-1453-smoltcp-upstream-fixes smoltcp fork: rebase onto upstream main and reapply the fork patches**](20261024-1453-smoltcp-upstream-fixes.md) `P2`
- [x] [**20261024-1454-ether-proxy-arp nsplane-ether: answer ARP and NDP for every address of the guest's link but its own**](20261024-1454-ether-proxy-arp.md) `P2`
- [x] [**20261024-2224-acl-rule-reply-revocation Revoke reply allowances of rule-accepted flows when their authority is gone**](20261024-2224-acl-rule-reply-revocation.md) `P1`
- [x] [**20261026-1848-split-large-modules Split the largest modules by responsibility and share e2e scenario setup**](20261026-1848-split-large-modules.md) `P3`
- [x] [**20261026-0819-node-gateway-requests Requests from the node and the gateway at 0.19.2, and two defects**](20261026-0819-node-gateway-requests.md) `P2`
- [x] [**20261026-0851-vnet-walk-v6-fixes Fix vnet IPv4 IHL 10 segmentation and the walk_v6 later-fragment header limit**](20261026-0851-vnet-walk-v6-fixes.md) `P1`
- [x] [**20261026-0837-scoped-flowgate nsplane-acl: scope-qualified flow gate decisions**](20261026-0837-scoped-flowgate.md) `P1`
- [x] [**20261026-0836-local-barrier-plaintext-ingress Engine local barrier and validated plaintext ingress**](20261026-0836-local-barrier-plaintext-ingress.md) `P2`
- [x] [**20261026-0838-first-input-flow-control Netstack flow control from the first input**](20261026-0838-first-input-flow-control.md) `P1`
- [x] [**20261027-0305-packet-tag-carrier Packet tag carrier on PacketBuf (release C, W4)**](20261027-0305-packet-tag-carrier.md) `P1`
- [x] [**20261027-0305-netstack-ingress-labels Netstack ingress labels and label revocation (release C, W5)**](20261027-0305-netstack-ingress-labels.md) `P1`
- [x] [**20261027-0305-plaintext-egress-send-receipts Plaintext egress and per-packet send receipts (release C, W6)**](20261027-0305-plaintext-egress-send-receipts.md) `P1`
- [x] [**20261027-0349-barrier-count-window Local barrier: cover a packet the source is handing out**](20261027-0349-barrier-count-window.md) `P1`
- [x] [**20261027-0537-tk-cleanup DNS fixture and source documentation cleanup**](20261027-0537-tk-cleanup.md) `P2`
- [x] [**20261027-0433-sink-spent-forwarding Wrapper sinks forward send_batch_spent**](20261027-0433-sink-spent-forwarding.md) `P2`
- [x] [**20261027-0433-filter-coarse-clock AclFilter and AclEngine on the coarse clock**](20261027-0433-filter-coarse-clock.md) `P2`
- [x] [**20261027-0433-peer-expiry-signal Peer-level connection expiry signal (design)**](20261027-0433-peer-expiry-signal.md) `P3`
- [x] [**20261028-0615-remove-wss-stream-carrier Remove the deprecated WsFrame stream carrier from nsplane-wss**](20261028-0615-remove-wss-stream-carrier.md) `P2`
- [x] [**20261028-0615-remove-transparent-admission Remove the deprecated TransparentConfig::admission**](20261028-0615-remove-transparent-admission.md) `P2`
- [ ] [**20261028-0611-expiry-queued-packets-dropped Report packets a tunnel expiry discards**](20261028-0611-expiry-queued-packets-dropped.md) `P3`
- [ ] [**20261028-0611-session-age-aborts-fresh-handshake Idle expiry aborts a handshake started just before it**](20261028-0611-session-age-aborts-fresh-handshake.md) `P3`

- [x] [**20261028-1630-plaintext-ipv4-validation Validate plaintext IPv4 and correct metadata**](20261028-1630-plaintext-ipv4-validation.md) `P2`

- [x] [**20261028-1644-decapsulated-ipv4-validation Validate decapsulated IPv4 header bounds**](20261028-1644-decapsulated-ipv4-validation.md) `P2`
- [x] [**20261029-0000-spent-forwarding-followups Spent buffer forwarding: the remaining sinks**](20261029-0000-spent-forwarding-followups.md) `P3`

- [x] [**20261105-1253-echo-code-state Enforce Echo code and state correlation**](20261105-1253-echo-code-state.md) `P1`

- [x] [**20261105-1420-release-022-metadata Prepare 0.22.0 metadata**](20261105-1420-release-022-metadata.md) `P1`

- [x] [**20261106-0900-netstack-label-followups Netstack label review follow-ups**](20261106-0900-netstack-label-followups.md) `P2`

- [x] [**20261106-2327-tcp-zero-checksum Accept zero TCP and ICMP checksums**](20261106-2327-tcp-zero-checksum.md) `P0`

- [x] [**20261107-0553-retransmitted-syn-second-socket Retransmitted SYN opens a second socket for one tuple**](20261107-0553-retransmitted-syn-second-socket.md) `P1`

- [x] [**20261110-1215-zero-window-ack-deadlock A zero receive window drops the ACK that would reopen it**](20261110-1215-zero-window-ack-deadlock.md) `P1`

- [x] [**20261111-2030-keepalive-expiry-and-cookie-rate-limit Persistent keepalive ends at the expiry; cookie holders are not rate limited**](20261111-2030-keepalive-expiry-and-cookie-rate-limit.md) `P1`

- [x] [**20261111-2031-responder-queue-flush A responder flushes its queue into a second handshake initiation**](20261111-2031-responder-queue-flush.md) `P2`

- [x] [**20261111-2032-splitter-gone-sink-closes-engine One gone sink of a Splitter closes the engine's whole sink**](20261111-2032-splitter-gone-sink-closes-engine.md) `P2`

- [x] [**20261111-2033-dns-tcp-cap-and-forwarder-ids DNS: TCP connection cap, accept under exhaustion, forwarder IDs**](20261111-2033-dns-tcp-cap-and-forwarder-ids.md) `P2`

- [x] [**20261111-2034-cli-uapi-hardening Hardening defects in the CLI and the UAPI server**](20261111-2034-cli-uapi-hardening.md) `P2`

- [x] [**20261111-2035-nat64-lan-checksum NAT64-LAN recomputes transport checksums and hides corruption**](20261111-2035-nat64-lan-checksum.md) `P2`

- [x] [**20261111-2036-ether-dhcp-rebind-and-periodic-ra The DHCP lease outlives its guest and router advertisements are sent once**](20261111-2036-ether-dhcp-rebind-and-periodic-ra.md) `P2`

- [x] [**20261111-2300-raw-fd-adoption-soundness Safe functions took ownership of a descriptor number**](20261111-2300-raw-fd-adoption-soundness.md) `P2`

- [x] [**20261111-2301-noise-hardening Hardening of the Noise state machine**](20261111-2301-noise-hardening.md) `P3`

- [x] [**20261111-2302-peer-listing-quadratic Listing all peers is quadratic in the number of peers**](20261111-2302-peer-listing-quadratic.md) `P3`

- [x] [**20261111-2303-driver-netstack-robustness Driver and netstack robustness items from the audit**](20261111-2303-driver-netstack-robustness.md) `P3`

- [x] [**20261111-2304-uapi-socket-and-jitter UAPI socket hardening, reconnect and router advertisement jitter**](20261111-2304-uapi-socket-and-jitter.md) `P3`

- [x] [**20261112-0001-acl-fairness-and-scans Fairness between peers and full-table scans in nsplane-acl**](20261112-0001-acl-fairness-and-scans.md) `P3`

- [x] [**20261112-0002-nat-quotas-and-fragments Masquerade quota, ICMP quotes with trailing bytes, NAT64-LAN fragments**](20261112-0002-nat-quotas-and-fragments.md) `P3`

- [x] [**20261112-0003-reassembly-and-dns-pools Reassembly table and DNS pool fairness**](20261112-0003-reassembly-and-dns-pools.md) `P3`

- [x] [**20261112-0004-netstack-scaling Netstack scaling and resource items from the audit**](20261112-0004-netstack-scaling.md) `P3`

- [x] [**20261112-0005-wss-batching-and-fairness WSS write batching, session fairness and idle sessions**](20261112-0005-wss-batching-and-fairness.md) `P3`

- [x] [**20261112-0006-driver-sink-recovery Sink recovery and local I/O robustness in the driver**](20261112-0006-driver-sink-recovery.md) `P3`

- [x] [**20261112-0007-tun-robustness TUN robustness: DLL loading, MTU watching, read sizing, slot framing**](20261112-0007-tun-robustness.md) `P3`

- [x] [**20261112-0008-ether-port-errors Transient transport errors no longer close an ethernet port**](20261112-0008-ether-port-errors.md) `P3`

- [x] [**20261112-0009-noise-core-leftovers Leftovers of the audit in the Noise state machine and the core**](20261112-0009-noise-core-leftovers.md) `P3`

- [x] [**20261112-0101-ipv6-extension-walker One shared walker for the IPv6 extension header chain**](20261112-0101-ipv6-extension-walker.md) `P3`

- [x] [**20261112-0102-parser-property-tests Property tests for the parsers that take untrusted bytes**](20261112-0102-parser-property-tests.md) `P3`

- [x] [**20261112-0103-sink-contract-outside-the-engine The sink batch contract outside the engine, and the macOS privilege drop**](20261112-0103-sink-contract-outside-the-engine.md) `P3`

- [x] [**20261112-0104-windows-udp-port-ownership A transport on `[::]:port` does not own the IPv4 side of its port on Windows**](20261112-0104-windows-udp-port-ownership.md) `P3`

- [x] [**20261112-0201-property-test-followups Follow-ups of the parser and codec property tests**](20261112-0201-property-test-followups.md) `P3`
