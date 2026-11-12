# 20261112-0008-ether-port-errors Transient transport errors no longer close an ethernet port

- **status**: completed
- **priority**: P3
- **owner**: audit-fix
- **createdAt**: 2026-11-12 00:08

## Description

Four audited P3 items in `nsplane-ether`:

1. Any error from the transport's read or write closed the port for good. The TAP and packet
   socket writers swallowed some errnos themselves, the readers had no such tolerance, and
   nothing said which errors are meant to be fatal.
2. `tap::IfReq::new` copied the interface name into the fixed array without a length check
   of its own; every caller validated first.
3. DHCP lifecycle review against RFC 2131 section 4.3 (RELEASE, DECLINE, NAK, INFORM, lease
   and renewal times).
4. Neighbor discovery review (prefix lifetimes against the advertisement interval, neighbor
   unreachability probes, duplicate address detection).

Acceptance: an explicit, documented and tested error policy; the constructor refuses an
over-long name; for 3 and 4 a list of what was checked, with fixes and tests only for real
deviations.

## ActiveForm

Classifying transport errors in the ethernet port and reviewing its DHCP and NDP lifecycle.

## Dependencies

- **blocked by**: (none)
- **blocks**: (none)

## Notes

### 1. Error policy

- `FrameRead::is_transient` and `FrameWrite::is_transient` are new trait methods with a
  default of `false` (fatal), so existing implementations keep their behavior. The framed
  stream keeps the default on purpose: a failed read or a partial write loses the frame
  boundary.
- TAP reader and writer: `EINTR`, `EAGAIN`, `ENOBUFS`, `ENOMEM`, `ENETDOWN`. Packet socket
  reader: the same, `ENETDOWN` only while the interface index still exists. Packet socket
  writer: the same set (`ENETDOWN`, `ENXIO`, `ENOBUFS`, `EMSGSIZE` never leave the writer).
  `EIO` on a TAP read and `EINVAL` on a write stay fatal: the kernel does not return them
  for a link that is down.
- Read side: counted, then retried after 10 ms doubling to 1 s, starting over after a frame.
  No backoff helper of the workspace is visible to this crate (`nsplane`'s `Backoff` is
  private to the engine and counts drains, not time), so the wait is two constants and one
  line in the read loop.
- Write side: counted and the frame dropped, reported as delivered; the write is **not**
  repeated. The writer is shared by local replies and the sink behind one mutex, a wait
  there would stall ARP, neighbor discovery and DHCP answers and every packet behind it,
  and the transports' own handling of a down link already drops the frame. Ethernet loses
  frames; the layers above retransmit.
- Logging: warn level, at most one line per second and direction, with the running total.
- Counters: `EtherStats` is an exhaustive public struct, so a new field there would break
  callers that build or destructure it. The counts are in a new `#[non_exhaustive]`
  `TransportErrors` from `EtherHandle::transport_errors`.
- The packet socket reader already waited through `ENETDOWN` inside `read_frame`; that stays
  (moving it out would change `read_frame` for callers that drive the reader themselves). A
  new test sets the link of a real TAP down and up under the bound socket and reads on.

### 2. `IfReq::new`

Returns `InvalidInput` for a name of 16 bytes or more. Before, 16 bytes filled the array
without a terminating NUL and more panicked on the slice.

### 3. DHCP, checked by reading against RFC 2131 (no deviation found, no change)

- DISCOVER: OFFER with `yiaddr`, server id and lease time; `xid`, `flags`, `giaddr`,
  `chaddr` echoed (table 3). No offer while another MAC holds the lease; the adapter frees
  the lease when the guest MAC changes.
- REQUEST, selecting (server id present): another server's id is ignored silently, ours with
  the lease address is ACKed, ours with another address is NAKed (4.3.2).
- REQUEST, init-reboot (no server id, option 50): the lease address is ACKed, any other
  address is NAKed. The RFC allows silence only for a server without knowledge of the
  network; this server is the only one on a point-to-point link, so the NAK is what sends
  a guest with a stale address back to DISCOVER at once.
- REQUEST, renewing and rebinding (no server id, `ciaddr`): ACK with `ciaddr` echoed and
  `yiaddr` set, unicast to `ciaddr` unless the broadcast flag is set.
- NAK: `yiaddr` and `ciaddr` zero, only message type and server id, always broadcast
  (4.3.2, table 3).
- RELEASE and DECLINE: free the lease when sent by the holder, no reply (4.3.3, 4.3.4). After
  a DECLINE the same address is offered again, since there is no other; the adapter never
  answers an ARP probe for the lease address (`is_lease`, sender `0.0.0.0`), so a client's
  address conflict detection has nothing to trip over.
- INFORM: ACK unicast to `ciaddr`, `yiaddr` zero, no lease, renewal or rebinding time
  (4.3.5).
- Lease times: option 51 from `lease_secs` (default 86 400 s), T1 half and T2 seven eighths
  of it, the defaults of 4.4.5, sent explicitly.
- Left as is, not a deviation a client notices: OFFER and ACK to a client without an address
  are broadcast even when the broadcast flag is clear (4.1 says unicast to `yiaddr` at
  `chaddr`); every client accepts the broadcast and the link has one guest. `giaddr` is
  echoed but replies are not sent to a relay: there is none on this link. The client
  identifier is not echoed (RFC 6842); a client must accept its absence.

### 4. NDP, checked by reading against RFC 4861 (no deviation found, no change)

- (a) Prefix information: valid 30 days, preferred 7 days (the RFC defaults), on-link and
  autonomous, repeated at most every 600 s, so both are refreshed thousands of times over.
  Router lifetime 1800 s is three times the longest interval (6.2.1), the RDNSS lifetime
  equals it (RFC 8106 default).
- (b) A solicitation for the gateway's link-local or global address is answered with the
  solicited, router and override flags, unicast to the solicitor, whether it was sent to
  the solicited-node address or unicast (a reachability probe). With the neighbor proxy on,
  the same holds for every on-link prefix address but the guest's own. Covered by
  `ndp::tests::ns_for_our_address_answered`, `ns_without_slla_uses_peer_mac` and
  `adapter::tests::ndp_proxy_answers_other_hosts` (which includes the unicast probe).
- (c) A duplicate address detection probe (unspecified source) is answered only for a
  gateway address, to all-nodes without the solicited flag (7.2.4). For any other target it
  is never answered and teaches the address as the guest's. Covered by
  `ndp::tests::dad_ns_handling` and `adapter::tests::ndp_proxy_leaves_the_guest_addresses_alone`.
- Left as is: proxied advertisements carry the override flag, where 7.2.8 suggests a proxy
  clears it; the adapter is the only answerer on the link, so nothing competes.

## Validation

Red first: with the classification ignored by the port,
`port::tests::a_transient_read_error_is_retried`,
`the_read_backoff_is_bounded_and_restarts_after_a_frame` and
`a_transient_write_error_drops_the_frame_and_a_fatal_one_closes_the_port` failed;
`tap::tests::ifreq_refuses_a_name_that_does_not_fit` failed on the 16-byte name before the
check. `a_fatal_read_error_closes_the_port` and `a_log_limit_passes_once_per_interval`
passed from the start (the first holds existing behavior).

Green: `cargo nextest run -p nsplane-ether --all-features --locked` in a container with
`NET_ADMIN`, `NET_RAW`, `/dev/net/tun` and `net.ipv6.conf.default.{autoconf=0,disable_ipv6=1}`
(the container's `/proc/sys` is read-only, and `ensure_tap` accepts inherited values): 92
passed, 1 skipped, including `packet::tests::reads_on_after_the_interface_went_down_and_up`
on a real TAP. `cargo fmt --all --check`, `cargo hack clippy --each-feature --all-targets`
(host, `x86_64-pc-windows-gnu`), `cargo-zigbuild clippy` for `aarch64-apple-darwin`, doc
tests, `cargo deny check`, `cargo shear`, `typos`, `scripts/check-docs.sh` and
`scripts/check-product-terms.sh` pass.

Not run: `nsplane-e2e` (no test there reaches a transport error path) and the VM scripts.
