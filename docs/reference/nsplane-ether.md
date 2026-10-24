# nsplane-ether

An ethernet adapter for one guest (a virtual machine or container that speaks ethernet):
it turns the guest's ethernet frames into IP packets and back, and stands in for the
gateway on the link with ARP, IPv6 neighbor discovery and router advertisements, an
optional single-lease `DHCPv4` server and guest MAC learning. The IP side is a
`PacketSource` / `PacketSink` pair, so a `NetStack` or an engine takes it unchanged. Builds
on `nsplane` and `nsplane-packet`.

## Public API

| Part | Entry points | Supporting types |
|---|---|---|
| adapter | `EtherAdapter` (`new`, `from_guest`, `to_guest`, `guest_mac`, `stats`, `count_backlog_drop`), `EtherConfig` (`new`) | `EtherStats`, `DEFAULT_MTU` |
| ports | `spawn_port` | `EtherSource` (`PacketSource`), `EtherSink` (`PacketSink`), `EtherHandle` (`stats`, `guest_mac`) |
| transports | `FrameRead`, `FrameWrite`; `stream::FramedReader`, `stream::FramedWriter` (`new`, `into_inner`), `stream::unix` (Unix); `TapDevice` (`open`, `from_fd`, `split`; Linux); `PacketSocket` (`bind`, `index`, `split`; Linux) | `TapReader`, `TapWriter`, `PacketReader`, `PacketWriter` (Linux), `MAX_FRAME_LEN` |
| interfaces | `ensure_tap` (Linux) | `TapConfig` (`new`, `owner`, `group`, `name`), `TapInterface` (`name`, `index`, `created`) |
| protocols | `Frame` (`parse`), `frame::write_header`; `ArpPacket` (`parse`, `write`, `is_gratuitous`), `arp::reply`; `Ndp` (`parse`), `ndp::answer_neighbor_solicitation`, `ndp::answer_router_solicitation`, `ndp::router_advertisement`; `DhcpMessage` (`parse`, `option`, `requested_ip`, `server_id`, `broadcast`), `DhcpServer` (`new`, `handle`, `reply_frame`, `bound`, `config`) | `EtherType`, `FrameError`, `frame::HEADER_LEN`; `ArpOp`, `ArpError`; `NdpMessage`, `NdpError`, `RaConfig`, `ndp::ALL_NODES`; `DhcpConfig` (`new`, `netmask`), `MessageType`, `DhcpError`, `dhcp::option`, `dhcp::SERVER_PORT`, `dhcp::CLIENT_PORT`; `MacAddr` (`link_local`, `ipv6_multicast`, `is_unicast`, `is_multicast`, `is_broadcast`) |

## Behavior

### Adapter

`EtherAdapter` is sans-I/O. `from_guest` takes one frame from the guest, appends the local
replies (ARP, neighbor and router advertisements, DHCP) to a caller vector and returns the
IP packet the frame carries when it is for the IP side, cut to the length its IP header
states (ethernet padding removed). `to_guest` returns the 14-byte ethernet header that
carries an IP packet to the guest: destination the learned guest MAC, source
`EtherConfig::gateway_mac`, `EtherType` from the IP version nibble.

A guest frame goes through these steps in order:

1. The Ethernet II header is parsed; a truncated, 802.3 length-framed or VLAN-tagged
   (802.1Q, 802.1ad, `0x9100`) frame, or one with a multicast source MAC, is dropped as
   `drop_malformed`.
2. The source MAC is learned as the guest MAC (also from frames dropped by the next step).
3. A frame to another unicast MAC is dropped as `drop_not_for_gateway`; frames to the
   gateway MAC, broadcast and multicast continue.
4. ARP, IPv4 and IPv6 are handled as below; any other `EtherType` is dropped as
   `drop_unsupported`.

### Guest MAC learning

Every frame with a unicast source MAC sets the guest MAC; a new source replaces the old one,
so the adapter follows a guest whose MAC changes. Until a MAC is learned, IP packets for the
guest are dropped (`drop_no_guest_mac`). The first time a MAC is learned and an IPv6 prefix
is configured, an unsolicited router advertisement to all-nodes (`ff02::1`) is sent.

### ARP

ARP requests for `EtherConfig::gateway_ipv4` from a unicast sender get a reply from the
gateway MAC, unicast to the requester. Only the ethernet / IPv4 form is accepted (hardware
type 1, protocol `0x0800`, lengths 6 and 4); trailing padding is ignored. Replies,
gratuitous announcements (sender IP equal to target IP), requests for other addresses and
every request when `gateway_ipv4` is `None` are consumed without a reply
(`drop_unanswered`). ARP never reaches the IP side.

### IPv6 neighbor discovery and router advertisements

Router solicitations, neighbor solicitations and neighbor advertisements are consumed by
the adapter; every other IPv6 packet, other `ICMPv6` types included, goes to the IP side.
Extension headers are not walked: a neighbor discovery message behind one passes to the
IP side as ordinary IPv6. A message is accepted only when it validates as RFC 4861
sections 6.1 and 7.1 require: hop limit 255, a correct `ICMPv6` checksum, code 0,
non-zero option lengths, no multicast target, no link-layer address option and a
solicited-node destination when the source is unspecified, no solicited advertisement to
multicast. A message that fails is dropped as `drop_malformed`.

- Neighbor solicitations for the gateway's link-local address (`fe80::/64` with the
  interface identifier derived from the gateway MAC) or for `EtherConfig::gateway_ipv6` get
  a neighbor advertisement from the target address with the router and override flags and a
  target link-layer address option. It goes to the solicitor at the MAC of its source
  link-layer address option, else the frame's source MAC, with the solicited flag; a
  solicitation from the unspecified address (duplicate address detection) is answered to
  all-nodes without it. Solicitations for other addresses get no reply.
- Router solicitations get a router advertisement, unicast to the solicitor or to
  all-nodes when the source is unspecified, whether or not a prefix is configured.
- Neighbor advertisements from the guest are consumed without a reply.
- Router advertisements come from the gateway's link-local address with hop limit 255:
  current hop limit 64, managed and other-configuration flags clear, router lifetime
  1800 s, reachable time and retransmission timer unspecified. Options, in order: source
  link-layer address; MTU (`EtherConfig::mtu`); prefix information for the /64 of
  `EtherConfig::ipv6_prefix` with the on-link and autonomous flags, valid lifetime 30 days
  and preferred lifetime 7 days (when a prefix is set); recursive DNS servers (RFC 8106)
  from `EtherConfig::ipv6_dns` with the router lifetime (when the list is not empty, at
  most 127 servers).

Unanswered solicitations and advertisements count as `drop_unanswered`, sent
advertisements (solicited or not) as `nd_replies`.

### DHCPv4

With `EtherConfig::dhcp` set, an unfragmented IPv4 UDP datagram to port 67 sent to
`255.255.255.255` or to `DhcpConfig::server_ip` is handled by a `DhcpServer` that hands out
exactly one address, `DhcpConfig::guest_ip`; port 67 to any other address is ordinary
traffic for the IP side. Without `dhcp`, DHCP traffic goes to the IP side too.

- DISCOVER: OFFER of the guest address.
- REQUEST naming this server, or naming no server with the guest address as requested
  address (option 50) or `ciaddr` (init-reboot, renewing, rebinding): ACK. A request for
  another address: NAK. A request naming another server: no reply.
- RELEASE and DECLINE from the lease holder free the lease; no reply.
- INFORM: ACK with the configuration, without lease times.
- BOOTP replies, malformed messages (no magic cookie, non-ethernet hardware type, missing
  or unknown message type, an option past the end) and OFFER, ACK and NAK from the guest get
  no reply.

The lease binds to the first client MAC that receives an ACK. While it is bound, another MAC
gets no offer and a NAK to its requests until the holder releases or declines. The lease
does not expire on its own: it stays bound across the lease time.

OFFER and ACK carry message type (53), server id (54), lease time (51), renewal time (58,
half the lease) and rebinding time (59, seven eighths), subnet mask (1, from
`prefix_len`), router (3, when `router` is set), DNS servers (6, when `dns` is not empty, at
most 63) and interface MTU (26, when `DhcpConfig::mtu` is set); an INFORM ACK carries the
same without the three lease times, a NAK only message type and server id. Replies are
padded to 300 bytes and sent from `server_ip:67` and the gateway MAC to port 68: a NAK, a
reply with the client's broadcast flag and a reply with `ciaddr` unspecified go to
`255.255.255.255` at the broadcast MAC, any other to `ciaddr` at `chaddr`. Unanswered DHCP
messages count as `drop_unanswered`.

### IP packets

IPv4 and IPv6 packets not handled above go to the IP side unchanged (no TTL or hop-limit
change, no checksum check), cut to their IP header's length; a packet shorter than its
header states is dropped as `drop_malformed`. In the other direction `to_guest` frames any
packet whose first nibble is 4 or 6 and drops anything else as `drop_bad_ip`. The MTU is
advertised (router advertisements, `EtherSource`'s MTU) and not enforced: a packet in either
direction is passed whatever its size, up to `MAX_FRAME_LEN`.

### Ports

`spawn_port(reader, writer, config)` spawns a reader task on the current Tokio runtime and
returns an `EtherSource` (IP packets from the guest), an `EtherSink` (IP packets for the
guest) and an `EtherHandle` (counters and the learned guest MAC).

- The reader task reads one frame at a time, runs it through the adapter, writes the local
  replies to the transport itself and queues the IP packet for the source. The queue holds
  256 packets and is lossy: when the IP side falls behind, new packets are dropped and
  counted as `drop_backlog`, so ARP, neighbor discovery and DHCP keep being answered whether
  or not the IP side reads.
- `EtherSource::recv` returns packets in order behind `HEADROOM`, is cancellation safe and
  takes buffers from a pool that `recycle` refills (up to 256 idle buffers). Its `mtu`
  reports `EtherConfig::mtu` and never changes.
- `EtherSink::send` writes the ethernet header into the packet's headroom (a copy only when
  there is less than 14 bytes of it) and writes the frame to the transport, waiting while
  the transport applies backpressure. Replies and sink writes share one writer behind an
  async mutex, so frames never interleave. A packet that cannot be framed (no guest MAC yet,
  not IPv4 or IPv6) is dropped, counted and reported as sent.
- The task ends when the transport reaches its end, a read or write fails, or the source is
  dropped. From then on the source returns `BrokenPipe` after the queued packets and the sink
  returns `BrokenPipe` on every call.

To attach a guest to a user-space stack, pass the source and sink where the stack's peer
expects them, for example to an engine through `EngineBuilder` as its local side, or
forward between `EtherSource` / `EtherSink` and `NetStack::split`'s sink and source.

### Transports

`FrameRead` and `FrameWrite` move whole ethernet frames; an error ends the transport and
neither future is cancellation safe. Three implementations:

- Framed byte stream (`stream`): every frame is a 4-byte big-endian length followed by the
  frame bytes, the convention of passt and of QEMU's `-netdev stream`, also used by libkrun
  in its passt mode. `FramedReader` and `FramedWriter` wrap any Tokio `AsyncRead` /
  `AsyncWrite`; `stream::unix` splits a connected `UnixStream` into both. The reader handles
  frames split over any number of reads and several frames in one read. End of stream
  before a prefix is the clean end; end of stream inside a prefix or a frame is
  `UnexpectedEof`, a zero length or one above `MAX_FRAME_LEN` is `InvalidData`. The writer
  sends prefix and frame in one write and flushes; an empty or oversized frame is
  `InvalidInput` and nothing is written.
- TAP device (`TapDevice`, Linux): `open(name)` attaches `/dev/net/tun` to the TAP
  interface `name` with `IFF_TAP | IFF_NO_PI`, creating it if missing (`""` or a `%d`
  pattern lets the kernel pick the name; longer than 15 bytes or containing NUL is
  `InvalidInput`), and needs `CAP_NET_ADMIN`; `from_fd` adopts an open TAP fd (or any fd
  that reads and writes one frame per call) and switches it to non-blocking mode. Every
  `read(2)` and `write(2)` is one frame; a read of zero bytes ends the transport. While the
  interface is down the kernel refuses writes with `EIO`; that frame is dropped and the
  transport stays open. Interface addresses and link state are left to the caller.
- Packet socket (`PacketSocket`, Linux): for a guest whose host-side TAP another process
  holds, as a virtual machine monitor such as Firecracker does. `bind(ifname)` opens an
  `AF_PACKET` / `SOCK_RAW` socket for every protocol (`ETH_P_ALL`) with a virtio-net header
  (`PACKET_VNET_HDR`), bound to the index of the existing interface `ifname`, non-blocking;
  it needs `CAP_NET_RAW`. A missing interface is `ENODEV`, an invalid name `InvalidInput`.
  The interface itself is not changed: every frame a TAP receives reaches the socket
  whatever its destination MAC, so no promiscuous mode is needed. The socket does not read
  back what is sent out of the interface, its own frames included (`PACKET_IGNORE_OUTGOING`;
  on kernels without it the reader skips frames of type `PACKET_OUTGOING`).
  - The reader returns one received frame per call and never `None`. A frame with a partial
    checksum (`VIRTIO_NET_HDR_F_NEEDS_CSUM`, as a guest with checksum offload sends it) is
    completed in place, a UDP checksum of 0 written as `0xFFFF`. A GSO frame (TCP over IPv4
    or IPv6, UDP) is split by `nsplane_packet::vnet::segment` into frames of `gso_size`
    payload bytes with their own lengths, identification, sequence numbers and checksums,
    each behind the original ethernet header, and returned one per call. A frame the
    kernel truncated, or one whose virtio-net header or headers do not match, is dropped and
    logged at debug level. While the interface is down the reader waits for it to come
    back; once it is deleted, the read fails with `ENETDOWN`.
  - The writer sends each frame behind an empty virtio-net header, so frames for the guest
    carry complete checksums. `ENETDOWN`, `ENXIO`, `ENOBUFS` and `EMSGSIZE` (the interface
    is down or gone, no buffer space, the frame exceeds the interface MTU) drop that frame
    and keep the transport open; while no process holds the TAP the kernel drops the frames
    without an error.

### TAP interfaces

`ensure_tap(&TapConfig)` (Linux) gives a packet socket its interface, so an embedder starts
nsplane before the virtual machine monitor and needs no other network setup.

- An interface named `TapConfig::name` that already exists is used as it is: nothing about
  it changes, and dropping the returned `TapInterface` leaves it in place
  (`created() == false`).
- A missing one is created as a persistent TAP: `TUNSETIFF` with `IFF_TAP | IFF_NO_PI |
  IFF_VNET_HDR` (and `IFF_TUN_EXCL`, so an interface created concurrently by someone else
  is not taken over), `TUNSETOWNER` / `TUNSETGROUP` from `TapConfig::owner` / `group`
  (without them only `CAP_NET_ADMIN` attaches), `TUNSETPERSIST`; the file descriptor is
  closed again so the monitor can attach. Then `net.ipv6.conf.<name>.autoconf` is set to 0
  and `disable_ipv6` to 1, and the interface is brought up with `IFF_NOARP`: the host
  kernel neither answers the guest's ARP and neighbor discovery nor sends frames of its own
  to the guest. A write to `/proc/sys` that fails (read-only in a container) is accepted
  when the setting already has the wanted value, for example inherited from
  `net.ipv6.conf.default`; a kernel without IPv6 skips both settings. Creating needs
  `CAP_NET_ADMIN`; using an existing interface needs nothing.
- Dropping a `TapInterface` with `created() == true` deletes the interface over rtnetlink
  (`RTM_DELLINK` by index), which works while the monitor still holds it; a failure is
  logged.
- A name that is empty, longer than 15 bytes, `.` or `..`, or contains NUL, `/`, `%`, `:`
  or whitespace is `InvalidInput`. A step that fails after the interface was created deletes
  it again and returns the error.

### Tests

`tests/guest.rs` (Unix) drives the adapter from a scripted guest over a Unix socket pair
through the public API: ARP, neighbor and router solicitations, a DHCP lease, TCP between
two `NetStack`s through the adapter, and the shutdown of both sides when the transport
closes. The TAP unit tests run the transport over a datagram socket pair; opening a real
TAP device needs `CAP_NET_ADMIN`, so that test is ignored by default. The offload handling
of the packet socket is tested on crafted frames (partial checksums, GSO frames beyond one
batch, malformed headers). The tests of `ensure_tap` and `PacketSocket` on real interfaces
(creation, owner, flags and IPv6 settings, deletion while attached, an existing interface
left in place, frames in both directions, GSO and partial-checksum frames through the
kernel) need `CAP_NET_ADMIN`, `CAP_NET_RAW` and `/dev/net/tun` and return early without
them.

[`scripts/vm-guest.sh`](../../crates/nsplane-ether/scripts/vm-guest.sh) checks the adapter
against a real Linux guest. It builds the
[`unix_gateway`](../../crates/nsplane-ether/examples/unix_gateway.rs) example (the adapter
on a Unix socket, its IP side on a `NetStack` that answers TCP with one echoed line) and a
labelled runner image with QEMU and a Debian kernel, then boots a minimal busybox guest
with `-enable-kvm` and `-netdev stream` on that socket. The guest takes a DHCP lease and
an IPv6 address from the router advertisement and exchanges TCP over IPv4 and IPv6; the
script exits 0 only when the guest prints its success marker. It needs docker and
`/dev/kvm`; the normal test run needs neither.

## Configuration and defaults

| Setting | Field | Default |
|---|---|---|
| Gateway MAC | `EtherConfig::gateway_mac` | required (`EtherConfig::new`) |
| Gateway IPv4 (answered by ARP) | `EtherConfig::gateway_ipv4` | `None`: no ARP replies |
| Gateway global IPv6 (answered by neighbor discovery next to the link-local one) | `EtherConfig::gateway_ipv6` | `None` |
| Advertised /64 | `EtherConfig::ipv6_prefix` | `None`: no prefix option, no unsolicited advertisement |
| Advertised IPv6 DNS servers | `EtherConfig::ipv6_dns` | empty: no RDNSS option |
| Link MTU (router advertisements, `EtherSource` MTU) | `EtherConfig::mtu` | `DEFAULT_MTU`, 1500 |
| DHCP server | `EtherConfig::dhcp = Some(DhcpConfig::new(server_ip, guest_ip, prefix_len))` | `None`: DHCP goes to the IP side |
| DHCP router, DNS servers, MTU option | `DhcpConfig::router`, `dns`, `mtu` | none of them sent |
| DHCP lease time | `DhcpConfig::lease_secs` | 86 400 s (renewal 43 200 s, rebinding 75 600 s) |
| Router lifetime and RDNSS lifetime | fixed | 1800 s |
| Prefix valid / preferred lifetime | fixed | 30 days / 7 days |

## Errors and drop reasons

Everything the adapter discards is counted in `EtherStats` (from `EtherAdapter::stats` or
`EtherHandle::stats`) next to `frames_in`, `frames_out`, `ip_in`, `ip_out`, `arp_replies`,
`nd_replies` and `dhcp_replies`:

| Counter | Dropped |
|---|---|
| `drop_malformed` | bad ethernet header (truncated, 802.3 length, VLAN tag), multicast source MAC, malformed ARP, IP shorter than its header states, neighbor discovery failing validation |
| `drop_not_for_gateway` | guest frame to another unicast MAC |
| `drop_unsupported` | guest frame that is neither ARP, IPv4 nor IPv6 |
| `drop_unanswered` | ARP, neighbor discovery or DHCP message consumed without a reply |
| `drop_no_guest_mac` | IP packet for the guest before a guest MAC is learned |
| `drop_bad_ip` | packet for the guest that is not IPv4 or IPv6 |
| `drop_backlog` | IP packet from the guest while the source queue is full |

The protocol parsers return `FrameError`, `ArpError`, `NdpError` and `DhcpError`; none
panics on truncated or malformed input. `EtherSource` and `EtherSink` return `BrokenPipe`
once the transport is gone.

## Limits and bounds

- One guest per adapter: one learned MAC, one DHCP lease.
- Frames up to `MAX_FRAME_LEN` (65 549 bytes: a 64 KiB IP packet behind the ethernet
  header); the reader task holds one buffer of that size.
- No VLAN tags (802.1Q / 802.1ad frames are dropped), no 802.3 length framing.
- Packet socket: one guest per interface; GSO types TCP over IPv4 and IPv6 and UDP, no
  IPv6 extension headers in GSO frames; frames for the guest no larger than the interface
  MTU plus the ethernet header. The reader holds a copy of the GSO frame being split and
  up to `MAX_BATCH` segment buffers.
- Source queue: 256 packets; buffer pool: 256 idle buffers.
- At most 63 IPv4 DNS servers in DHCP, 127 IPv6 DNS servers in router advertisements.

## Platform notes

- The framed stream transport builds on every platform; `stream::unix` is Unix only.
- `TapDevice`, `TapReader`, `TapWriter`, `PacketSocket`, `PacketReader`, `PacketWriter`,
  `ensure_tap`, `TapConfig` and `TapInterface` are Linux only, and the `libc` dependency is
  Linux only. `unsafe` code lives only in the TAP and packet socket modules (`ioctl`,
  `fcntl`, `socket`, `setsockopt`, `bind`, `send`, `recv`, `recvmsg`, `writev`, `read`,
  `write`, interface name and index lookups, and the reactor registration), each with a
  SAFETY comment.
- Capabilities: `PacketSocket::bind` needs `CAP_NET_RAW`; `ensure_tap` needs
  `CAP_NET_ADMIN` when it creates the interface; `TapDevice::open` needs `CAP_NET_ADMIN`.

## See also

- [nsplane](nsplane.md): `PacketSource` / `PacketSink` and the engine.
- [nsplane-netstack](nsplane-netstack.md): the user-space stack the IP side plugs into.
- [nsplane-packet](nsplane-packet.md): the IP and UDP headers the adapter parses and builds.
- [nsplane-tun](nsplane-tun.md): OS TUN devices, the IP-level counterpart of a TAP device.
