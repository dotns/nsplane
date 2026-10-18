# nsplane usage guide

[中文版](guide.zh-CN.md)

This guide shows how to embed nsplane in an application: which crates to pick, how an engine
is assembled, and complete code for the common deployments. It describes nsplane 0.16.0.

- Signatures and contracts: rustdoc (`cargo doc --workspace --no-deps --open`).
- Design: [architecture.md](architecture.md); behavior per crate: [reference](reference/);
  measurements: [performance.md](performance.md).
- Runnable programs: [examples/README.md](../examples/README.md).

## Contents

1. [What nsplane is](#1-what-nsplane-is)
2. [Crates and when to use them](#2-crates-and-when-to-use-them)
3. [Adding the dependency](#3-adding-the-dependency)
4. [Concepts](#4-concepts)
5. [Quick start: two nodes in one process](#5-quick-start-two-nodes-in-one-process)
6. [A client on a TUN device](#6-a-client-on-a-tun-device)
7. [Mobile and host-managed devices](#7-mobile-and-host-managed-devices)
8. [A userspace node: nsplane-netstack](#8-a-userspace-node-nsplane-netstack)
9. [TUN and netstack behind one engine](#9-tun-and-netstack-behind-one-engine)
10. [Access control: nsplane-acl](#10-access-control-nsplane-acl)
11. [Address translation and NAT: nsplane-nat](#11-address-translation-and-nat-nsplane-nat)
12. [Transports: UDP, links and WebSocket over TLS](#12-transports-udp-links-and-websocket-over-tls)
13. [Several local identities](#13-several-local-identities)
14. [Operating an engine](#14-operating-an-engine)
15. [Platforms and building](#15-platforms-and-building)
16. [Examples index](#16-examples-index)

## 1. What nsplane is

nsplane is a userspace WireGuard<sup>®</sup> data plane written in Rust. It is a library:
the application owns configuration, identities and policy, and hands nsplane generic inputs
(keys, peers, allowed IPs, rules, labels). It does no control-plane work of its own: no
coordination server, no DNS, no product model.

What it provides:

- the WireGuard protocol (Noise IKpsk2 handshake, sessions, timers, cookies), interoperable
  with kernel WireGuard and wireguard-go;
- an engine that moves packets between a local side (TUN device, userspace TCP/IP stack,
  host callbacks or channels) and one or more transports (UDP, message links, WebSocket
  over TLS);
- packet filters on the data path: label-based ACLs and a flow gate, IPv4/IPv6 translation,
  DNAT/SNAT service publishing, NAT64 to a LAN;
- the `wg` configuration protocol (UAPI), so `wg show` / `wg set` work against an engine;
- batching and segmentation offload (TUN TSO/USO on Linux and Android, UDP GSO/GRO), an
  optional crypto worker pool, and an optional fragmentation stage.

A feature that is not installed is not on the data path: a plain client pays nothing for
ACLs, NAT or the netstack.

## 2. Crates and when to use them

```text
nsplane-noise ─► nsplane-core ─► nsplane ─► nsplane-tun, nsplane-uapi ─► nsplane-cli
nsplane-packet ─► nsplane-core, nsplane
nsplane, nsplane-packet ─► nsplane-netstack
nsplane-core, nsplane-packet ─► nsplane-acl, nsplane-nat
nsplane ─► nsplane-nat, nsplane-wss
```

| Crate | Use it for | Main types |
|---|---|---|
| `nsplane` | Always: the tokio engine and its I/O traits | `EngineBuilder`, `Engine`, `EngineHandle`, `Peer`, `UdpTransport`, `LinkTransport`, `Splitter`, `MergeSource`, `ChannelSource` / `ChannelSink`, `Event` |
| `nsplane-tun` | An OS TUN device as the local side (Linux, Android, macOS, iOS, Windows via Wintun) | `Tun`, `TunSlot` (Android), `host_tun` (iOS / callbacks) |
| `nsplane-netstack` | Applications that open TCP/UDP connections inside the tunnel without a TUN device or root | `NetStack`, `NetStackHandle`, `TcpConnection`, `UdpFlow`, `UdpSocket`, `FlowControl` |
| `nsplane-uapi` | `wg show` / `wg set` against the engine (Unix socket, Windows named pipe) | `Uapi`, `UapiListener` |
| `nsplane-acl` | Inbound and outbound access control by peer labels, addresses and ports; app sessions; stateful flow gate | `AclEngine`, `AclFilter`, `FlowTracker`, `RuleSet`, `PeerLabelMap`, `gate::GateFilter` |
| `nsplane-nat` | IPv4 applications over IPv6 peers (RFC 7915), publishing local services, NAT64 to an IPv4 LAN, local redirect and masquerade | `Translator`, `TranslationTable`, `PortMap`, `Conntrack`, `Nat64Lan`, `Redirect`, `Masquerade` |
| `nsplane-wss` | WireGuard over WebSocket over TLS where UDP is blocked | `WssDialer`, `WssServerTransport`, `WssAcceptor` |
| `nsplane-core` | Writing your own driver, or implementing `PacketFilter` / `PathPolicy` (both are re-exported by `nsplane`; `Verdict` comes from here) | `Core`, `PacketFilter`, `PathPolicy`, `Verdict` |
| `nsplane-packet` | Packet buffers and IP header views in custom filters, splitters or local sides | `PacketBuf`, `IpPacket`, `SharedPacketPool`, `build::udp_packet` |
| `nsplane-noise` | The protocol alone, with your own I/O | `noise::Tunn` |
| `nsplane-cli` | Not a library: a development daemon for Linux and macOS, configured with `wg` | — |

Typical combinations:

| Application | Crates |
|---|---|
| Desktop or server VPN client / node | `nsplane`, `nsplane-tun`, optionally `nsplane-uapi` |
| Android / iOS VPN | `nsplane`, `nsplane-tun` (`TunSlot` / `host_tun`) |
| Application-embedded tunnel, no root (SDK, sidecar, test harness) | `nsplane`, `nsplane-netstack` |
| Gateway with access control | `nsplane`, `nsplane-tun`, `nsplane-acl` |
| Subnet router / IPv6-only fabric | `nsplane`, `nsplane-tun`, `nsplane-nat` |
| Behind firewalls that block UDP | add `nsplane-wss` |

## 3. Adding the dependency

nsplane is consumed from git. Pin a tag or a commit so builds are reproducible:

```toml
[dependencies]
nsplane = { git = "https://github.com/dotns/nsplane", tag = "v0.16.0" }
nsplane-tun = { git = "https://github.com/dotns/nsplane", tag = "v0.16.0" }
# as needed:
# nsplane-netstack, nsplane-uapi, nsplane-acl, nsplane-nat, nsplane-wss, nsplane-core
tokio = { version = "1", features = ["macros", "rt-multi-thread"] }
```

For local co-development, override the git source with paths:

```toml
[patch."https://github.com/dotns/nsplane"]
nsplane = { path = "../nsplane/crates/nsplane" }
nsplane-tun = { path = "../nsplane/crates/nsplane-tun" }
```

Requirements: Rust 1.95 or newer (the repository pins 1.99.0), a C compiler for `aws-lc-sys`,
and NASM for x86_64 Windows targets. Keys are `x25519_dalek` types re-exported as
`nsplane::x25519`; to generate one, add `rand_core = { version = "0.6", features =
["getrandom"] }` and call `StaticSecret::random_from_rng(rand_core::OsRng)`.

## 4. Concepts

```text
           local side                    engine                     transports
 ┌──────────────────────────┐   ┌─────────────────────────┐   ┌──────────────────────┐
 │ PacketSource (packets out│──►│ filters (outbound)      │   │ UdpTransport         │
 │ of the host / app)       │   │ cryptokey routing       │──►│ LinkTransport (WSS)  │
 │                          │   │ seal ─► path policy     │   │ your Transport impl  │
 │ PacketSink (packets into │◄──│ open ◄─ filters(inbound)│◄──│                      │
 │ the host / app)          │   │ timers, handshakes      │   │                      │
 └──────────────────────────┘   └─────────────────────────┘   └──────────────────────┘
       Tun / TunSlot / host_tun / NetStack / ChannelSource+ChannelSink / Splitter+MergeSource
```

- **Engine.** `EngineBuilder::new(source, sink)` plus a private key and at least one
  transport, then `build()`. The engine runs on the current tokio runtime. `Engine::handle()`
  returns a cloneable `EngineHandle` for every later change; `Engine::wait()` resolves when it
  stops (`EngineHandle::shutdown()`).
- **Local side.** Any `PacketSource` (IP packets the engine encrypts) and `PacketSink` (IP
  packets the engine decrypted, with the sending `PeerId`). nsplane ships TUN devices,
  a userspace stack, host callback bridges, channels, and combinators.
- **Transport.** A `Transport` sends and receives datagrams for a `TransportId` you choose.
  An engine may run several at once; each peer's `Path { transport, addr, ecn }` names the
  transport and remote address it is reached on.
- **Peer.** `Peer` (alias of `PeerConfig`): public key, allowed IPs (cryptokey routing),
  optional preshared key, keepalive and initial path. `add_or_update_peer` inserts or
  updates it; the engine assigns a `PeerId` (`EngineHandle::peer_id(key)`), which filters,
  sinks and statistics use.
- **Roaming.** A peer's path follows authenticated packets from a new address by default
  (`StandardRoaming`). `EngineBuilder::policy` installs another `PathPolicy`.
- **Filters.** `EngineBuilder::filter(Box<dyn PacketFilter>)` adds a filter; filters run in
  order on every inbound packet (after decryption) and outbound packet (before routing), and
  return a `Verdict` (accept, or drop with a reason). ACL and NAT types are filters.
- **Events and stats.** `EngineHandle::subscribe()` yields a broadcast receiver of `Event`s
  (handshakes, path changes, session expiry, drops, MTU, suspend/resume); counters are
  queried on demand.

Address families are the caller's choice: IPv4, IPv6 or dual stack follow from the transport
bind address, the local side's addresses and the peers' allowed IPs.

## 5. Quick start: two nodes in one process

No root and no TUN device: each engine's local side is a userspace TCP/IP stack, the
transport is UDP on loopback. Node B runs a TCP echo server; node A connects to it through
the tunnel. (The repository's `udp_pair` example is the same, with UDP and stats.)

```rust
use std::net::SocketAddr;
use std::time::Duration;

use futures_util::StreamExt as _;
use nsplane::x25519::{PublicKey, StaticSecret};
use nsplane::{AllowedIp, Ecn, Engine, EngineBuilder, Path, Peer, TransportId, UdpTransport};
use nsplane_netstack::{DEFAULT_MTU, NetStack, NetStackConfig, NetStackHandle};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

const UDP: TransportId = TransportId::new(0);

/// One node: a userspace TCP/IP stack owning `addr`, a UDP transport on loopback.
fn node(key: StaticSecret, addr: AllowedIp) -> anyhow::Result<(Engine, NetStackHandle, SocketAddr)> {
    let (stack, handle) =
        NetStack::new(NetStackConfig::new(vec![(addr.addr, addr.cidr)], DEFAULT_MTU));
    let (source, sink) = stack.split();
    let udp = UdpTransport::bind(UDP, "127.0.0.1:0".parse()?)?;
    let outer = udp.local_addr();
    let engine = EngineBuilder::new(source, sink)
        .private_key(key)
        .transport(udp)
        .build()?;
    Ok((engine, handle, outer))
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let key_a = StaticSecret::random_from_rng(rand_core::OsRng);
    let key_b = StaticSecret::random_from_rng(rand_core::OsRng);
    let (pub_a, pub_b) = (PublicKey::from(&key_a), PublicKey::from(&key_b));
    let (a, stack_a, _) = node(key_a, AllowedIp { addr: "10.0.0.1".parse()?, cidr: 24 })?;
    let (b, stack_b, outer_b) = node(key_b, AllowedIp { addr: "10.0.0.2".parse()?, cidr: 24 })?;

    // A knows B's endpoint; B learns A's from the handshake.
    let mut peer_b = Peer::new(pub_b);
    peer_b.allowed_ips = vec![AllowedIp { addr: "10.0.0.2".parse()?, cidr: 32 }];
    peer_b.path = Some(Path { transport: UDP, addr: outer_b, ecn: Ecn::NotEct });
    a.handle().add_or_update_peer(peer_b).await?;
    let mut peer_a = Peer::new(pub_a);
    peer_a.allowed_ips = vec![AllowedIp { addr: "10.0.0.1".parse()?, cidr: 32 }];
    b.handle().add_or_update_peer(peer_a).await?;

    // B: a TCP echo server on every port of 10.0.0.2.
    let mut incoming = stack_b.incoming_tcp();
    tokio::spawn(async move {
        while let Some(mut conn) = incoming.next().await {
            tokio::spawn(async move {
                let mut buf = [0u8; 1024];
                while let Ok(n @ 1..) = conn.read(&mut buf).await {
                    if conn.write_all(&buf[..n]).await.is_err() {
                        break;
                    }
                }
            });
        }
    });

    // A: connect through the tunnel (the first packet triggers the handshake).
    let mut conn = tokio::time::timeout(
        Duration::from_secs(10),
        stack_a.connect_tcp("10.0.0.2:7".parse()?),
    )
    .await??;
    conn.write_all(b"hello").await?;
    let mut reply = [0u8; 5];
    conn.read_exact(&mut reply).await?;
    assert_eq!(&reply, b"hello");

    for engine in [a, b] {
        engine.handle().shutdown().await?;
        engine.wait().await?;
    }
    Ok(())
}
```

Dependencies: `nsplane`, `nsplane-netstack`, `tokio` (`macros`, `rt-multi-thread`, `io-util`,
`time`), `futures-util`, `rand_core` (`getrandom`), `anyhow`.

## 6. A client on a TUN device

A classic VPN client: a TUN device as the local side, one UDP transport, one server peer,
and optionally the UAPI so `wg` can inspect and change it. Needs root or `CAP_NET_ADMIN`.

```rust
use std::net::SocketAddr;

use nsplane::x25519::{PublicKey, StaticSecret};
use nsplane::{AllowedIp, Ecn, EngineBuilder, Path, Peer, StandardRoaming, TransportId, UdpTransport};
use nsplane_tun::Tun;
use nsplane_uapi::{TRANSPORT_ID, Uapi, UapiListener};

async fn client(key: StaticSecret, server_key: PublicKey, server: SocketAddr) -> anyhow::Result<()> {
    // `wg set listen-port` rebinds the transport with id TRANSPORT_ID.
    const UDP: TransportId = TRANSPORT_ID;
    // Addresses and routes of the device are set outside nsplane, e.g.
    //   ip addr add 10.0.0.2/32 dev wg0 && ip link set wg0 up
    //   ip route add 10.0.0.0/24 dev wg0
    let tun = Tun::create("wg0")?;
    let name = tun.name()?;
    let (source, sink) = tun.split()?;
    let udp = UdpTransport::bind(UDP, "0.0.0.0:0".parse()?)?;
    let port = udp.local_addr().port();
    let engine = EngineBuilder::new(source, sink)
        .private_key(key)
        .transport(udp)
        .policy(Box::new(StandardRoaming))
        .build()?;

    let mut peer = Peer::new(server_key);
    peer.allowed_ips = vec![AllowedIp { addr: "10.0.0.0".parse()?, cidr: 24 }];
    peer.persistent_keepalive = Some(25);
    peer.path = Some(Path { transport: UDP, addr: server, ecn: Ecn::NotEct });
    engine.handle().add_or_update_peer(peer).await?;

    // Optional: `wg show wg0` / `wg set wg0 ...` on /var/run/wireguard/wg0.sock.
    let uapi = Uapi::with_listen_port(engine.handle(), port);
    let listener = UapiListener::bind(&name)?;
    tokio::spawn(async move { uapi.serve(listener).await });

    engine.wait().await?;
    Ok(())
}
```

Notes:

- nsplane does not configure addresses, routes or DNS of the device; the host does.
- `Tun::create` turns on TSO/USO offload where the kernel supports it;
  `Tun::create_with(name, TunOptions::new().offload(false))` opts out.
  `UdpTransport::bind_with_offload(id, addr, false)` does the same for GSO/GRO.
- On Linux raise `net.core.rmem_max` / `wmem_max` (e.g. 4194304) for full socket buffers.
- A server is the same code with a fixed listen address (`0.0.0.0:51820`) and peers without
  `path`: their endpoints are learned from handshakes.
- `Tun::from_fd` / `from_raw_fd(fd, mtu)` adopt a TUN fd created by another process
  (see `nsplane-cli --tun-fd` and the `fd_bridge` example).

## 7. Mobile and host-managed devices

### Android: `TunSlot`

`VpnService.Builder.establish()` returns a new fd on every reconfiguration. `TunSlot` keeps
the engine running and swaps the fd under it:

```rust
use std::os::fd::OwnedFd;

use nsplane::EngineBuilder;
use nsplane_tun::TunSlot;

fn start(
    fd: OwnedFd,
    key: nsplane::x25519::StaticSecret,
    udp: nsplane::UdpTransport,
) -> anyhow::Result<(TunSlot, nsplane::Engine)> {
    let (slot, source, sink) = TunSlot::new(1280);
    slot.replace(fd)?; // the fd from VpnService.Builder.establish()
    let engine = EngineBuilder::new(source, sink)
        .private_key(key)
        .transport(udp)
        .build()?;
    Ok((slot, engine))
}

fn reconfigure(slot: &TunSlot, new_fd: OwnedFd) -> std::io::Result<()> {
    // Once replace returns, no read or write runs on the previous fd.
    slot.replace(new_fd)
}
```

`disable` / `enable` park I/O between reconfigurations, `clear` drops the fd, `close` ends the
slot.

### iOS and other callback hosts: `host_tun`

`NEPacketTunnelFlow` exposes packets through callbacks rather than an fd:

```rust
use std::sync::Arc;

use nsplane::EngineBuilder;
use nsplane_tun::{HOST_TUN_DEFAULT_CAPACITY, host_tun};

fn start(
    key: nsplane::x25519::StaticSecret,
    udp: nsplane::UdpTransport,
    write_packets: impl Fn(&[u8]) -> bool + Send + Sync + 'static,
) -> anyhow::Result<(nsplane_tun::HostTunInput, nsplane::Engine)> {
    let (input, source, sink) =
        host_tun(1280, HOST_TUN_DEFAULT_CAPACITY, Arc::new(write_packets));
    let engine = EngineBuilder::new(source, sink)
        .private_key(key)
        .transport(udp)
        .build()?;
    // From the packetFlow.readPackets callback, on any thread:
    //   input.push(&packet)  // Err(PushError::Full) drops the packet
    Ok((input, engine))
}
```

`write_packets` runs on the engine task and must not block (`writePackets` does not);
it returns `false` once the host can no longer take packets. `HostTunSource::set_mtu`
changes the MTU.

### Packet channels

When the host pumps packets itself (any platform, or tests), use channels:

```rust
use nsplane::{ChannelSink, ChannelSource, EngineBuilder};

let (source, to_engine, mtu) = ChannelSource::new(1024, 1420);
let (sink, mut from_engine) = ChannelSink::new(1024);
let engine = EngineBuilder::new(source, sink).private_key(key).transport(udp).build()?;
// host -> engine: to_engine.send(PacketBuf::from_packet(&bytes)).await
// engine -> host: while let Some((peer, packet)) = from_engine.recv().await { packet.as_packet() }
// MTU change:     mtu.send(1280)
```

`pipe`, `pump`, `SwapSink` and `AbortSink` cover in-process wiring, live sink replacement and
fencing a sink at shutdown; see rustdoc.

## 8. A userspace node: nsplane-netstack

`nsplane-netstack` is a TCP/IP stack (smoltcp fork) that is both the engine's local side and
an API for the application: it owns addresses inside the tunnel and serves TCP and UDP
endpoints on them, IPv4 and IPv6. No TUN device, no root, no host routing.

```rust
let (stack, handle) = NetStack::new(NetStackConfig::new(
    vec![("10.0.0.1".parse()?, 24), ("fd00::1".parse()?, 64)],
    DEFAULT_MTU,
));
let (source, sink) = stack.split();
let engine = EngineBuilder::new(source, sink).private_key(key).transport(udp).build()?;
// `handle` (NetStackHandle, Clone) is the application's API.
```

### TCP and UDP

```rust
use futures_util::StreamExt as _;
use nsplane_netstack::NetStackHandle;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

// Server: every inbound connection to an owned address arrives here; filter by port.
async fn tcp_server(stack: NetStackHandle) {
    let mut incoming = stack.incoming_tcp();
    while let Some(conn) = incoming.next().await {
        if conn.local_addr().port() != 80 {
            continue;
        }
        tokio::spawn(async move {
            let (mut rd, mut wr) = tokio::io::split(conn);
            let _ = tokio::io::copy(&mut rd, &mut wr).await;
        });
    }
}

// UDP server: one UdpFlow per remote endpoint.
async fn udp_server(stack: NetStackHandle) {
    let mut flows = stack.incoming_udp();
    while let Some(mut flow) = flows.next().await {
        tokio::spawn(async move {
            while let Some(datagram) = flow.recv().await {
                let _ = flow.send(&datagram).await;
            }
        });
    }
}

async fn clients(stack: &NetStackHandle) -> anyhow::Result<()> {
    // TcpConnection is AsyncRead + AsyncWrite.
    let mut tcp = stack.connect_tcp("10.0.0.2:80".parse()?).await?;
    tcp.write_all(b"GET / HTTP/1.0\r\n\r\n").await?;
    let mut body = Vec::new();
    tcp.read_to_end(&mut body).await?;

    // Unconnected UDP socket.
    let mut udp = stack.bind_udp("0.0.0.0:0".parse()?).await?;
    udp.send_to(b"ping", "10.0.0.2:53".parse()?).await?;
    let (reply, from) = udp.recv_from().await?;

    // Connected UDP socket.
    let connected = stack.connect_udp("10.0.0.2:53".parse()?).await?;
    connected.send(b"ping").await?;
    Ok(())
}
```

Also: `connect_tcp_from` / `connect_udp_from` choose the local address; `TcpConnection::abort`
sends an RST and releases the socket at once, and `terminated()` waits for that release;
`UdpFlow::reply_handle()` gives cloneable `UdpReply` senders; `NetStackHandle::stats()`
returns drop counters; `NetStackConfig::reassembly` enables IP fragment reassembly.

### Revoking one flow

On a stack shared by many flows, `FlowControl` ends one flow at once and reports whether its
resources were released. It is independent of the data handles, so it still works after the
connection was moved into another task.

```rust
use nsplane_netstack::RetirementOutcome;

let conn = stack.connect_tcp("10.0.0.2:80".parse()?).await?;
let control = conn.control(); // Clone; also on UdpFlow, UdpReply and UdpSocket
let context = control.bind_context(42)?; // optional, once per flow; 42 is your domain
tokio::spawn(async move { use_connection(conn).await });

// later, e.g. when the caller's permit for this flow is withdrawn:
let receipt = control.revoke(); // idempotent, never waits, sends no FIN or RST
match receipt.wait().await {
    RetirementOutcome::Retired => {} // state removed, queued output dropped
    RetirementOutcome::Failed => {}  // state removed, a bound was full: output may still leave
    RetirementOutcome::Unknown => {} // the stack stopped first
    _ => {}                          // non_exhaustive
}
```

- After `revoke` every handle of the flow fails with `ConnectionAborted`
  (`UdpFlow::recv` returns `None`), and the next driver turn removes the flow's socket,
  queues and pending output. Other flows and the stack keep running.
- `wait` is cancellation-safe and can be called again; `outcome()` polls without waiting.
- The proof boundary is the stack: packets it already handed to the engine are not covered.
- `FlowContext` (`domain()`, `instance()`) is an opaque label with a process-wide instance
  number that is never handed out twice; nsplane never interprets it. A new connection on
  the same 5-tuple is a new flow with a new instance.
- `NetStackHandle::retired_drops()` counts packets dropped for revoked flows.

## 9. TUN and netstack behind one engine

`Splitter` routes each decrypted packet to one of several sinks by a closure;
`MergeSource` merges several sources into one. Here, packets for 10.0.0.0/16 go to the TUN
device and everything else to the netstack:

```rust
use std::sync::Arc;

use nsplane::{EngineBuilder, MergeSource, PacketBuf, PacketSink, PeerId, Splitter};
use nsplane_netstack::{NetStack, NetStackConfig};
use nsplane_packet::IpPacket;

const TUN: usize = 0;
const STACK: usize = 1;

let (tun_source, tun_sink) = nsplane_tun::Tun::create("wg0")?.split()?;
let (stack, stack_handle) =
    NetStack::new(NetStackConfig::new(vec![("10.1.0.1".parse()?, 24)], 1420));
let (stack_source, stack_sink) = stack.split();

let splitter = Splitter::new(|_peer, packet: &PacketBuf| match IpPacket::parse(packet.as_packet()) {
    Ok(ip) if matches!(ip.dst(), std::net::IpAddr::V4(a) if a.octets()[..2] == [10, 0]) => TUN,
    Ok(_) => STACK,
    Err(_) => 2, // no such sink: counted as misrouted and dropped
})
.sink(tun_sink)
.sink(stack_sink);
let merge = MergeSource::new().source(tun_source).source(stack_source);
let engine = EngineBuilder::new(merge, splitter).private_key(key).transport(udp).build()?;
```

To read `Splitter::misrouted()` or `stats()` later, keep it in an `Arc` and pass a small
`PacketSink` wrapper that forwards to it (see the `hybrid` example).
`MapSink` / `MapSource` rewrite or drop packets on one side without a full filter.

## 10. Access control: nsplane-acl

The ACL is accept-only: a packet passes only if a rule allows it. Rules match the sending
peer's **labels** (opaque strings you assign), source and destination prefixes, and
protocol/ports. Policies are installed atomically and can be reloaded at any time; until the
first install everything is dropped (fail closed).

```rust
use std::sync::Arc;

use nsplane::{EngineBuilder, PeerId};
use nsplane_acl::{
    AclEngine, AclFilter, AclFilterConfig, FlowTracker, Label, LabelSet, PeerLabelMap, PortSet,
    ProtocolMatch, Rule, RuleSet,
};

fn rules() -> anyhow::Result<RuleSet> {
    let mut rule = Rule::new("ssh-from-ops", vec![ProtocolMatch::Tcp(PortSet::Ranges(vec![22..=22]))]);
    rule.labels = vec![Label::new("ops")];
    rule.destinations = vec!["10.0.0.1/32".parse()?];
    Ok(RuleSet::new([rule])?)
}

let acl = Arc::new(AclEngine::new());
let labels = Arc::new(PeerLabelMap::new());
let config = AclFilterConfig { stateful_replies: true, ..AclFilterConfig::default() };
let filter = AclFilter::with_config(Arc::clone(&acl), Arc::clone(&labels), config);
let tracker = FlowTracker::new(4096); // optional: per-flow counters of accepted traffic

let engine = EngineBuilder::new(source, sink)
    .private_key(key)
    .transport(udp)
    .filter(Box::new(filter.clone()))
    .filter(Box::new(tracker.clone()))
    .build()?;
let handle = engine.handle();
handle.add_or_update_peer(nsplane::Peer::new(ops_key)).await?;
let id: PeerId = handle.peer_id(ops_key).await?.expect("just added");
labels.insert(id, LabelSet::new([Label::new("ops")]));
acl.install(rules()?); // call again to reload
```

- `Rule` and `RuleSet` deserialize from JSON (serde), e.g.
  [examples/policies/acl_gateway.json](../examples/policies/acl_gateway.json).
- `stateful_replies` lets replies to connections this side opened through.
- `AclFilter::stats()` and `FlowTracker` expose counters; `AclEngine::evaluate` tests a flow
  without a packet.
- Beyond static rules: per-source **namespaces** (`store_namespace`), directed **grants**
  between namespaces (`store_grant`), outbound rules, and short-lived **pinholes**
  (`open_pinhole`, closed when the `PinholeGuard` drops) for app sessions — see the
  `app_session` example and [specs/acl-generic-api.md](specs/acl-generic-api.md).
- `gate::GateFilter` is a stateful flow gate keyed by peer (admission, holds, timeouts,
  diverting packets to the application); see [the nsplane-acl reference](reference/nsplane-acl.md).

## 11. Address translation and NAT: nsplane-nat

All NAT types are packet filters (`EngineBuilder::filter`) or wrap the local side.

### IPv4 applications over IPv6 peers: `Translator`

`Translator` (RFC 7915) lets local IPv4 traffic reach peers addressed by IPv6, using explicit
address mappings (EAM) per peer and LAN prefixes behind peers. The table is built once the
peers have ids, and can be swapped live with `Translator::store`:

```rust
use nsplane_nat::{LanPrefix, PeerMapping, SelfMapping, TranslationTable, Translator};

fn table(gw: PeerId, other: PeerId) -> anyhow::Result<TranslationTable> {
    Ok(TranslationTable::builder()
        .self_mapping(SelfMapping { eam4: "192.168.100.1".parse()?, eam6: "fd00::1".parse()? })
        .peer(gw, PeerMapping {
            peer6: "fd00::2".parse()?,
            eam6: "fd00::2".parse()?,
            local6: None,
            eam4: Some("192.168.100.2".parse()?),
        })
        // default route behind `gw`, a more specific LAN behind `other`
        .lan(LanPrefix { lan4: ("0.0.0.0".parse()?, 0), lan6: ("fd64:1::".parse()?, 96), peer: Some(gw) })
        .lan(LanPrefix { lan4: ("10.1.0.0".parse()?, 16), lan6: ("fd64:2::".parse()?, 96), peer: Some(other) })
        .nested_lans() // 0.15.0: allow nested prefixes, longest prefix wins
        .build()?)
}
```

Without `nested_lans()` LAN prefixes must be disjoint (the strict default). With it, an
address belongs to the longest prefix that contains it, and the exact addresses (self
`eam4`, every `eam4` and `peer6_eam4`) win over every prefix.

To keep a handle for `store` while the engine owns the filter, share it through an `Arc` and a
forwarding filter (`Verdict` is from `nsplane-core`):

```rust
use nsplane_core::{PacketFilter, Verdict};

struct Shared(Arc<Translator>);

impl PacketFilter for Shared {
    fn inbound(&self, peer: PeerId, packet: &mut PacketBuf) -> Verdict {
        self.0.inbound(peer, packet)
    }
    fn outbound(&self, peer: PeerId, packet: &mut PacketBuf) -> Verdict {
        self.0.outbound(peer, packet)
    }
}

let translator = Arc::new(Translator::new(TranslationTable::default()));
let builder = builder.filter(Box::new(Shared(Arc::clone(&translator))));
// ... build, add peers, then:
translator.store(table(gw, other)?);
```

### Publishing local services: `PortMap`

DNAT/SNAT from a tunnel-facing address to a local service, optionally limited to some peers:

```rust
use nsplane_nat::{Conntrack, ConntrackConfig, PortMap, PortMapProtocol, PortMapRule};

let map = PortMap::with_conntrack(Vec::new(), Conntrack::new(ConntrackConfig::default()))?;
map.set_rules(vec![PortMapRule {
    protocol: PortMapProtocol::Tcp,
    listen: "10.0.0.1:8080".parse()?, // what peers connect to
    target: "127.0.0.1:80".parse()?,  // the local service
    peers: Some(vec![web_peer]),       // None: every peer
}])?;
```

### IPv6 peers into an IPv4 LAN: `Nat64Lan`

A gateway wraps its local side so that IPv6 peers reach an IPv4 LAN through stateful NAT64:

```rust
use nsplane_nat::{LanRoute, LanRoutes, Nat64Lan, Nat64LanConfig, Nat64LanSink, Nat64LanSource};

let route = LanRoute::new(
    ("fd64:a::".parse()?, 96),      // the IPv6 prefix peers address
    ("192.168.1.0".parse()?, 24),   // the real LAN
    "192.168.1.250".parse()?,       // SNAT source on the LAN (route it into the TUN)
)?;
let nat = Arc::new(Nat64Lan::new(LanRoutes::new(vec![route]), Nat64LanConfig::default()));
let engine = EngineBuilder::new(
    Nat64LanSource::new(tun_source, Arc::clone(&nat)),
    Nat64LanSink::new(tun_sink, Arc::clone(&nat)),
)
.private_key(key)
.transport(udp)
.build()?;
```

`Nat64LanConfig::nested_routes` lets routes nest their IPv4 prefixes (longest wins).
Two more local-side types: `Redirect` sends IPv4 TCP/UDP flows that a local application
opens to a service address on to an endpoint the caller picks per flow (DNAT with the
reverse SNAT of the replies), and `Masquerade` is stateful IPv6 source NAPT for routed LAN
ingress. See rustdoc.

## 12. Transports: UDP, links and WebSocket over TLS

- `UdpTransport::bind(id, addr)`: the default. `with_side_channel(classify, capacity)` splits
  non-WireGuard datagrams (e.g. your own discovery protocol on the same port) into a
  `SideSender` / receiver; `set_path_mtu_discovery` turns on PMTU reports.
- `LinkTransport::new(id, peer_addr, dialer, LinkConfig)`: datagrams over a message link that
  your `LinkDialer` opens (and re-opens); the link is one path, `peer_addr` the address
  peers' `Path` uses for it.
- Your own: implement `Transport` (with its batch methods) for anything else.
- Several transports at once, each with its own `TransportId`; `EngineHandle::add_transport`,
  `remove_transport` and `replace_transport` change them while the engine runs.

### WebSocket over TLS: nsplane-wss

Client side: `WssDialer` is a `LinkDialer`, so a WSS connection becomes a transport. TLS
trust is the caller's (no built-in roots):

```rust
use nsplane::{LinkConfig, TransportId};
use nsplane_wss::{WssConfig, WssDialer, WssTls};

const WSS: TransportId = TransportId::new(1);
let config = WssConfig::new("wss://relay.example.net/wg", WssTls::Roots(roots));
let dialer = WssDialer::new(config)?;
let state = dialer.state(); // take state/stats/events before into_transport
let transport = dialer.into_transport(WSS, "192.0.2.10:443".parse()?, LinkConfig::default());
// builder.transport(transport); peers reached over it use Path { transport: WSS, addr: 192.0.2.10:443, .. }
```

`WssConfig` also carries extra headers, a `BearerProvider` (an `Authorization: Bearer` token
per dial), keepalive, backoff and `allow_plaintext` for `ws://` in tests.

Server side: the embedder runs its own HTTP server, authenticates, upgrades, and hands each
WebSocket to the `WssAcceptor` of a `WssServerTransport`:

```rust
use nsplane_wss::{WssAcceptor, WssServerConfig, WssServerTransport};

let (transport, acceptor) = WssServerTransport::new(TransportId::new(1), WssServerConfig::default());
// builder.transport(transport)

async fn on_upgrade<S>(acceptor: &WssAcceptor, stream: S) -> anyhow::Result<()>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Send + Unpin + 'static,
{
    let ws = tokio_tungstenite::accept_async_with_config(stream, Some(WssAcceptor::ws_config())).await?;
    let session = acceptor.accept(ws)?; // the session's address is session.addr()
    Ok(())
}
```

`WssStreamClient` / `WssStreamServer` (multiplexed TCP/UDP streams) are deprecated; use a
WireGuard peer over `WssDialer` instead.

## 13. Several local identities

One engine can answer as several WireGuard identities (private keys) on the same transports:

```rust
let id = handle.add_local_identity(second_key).await?.expect("a new key");
let mut peer = nsplane::Peer::new(peer_key);
peer.local_identity = Some(id); // this peer talks to `second_key`
handle.add_or_update_peer(peer).await?;
```

`add_local_identity_on` limits an identity to some transports, `set_local_sources` routes
outbound packets by source address to an identity's peers (per-identity routing), and
`peer_id_in` / `remove_peer_in` address a peer within one identity.

## 14. Operating an engine

### Events and statistics

```rust
use nsplane::Event;

let mut events = handle.subscribe().await?;
tokio::spawn(async move {
    while let Ok(event) = events.recv().await {
        match event {
            Event::HandshakeCompleted { peer, .. } => println!("up {}", peer.get()),
            Event::SessionExpired { peer, .. } => println!("down {}", peer.get()),
            _ => {}
        }
    }
});

for p in handle.peers().await? {
    println!("{:?} rx={} tx={} last_handshake={:?}", p.path, p.rx, p.tx, p.last_handshake);
}
let drops = handle.drop_counters().await?; // reason -> count
let queues = handle.queue_stats().await?;  // high-water marks
let status = handle.status().await?;
```

A lagging receiver gets `RecvError::Lagged` and continues. Other counters:
`transport_stats`, `fragment_stats`, `path_mtu_stats`, `peer_mtus`, `unanswered_handshakes`.

### Runtime changes

Everything is on `EngineHandle` and takes effect without a restart: `set_private_key`,
`add_or_update_peer` / `remove_peer`, `set_allowed_ips`, `set_preshared_key`,
`set_keepalive`, `set_path`, `force_handshake`, transports (above), `inject_inbound` /
`inject_outbound` (hand a packet to the local sink as if a peer sent it, or to a peer as if
the local side did; injected packets bypass the filters),
`suspend` / `resume` (mobile background: stop timers and I/O, keep state), `shutdown`.

### Tuning

| Knob | Default | When to change |
|---|---|---|
| `EngineBuilder::crypto_workers(n)` | 0 (crypto on the engine task) | hubs with several busy peers on a multi-threaded runtime; `n` >= 2 |
| `EngineBuilder::queue_capacity(n)` | 1024 packets | a queue's high-water mark at capacity with `DROP_SINK_FULL` / `DROP_TRANSMIT_FULL` |
| `EngineBuilder::fragmenter(FragmentConfig::default())` | off | paths whose MTU is below the inner packets and peers that need IP fragments |
| TUN / UDP offload | on where supported | turn off only to debug |
| `EngineBuilder::stats_interval` | off | periodic `Event::PeerStats` |

Reference numbers (x86-64, 0.11.0, real TUN, iperf3): about 11 Gbit/s for one TCP stream
between two nsplane nodes, 14.5 Gbit/s with two crypto workers, 8.6 Gbit/s between two
netstack nodes. See [performance.md](performance.md).

## 15. Platforms and building

| Platform | Local side | Notes |
|---|---|---|
| Linux | `Tun` (TSO/USO), `Tun::from_fd`, netstack | `CAP_NET_ADMIN` for TUN |
| Android | `TunSlot` over the `VpnService` fd | protect the UDP socket |
| macOS | `Tun` (`utun`) | |
| iOS | `host_tun` over `NEPacketTunnelFlow` | |
| Windows | `Tun` via Wintun | `wintun.dll` next to the executable, run elevated; UAPI on a named pipe |
| any | netstack, channels | no privileges |

```bash
cargo build -p nsplane -p nsplane-tun -p nsplane-uapi --release
cargo build -p nsplane-cli --release      # development daemon, Linux and macOS
```

The development daemon runs an engine on a TUN device and is configured with `wg`:

```bash
sudo setcap cap_net_admin+epi target/release/nsplane-cli
target/release/nsplane-cli -v info wg0
wg setconf wg0 /path/to/wg0.conf
```

See the [README](../README.md#development-cli-linux-and-macos) for its flags.

## 16. Examples index

All in `examples/` (`cargo run -p nsplane-examples --bin <name> -- --help`):

| Example | Shows | Root |
|---|---|---|
| `udp_pair` | two engines on netstacks over loopback UDP | no |
| `tun_node` | a TUN node managed with `wg` | yes |
| `netstack_node` | a node whose local side is the netstack | no |
| `netstack_bench` | load generator on a netstack node | no |
| `hybrid` | TUN and netstack behind one engine | yes |
| `acl_gateway` | a node filtered by a reloadable ACL policy | yes |
| `translate_node` | local IPv4 to IPv6-only peers | yes |
| `port_map` | services published by DNAT/SNAT | yes |
| `subnet_gateway` | IPv6 peers into an IPv4 LAN (NAT64) | yes |
| `fd_bridge` | engine on a TUN handed over by fd or channels | yes |
| `events_stats` | events, stats, drops, suspend/resume, MTU | no |
| `relay_server` | a single-port relay that is also a WireGuard node | no |
| `relay_transport` | relay discovery and the direct/relay path ladder | no |
| `app_session` | app sessions on ACL namespaces and pinholes | no |

The relay in `relay_server` / `relay_transport` is example code, not a published API.
