//! App sessions on rule namespaces: a file transfer through source-gated pinholes, between
//! existing peers and between session-only peers.
//!
//! Every node is an engine on loopback UDP with an `nsplane-netstack`, an [`AclFilter`], a
//! [`PeerIdentityMap`] (each peer's principal is its WireGuard key, `key:<hex>`) and its
//! own [`AclEngine`]. A minimal in-process mailbox (tokio channels) stands in for the
//! rendezvous: it carries the session offer, the receiver's app port and, for
//! session-only peers, fresh keys. Each step prints `STEP <name> PASS|FAIL`; the run ends
//! with `CHECKS PASS` (exit 0) or `CHECKS FAIL` (exit 1).
//!
//! - `a` reuse: A and B are already peers in their `quick` namespace (TCP echo on port 7
//!   allowed, app kind `transfer` allowed; B restricts its outbound traffic to A to port
//!   7). A session adds `app:<id>` with the peer as member on both sides, the receiver A
//!   opens an inbound pinhole on its app port and the sender B an outbound one; a
//!   generated file (1 MiB and a bit) crosses an in-tunnel TCP connection and its SHA-256
//!   is verified. No peer is added and no handshake runs, the echo still works, and once
//!   the session ends only `app:<id>` is gone: a new connection to the app port is
//!   dropped (`acl denied`, printed as a `DROP` line).
//! - `b` not-permitted: A's `quick` no longer allows `transfer`, so A's pinhole is refused
//!   ([`PinholeError::NotPermitted`]) and the sender cannot reach the app port.
//! - `c` revoke: `transfer` is removed from A's `quick` while a transfer runs; the pinhole
//!   closes (revoked) and the transfer stops.
//! - `d` session-only peer: two fresh nodes that are not peers exchange keys through the
//!   mailbox and add each other as a session-only peer (allowed IPs: only the other
//!   node's IPv6 /128, a session preshared key) in `app:<id>` with `outbound: Some([])`
//!   and a pinhole on the app port. The file crosses; every other port is unreachable in
//!   both directions (`acl outbound denied`); ending the session removes the pinholes,
//!   the namespace and the peer, and nothing passes afterwards.
//! - `e` cross-namespace: a hub node forwards between a peer C (namespace `nsd:c`) and a
//!   session-only peer S (`app:<id>`). Neither reaches the other (`acl cross namespace`)
//!   until a directed [`Grant`] from S to `nsd:c` (TCP 7) lets S reach C's echo, in that
//!   direction only; removing the grant stops new flows. The hub forwards through a
//!   [`Splitter`] and a [`MergeSource`], so forwarded packets cross its filter twice.
//! - `--tun <NAME>` (Linux, needs `CAP_NET_ADMIN`) adds `STEP tun-outbound`: node A runs
//!   the hybrid layout (a TUN device for `10.99.0.1/24` or `fd99::1/64` next to its
//!   netstack, like `hybrid`), a session-only peer T is added and its address is routed
//!   to the TUN. Host traffic to T (TCP to any port, ping) is dropped by the outbound rule
//!   (`acl outbound denied`, counted in the status) while T's transfer to A's netstack app
//!   port works.
//!
//! `--status <PATH>` writes node A's status file (see `status.rs`) at the end, with
//! `extra.acl` (the [`AclFilter::stats`] counters and the namespaces) and
//! `extra.pinhole_stats` ([`AclEngine::pinhole_stats`]).
//!
//! APIs shown: [`AclEngine::store_namespace`] and [`AclEngine::remove_namespace`] with
//! [`NamespacePolicy`] (members, rules, `outbound`, `allow_app_pinholes`),
//! [`AclEngine::open_pinhole`] with [`PinholeSpec`] and [`PinholeGuard`],
//! [`AclEngine::store_grant`] and [`AclEngine::remove_grant`], [`AclFilter`] as an engine
//! filter, [`PeerIdentityMap`], `EngineHandle::add_or_update_peer` / `remove_peer` with a
//! preshared key, [`Splitter`], [`MergeSource`], [`ChannelSource`] and [`ChannelSink`].
//!
//! Usage: `cargo run -p nsplane-examples --bin app_session -- [--step a|b|c|d|e|all]
//! [--ipv6] [--tun nsp-app] [--status app_session.json]`
//!
//! [`AclEngine`]: nsplane_acl::AclEngine
//! [`AclEngine::open_pinhole`]: nsplane_acl::AclEngine::open_pinhole
//! [`AclEngine::pinhole_stats`]: nsplane_acl::AclEngine::pinhole_stats
//! [`AclEngine::remove_grant`]: nsplane_acl::AclEngine::remove_grant
//! [`AclEngine::remove_namespace`]: nsplane_acl::AclEngine::remove_namespace
//! [`AclEngine::store_grant`]: nsplane_acl::AclEngine::store_grant
//! [`AclEngine::store_namespace`]: nsplane_acl::AclEngine::store_namespace
//! [`AclFilter`]: nsplane_acl::AclFilter
//! [`AclFilter::stats`]: nsplane_acl::AclFilter::stats
//! [`Grant`]: nsplane_acl::Grant
//! [`NamespacePolicy`]: nsplane_acl::NamespacePolicy
//! [`PeerIdentityMap`]: nsplane_acl::PeerIdentityMap
//! [`PinholeError::NotPermitted`]: nsplane_acl::PinholeError::NotPermitted
//! [`PinholeGuard`]: nsplane_acl::PinholeGuard
//! [`PinholeSpec`]: nsplane_acl::PinholeSpec
//! [`Splitter`]: nsplane::Splitter
//! [`MergeSource`]: nsplane::MergeSource
//! [`ChannelSource`]: nsplane::ChannelSource
//! [`ChannelSink`]: nsplane::ChannelSink

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::fmt::Write as _;
use std::future::poll_fn;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::path::PathBuf;
use std::pin::Pin;
use std::process::ExitCode;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Duration, Instant};

use anyhow::{Context as _, anyhow, bail, ensure};
use clap::{Parser, ValueEnum};
use futures_core::Stream;
use nsplane::x25519::{PublicKey, StaticSecret};
use nsplane::{
    AllowedIp, ChannelSink, ChannelSource, Ecn, Engine, EngineBuilder, Event, MergeSource,
    PacketSink, PacketSource, Path, Peer, Splitter, UdpTransport,
};
use nsplane_acl::{
    AclAction, AclEngine, AclFilter, AclPolicy, AclRule, Direction, Grant, GrantEnd, IpNet,
    NamespaceMember, NamespacePolicy, OutboundRule, PeerIdentityMap, PinholeError, PinholeGuard,
    PinholeSpec, Protocol, SourceAssertion, reasons, wg_peer_anchor,
};
use nsplane_examples::echo::{self, Backend, Check, Proto};
use nsplane_examples::node::{UDP_TRANSPORT, generate_key, init_logging};
use nsplane_examples::out;
use nsplane_examples::status::{Status, netstack_json};
use nsplane_netstack::{DEFAULT_MTU, NetStack, NetStackConfig, NetStackHandle, TcpConnection};
use nsplane_packet::IpPacket;
use rand_core::{OsRng, RngCore as _};
use serde_json::json;
use sha2::{Digest as _, Sha256};
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio::sync::broadcast::error::RecvError;
use tokio::sync::mpsc;
use tokio::task::JoinHandle;
use tokio::time::{sleep, timeout};

/// App sessions on rule namespaces: pinholes for a file transfer, session-only peers,
/// cross-namespace grants.
#[derive(Debug, Parser)]
#[command(name = "app_session", version)]
struct Args {
    /// The step to run (a reuse, b not-permitted, c revoke, d session-only peer, e
    /// cross-namespace) or all of them
    #[arg(long, value_enum, default_value_t = StepArg::All)]
    step: StepArg,

    /// Address the existing peers (steps a, b, c, e and the TUN step) over IPv6 instead of
    /// IPv4; step d always uses IPv6 /128s
    #[arg(long)]
    ipv6: bool,

    /// Run node A with a TUN device of this name next to its netstack and add `STEP
    /// tun-outbound` (Linux, needs `CAP_NET_ADMIN`)
    #[arg(long, value_name = "NAME")]
    tun: Option<String>,

    /// Write node A's JSON status to this file at the end
    #[arg(long, value_name = "PATH")]
    status: Option<PathBuf>,

    /// Log filter for stderr
    #[arg(long, value_name = "FILTER", default_value = "warn")]
    log: String,
}

/// `--step`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
enum StepArg {
    A,
    B,
    C,
    D,
    E,
    All,
}

impl StepArg {
    fn runs(self, step: Self) -> bool {
        self == Self::All || self == step
    }
}

/// TCP echo port of every node; the `quick` namespaces allow it.
const ECHO_PORT: u16 = 7;
/// The app port a receiver listens on for the transfer.
const APP_PORT: u16 = 9000;
/// The app kind of the transfer pinholes.
const APP_KIND: &str = "transfer";
/// The source namespace A and B share.
const QUICK: &str = "quick";
/// The namespace of C on the hub.
const NSD_C: &str = "nsd:c";
/// Size of the transferred file.
const FILE_LEN: usize = (1 << 20) + 4321;
/// Size of the file of the revoked transfer, sent slowly.
const SLOW_FILE_LEN: usize = 4 << 20;
/// Bytes per write of a transfer.
const CHUNK: usize = 16 << 10;
/// Pause between the writes of the slow transfer.
const SLOW_PACE: Duration = Duration::from_millis(10);
/// How long a connection attempt that should be dropped gets.
const PROBE_TIMEOUT: Duration = Duration::from_millis(1500);
/// How long an echo check retries.
const CHECK_TIMEOUT: Duration = Duration::from_secs(10);
/// How long a transfer may take.
const TRANSFER_TIMEOUT: Duration = Duration::from_secs(30);
/// The safety-net lifetime of a pinhole.
const PINHOLE_LIFETIME: Duration = Duration::from_secs(300);
/// Queue sizes of the hub's forwarding channel.
const FORWARD_QUEUE: usize = 1024;

// ── Mailbox ──────────────────────────────────────────────────────────────────

/// What two nodes need to become session-only peers.
#[derive(Debug, Clone, Copy)]
struct Contact {
    public_key: PublicKey,
    endpoint: SocketAddr,
    address: IpAddr,
}

/// A mailbox message; the real protocol (`/quick/v2`) carries the same information.
#[derive(Debug)]
enum Message {
    /// Fresh keys and the address of a session-only peer.
    Hello {
        contact: Contact,
        preshared_key: Option<[u8; 32]>,
    },
    /// The sender offers a file.
    Offer {
        session: String,
        len: usize,
        digest: [u8; 32],
    },
    /// The receiver takes it on `port`.
    Accept { port: u16 },
    /// The receiver cannot take it.
    Reject { reason: String },
}

/// One end of the in-process mailbox standing in for the rendezvous.
#[derive(Debug)]
struct Mailbox {
    tx: mpsc::UnboundedSender<Message>,
    rx: mpsc::UnboundedReceiver<Message>,
}

/// Two connected mailbox ends.
fn mailbox() -> (Mailbox, Mailbox) {
    let (a_tx, b_rx) = mpsc::unbounded_channel();
    let (b_tx, a_rx) = mpsc::unbounded_channel();
    (
        Mailbox { tx: a_tx, rx: a_rx },
        Mailbox { tx: b_tx, rx: b_rx },
    )
}

impl Mailbox {
    fn send(&self, message: Message) -> anyhow::Result<()> {
        self.tx
            .send(message)
            .map_err(|_| anyhow!("the mailbox is closed"))
    }

    async fn recv(&mut self) -> anyhow::Result<Message> {
        self.rx
            .recv()
            .await
            .ok_or_else(|| anyhow!("the mailbox is closed"))
    }

    async fn hello(&mut self) -> anyhow::Result<(Contact, Option<[u8; 32]>)> {
        match self.recv().await? {
            Message::Hello {
                contact,
                preshared_key,
            } => Ok((contact, preshared_key)),
            other => bail!("expected a hello, got {other:?}"),
        }
    }

    async fn offer(&mut self) -> anyhow::Result<(String, usize, [u8; 32])> {
        match self.recv().await? {
            Message::Offer {
                session,
                len,
                digest,
            } => Ok((session, len, digest)),
            other => bail!("expected an offer, got {other:?}"),
        }
    }
}

// ── Nodes ────────────────────────────────────────────────────────────────────

/// How a node's engine meets its local side.
#[derive(Debug)]
enum Layout {
    /// A netstack only.
    Stack,
    /// A netstack for its own addresses; every other delivered packet is sent out again
    /// (a hub forwarding between its peers).
    Hub,
    /// A TUN device for `address`'s prefix next to the netstack (the hybrid layout).
    Tun { name: String, address: AllowedIp },
}

/// One engine with its netstack and ACL.
struct Node {
    name: &'static str,
    engine: Engine,
    stack: NetStackHandle,
    public_key: PublicKey,
    udp: SocketAddr,
    v4: IpAddr,
    v6: IpAddr,
    acl: Arc<AclEngine>,
    identities: Arc<PeerIdentityMap>,
    filter: AclFilter,
    apps: Apps,
    handshakes: Arc<AtomicU64>,
    tun: Option<(String, AllowedIp)>,
}

/// The netstack's TCP connections to app ports, by port; the echo port is served
/// directly, connections to any other port are closed.
#[derive(Debug, Clone, Default)]
struct Apps(Arc<Mutex<HashMap<u16, mpsc::Sender<TcpConnection>>>>);

impl Apps {
    fn listen(&self, port: u16) -> mpsc::Receiver<TcpConnection> {
        let (tx, rx) = mpsc::channel(4);
        self.0
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .insert(port, tx);
        rx
    }

    fn close(&self, port: u16) {
        self.0
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .remove(&port);
    }

    fn get(&self, port: u16) -> Option<mpsc::Sender<TcpConnection>> {
        self.0
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .get(&port)
            .cloned()
    }
}

/// The next item of `stream`.
async fn next<S: Stream + Unpin>(stream: &mut S) -> Option<S::Item> {
    poll_fn(|cx| Pin::new(&mut *stream).poll_next(cx)).await
}

/// Takes `stack`'s inbound TCP connections: echo on [`ECHO_PORT`], app ports to `apps`.
fn serve(stack: &NetStackHandle, apps: Apps) {
    let mut incoming = stack.incoming_tcp();
    tokio::spawn(async move {
        while let Some(conn) = next(&mut incoming).await {
            let port = conn.local_addr().port();
            if port == ECHO_PORT {
                tokio::spawn(async move {
                    let (mut reader, mut writer) = tokio::io::split(conn);
                    if tokio::io::copy(&mut reader, &mut writer).await.is_ok() {
                        let _ = writer.shutdown().await;
                    }
                });
            } else if let Some(app) = apps.get(port) {
                let _ = app.try_send(conn);
            }
        }
    });
}

/// The address of host `host` in tunnel network `net`: `10.0.<net>.<host>` or
/// `fd00:<net>::<host>`.
fn tunnel_addr(net: u8, host: u8, v6: bool) -> IpAddr {
    if v6 {
        IpAddr::V6(Ipv6Addr::new(
            0xfd00,
            net.into(),
            0,
            0,
            0,
            0,
            0,
            host.into(),
        ))
    } else {
        IpAddr::V4(Ipv4Addr::new(10, 0, net, host))
    }
}

/// A host route to `addr`.
const fn host_route(addr: IpAddr) -> AllowedIp {
    AllowedIp {
        addr,
        cidr: if addr.is_ipv4() { 32 } else { 128 },
    }
}

/// `addr` as a host network.
fn host_net(addr: IpAddr) -> anyhow::Result<IpNet> {
    let route = host_route(addr);
    format!("{}/{}", route.addr, route.cidr)
        .parse()
        .map_err(|e| anyhow!("invalid address {addr}: {e}"))
}

/// A namespace member: `public_key`'s principal with `addresses`.
fn member(public_key: &PublicKey, addresses: &[IpAddr]) -> anyhow::Result<NamespaceMember> {
    Ok(NamespaceMember {
        principal: wg_peer_anchor(public_key.as_bytes()),
        addresses: addresses
            .iter()
            .map(|addr| host_net(*addr))
            .collect::<anyhow::Result<_>>()?,
    })
}

/// Builds an engine on loopback UDP with `filter` on `source` and `sink`.
fn start_engine<Src: PacketSource, Snk: PacketSink>(
    key: StaticSecret,
    source: Src,
    sink: Snk,
    filter: AclFilter,
) -> anyhow::Result<(Engine, SocketAddr)> {
    let udp = UdpTransport::bind(
        UDP_TRANSPORT,
        SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0),
    )
    .context("cannot bind UDP on loopback")?;
    let addr = udp.local_addr();
    let engine = EngineBuilder::new(source, sink)
        .private_key(key)
        .transport(udp)
        .filter(Box::new(filter))
        .build()?;
    Ok((engine, addr))
}

/// The splitter sink of `packet`: 0 if `local` holds its destination, 1 for any other IP
/// packet, out of range (misrouted) for anything else.
fn route(local: impl Fn(IpAddr) -> bool, packet: &nsplane::PacketBuf) -> usize {
    match IpPacket::parse(packet.as_packet()) {
        Ok(ip) if local(ip.dst()) => 0,
        Ok(_) => 1,
        Err(_) => 2,
    }
}

impl Node {
    /// A node with addresses `10.0.<net>.<host>` and `fd00:<net>::<host>` on `layout`.
    async fn new(name: &'static str, net: u8, host: u8, layout: Layout) -> anyhow::Result<Self> {
        let key = generate_key();
        let public_key = PublicKey::from(&key);
        let (v4, v6) = (tunnel_addr(net, host, false), tunnel_addr(net, host, true));
        let (stack, stack_handle) =
            NetStack::new(NetStackConfig::new(vec![(v4, 24), (v6, 64)], DEFAULT_MTU));
        let (stack_source, stack_sink) = stack.split();
        let acl = Arc::new(AclEngine::new());
        let identities = Arc::new(PeerIdentityMap::new());
        let filter = AclFilter::new(Arc::clone(&acl), Arc::clone(&identities));
        let engine_filter = filter.clone();
        let mut tun = None;
        let (engine, udp) = match layout {
            Layout::Stack => start_engine(key, stack_source, stack_sink, engine_filter)?,
            Layout::Hub => {
                // Packets to other peers go back into the engine as if the local side sent
                // them, so the filter sees them inbound and again outbound.
                let (forward_sink, mut forwarded) = ChannelSink::new(FORWARD_QUEUE);
                let (forward_source, tx, mtu) = ChannelSource::new(FORWARD_QUEUE, DEFAULT_MTU);
                tokio::spawn(async move {
                    let _mtu = mtu;
                    while let Some((_, packet)) = forwarded.recv().await {
                        if tx.send(packet).await.is_err() {
                            break;
                        }
                    }
                });
                let splitter =
                    Splitter::new(move |_, packet| route(|dst| dst == v4 || dst == v6, packet))
                        .sink(stack_sink)
                        .sink(forward_sink);
                let merge = MergeSource::new()
                    .source(stack_source)
                    .source(forward_source);
                start_engine(key, merge, splitter, engine_filter)?
            }
            Layout::Tun { name, address } => {
                let (tun_source, tun_sink, name) = open_tun(&name, address)?;
                let splitter = Splitter::new(move |_, packet| {
                    route(
                        |dst| nsplane_examples::node::contains(&address, dst),
                        packet,
                    )
                })
                .sink(tun_sink)
                .sink(stack_sink);
                let merge = MergeSource::new().source(tun_source).source(stack_source);
                tun = Some((name, address));
                start_engine(key, merge, splitter, engine_filter)?
            }
        };
        let apps = Apps::default();
        serve(&stack_handle, apps.clone());
        let handshakes = Arc::new(AtomicU64::new(0));
        let mut events = engine.handle().subscribe().await?;
        let counter = Arc::clone(&handshakes);
        tokio::spawn(async move {
            loop {
                match events.recv().await {
                    Ok(Event::HandshakeCompleted { .. }) => {
                        counter.fetch_add(1, Ordering::Relaxed);
                    }
                    Ok(_) | Err(RecvError::Lagged(_)) => {}
                    Err(RecvError::Closed) => return,
                }
            }
        });
        out::line(format_args!(
            "NODE {name} udp={udp} tunnel={v4},{v6}{}",
            tun.as_ref().map_or_else(
                String::new,
                |(name, address): &(String, AllowedIp)| format!(
                    " tun={name}:{}/{}",
                    address.addr, address.cidr
                )
            )
        ));
        Ok(Self {
            name,
            engine,
            stack: stack_handle,
            public_key,
            udp,
            v4,
            v6,
            acl,
            identities,
            filter,
            apps,
            handshakes,
            tun,
        })
    }

    /// The node's tunnel address of the chosen family.
    const fn addr(&self, v6: bool) -> IpAddr {
        if v6 { self.v6 } else { self.v4 }
    }

    fn principal(&self) -> String {
        wg_peer_anchor(self.public_key.as_bytes())
    }

    /// This node as a namespace member with both its addresses.
    fn member(&self) -> anyhow::Result<NamespaceMember> {
        member(&self.public_key, &[self.v4, self.v6])
    }

    /// This node's contact for a session-only peer, with its address of one family.
    const fn contact(&self, v6: bool) -> Contact {
        Contact {
            public_key: self.public_key,
            endpoint: self.udp,
            address: self.addr(v6),
        }
    }

    /// Adds the peer of `contact` with `allowed` host routes and its identity (its key).
    async fn add_peer(
        &self,
        contact: &Contact,
        allowed: &[IpAddr],
        preshared_key: Option<[u8; 32]>,
    ) -> anyhow::Result<()> {
        let mut peer = Peer::new(contact.public_key);
        peer.allowed_ips = allowed.iter().copied().map(host_route).collect();
        peer.replace_allowed_ips = true;
        peer.preshared_key = preshared_key;
        peer.path = Some(Path {
            transport: UDP_TRANSPORT,
            addr: contact.endpoint,
            ecn: Ecn::NotEct,
        });
        let handle = self.engine.handle();
        handle.add_or_update_peer(peer).await?;
        let id = handle
            .peer_id(contact.public_key)
            .await?
            .context("the peer just added is gone")?;
        self.identities.insert(
            id,
            SourceAssertion::WgPeerKey {
                pubkey: contact.public_key.to_bytes(),
            },
        );
        Ok(())
    }

    /// Removes the peer of `contact` and its identity.
    async fn remove_peer(&self, contact: &Contact) -> anyhow::Result<()> {
        let handle = self.engine.handle();
        if let Some(id) = handle.peer_id(contact.public_key).await? {
            self.identities.remove(id);
        }
        handle.remove_peer(contact.public_key).await?;
        Ok(())
    }

    /// Lets every principal in no namespace in (a leaf whose hub does the enforcing).
    fn permit_all(&self) -> anyhow::Result<()> {
        self.acl.load(AclPolicy {
            acls: vec![accept("*:*")],
            ..AclPolicy::default()
        })?;
        Ok(())
    }

    async fn peer_count(&self) -> anyhow::Result<usize> {
        Ok(self.engine.handle().peers().await?.len())
    }

    fn namespaces(&self) -> Vec<String> {
        self.acl
            .namespaces()
            .iter()
            .map(|id| id.as_str().to_owned())
            .collect()
    }

    async fn drops(&self) -> anyhow::Result<BTreeMap<&'static str, u64>> {
        Ok(self.engine.handle().drop_counters().await?)
    }

    /// Prints the drop counters that grew since `before`; returns the growth of `reason`.
    async fn dropped_since(
        &self,
        before: &BTreeMap<&'static str, u64>,
        reason: &str,
    ) -> anyhow::Result<u64> {
        let mut grown = 0;
        for (name, count) in self.drops().await? {
            let delta = count - before.get(name).copied().unwrap_or(0);
            if delta > 0 {
                out::line(format_args!("DROP {} \"{name}\" +{delta}", self.name));
            }
            if name == reason {
                grown = delta;
            }
        }
        Ok(grown)
    }

    /// One TCP echo check from this node to `target`'s echo port.
    async fn check_echo(&self, target: IpAddr) -> anyhow::Result<()> {
        let check = Check {
            proto: Proto::Tcp,
            target: SocketAddr::new(target, ECHO_PORT),
        };
        let backend = Backend::NetStack(self.stack.clone());
        ensure!(
            echo::run_check(&backend, &check, CHECK_TIMEOUT).await,
            "{}: the echo of {target} fails",
            self.name
        );
        Ok(())
    }

    /// Whether a new TCP connection from this node's netstack reaches `target`.
    async fn reaches(&self, target: SocketAddr) -> bool {
        matches!(
            timeout(PROBE_TIMEOUT, self.stack.connect_tcp(target)).await,
            Ok(Ok(_))
        )
    }

    /// Fails if a new TCP connection to `target` gets through.
    async fn unreachable(&self, target: SocketAddr) -> anyhow::Result<()> {
        ensure!(
            !self.reaches(target).await,
            "{}: {target} is reachable",
            self.name
        );
        out::line(format_args!("BLOCKED {} -> {target}", self.name));
        Ok(())
    }

    async fn shutdown(self) -> anyhow::Result<()> {
        self.engine.handle().shutdown().await?;
        self.engine.wait().await?;
        Ok(())
    }
}

#[cfg(unix)]
fn open_tun(
    name: &str,
    address: AllowedIp,
) -> anyhow::Result<(nsplane_tun::TunSource, nsplane_tun::TunSink, String)> {
    let tun =
        nsplane_tun::Tun::create(name).with_context(|| format!("cannot create TUN {name}"))?;
    let name = tun.name().unwrap_or_else(|_| name.to_owned());
    nsplane_examples::node::configure_tun(&name, &[address], DEFAULT_MTU, &[])?;
    let (source, sink) = tun.split().context("cannot open the TUN device")?;
    Ok((source, sink, name))
}

#[cfg(not(unix))]
fn open_tun(
    _name: &str,
    _address: AllowedIp,
) -> anyhow::Result<(ChannelSource, ChannelSink, String)> {
    bail!("--tun runs on Linux only")
}

/// An accept rule for TCP to `dst` from anyone.
fn accept(dst: &str) -> AclRule {
    AclRule {
        action: AclAction::Accept,
        src: vec!["*".to_owned()],
        dst: vec![dst.to_owned()],
        proto: None,
    }
}

/// The `quick` namespace with `peer` as its member: TCP echo allowed, the transfer app
/// allowed iff `transfer`, outbound to the peer restricted to `outbound` if set.
fn quick(
    peer: NamespaceMember,
    transfer: bool,
    outbound: Option<Vec<OutboundRule>>,
) -> NamespacePolicy {
    let mut echo = accept(&format!("*:{ECHO_PORT}"));
    echo.proto = Some("tcp".to_owned());
    NamespacePolicy {
        members: vec![peer],
        policy: AclPolicy {
            acls: vec![echo],
            ..AclPolicy::default()
        },
        outbound,
        allow_app_pinholes: if transfer {
            BTreeSet::from([APP_KIND.to_owned()])
        } else {
            BTreeSet::new()
        },
    }
}

/// B's outbound rules towards A: TCP echo only.
fn echo_only() -> Vec<OutboundRule> {
    vec![OutboundRule {
        proto: Some("tcp".to_owned()),
        ports: ECHO_PORT.to_string(),
    }]
}

/// A and B as peers in their `quick` namespaces.
async fn pair(a: &Node, b: &Node) -> anyhow::Result<()> {
    let both = |node: &Node| [node.v4, node.v6];
    a.add_peer(&b.contact(false), &both(b), None).await?;
    b.add_peer(&a.contact(false), &both(a), None).await?;
    store_quick(a, b, true)?;
    b.acl
        .store_namespace(QUICK, quick(a.member()?, true, Some(echo_only())))?;
    Ok(())
}

/// Stores A's `quick` namespace (B as member, outbound unrestricted).
fn store_quick(a: &Node, b: &Node, transfer: bool) -> anyhow::Result<()> {
    a.acl
        .store_namespace(QUICK, quick(b.member()?, transfer, None))?;
    Ok(())
}

// ── Sessions and transfers ───────────────────────────────────────────────────

/// One side of an app session: its app namespace and pinholes. Dropping it ends the
/// session: the guards close the pinholes, then the namespace is removed.
struct Session {
    acl: Arc<AclEngine>,
    id: String,
    guards: Vec<PinholeGuard>,
}

impl Session {
    /// Stores `app:<session>` on `node` with `peer` as its only member. The members of an
    /// app namespace get nothing through it, and `outbound: Some([])` keeps it from
    /// lifting an outbound restriction of the peer's other namespaces.
    fn open(node: &Node, session: &str, peer: NamespaceMember) -> anyhow::Result<Self> {
        let id = format!("app:{session}");
        node.acl.store_namespace(
            id.as_str(),
            NamespacePolicy {
                members: vec![peer],
                outbound: Some(Vec::new()),
                ..NamespacePolicy::default()
            },
        )?;
        out::line(format_args!("SESSION {} {id}", node.name));
        Ok(Self {
            acl: Arc::clone(&node.acl),
            id,
            guards: Vec::new(),
        })
    }

    /// Opens a TCP pinhole to or from `peer` on `port`.
    fn pinhole(&mut self, peer: &str, direction: Direction, port: u16) -> Result<(), PinholeError> {
        let guard = self.acl.open_pinhole(
            self.id.as_str(),
            PinholeSpec {
                peer: peer.to_owned(),
                kind: APP_KIND.to_owned(),
                protocol: Protocol::Tcp,
                direction,
                dst_port: port,
                expires_at: Instant::now() + PINHOLE_LIFETIME,
            },
        )?;
        self.guards.push(guard);
        Ok(())
    }

    fn is_open(&self) -> bool {
        !self.guards.is_empty() && self.guards.iter().all(PinholeGuard::is_open)
    }
}

impl Drop for Session {
    fn drop(&mut self) {
        self.guards.clear();
        self.acl.remove_namespace(&self.id);
    }
}

/// A fresh session id.
fn session_id() -> String {
    format!("{:016x}", OsRng.next_u64())
}

/// `len` random bytes.
fn file(len: usize) -> Arc<Vec<u8>> {
    let mut data = vec![0; len];
    OsRng.fill_bytes(&mut data);
    Arc::new(data)
}

fn sha256(data: &[u8]) -> [u8; 32] {
    Sha256::digest(data).into()
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().fold(String::new(), |mut hex, b| {
        let _ = write!(hex, "{b:02x}");
        hex
    })
}

/// The receiving end of a transfer.
struct Receiver {
    received: Arc<AtomicUsize>,
    task: JoinHandle<anyhow::Result<(usize, [u8; 32])>>,
}

/// Receives one file from the first connection on `conns`: its length and SHA-256.
fn receive(mut conns: mpsc::Receiver<TcpConnection>) -> Receiver {
    let received = Arc::new(AtomicUsize::new(0));
    let counter = Arc::clone(&received);
    let task = tokio::spawn(async move {
        let mut conn = timeout(TRANSFER_TIMEOUT, conns.recv())
            .await
            .context("no connection on the app port")?
            .context("the app port closed")?;
        let mut hasher = Sha256::new();
        let mut buf = vec![0; CHUNK];
        loop {
            let n = conn.read(&mut buf).await?;
            if n == 0 {
                break;
            }
            hasher.update(&buf[..n]);
            counter.fetch_add(n, Ordering::Relaxed);
        }
        conn.shutdown().await?;
        Ok((counter.load(Ordering::Relaxed), hasher.finalize().into()))
    });
    Receiver { received, task }
}

/// Sends `data` over a new TCP connection to `target`, pausing `pace` between writes;
/// returns once the receiver closed its end.
async fn send(
    stack: NetStackHandle,
    target: SocketAddr,
    data: Arc<Vec<u8>>,
    pace: Option<Duration>,
) -> anyhow::Result<()> {
    let mut conn = timeout(CHECK_TIMEOUT, stack.connect_tcp(target))
        .await
        .with_context(|| format!("connecting to {target} timed out"))??;
    for chunk in data.chunks(CHUNK) {
        conn.write_all(chunk).await?;
        if let Some(pace) = pace {
            sleep(pace).await;
        }
    }
    conn.shutdown().await?;
    let mut rest = Vec::new();
    conn.read_to_end(&mut rest).await?;
    Ok(())
}

/// Sends a file from `from` to `target` and checks what `conns` received.
async fn transfer(
    from: &Node,
    target: SocketAddr,
    conns: mpsc::Receiver<TcpConnection>,
    data: Arc<Vec<u8>>,
    digest: [u8; 32],
) -> anyhow::Result<()> {
    let receiver = receive(conns);
    let started = Instant::now();
    timeout(
        TRANSFER_TIMEOUT,
        send(from.stack.clone(), target, Arc::clone(&data), None),
    )
    .await
    .context("the transfer timed out")??;
    let (len, got) = timeout(TRANSFER_TIMEOUT, receiver.task)
        .await
        .context("the receiver timed out")???;
    ensure!(
        len == data.len() && got == digest,
        "received {len} of {} bytes, sha256 {}",
        data.len(),
        hex(&got)
    );
    out::line(format_args!(
        "TRANSFER {} -> {target} {len} bytes sha256={} PASS {}ms",
        from.name,
        hex(&got),
        started.elapsed().as_millis()
    ));
    Ok(())
}

/// Waits until `node` counted a completed handshake.
async fn handshaken(node: &Node) -> anyhow::Result<u64> {
    for _ in 0..50 {
        let count = node.handshakes.load(Ordering::Relaxed);
        if count > 0 {
            return Ok(count);
        }
        sleep(Duration::from_millis(100)).await;
    }
    bail!("{}: no handshake event", node.name)
}

// ── Steps ────────────────────────────────────────────────────────────────────

/// Step a: a session between existing `quick` peers.
async fn step_reuse(a: &Node, b: &Node, v6: bool) -> anyhow::Result<()> {
    a.check_echo(b.addr(v6)).await?;
    b.check_echo(a.addr(v6)).await?;
    handshaken(a).await?;
    sleep(Duration::from_millis(200)).await;
    let peers = (a.peer_count().await?, b.peer_count().await?);
    let handshakes = (
        a.handshakes.load(Ordering::Relaxed),
        b.handshakes.load(Ordering::Relaxed),
    );

    // B offers a file; A takes it on its app port.
    let (mut at_a, mut at_b) = mailbox();
    let data = file(FILE_LEN);
    let digest = sha256(&data);
    at_b.send(Message::Offer {
        session: session_id(),
        len: data.len(),
        digest,
    })?;
    let (session, _, _) = at_a.offer().await?;
    let mut on_a = Session::open(a, &session, b.member()?)?;
    on_a.pinhole(&b.principal(), Direction::Inbound, APP_PORT)?;
    let conns = a.apps.listen(APP_PORT);
    at_a.send(Message::Accept { port: APP_PORT })?;

    // B restricts its outbound traffic to A, so it opens an outbound pinhole too.
    let Message::Accept { port } = at_b.recv().await? else {
        bail!("the receiver did not accept");
    };
    let mut on_b = Session::open(b, &session, a.member()?)?;
    on_b.pinhole(&a.principal(), Direction::Outbound, port)?;
    let target = SocketAddr::new(a.addr(v6), port);
    transfer(b, target, conns, data, digest).await?;

    let now = (a.peer_count().await?, b.peer_count().await?);
    ensure!(now == peers, "peer counts {peers:?} became {now:?}");
    let now = (
        a.handshakes.load(Ordering::Relaxed),
        b.handshakes.load(Ordering::Relaxed),
    );
    ensure!(
        now == handshakes,
        "handshakes {handshakes:?} became {now:?}"
    );
    out::line(format_args!(
        "REUSE peers a={} b={} handshakes a={} b={} unchanged",
        peers.0, peers.1, handshakes.0, handshakes.1
    ));
    a.check_echo(b.addr(v6)).await?;
    b.check_echo(a.addr(v6)).await?;

    // The receiver ends first: its pinhole and only `app:<id>` go.
    let before = a.drops().await?;
    a.apps.close(APP_PORT);
    drop(on_a);
    ensure!(
        a.namespaces() == [QUICK],
        "a keeps namespaces {:?}",
        a.namespaces()
    );
    b.unreachable(target).await?;
    ensure!(
        a.dropped_since(&before, reasons::DENIED).await? > 0,
        "a counted no denied packet"
    );
    drop(on_b);
    ensure!(
        b.namespaces() == [QUICK],
        "b keeps namespaces {:?}",
        b.namespaces()
    );
    Ok(())
}

/// Step b: A's `quick` does not allow the app, so A's pinhole is refused.
async fn step_not_permitted(a: &Node, b: &Node, v6: bool) -> anyhow::Result<()> {
    store_quick(a, b, false)?;
    let result = not_permitted(a, b, v6).await;
    store_quick(a, b, true)?;
    result
}

async fn not_permitted(a: &Node, b: &Node, v6: bool) -> anyhow::Result<()> {
    let (mut at_a, mut at_b) = mailbox();
    let refused = a.acl.pinhole_stats().not_permitted;
    at_b.send(Message::Offer {
        session: session_id(),
        len: FILE_LEN,
        digest: [0; 32],
    })?;
    let (session, _, _) = at_a.offer().await?;
    let mut on_a = Session::open(a, &session, b.member()?)?;
    match on_a.pinhole(&b.principal(), Direction::Inbound, APP_PORT) {
        Err(PinholeError::NotPermitted) => {}
        other => bail!("open_pinhole gave {other:?}, not NotPermitted"),
    }
    ensure!(a.acl.pinhole_stats().not_permitted == refused + 1);
    out::line(format_args!(
        "PINHOLE a {APP_KIND} for b: {}",
        PinholeError::NotPermitted
    ));
    at_a.send(Message::Reject {
        reason: PinholeError::NotPermitted.to_string(),
    })?;

    // A sender that tries anyway gets nowhere.
    let Message::Reject { reason } = at_b.recv().await? else {
        bail!("the receiver did not reject");
    };
    out::line(format_args!("REJECT b: {reason}"));
    let mut on_b = Session::open(b, &session, a.member()?)?;
    on_b.pinhole(&a.principal(), Direction::Outbound, APP_PORT)?;
    let before = a.drops().await?;
    b.unreachable(SocketAddr::new(a.addr(v6), APP_PORT)).await?;
    ensure!(
        a.dropped_since(&before, reasons::DENIED).await? > 0,
        "a counted no denied packet"
    );
    Ok(())
}

/// Step c: the permission goes while a transfer runs.
async fn step_revoke(a: &Node, b: &Node, v6: bool) -> anyhow::Result<()> {
    let result = revoke(a, b, v6).await;
    a.apps.close(APP_PORT);
    store_quick(a, b, true)?;
    result
}

async fn revoke(a: &Node, b: &Node, v6: bool) -> anyhow::Result<()> {
    let session = session_id();
    let mut on_a = Session::open(a, &session, b.member()?)?;
    on_a.pinhole(&b.principal(), Direction::Inbound, APP_PORT)?;
    let mut on_b = Session::open(b, &session, a.member()?)?;
    on_b.pinhole(&a.principal(), Direction::Outbound, APP_PORT)?;
    let receiver = receive(a.apps.listen(APP_PORT));
    let target = SocketAddr::new(a.addr(v6), APP_PORT);
    let sender = tokio::spawn(send(
        b.stack.clone(),
        target,
        file(SLOW_FILE_LEN),
        Some(SLOW_PACE),
    ));
    let result = revoke_mid_transfer(a, b, &on_a, &receiver.received).await;
    sender.abort();
    receiver.task.abort();
    result
}

async fn revoke_mid_transfer(
    a: &Node,
    b: &Node,
    on_a: &Session,
    received: &AtomicUsize,
) -> anyhow::Result<()> {
    let started = Instant::now();
    while received.load(Ordering::Relaxed) < SLOW_FILE_LEN / 16 {
        ensure!(
            started.elapsed() < TRANSFER_TIMEOUT,
            "the transfer does not start"
        );
        sleep(Duration::from_millis(20)).await;
    }
    let revoked = a.acl.pinhole_stats().revoked;
    let denied = a.filter.stats().denied;
    store_quick(a, b, false)?;
    ensure!(!on_a.is_open(), "the pinhole is still open");
    ensure!(a.acl.pinhole_stats().revoked == revoked + 1);
    out::line(format_args!(
        "REVOKED a {APP_KIND} at {} bytes",
        received.load(Ordering::Relaxed)
    ));
    sleep(Duration::from_secs(1)).await;
    let settled = received.load(Ordering::Relaxed);
    sleep(Duration::from_millis(1500)).await;
    let last = received.load(Ordering::Relaxed);
    ensure!(
        last == settled && last < SLOW_FILE_LEN,
        "the transfer goes on: {settled} then {last} of {SLOW_FILE_LEN} bytes"
    );
    let stats = a.filter.stats();
    ensure!(
        stats.denied > denied,
        "a denied nothing after the revocation"
    );
    out::line(format_args!(
        "STOPPED at {last} of {SLOW_FILE_LEN} bytes, a denied +{} reply_revoked={}",
        stats.denied - denied,
        stats.reply_revoked
    ));
    Ok(())
}

/// Step d: two nodes that are not peers become session-only peers.
async fn step_session_only() -> anyhow::Result<()> {
    let r = Node::new("r", 1, 1, Layout::Stack).await?;
    let s = Node::new("s", 1, 2, Layout::Stack).await?;
    let result = session_only(&r, &s).await;
    r.shutdown().await?;
    s.shutdown().await?;
    result
}

async fn session_only(r: &Node, s: &Node) -> anyhow::Result<()> {
    ensure!(r.peer_count().await? == 0 && s.peer_count().await? == 0);
    let (mut at_r, mut at_s) = mailbox();
    let mut session_psk = [0; 32];
    OsRng.fill_bytes(&mut session_psk);
    let data = file(FILE_LEN);
    let digest = sha256(&data);
    at_s.send(Message::Hello {
        contact: s.contact(true),
        preshared_key: Some(session_psk),
    })?;
    at_s.send(Message::Offer {
        session: session_id(),
        len: data.len(),
        digest,
    })?;

    // R: the sender becomes a session-only peer with an inbound pinhole on the app port.
    let (sender, psk) = at_r.hello().await?;
    let (session, _, _) = at_r.offer().await?;
    let sender_principal = wg_peer_anchor(sender.public_key.as_bytes());
    let mut on_r = Session::open(r, &session, member(&sender.public_key, &[sender.address])?)?;
    on_r.pinhole(&sender_principal, Direction::Inbound, APP_PORT)?;
    r.add_peer(&sender, &[sender.address], psk).await?;
    let conns = r.apps.listen(APP_PORT);
    at_r.send(Message::Hello {
        contact: r.contact(true),
        preshared_key: None,
    })?;
    at_r.send(Message::Accept { port: APP_PORT })?;

    // S: the receiver likewise, with an outbound pinhole to its app port.
    let (receiver, _) = at_s.hello().await?;
    let Message::Accept { port } = at_s.recv().await? else {
        bail!("the receiver did not accept");
    };
    let receiver_principal = wg_peer_anchor(receiver.public_key.as_bytes());
    let mut on_s = Session::open(
        s,
        &session,
        member(&receiver.public_key, &[receiver.address])?,
    )?;
    on_s.pinhole(&receiver_principal, Direction::Outbound, port)?;
    s.add_peer(&receiver, &[receiver.address], Some(session_psk))
        .await?;
    let target = SocketAddr::new(receiver.address, port);
    transfer(s, target, conns, data, digest).await?;

    // Nothing but the app port, either way.
    let before = (s.drops().await?, r.drops().await?);
    s.unreachable(SocketAddr::new(receiver.address, ECHO_PORT))
        .await?;
    r.unreachable(SocketAddr::new(sender.address, ECHO_PORT))
        .await?;
    ensure!(s.dropped_since(&before.0, reasons::OUTBOUND).await? > 0);
    ensure!(r.dropped_since(&before.1, reasons::OUTBOUND).await? > 0);

    // The session ends: pinholes, namespace and peer go on both sides.
    r.apps.close(APP_PORT);
    drop((on_r, on_s));
    r.remove_peer(&sender).await?;
    s.remove_peer(&receiver).await?;
    for node in [r, s] {
        ensure!(
            node.namespaces().is_empty() && node.peer_count().await? == 0,
            "{} keeps a namespace or a peer",
            node.name
        );
    }
    s.unreachable(target).await?;
    Ok(())
}

/// Step e: a hub between C (`nsd:c`) and a session-only peer S.
async fn step_cross_namespace(v6: bool) -> anyhow::Result<()> {
    let h = Node::new("h", 2, 1, Layout::Hub).await?;
    let s = Node::new("s", 2, 2, Layout::Stack).await?;
    let c = Node::new("c", 2, 3, Layout::Stack).await?;
    let result = cross_namespace(&h, &s, &c, v6).await;
    for node in [h, s, c] {
        node.shutdown().await?;
    }
    result
}

async fn cross_namespace(h: &Node, s: &Node, c: &Node, v6: bool) -> anyhow::Result<()> {
    let (h_addr, s_addr, c_addr) = (h.addr(v6), s.addr(v6), c.addr(v6));
    // The leaves let everything in; the hub enforces.
    s.permit_all()?;
    c.permit_all()?;
    h.add_peer(&c.contact(v6), &[c_addr], None).await?;
    c.add_peer(&h.contact(v6), &[h_addr, s_addr], None).await?;
    h.acl.store_namespace(
        NSD_C,
        NamespacePolicy {
            members: vec![member(&c.public_key, &[c_addr])?],
            ..NamespacePolicy::default()
        },
    )?;

    // S becomes a session-only peer of the hub through the mailbox.
    let (mut at_h, mut at_s) = mailbox();
    let mut psk = [0; 32];
    OsRng.fill_bytes(&mut psk);
    at_s.send(Message::Hello {
        contact: s.contact(v6),
        preshared_key: Some(psk),
    })?;
    let (session_peer, psk) = at_h.hello().await?;
    let _session = Session::open(h, &session_id(), member(&s.public_key, &[s_addr])?)?;
    h.add_peer(&session_peer, &[s_addr], psk).await?;
    at_h.send(Message::Hello {
        contact: h.contact(v6),
        preshared_key: None,
    })?;
    let (hub, _) = at_s.hello().await?;
    s.add_peer(&hub, &[h_addr, c_addr], psk).await?;

    let before = h.drops().await?;
    c.unreachable(SocketAddr::new(s_addr, ECHO_PORT)).await?;
    s.unreachable(SocketAddr::new(c_addr, ECHO_PORT)).await?;
    ensure!(
        h.dropped_since(&before, reasons::CROSS_NAMESPACE).await? > 0,
        "h counted no cross-namespace packet"
    );

    let grant = Grant {
        from: GrantEnd::Peer(s.principal()),
        to: GrantEnd::Namespace(NSD_C.into()),
        proto: Some("tcp".to_owned()),
        ports: Some(ECHO_PORT.to_string()),
    };
    h.acl.store_grant("s-to-c", grant)?;
    out::line(format_args!("GRANT h s -> {NSD_C} tcp/{ECHO_PORT}"));
    s.check_echo(c_addr).await?;
    c.unreachable(SocketAddr::new(s_addr, ECHO_PORT)).await?;

    ensure!(h.acl.remove_grant("s-to-c"));
    out::line(format_args!("REVOKED h grant s -> {NSD_C}"));
    let before = h.drops().await?;
    s.unreachable(SocketAddr::new(c_addr, ECHO_PORT)).await?;
    ensure!(
        h.dropped_since(&before, reasons::CROSS_NAMESPACE).await? > 0,
        "h counted no cross-namespace packet after the revocation"
    );
    Ok(())
}

/// The TUN step: host traffic to a session-only peer is dropped, the app works.
async fn step_tun_outbound(a: &Node, v6: bool) -> anyhow::Result<()> {
    let t = Node::new("t", 0, 3, Layout::Stack).await?;
    let result = tun_outbound(a, &t, v6).await;
    a.apps.close(APP_PORT);
    t.shutdown().await?;
    result
}

async fn tun_outbound(a: &Node, t: &Node, v6: bool) -> anyhow::Result<()> {
    let (tun, _) = a.tun.as_ref().context("node a has no TUN")?;
    let (a_addr, t_addr) = (a.addr(v6), t.addr(v6));
    let (mut at_a, mut at_t) = mailbox();
    let mut psk = [0; 32];
    OsRng.fill_bytes(&mut psk);
    let data = file(FILE_LEN);
    let digest = sha256(&data);
    at_t.send(Message::Hello {
        contact: t.contact(v6),
        preshared_key: Some(psk),
    })?;
    at_t.send(Message::Offer {
        session: session_id(),
        len: data.len(),
        digest,
    })?;
    let (sender, psk) = at_a.hello().await?;
    let (session, _, _) = at_a.offer().await?;
    let mut on_a = Session::open(a, &session, member(&t.public_key, &[t_addr])?)?;
    on_a.pinhole(&t.principal(), Direction::Inbound, APP_PORT)?;
    a.add_peer(&sender, &[t_addr], psk).await?;
    route_to_tun(tun, t_addr)?;
    let conns = a.apps.listen(APP_PORT);
    at_a.send(Message::Hello {
        contact: a.contact(v6),
        preshared_key: None,
    })?;
    at_a.send(Message::Accept { port: APP_PORT })?;
    let (receiver, _) = at_t.hello().await?;
    let mut on_t = Session::open(t, &session, member(&a.public_key, &[a_addr])?)?;
    on_t.pinhole(&a.principal(), Direction::Outbound, APP_PORT)?;
    t.add_peer(&receiver, &[a_addr], psk).await?;
    transfer(t, SocketAddr::new(a_addr, APP_PORT), conns, data, digest).await?;

    // The host, through the TUN: TCP to any port and ping are dropped by the outbound rule.
    let before = a.drops().await?;
    let denied = a.filter.stats().outbound_denied;
    for port in [ECHO_PORT, APP_PORT] {
        let target = SocketAddr::new(t_addr, port);
        let connected = timeout(PROBE_TIMEOUT, tokio::net::TcpStream::connect(target)).await;
        ensure!(!matches!(connected, Ok(Ok(_))), "the host reaches {target}");
        out::line(format_args!("BLOCKED host -> {target}"));
    }
    let ping = tokio::process::Command::new("ping")
        .args(["-c", "1", "-W", "1", &t_addr.to_string()])
        .output()
        .await
        .context("cannot run ping")?;
    ensure!(!ping.status.success(), "the host pings {t_addr}");
    out::line(format_args!("BLOCKED host ping {t_addr}"));
    ensure!(
        a.dropped_since(&before, reasons::OUTBOUND).await? > 0,
        "a counted no outbound denied packet"
    );
    ensure!(a.filter.stats().outbound_denied > denied);

    drop((on_a, on_t));
    a.remove_peer(&sender).await?;
    Ok(())
}

/// Routes `addr` to the TUN `name` (Linux: `ip route`; its address is already set).
fn route_to_tun(name: &str, addr: IpAddr) -> anyhow::Result<()> {
    let mut peer = nsplane_examples::node::PeerSpec::new(PublicKey::from([0; 32]));
    peer.allowed_ips = vec![host_route(addr)];
    nsplane_examples::node::configure_tun(name, &[], DEFAULT_MTU, &[peer])
}

/// Prints `STEP <name> PASS|FAIL`; returns whether it passed.
fn report(name: &str, result: anyhow::Result<()>) -> bool {
    match result {
        Ok(()) => {
            out::line(format_args!("STEP {name} PASS"));
            true
        }
        Err(e) => {
            out::line(format_args!("STEP {name} FAIL {e:#}"));
            false
        }
    }
}

/// Node A's status file: the engine, `extra.acl`, `extra.pinhole_stats`, `extra.netstack`.
async fn write_status(path: PathBuf, a: &Node) -> anyhow::Result<()> {
    let (filter, acl, stack) = (a.filter.clone(), Arc::clone(&a.acl), a.stack.clone());
    let status = Status::new(path, a.engine.handle(), a.udp).extra(move |extra| {
        let stats = filter.stats();
        let namespaces: Vec<String> = acl
            .namespaces()
            .iter()
            .map(|id| id.as_str().to_owned())
            .collect();
        extra.insert(
            "acl".to_owned(),
            json!({
                "namespaces": namespaces,
                "accepted": stats.accepted,
                "replies": stats.replies,
                "denied": stats.denied,
                "no_policy": stats.no_policy,
                "unknown_peer": stats.unknown_peer,
                "protocol": stats.protocol,
                "malformed": stats.malformed,
                "cross_namespace": stats.cross_namespace,
                "outbound_denied": stats.outbound_denied,
                "outbound_replies": stats.outbound_replies,
                "reply_revoked": stats.reply_revoked,
            }),
        );
        let pinholes = acl.pinhole_stats();
        extra.insert(
            "pinhole_stats".to_owned(),
            json!({
                "opened": pinholes.opened,
                "closed": pinholes.closed,
                "expired": pinholes.expired,
                "namespace_removed": pinholes.namespace_removed,
                "revoked": pinholes.revoked,
                "cleared": pinholes.cleared,
                "not_permitted": pinholes.not_permitted,
            }),
        );
        extra.insert("netstack".to_owned(), netstack_json(&stack));
    });
    status.write().await
}

#[tokio::main]
async fn main() -> anyhow::Result<ExitCode> {
    let args = Args::parse();
    init_logging(&args.log)?;
    let v6 = args.ipv6;
    let layout = args.tun.as_ref().map_or(Layout::Stack, |name| Layout::Tun {
        name: name.clone(),
        address: if v6 {
            AllowedIp {
                addr: IpAddr::V6(Ipv6Addr::new(0xfd99, 0, 0, 0, 0, 0, 0, 1)),
                cidr: 64,
            }
        } else {
            AllowedIp {
                addr: IpAddr::V4(Ipv4Addr::new(10, 99, 0, 1)),
                cidr: 24,
            }
        },
    });
    let a = Node::new("a", 0, 1, layout).await?;
    let b = Node::new("b", 0, 2, Layout::Stack).await?;
    pair(&a, &b).await?;

    let mut passed = true;
    if args.step.runs(StepArg::A) {
        passed &= report("reuse", step_reuse(&a, &b, v6).await);
    }
    if args.step.runs(StepArg::B) {
        passed &= report("not-permitted", step_not_permitted(&a, &b, v6).await);
    }
    if args.step.runs(StepArg::C) {
        passed &= report("revoke", step_revoke(&a, &b, v6).await);
    }
    if args.step.runs(StepArg::D) {
        passed &= report("session-only-peer", step_session_only().await);
    }
    if args.step.runs(StepArg::E) {
        passed &= report("cross-namespace", step_cross_namespace(v6).await);
    }
    if a.tun.is_some() {
        passed &= report("tun-outbound", step_tun_outbound(&a, v6).await);
    }
    if let Some(path) = args.status {
        write_status(path, &a).await?;
    }
    a.shutdown().await?;
    b.shutdown().await?;
    out::line(format_args!(
        "CHECKS {}",
        if passed { "PASS" } else { "FAIL" }
    ));
    Ok(if passed {
        ExitCode::SUCCESS
    } else {
        ExitCode::FAILURE
    })
}
