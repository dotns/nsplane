//! A relay, two nodes and a plain WireGuard peer in one process, on loopback (no root).
//!
//! The relay is a [`Router`] behind a [`RelayServerTransport`] with its own engine. Nodes
//! A and B run the extension-aware transport ([`RelayClient`]) and the direct-first path
//! ladder; their `--peer` endpoint for each other is the relay, and each knows the other's
//! socket as a direct candidate. Node A's socket sits behind a gate that can block the
//! direct path. Node A also lists a plain [`UdpTransport`] engine (P) as a relay endpoint:
//! it never answers control messages.
//!
//! Prints `STEP <name> PASS|FAIL` for each step, then `STEPS PASS` or `STEPS FAIL`:
//!
//! - `discovery`: both nodes find the relay extension-capable;
//! - `relay-engine`: A reaches the relay's own engine through the tunnel;
//! - `direct-first`: A and B settle on the direct path without passing through the relay;
//! - `direct-checks`: TCP/UDP echo between A and B pass and nothing is relayed;
//! - `block`: the gate blocks the direct path, both fall back to the relay, checks pass;
//! - `unblock`: the gate opens, both return to direct, checks pass;
//! - `plain-endpoint`: P was probed, backed off and stopped, and WireGuard to it works.
//!
//! APIs shown: custom [`Transport`]s wrapping [`UdpTransport`] (relay, extension-aware
//! client, a test gate), a custom [`PathPolicy`] (`relay::ladder::LadderPolicy`),
//! [`EngineHandle::force_handshake`] and [`EngineHandle::set_path`] driven by it.
//!
//! Usage: `cargo run -p nsplane-examples --bin relay_transport -- --carrier udp`
//!
//! [`Transport`]: nsplane::Transport
//! [`PathPolicy`]: nsplane::PathPolicy
//! [`EngineHandle::force_handshake`]: nsplane::EngineHandle::force_handshake
//! [`EngineHandle::set_path`]: nsplane::EngineHandle::set_path

use std::collections::HashMap;
use std::io;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::process::ExitCode;
use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Duration, Instant};

use anyhow::Context as _;
use clap::{Parser, ValueEnum};
use nsplane::x25519::{PublicKey, StaticSecret};
use nsplane::{
    Engine, EngineBuilder, PacketBuf, Path, StandardRoaming, Transport, TransportId, UdpTransport,
};
use nsplane_examples::echo::{self, Backend, Check, Proto};
use nsplane_examples::node::{
    PeerSpec, UDP_TRANSPORT, configure_peers, generate_key, init_logging, parse_cidr,
};
use nsplane_examples::out;
use nsplane_examples::relay::client::{ClientConfig, EndpointState, ProbeTimers, RelayClient};
use nsplane_examples::relay::envelope::MachineKey;
use nsplane_examples::relay::ladder::{Active, LadderTimers, Pin};
use nsplane_examples::relay::router::{MachinePin, Router, TargetConfig, machine_id};
use nsplane_examples::relay::server::RelayServerTransport;
use nsplane_netstack::{DEFAULT_MTU, NetStack, NetStackConfig, NetStackHandle};

/// How the nodes reach the relay.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
enum Carrier {
    /// The relay's UDP port.
    Udp,
}

/// Single-port relay, extension discovery and the direct/relay path ladder, in-process.
#[derive(Debug, Parser)]
#[command(name = "relay_transport", version)]
struct Args {
    /// Carrier between the nodes and the relay
    #[arg(long, value_enum, default_value_t = Carrier::Udp)]
    carrier: Carrier,

    /// Wait after the first unanswered probe of an endpoint, doubled per attempt
    #[arg(long, value_name = "MS", default_value_t = 200)]
    probe_backoff_ms: u64,

    /// Time a direct path has to authenticate before the relay is used
    #[arg(long, value_name = "MS", default_value_t = 2000)]
    direct_timeout_ms: u64,

    /// Interval of direct probes while on the relay
    #[arg(long, value_name = "MS", default_value_t = 3000)]
    direct_probe_interval_ms: u64,

    /// Seconds each step may take
    #[arg(long, value_name = "SECS", default_value_t = 20)]
    step_timeout: u64,

    /// Log filter for stderr
    #[arg(long, value_name = "FILTER", default_value = "warn")]
    log: String,
}

/// Echo port of every stack.
const ECHO_PORT: u16 = 7;
/// Probe attempts before an endpoint is stopped.
const PROBE_ATTEMPTS: u32 = 5;

/// A transport that drops datagrams to and from blocked addresses.
#[derive(Debug)]
struct Gate<T> {
    inner: T,
    blocked: Arc<Mutex<Vec<SocketAddr>>>,
}

impl<T> Gate<T> {
    fn is_blocked(&self, addr: SocketAddr) -> bool {
        self.blocked
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .contains(&addr)
    }
}

impl<T: Transport> Transport for Gate<T> {
    fn id(&self) -> TransportId {
        self.inner.id()
    }

    async fn recv(&self, buf: &mut PacketBuf) -> io::Result<(usize, Path)> {
        loop {
            let (len, path) = self.inner.recv(buf).await?;
            if !self.is_blocked(path.addr) {
                return Ok((len, path));
            }
        }
    }

    async fn send(&self, datagram: &[u8], to: &Path) -> io::Result<()> {
        if self.is_blocked(to.addr) {
            return Ok(());
        }
        self.inner.send(datagram, to).await
    }
}

/// An engine on a userspace stack serving echo.
struct Host {
    engine: Engine,
    stack: NetStackHandle,
    public: PublicKey,
    listen: SocketAddr,
}

fn stack(address: &str) -> anyhow::Result<(NetStack, NetStackHandle)> {
    let ip = parse_cidr(address)?;
    Ok(NetStack::new(NetStackConfig::new(
        vec![(ip.addr, ip.cidr)],
        DEFAULT_MTU,
    )))
}

const fn loopback() -> SocketAddr {
    SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0)
}

async fn host<T: Transport>(
    key: StaticSecret,
    address: &str,
    transport: T,
    listen: SocketAddr,
    policy: Box<dyn nsplane::PathPolicy>,
) -> anyhow::Result<Host> {
    let public = PublicKey::from(&key);
    let (stack, handle) = stack(address)?;
    let (source, sink) = stack.split();
    let engine = EngineBuilder::new(source, sink)
        .private_key(key)
        .transport(transport)
        .policy(policy)
        .build()
        .context("cannot build an engine")?;
    echo::serve(&Backend::NetStack(handle.clone()), ECHO_PORT).await?;
    Ok(Host {
        engine,
        stack: handle,
        public,
        listen,
    })
}

fn peer(
    key: PublicKey,
    endpoint: Option<SocketAddr>,
    allowed: &str,
    keepalive: Option<u16>,
) -> anyhow::Result<PeerSpec> {
    let mut spec = PeerSpec::new(key);
    spec.endpoint = endpoint;
    spec.allowed_ips.push(parse_cidr(allowed)?);
    spec.keepalive = keepalive;
    Ok(spec)
}

/// A node with the extension-aware transport behind a gate.
struct Node {
    host: Host,
    client: RelayClient,
    gate: Arc<Mutex<Vec<SocketAddr>>>,
    machine: MachineKey,
}

async fn node(
    args: &Args,
    relays: Vec<SocketAddr>,
    address: &str,
    key: StaticSecret,
) -> anyhow::Result<Node> {
    let udp = UdpTransport::bind(UDP_TRANSPORT, loopback()).context("cannot bind a node")?;
    let listen = udp.local_addr();
    let gate = Arc::new(Mutex::new(Vec::new()));
    let machine = MachineKey::generate();
    let config = ClientConfig {
        relays,
        machine_key: machine.clone(),
        pin: Pin::Auto,
        probe: ProbeTimers {
            backoff: Duration::from_millis(args.probe_backoff_ms),
            attempts: PROBE_ATTEMPTS,
            register_interval: Duration::from_secs(5),
            reflexive_interval: Duration::from_secs(5),
            ..ProbeTimers::default()
        },
        ladder: LadderTimers {
            direct_timeout: Duration::from_millis(args.direct_timeout_ms),
            probe_interval: Duration::from_millis(args.direct_probe_interval_ms),
        },
        peer_candidates: None,
        reflexive_out: None,
    };
    let (client, ext, policy) = RelayClient::new(
        Gate {
            inner: udp,
            blocked: Arc::clone(&gate),
        },
        config,
    );
    let host = host(key, address, ext, listen, Box::new(policy)).await?;
    Ok(Node {
        host,
        client,
        gate,
        machine,
    })
}

/// Polls `condition` every 100 ms until it holds or `limit` passes.
async fn wait_for(limit: Duration, mut condition: impl FnMut() -> bool) -> bool {
    let deadline = Instant::now() + limit;
    while Instant::now() < deadline {
        if condition() {
            return true;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    condition()
}

/// Runs a TCP and a UDP echo check from `from` to `ip`.
async fn checks(from: &Host, ip: &str, limit: Duration) -> anyhow::Result<bool> {
    let backend = Backend::NetStack(from.stack.clone());
    let mut passed = true;
    for proto in [Proto::Tcp, Proto::Udp] {
        let check = Check {
            proto,
            target: SocketAddr::new(ip.parse()?, ECHO_PORT),
        };
        passed &= echo::run_check(&backend, &check, limit).await;
    }
    Ok(passed)
}

fn step(name: &str, passed: bool, all: &mut bool) {
    out::line(format_args!(
        "STEP {name} {}",
        if passed { "PASS" } else { "FAIL" }
    ));
    *all &= passed;
}

/// The ladder state of `node`'s path to the peer with key `peer`.
fn path_of(node: &Node, peer: &PublicKey) -> Option<(Active, bool, u64, u64)> {
    node.client
        .ladder()
        .paths()
        .into_iter()
        .find(|p| p.key == peer.to_bytes())
        .map(|p| (p.active, p.confirmed, p.to_direct, p.to_relay))
}

fn endpoint_state(node: &Node, addr: SocketAddr) -> Option<EndpointState> {
    node.client
        .endpoints()
        .into_iter()
        .find(|e| e.addr == addr)
        .map(|e| e.state)
}

/// Everything the steps act on.
struct Lab {
    router: Arc<Mutex<Router>>,
    relay: Host,
    plain: Host,
    a: Node,
    b: Node,
}

impl Lab {
    /// Datagrams the relay forwarded so far.
    fn forwarded(&self) -> u64 {
        self.router
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .counters()
            .forwarded
    }

    /// Blocks (or unblocks) the direct path between A and B at A's gate.
    fn block_direct(&self, block: bool) {
        let mut gate = self.a.gate.lock().unwrap_or_else(PoisonError::into_inner);
        gate.clear();
        if block {
            gate.push(self.b.host.listen);
        }
    }

    /// The active path of A to B and of B to A.
    fn actives(&self) -> (Option<Active>, Option<Active>) {
        (
            path_of(&self.a, &self.b.host.public).map(|p| p.0),
            path_of(&self.b, &self.a.host.public).map(|p| p.0),
        )
    }
}

/// Starts the relay, the plain peer and both nodes; pins the nodes' machines at the relay.
async fn start(args: &Args) -> anyhow::Result<Lab> {
    let relay_key = generate_key();
    let relay_udp =
        UdpTransport::bind(UDP_TRANSPORT, loopback()).context("cannot bind the relay")?;
    let relay_addr = relay_udp.local_addr();
    let router = Arc::new(Mutex::new(Router::new(
        PublicKey::from(&relay_key).to_bytes(),
        "relay".into(),
        relay_addr,
    )));
    let relay = host(
        relay_key,
        "10.77.0.1/24",
        RelayServerTransport::new(relay_udp, Arc::clone(&router)),
        relay_addr,
        Box::new(StandardRoaming),
    )
    .await?;
    let plain_udp =
        UdpTransport::bind(UDP_TRANSPORT, loopback()).context("cannot bind the plain peer")?;
    let plain_addr = plain_udp.local_addr();
    let plain = host(
        generate_key(),
        "10.77.0.9/24",
        plain_udp,
        plain_addr,
        Box::new(StandardRoaming),
    )
    .await?;
    let a = node(
        args,
        vec![relay_addr, plain_addr],
        "10.77.0.2/24",
        generate_key(),
    )
    .await?;
    let b = node(args, vec![relay_addr], "10.77.0.3/24", generate_key()).await?;
    let pins: Vec<TargetConfig> = [&a, &b]
        .iter()
        .map(|n| TargetConfig {
            wg_public_key: n.host.public.to_bytes(),
            pin: Some(MachinePin {
                machine_id: machine_id(&n.machine.public()),
                machine_key: n.machine.public(),
            }),
            static_source: None,
        })
        .collect();
    router
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .set_targets(pins);
    Ok(Lab {
        router,
        relay,
        plain,
        a,
        b,
    })
}

/// Configures the peers (A and B reach each other through the relay endpoint), hands out
/// the direct candidates and starts the relay clients.
async fn connect(lab: &Lab) -> anyhow::Result<()> {
    let (relay, plain, a, b) = (&lab.relay, &lab.plain, &lab.a, &lab.b);
    configure_peers(
        &relay.engine.handle(),
        &[
            peer(a.host.public, None, "10.77.0.2/32", None)?,
            peer(b.host.public, None, "10.77.0.3/32", None)?,
        ],
    )
    .await?;
    configure_peers(
        &plain.engine.handle(),
        &[peer(a.host.public, None, "10.77.0.2/32", None)?],
    )
    .await?;
    let a_peers = [
        peer(relay.public, Some(relay.listen), "10.77.0.1/32", None)?,
        peer(b.host.public, Some(relay.listen), "10.77.0.3/32", Some(1))?,
        peer(plain.public, Some(plain.listen), "10.77.0.9/32", None)?,
    ];
    let b_peers = [
        peer(relay.public, Some(relay.listen), "10.77.0.1/32", None)?,
        peer(a.host.public, Some(relay.listen), "10.77.0.2/32", Some(1))?,
    ];
    // The control plane: each node's socket is a direct candidate of the other.
    a.client.set_candidates(HashMap::from([(
        b.host.public.to_bytes(),
        vec![b.host.listen],
    )]));
    b.client.set_candidates(HashMap::from([(
        a.host.public.to_bytes(),
        vec![a.host.listen],
    )]));
    for (node, peers) in [(a, &a_peers[..]), (b, &b_peers[..])] {
        configure_peers(&node.host.engine.handle(), peers).await?;
        let specs = peers
            .iter()
            .map(|p| (p.public_key.to_bytes(), p.endpoint))
            .collect();
        node.client.start(
            node.host.engine.handle(),
            node.host.public.to_bytes(),
            specs,
        );
    }
    Ok(())
}

/// Runs the steps; returns whether all passed.
async fn steps(lab: &Lab, limit: Duration) -> anyhow::Result<bool> {
    let (a, b) = (&lab.a, &lab.b);
    let (relay_addr, plain_addr) = (lab.relay.listen, lab.plain.listen);
    let mut all = true;

    let capable = wait_for(limit, || {
        endpoint_state(a, relay_addr) == Some(EndpointState::Capable)
            && endpoint_state(b, relay_addr) == Some(EndpointState::Capable)
    })
    .await;
    step("discovery", capable, &mut all);

    let reached = checks(&a.host, "10.77.0.1", limit).await?;
    step("relay-engine", reached, &mut all);

    let direct = wait_for(limit, || {
        path_of(a, &b.host.public) == Some((Active::Direct, true, 0, 0))
            && path_of(b, &a.host.public) == Some((Active::Direct, true, 0, 0))
    })
    .await;
    step("direct-first", direct, &mut all);

    let before = lab.forwarded();
    let passed = checks(&a.host, "10.77.0.3", limit).await?;
    let stayed = lab.actives() == (Some(Active::Direct), Some(Active::Direct));
    step(
        "direct-checks",
        passed && stayed && lab.forwarded() == before,
        &mut all,
    );

    lab.block_direct(true);
    let fell_back = wait_for(limit, || {
        lab.actives() == (Some(Active::Relay), Some(Active::Relay))
    })
    .await;
    let before = lab.forwarded();
    let passed = checks(&a.host, "10.77.0.3", limit).await?;
    step(
        "block",
        fell_back && passed && lab.forwarded() > before,
        &mut all,
    );

    lab.block_direct(false);
    let returned = wait_for(limit, || {
        matches!(
            path_of(a, &b.host.public),
            Some((Active::Direct, true, 1.., _))
        ) && matches!(
            path_of(b, &a.host.public),
            Some((Active::Direct, true, 1.., _))
        )
    })
    .await;
    let passed = checks(&a.host, "10.77.0.3", limit).await?;
    step("unblock", returned && passed, &mut all);

    let stopped = wait_for(limit, || {
        endpoint_state(a, plain_addr) == Some(EndpointState::Stopped)
    })
    .await;
    let backed_off = a
        .client
        .endpoints()
        .into_iter()
        .find(|e| e.addr == plain_addr)
        .is_some_and(|e| e.attempts == PROBE_ATTEMPTS && e.control_answered == 0);
    let passed = checks(&a.host, "10.77.0.9", limit).await?;
    step("plain-endpoint", stopped && backed_off && passed, &mut all);
    Ok(all)
}

#[tokio::main]
async fn main() -> anyhow::Result<ExitCode> {
    let args = Args::parse();
    init_logging(&args.log)?;
    let Carrier::Udp = args.carrier;
    let lab = start(&args).await?;
    connect(&lab).await?;
    let all = steps(&lab, Duration::from_secs(args.step_timeout)).await?;
    out::line(format_args!("STEPS {}", if all { "PASS" } else { "FAIL" }));
    for host in [&lab.relay, &lab.plain, &lab.a.host, &lab.b.host] {
        let _ = host.engine.handle().shutdown().await;
    }
    Ok(if all {
        ExitCode::SUCCESS
    } else {
        ExitCode::FAILURE
    })
}
