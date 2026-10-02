//! Engine events, peer statistics and drop counters, demonstrated step by step.
//!
//! Two engines in one process talk over UDP on the loopback interface, each on an
//! `nsplane-netstack` (no TUN, no root), like `udp_pair`. Engine B serves TCP and UDP
//! echo. Every [`Event`] of both engines is printed as an `EVENT <a|b> ...` line, then
//! these steps run against engine A, each printing `STEP <name> PASS|FAIL`:
//!
//! 1. `handshake`: TCP and UDP checks pass, a handshake completes, and A's peer counters
//!    (`rx`, `tx`, `data_rx`, `data_tx`) grow.
//! 2. `suspend`: after [`EngineHandle::suspend`] (`Event::Suspended`) a UDP check fails
//!    and A's peer counters do not move.
//! 3. `resume`: after [`EngineHandle::resume`] (`Event::Resumed`) and
//!    [`EngineHandle::force_handshake`], a new handshake completes and a UDP check passes.
//! 4. `mtu`: A's packet source is a [`MergeSource`] of its netstack and a
//!    [`ChannelSource`]; lowering the channel's MTU through its `watch::Sender` lowers the
//!    merged MTU, yields `Event::MtuChanged` and [`EngineHandle::mtu`] reports it.
//! 5. `drop`: a datagram to a tunnel address no peer owns is dropped as `no route`
//!    (`Event::Dropped`, [`EngineHandle::drop_counters`]).
//!
//! `STATS` lines print [`EngineHandle::peer_stats`], `DROPS` lines the drop counters. The
//! run ends with `STEPS PASS` and exit code 0, or `STEPS FAIL` and 1.
//!
//! Usage: `cargo run -p nsplane-examples --bin events_stats`

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::process::ExitCode;
use std::time::Duration;

use anyhow::Context as _;
use clap::Parser;
use nsplane::x25519::{PublicKey, StaticSecret};
use nsplane::{
    AllowedIp, ChannelSource, Engine, EngineBuilder, EngineHandle, Event, MergeSource, PacketBuf,
    PeerId, UdpTransport, reasons,
};
use nsplane_examples::echo::{self, Backend, Check, Proto};
use nsplane_examples::node::{
    PeerSpec, UDP_TRANSPORT, configure_peers, encode_public_key, generate_key, init_logging,
};
use nsplane_examples::out;
use nsplane_netstack::{DEFAULT_MTU, NetStack, NetStackConfig, NetStackHandle};
use tokio::sync::broadcast::{self, error::RecvError};
use tokio::sync::{mpsc, watch};
use tokio::time::{Instant, sleep, timeout_at};

/// Two engines over loopback UDP: events, peer stats, drop counters, suspend/resume, MTU.
#[derive(Debug, Parser)]
#[command(name = "events_stats", version)]
struct Args {
    /// Seconds a step waits for an event or a check
    #[arg(long, value_name = "SECS", default_value_t = 10)]
    step_timeout: u64,

    /// Seconds a check runs while the engine is suspended (it is expected to fail)
    #[arg(long, value_name = "SECS", default_value_t = 3)]
    suspended_check: u64,

    /// Log filter for stderr
    #[arg(long, value_name = "FILTER", default_value = "warn")]
    log: String,
}

/// Echo port of engine B.
const ECHO_PORT: u16 = 7;
/// Tunnel addresses.
const A_IP: Ipv4Addr = Ipv4Addr::new(10, 0, 0, 1);
const B_IP: Ipv4Addr = Ipv4Addr::new(10, 0, 0, 2);
/// A tunnel address no peer owns.
const NOWHERE: Ipv4Addr = Ipv4Addr::new(10, 0, 0, 99);
/// The MTU the `mtu` step sets.
const LOWER_MTU: u16 = 1280;
/// Interval of `Event::PeerStats`.
const STATS_INTERVAL: Duration = Duration::from_secs(2);

/// One engine of the pair.
struct Side {
    engine: Engine,
    stack: NetStackHandle,
    public_key: PublicKey,
    addr: SocketAddr,
    /// The MTU of the channel source merged next to the netstack.
    mtu: watch::Sender<u16>,
    /// Keeps the channel source open; nothing is sent on it.
    _packets: mpsc::Sender<PacketBuf>,
}

/// Builds an engine whose source merges a netstack with `tunnel` as its address and a
/// channel source, with a UDP transport on loopback port 0.
fn side(key: StaticSecret, tunnel: Ipv4Addr) -> anyhow::Result<Side> {
    let public_key = PublicKey::from(&key);
    let (stack, handle) = NetStack::new(NetStackConfig::new(
        vec![(IpAddr::V4(tunnel), 24)],
        DEFAULT_MTU,
    ));
    let (stack_source, sink) = stack.split();
    let (channel, packets, mtu) = ChannelSource::new(1, DEFAULT_MTU);
    let source = MergeSource::new().source(stack_source).source(channel);
    let udp = UdpTransport::bind(UDP_TRANSPORT, SocketAddr::from((Ipv4Addr::LOCALHOST, 0)))
        .context("cannot bind UDP on loopback")?;
    let addr = udp.local_addr();
    let engine = EngineBuilder::new(source, sink)
        .private_key(key)
        .transport(udp)
        .stats_interval(STATS_INTERVAL)
        .build()?;
    Ok(Side {
        engine,
        stack: handle,
        public_key,
        addr,
        mtu,
        _packets: packets,
    })
}

/// A host route to `addr`.
const fn host(addr: Ipv4Addr) -> AllowedIp {
    AllowedIp {
        addr: IpAddr::V4(addr),
        cidr: 32,
    }
}

/// `value` or `-`.
fn or_dash<T: std::fmt::Display>(value: Option<T>) -> String {
    value.map_or_else(|| "-".to_owned(), |value| value.to_string())
}

/// One line describing `event`.
fn describe(event: &Event) -> String {
    match event {
        Event::HandshakeCompleted { peer, path, rtt } => format!(
            "handshake peer={} via={} rtt={}",
            peer.get(),
            or_dash(path.map(|path| path.addr)),
            rtt.map_or_else(|| "-".to_owned(), |rtt| format!("{rtt:?}"))
        ),
        Event::Authenticated { peer, from } => {
            format!("authenticated peer={} from={}", peer.get(), from.addr)
        }
        Event::PathAdopted { peer, path } => {
            format!("path-adopted peer={} path={}", peer.get(), path.addr)
        }
        Event::SessionExpired { peer } => format!("session-expired peer={}", peer.get()),
        Event::PeerStats {
            peer,
            rx,
            tx,
            data_rx,
            data_tx,
            last_handshake,
        } => format!(
            "stats peer={} rx={rx} tx={tx} data_rx={data_rx} data_tx={data_tx} handshake={}",
            peer.get(),
            last_handshake.map_or_else(|| "never".to_owned(), |age| format!("{}s", age.as_secs()))
        ),
        Event::Dropped { peer, reason } => format!(
            "dropped peer={} reason={reason:?}",
            or_dash(peer.map(PeerId::get))
        ),
        Event::Suspended => "suspended".to_owned(),
        Event::Resumed => "resumed".to_owned(),
        Event::MtuChanged { mtu } => format!("mtu-changed mtu={mtu}"),
    }
}

/// Prints every event of `handle`'s engine as `EVENT <name> ...` until it stops.
async fn print_events(name: &'static str, handle: &EngineHandle) -> anyhow::Result<()> {
    let mut events = handle.subscribe().await?;
    tokio::spawn(async move {
        loop {
            match events.recv().await {
                Ok(event) => out::line(format_args!("EVENT {name} {}", describe(&event))),
                Err(RecvError::Lagged(n)) => {
                    out::line(format_args!("EVENT {name} lagged missed={n}"));
                }
                Err(RecvError::Closed) => return,
            }
        }
    });
    Ok(())
}

/// Waits until `events` yields an event `matches` accepts, or `limit` elapses.
async fn wait_event(
    events: &mut broadcast::Receiver<Event>,
    limit: Duration,
    matches: impl Fn(&Event) -> bool,
) -> bool {
    let deadline = Instant::now() + limit;
    loop {
        match timeout_at(deadline, events.recv()).await {
            Ok(Ok(event)) if matches(&event) => return true,
            Ok(Ok(_) | Err(RecvError::Lagged(_))) => {}
            Ok(Err(RecvError::Closed)) | Err(_) => return false,
        }
    }
}

/// The counters of `peer` on `handle`'s engine: `(rx, tx, data_rx, data_tx)`; prints a
/// `STATS` line.
async fn stats(
    label: &str,
    handle: &EngineHandle,
    peer: PeerId,
) -> anyhow::Result<(u64, u64, u64, u64)> {
    let stats = handle.peer_stats(peer).await?.context("the peer is gone")?;
    out::line(format_args!(
        "STATS {label} peer={} key={} rx={} tx={} data_rx={} data_tx={} handshake={}",
        peer.get(),
        encode_public_key(&stats.public_key),
        stats.rx,
        stats.tx,
        stats.data_rx,
        stats.data_tx,
        stats.last_handshake.map_or_else(
            || "never".to_owned(),
            |age| format!("{}s ago", age.as_secs())
        ),
    ));
    Ok((stats.rx, stats.tx, stats.data_rx, stats.data_tx))
}

/// The drop counters of `handle`'s engine; prints a `DROPS` line.
async fn drops(label: &str, handle: &EngineHandle) -> anyhow::Result<u64> {
    let counters = handle.drop_counters().await?;
    let listed: Vec<String> = counters
        .iter()
        .map(|(reason, n)| format!("{reason:?}={n}"))
        .collect();
    let listed = if listed.is_empty() {
        "none".to_owned()
    } else {
        listed.join(" ")
    };
    out::line(format_args!("DROPS {label} {listed}"));
    Ok(counters.get(reasons::NO_ROUTE).copied().unwrap_or(0))
}

/// Prints `STEP <name> PASS|FAIL`; returns `passed`.
fn step(name: &str, passed: bool) -> bool {
    out::line(format_args!(
        "STEP {name} {}",
        if passed { "PASS" } else { "FAIL" }
    ));
    passed
}

/// The steps against engine A, whose peer B is `peer`; whether all passed.
async fn steps(args: &Args, a: &Side, peer: PeerId) -> anyhow::Result<bool> {
    let handle = a.engine.handle();
    let backend = Backend::NetStack(a.stack.clone());
    let limit = Duration::from_secs(args.step_timeout);
    let udp = Check {
        proto: Proto::Udp,
        target: SocketAddr::from((B_IP, ECHO_PORT)),
    };
    let tcp = Check {
        proto: Proto::Tcp,
        ..udp
    };
    let mut passed = true;

    // 1. Handshake and traffic.
    let mut events = handle.subscribe().await?;
    let before = stats("a-before", &handle, peer).await?;
    let checks =
        echo::run_check(&backend, &tcp, limit).await & echo::run_check(&backend, &udp, limit).await;
    let handshake = wait_event(
        &mut events,
        limit,
        |event| matches!(event, Event::HandshakeCompleted { peer: p, .. } if *p == peer),
    )
    .await;
    let after = stats("a-traffic", &handle, peer).await?;
    let grew = after.0 > before.0 && after.1 > before.1 && after.2 > before.2 && after.3 > before.3;
    passed &= step("handshake", checks && handshake && grew);

    // 2. Suspended: no traffic, counters frozen.
    let mut events = handle.subscribe().await?;
    handle.suspend().await?;
    let suspended = wait_event(&mut events, limit, |event| *event == Event::Suspended).await;
    let frozen = stats("a-suspended", &handle, peer).await?;
    let check = echo::run_check(&backend, &udp, Duration::from_secs(args.suspended_check)).await;
    let still = stats("a-suspended-after-check", &handle, peer).await?;
    passed &= step("suspend", suspended && !check && still == frozen);

    // 3. Resumed: a new handshake, traffic again.
    let mut events = handle.subscribe().await?;
    handle.resume().await?;
    let resumed = wait_event(&mut events, limit, |event| *event == Event::Resumed).await;
    handle.force_handshake(peer, None).await?;
    let handshake = wait_event(
        &mut events,
        limit,
        |event| matches!(event, Event::HandshakeCompleted { peer: p, .. } if *p == peer),
    )
    .await;
    let check = echo::run_check(&backend, &udp, limit).await;
    let after = stats("a-resumed", &handle, peer).await?;
    passed &= step("resume", resumed && handshake && check && after.1 > still.1);

    // 4. MTU change of the packet source.
    let mut events = handle.subscribe().await?;
    let mtu_before = handle.mtu().await?;
    a.mtu.send(LOWER_MTU)?;
    let changed = wait_event(&mut events, limit, |event| {
        *event == Event::MtuChanged { mtu: LOWER_MTU }
    })
    .await;
    let mtu_after = handle.mtu().await?;
    out::line(format_args!("MTU a before={mtu_before} after={mtu_after}"));
    passed &= step("mtu", changed && mtu_after == LOWER_MTU);

    // 5. A drop: a datagram to an address no peer owns.
    let mut events = handle.subscribe().await?;
    let no_route_before = drops("a-before", &handle).await?;
    let socket = a
        .stack
        .bind_udp(SocketAddr::from((Ipv4Addr::UNSPECIFIED, 0)))
        .await?;
    socket
        .send_to(b"nobody", SocketAddr::from((NOWHERE, ECHO_PORT)))
        .await?;
    let dropped = wait_event(
        &mut events,
        limit,
        |event| matches!(event, Event::Dropped { reason, .. } if *reason == reasons::NO_ROUTE),
    )
    .await;
    let no_route_after = drops("a-after", &handle).await?;
    passed &= step("drop", dropped && no_route_after > no_route_before);
    Ok(passed)
}

#[tokio::main]
async fn main() -> anyhow::Result<ExitCode> {
    let args = Args::parse();
    init_logging(&args.log)?;
    let a = side(generate_key(), A_IP)?;
    let b = side(generate_key(), B_IP)?;
    out::line(format_args!(
        "NODE a key={} udp={} tunnel={A_IP}",
        encode_public_key(&a.public_key),
        a.addr
    ));
    out::line(format_args!(
        "NODE b key={} udp={} tunnel={B_IP}",
        encode_public_key(&b.public_key),
        b.addr
    ));
    print_events("a", &a.engine.handle()).await?;
    print_events("b", &b.engine.handle()).await?;

    // A dials B; B learns A's endpoint from the handshake.
    let mut b_on_a = PeerSpec::new(b.public_key);
    b_on_a.endpoint = Some(b.addr);
    b_on_a.allowed_ips = vec![host(B_IP)];
    let mut a_on_b = PeerSpec::new(a.public_key);
    a_on_b.allowed_ips = vec![host(A_IP)];
    configure_peers(&a.engine.handle(), &[b_on_a]).await?;
    configure_peers(&b.engine.handle(), &[a_on_b]).await?;
    echo::serve(&Backend::NetStack(b.stack.clone()), ECHO_PORT).await?;
    let peer = a
        .engine
        .handle()
        .peer_id(b.public_key)
        .await?
        .context("B is no peer of A")?;

    let passed = steps(&args, &a, peer).await?;

    // Let the events of the last step print before the engines stop.
    sleep(Duration::from_millis(100)).await;
    for (name, side) in [("a", a), ("b", b)] {
        drops(name, &side.engine.handle()).await?;
        side.engine.handle().shutdown().await?;
        side.engine.wait().await?;
    }
    out::line(format_args!(
        "STEPS {}",
        if passed { "PASS" } else { "FAIL" }
    ));
    Ok(if passed {
        ExitCode::SUCCESS
    } else {
        ExitCode::FAILURE
    })
}
