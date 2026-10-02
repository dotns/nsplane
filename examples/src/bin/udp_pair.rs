//! Quick start: two engines in one process, talking over UDP on the loopback interface.
//!
//! Each engine gets a fresh key, a [`UdpTransport`] on an ephemeral loopback port and an
//! `nsplane-netstack` as its local side, so no TUN device and no root are needed. Engine B
//! serves TCP and UDP echo; engine A runs one TCP and one UDP check through the tunnel,
//! printing the handshake event, the check lines and both engines' peer stats.
//!
//! APIs shown: [`EngineBuilder`] (private key, transport, source and sink),
//! [`UdpTransport::bind`], [`EngineHandle::add_or_update_peer`] (through
//! `configure_peers`), [`EngineHandle::subscribe`] and [`Event::HandshakeCompleted`],
//! [`EngineHandle::peers`], [`NetStack`] as packet source and sink.
//!
//! Usage: `cargo run -p nsplane-examples --bin udp_pair -- [--ipv6]`
//!
//! [`EngineHandle::add_or_update_peer`]: nsplane::EngineHandle::add_or_update_peer
//! [`EngineHandle::subscribe`]: nsplane::EngineHandle::subscribe
//! [`EngineHandle::peers`]: nsplane::EngineHandle::peers

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::process::ExitCode;
use std::time::Duration;

use anyhow::Context as _;
use clap::Parser;
use nsplane::x25519::{PublicKey, StaticSecret};
use nsplane::{AllowedIp, Engine, EngineBuilder, Event, UdpTransport};
use nsplane_examples::echo::{self, Backend, Check, Proto};
use nsplane_examples::node::{
    PeerSpec, UDP_TRANSPORT, configure_peers, encode_public_key, generate_key, init_logging,
};
use nsplane_examples::out;
use nsplane_netstack::{DEFAULT_MTU, NetStack, NetStackConfig, NetStackHandle};
use tokio::sync::broadcast::error::RecvError;

/// Two engines over loopback UDP with netstacks: handshake, TCP and UDP echo, stats.
#[derive(Debug, Parser)]
#[command(name = "udp_pair", version)]
struct Args {
    /// Run over IPv6: UDP on `::1`, tunnel addresses `fd00::1` and `fd00::2`
    #[arg(long)]
    ipv6: bool,

    /// Seconds each check retries before it fails
    #[arg(long, value_name = "SECS", default_value_t = 10)]
    check_timeout: u64,

    /// Log filter for stderr
    #[arg(long, value_name = "FILTER", default_value = "warn")]
    log: String,
}

/// Echo port of engine B.
const ECHO_PORT: u16 = 7;

/// One engine of the pair.
struct Side {
    engine: Engine,
    stack: NetStackHandle,
    public_key: PublicKey,
    addr: SocketAddr,
}

/// Builds an engine on a netstack with `tunnel` as its address and a UDP transport on
/// `outer` port 0.
fn side(key: StaticSecret, tunnel: AllowedIp, outer: IpAddr) -> anyhow::Result<Side> {
    let public_key = PublicKey::from(&key);
    let (stack, handle) = NetStack::new(NetStackConfig::new(
        vec![(tunnel.addr, tunnel.cidr)],
        DEFAULT_MTU,
    ));
    let (source, sink) = stack.split();
    let udp = UdpTransport::bind(UDP_TRANSPORT, SocketAddr::new(outer, 0))
        .with_context(|| format!("cannot bind UDP on {outer}"))?;
    let addr = udp.local_addr();
    let engine = EngineBuilder::new(source, sink)
        .private_key(key)
        .transport(udp)
        .build()?;
    Ok(Side {
        engine,
        stack: handle,
        public_key,
        addr,
    })
}

/// A host route to `addr`.
const fn host(addr: IpAddr) -> AllowedIp {
    AllowedIp {
        addr,
        cidr: if addr.is_ipv4() { 32 } else { 128 },
    }
}

/// Prints the first completed handshake of `a`.
async fn print_handshake(a: &Engine) -> anyhow::Result<()> {
    let mut events = a.handle().subscribe().await?;
    tokio::spawn(async move {
        loop {
            match events.recv().await {
                Ok(Event::HandshakeCompleted { peer, path, rtt }) => {
                    let via = path.map_or_else(|| "-".to_owned(), |path| path.addr.to_string());
                    let rtt = rtt.map_or_else(|| "-".to_owned(), |rtt| format!("{rtt:?}"));
                    out::line(format_args!(
                        "EVENT handshake peer={} via={via} rtt={rtt}",
                        peer.get()
                    ));
                    return;
                }
                Ok(_) | Err(RecvError::Lagged(_)) => {}
                Err(RecvError::Closed) => return,
            }
        }
    });
    Ok(())
}

/// Prints every peer of `side`'s engine.
async fn print_peers(name: &str, side: &Side) -> anyhow::Result<()> {
    for peer in side.engine.handle().peers().await? {
        let endpoint = peer
            .path
            .map_or_else(|| "-".to_owned(), |path| path.addr.to_string());
        let handshake = peer.last_handshake.map_or_else(
            || "never".to_owned(),
            |elapsed| format!("{}s ago", elapsed.as_secs()),
        );
        out::line(format_args!(
            "PEER {name}->{} endpoint={endpoint} rx={} tx={} data_rx={} data_tx={} handshake={handshake}",
            encode_public_key(&peer.public_key),
            peer.rx,
            peer.tx,
            peer.data_rx,
            peer.data_tx,
        ));
    }
    Ok(())
}

#[tokio::main]
async fn main() -> anyhow::Result<ExitCode> {
    let args = Args::parse();
    init_logging(&args.log)?;
    let (outer, a_ip, b_ip, prefix) = if args.ipv6 {
        (
            IpAddr::V6(Ipv6Addr::LOCALHOST),
            IpAddr::V6(Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 1)),
            IpAddr::V6(Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 2)),
            64,
        )
    } else {
        (
            IpAddr::V4(Ipv4Addr::LOCALHOST),
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
            24,
        )
    };
    let a = side(
        generate_key(),
        AllowedIp {
            addr: a_ip,
            cidr: prefix,
        },
        outer,
    )?;
    let b = side(
        generate_key(),
        AllowedIp {
            addr: b_ip,
            cidr: prefix,
        },
        outer,
    )?;
    out::line(format_args!(
        "NODE a key={} udp={} tunnel={a_ip}",
        encode_public_key(&a.public_key),
        a.addr
    ));
    out::line(format_args!(
        "NODE b key={} udp={} tunnel={b_ip}",
        encode_public_key(&b.public_key),
        b.addr
    ));

    // A dials B; B learns A's endpoint from the handshake.
    let mut b_on_a = PeerSpec::new(b.public_key);
    b_on_a.endpoint = Some(b.addr);
    b_on_a.allowed_ips = vec![host(b_ip)];
    let mut a_on_b = PeerSpec::new(a.public_key);
    a_on_b.allowed_ips = vec![host(a_ip)];
    configure_peers(&a.engine.handle(), &[b_on_a]).await?;
    configure_peers(&b.engine.handle(), &[a_on_b]).await?;

    print_handshake(&a.engine).await?;
    echo::serve(&Backend::NetStack(b.stack.clone()), ECHO_PORT).await?;
    let target = SocketAddr::new(b_ip, ECHO_PORT);
    let checks = [
        Check {
            proto: Proto::Tcp,
            target,
        },
        Check {
            proto: Proto::Udp,
            target,
        },
    ];
    let passed = echo::run_checks(
        &Backend::NetStack(a.stack.clone()),
        &checks,
        Duration::from_secs(args.check_timeout),
    )
    .await;

    print_peers("a", &a).await?;
    print_peers("b", &b).await?;
    for side in [a, b] {
        side.engine.handle().shutdown().await?;
        side.engine.wait().await?;
    }
    Ok(if passed {
        ExitCode::SUCCESS
    } else {
        ExitCode::FAILURE
    })
}
