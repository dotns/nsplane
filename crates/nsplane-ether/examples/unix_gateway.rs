//! A gateway for one guest on a Unix socket: the adapter in front of a user-space stack
//! that answers TCP on every port with one line, `echo <line>`, then closes.
//!
//! Listens on the socket path given as the only argument and serves the first connection,
//! a guest runtime speaking the length-prefixed frame protocol (QEMU's `-netdev stream`).
//! The guest gets `10.0.2.15/24` by DHCP with gateway `10.0.2.2`, and the prefix
//! `fd00:1::/64` with gateway `fd00:1::1` by router advertisement. Exits when the guest
//! disconnects, printing the adapter counters.
//!
//! ```text
//! cargo run -p nsplane-ether --example unix_gateway -- /tmp/guest.sock
//! ```

use std::error::Error;
use std::fmt;
use std::future::poll_fn;
use std::io::{self, Write};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::pin::Pin;

use futures_core::Stream;
use nsplane::{PacketSink, PacketSource, PeerId};
use nsplane_ether::{DhcpConfig, EtherConfig, MacAddr, spawn_port, stream};
use nsplane_netstack::{NetStack, NetStackConfig, TcpConnection};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::UnixListener;

const GW_MAC: MacAddr = MacAddr([0x02, 0x00, 0x00, 0x00, 0x00, 0x01]);
const GW_IP: Ipv4Addr = Ipv4Addr::new(10, 0, 2, 2);
const GUEST_IP: Ipv4Addr = Ipv4Addr::new(10, 0, 2, 15);
const PREFIX: Ipv6Addr = Ipv6Addr::new(0xfd00, 1, 0, 0, 0, 0, 0, 0);
const GW_IPV6: Ipv6Addr = Ipv6Addr::new(0xfd00, 1, 0, 0, 0, 0, 0, 1);

fn config() -> EtherConfig {
    EtherConfig {
        gateway_ipv4: Some(GW_IP),
        gateway_ipv6: Some(GW_IPV6),
        ipv6_prefix: Some(PREFIX),
        ipv6_dns: vec![GW_IPV6],
        dhcp: Some(DhcpConfig {
            router: Some(GW_IP),
            dns: vec![GW_IP],
            ..DhcpConfig::new(GW_IP, GUEST_IP, 24)
        }),
        ..EtherConfig::new(GW_MAC)
    }
}

/// Prints one line to stdout; a closed stdout is ignored.
fn say(args: fmt::Arguments<'_>) {
    let mut stdout = io::stdout().lock();
    let _ = writeln!(stdout, "{args}");
    let _ = stdout.flush();
}

/// Forwards every packet from `from` to `to`.
async fn forward(mut from: impl PacketSource, to: impl PacketSink) {
    while let Ok(packet) = from.recv().await {
        if to.send(packet, PeerId::new(1)).await.is_err() {
            break;
        }
    }
}

/// Reads one line from `conn` and answers `echo <line>`.
async fn echo(conn: TcpConnection) -> io::Result<()> {
    let peer = conn.peer_addr();
    let local = conn.local_addr();
    let mut conn = BufReader::new(conn);
    let mut line = String::new();
    conn.read_line(&mut line).await?;
    let line = line.trim_end();
    say(format_args!("tcp {peer} -> {local}: {line:?}"));
    conn.write_all(format!("echo {line}\n").as_bytes()).await?;
    conn.shutdown().await
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let path = std::env::args()
        .nth(1)
        .ok_or("usage: unix_gateway <socket path>")?;
    let listener = UnixListener::bind(&path)?;
    say(format_args!("listening on {path}"));
    let (conn, _) = listener.accept().await?;
    say(format_args!("guest connected"));

    let (reader, writer) = stream::unix(conn);
    let (source, sink, handle) = spawn_port(reader, writer, config());
    let (stack, net) = NetStack::new(NetStackConfig::new(
        vec![(IpAddr::V4(GW_IP), 24), (IpAddr::V6(GW_IPV6), 64)],
        config().mtu,
    ));
    let (stack_source, stack_sink) = stack.split();
    let to_stack = tokio::spawn(forward(source, stack_sink));
    tokio::spawn(forward(stack_source, sink));

    let mut incoming = net.incoming_tcp();
    tokio::spawn(async move {
        while let Some(conn) = poll_fn(|cx| Pin::new(&mut incoming).poll_next(cx)).await {
            tokio::spawn(async move {
                if let Err(err) = echo(conn).await {
                    say(format_args!("tcp echo failed: {err}"));
                }
            });
        }
    });

    to_stack.await?;
    say(format_args!(
        "guest disconnected, guest MAC {:?}",
        handle.guest_mac()
    ));
    say(format_args!("{:?}", handle.stats()));
    Ok(())
}
