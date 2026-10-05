//! An iperf-like load generator on a node whose local side is an `nsplane-netstack`.
//!
//! Both ends run in process on the stack's [`NetStackHandle`] (no TUN, no root), so the
//! numbers measure the user-space data path: WireGuard engine plus userspace TCP/IP. The
//! `server` serves repeated runs; a `client` run prints one JSON line on stdout:
//!
//! - `tcp`: `--streams` bulk streams for `--duration`; the server counts the bytes it
//!   received and returns the count once the client's write half closed.
//! - `udp`: sequence-numbered datagrams paced at `--rate`; afterwards a TCP control
//!   connection asks the server how many of the flow's datagrams arrived.
//! - `rr`: `--count` round trips of 1-byte request and 1-byte response on one connection.
//!
//! Every TCP connection starts with one op byte (`T` bulk, `R` request/response, `U` UDP
//! result) so one port serves all modes.
//!
//! APIs shown: [`NetStack::new`] and [`NetStack::split`] as the engine's packet source and
//! sink, [`NetStackHandle`] (`connect_tcp`, `bind_udp`, `incoming_tcp`) and
//! [`TcpConnection`] as `AsyncRead`/`AsyncWrite`.
//!
//! Usage: `cargo run -p nsplane-examples --bin netstack_bench -- --private-key <KEY>
//! --listen 127.0.0.1:51821 --address 10.0.0.2/24 --peer
//! <PUBKEY>,endpoint=127.0.0.1:51820,allowed-ips=10.0.0.1/32 client --target 10.0.0.1:5201
//! --mode tcp --streams 4`

use std::collections::HashMap;
use std::future::poll_fn;
use std::io;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

use anyhow::{Context as _, bail};
use clap::{Parser, Subcommand, ValueEnum};
use futures_core::Stream;
use nsplane::AllowedIp;
use nsplane_examples::node::{NodeArgs, build_engine, configure_peers, init_logging, parse_cidr};
use nsplane_examples::out;
use nsplane_netstack::{DEFAULT_MTU, NetStack, NetStackConfig, NetStackHandle, TcpConnection};
use serde_json::json;
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio::time::{Instant, sleep, sleep_until, timeout_at};

/// Op byte of a bulk stream: the server counts bytes until EOF and answers the count.
const OP_BULK: u8 = b'T';
/// Op byte of a request/response connection: the server echoes each byte.
const OP_RR: u8 = b'R';
/// Op byte of a UDP result query: a `u16` source port in, the datagram count out.
const OP_UDP: u8 = b'U';

/// Payload of a UDP datagram before the MTU cap.
const UDP_PAYLOAD: usize = 1380;
/// How long the client retries the first connect while the handshake completes.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
/// How long the client waits after the last datagram before it asks for the count.
const UDP_SETTLE: Duration = Duration::from_secs(1);
/// Datagrams queued for the server's UDP socket: the stack's ingress capacity, so a burst
/// the driver routes in one step fits even before the counting task runs (see
/// [`NetStackConfig::datagram_capacity`]); the default 128 loses part of larger bursts.
const SERVER_DATAGRAM_CAPACITY: usize = 1024;

/// An nsplane node on a userspace TCP/IP stack with an in-process TCP/UDP load generator.
#[derive(Debug, Parser)]
#[command(name = "netstack_bench", version)]
struct Args {
    #[command(flatten)]
    node: NodeArgs,

    /// Address of the stack with its prefix, repeatable
    #[arg(long, value_name = "CIDR", value_parser = parse_cidr, required = true)]
    address: Vec<AllowedIp>,

    /// MTU of the stack
    #[arg(long, value_name = "N", default_value_t = DEFAULT_MTU)]
    mtu: u16,

    #[command(subcommand)]
    role: Role,
}

#[derive(Debug, Subcommand)]
enum Role {
    /// Serve TCP and UDP load on a port of the stack until Ctrl-C
    Server {
        /// TCP and UDP port
        #[arg(long, value_name = "PORT")]
        port: u16,
    },
    /// Run one measurement against a server and print one JSON line
    Client {
        /// The server's tunnel address and port
        #[arg(long, value_name = "IP:PORT")]
        target: SocketAddr,

        /// What to measure
        #[arg(long, value_enum)]
        mode: Mode,

        /// Parallel TCP streams (tcp)
        #[arg(long, value_name = "N", default_value_t = 1)]
        streams: usize,

        /// Seconds of load (tcp, udp)
        #[arg(long, value_name = "SECS", default_value_t = 10.0)]
        duration: f64,

        /// Offered payload rate in bits per second (udp, required)
        #[arg(long, value_name = "BITS_PER_SEC", required_if_eq("mode", "udp"))]
        rate: Option<u64>,

        /// Round trips (rr)
        #[arg(long, value_name = "N", default_value_t = 1000)]
        count: usize,
    },
}

#[derive(Debug, Clone, Copy, ValueEnum)]
enum Mode {
    /// Bulk TCP throughput
    Tcp,
    /// Paced UDP throughput and loss
    Udp,
    /// TCP request/response latency
    Rr,
}

/// Datagrams received per UDP flow (the client's tunnel address and port).
type Counts = Arc<Mutex<HashMap<SocketAddr, u64>>>;

/// The next item of `stream`.
async fn next<S: Stream + Unpin>(stream: &mut S) -> Option<S::Item> {
    poll_fn(|cx| Pin::new(&mut *stream).poll_next(cx)).await
}

/// Starts the server on `port` of `local`: TCP connections by op byte, UDP counted per flow.
async fn serve(stack: &NetStackHandle, local: SocketAddr) -> anyhow::Result<()> {
    let counts = Counts::default();
    let mut socket = stack
        .bind_udp(local)
        .await
        .with_context(|| format!("cannot bind UDP {local}"))?;
    let udp_counts = Arc::clone(&counts);
    tokio::spawn(async move {
        while let Ok((_, from)) = socket.recv_from().await {
            *udp_counts
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .entry(from)
                .or_default() += 1;
        }
    });
    let mut connections = stack.incoming_tcp();
    tokio::spawn(async move {
        while let Some(conn) = next(&mut connections).await {
            if conn.local_addr().port() != local.port() {
                continue;
            }
            let counts = Arc::clone(&counts);
            tokio::spawn(async move {
                let from = conn.peer_addr();
                if let Err(e) = serve_connection(conn, &counts).await {
                    tracing::debug!(%from, error = %e, "connection failed");
                }
            });
        }
    });
    tracing::info!(%local, "bench server serving");
    Ok(())
}

async fn serve_connection(mut conn: TcpConnection, counts: &Counts) -> io::Result<()> {
    match conn.read_u8().await? {
        OP_BULK => {
            let mut buf = vec![0; 64 * 1024];
            let mut total = 0_u64;
            loop {
                let n = conn.read(&mut buf).await?;
                if n == 0 {
                    break;
                }
                total += n as u64;
            }
            conn.write_u64(total).await?;
            conn.shutdown().await
        }
        OP_RR => {
            let mut byte = [0];
            while conn.read(&mut byte).await? == 1 {
                conn.write_all(&byte).await?;
            }
            conn.shutdown().await
        }
        OP_UDP => {
            let flow = SocketAddr::new(conn.peer_addr().ip(), conn.read_u16().await?);
            let received = counts
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .remove(&flow)
                .unwrap_or(0);
            conn.write_u64(received).await?;
            conn.shutdown().await
        }
        op => Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("unknown op byte {op:#04x}"),
        )),
    }
}

/// Connects to `target`, retrying while the WireGuard handshake completes.
async fn connect_retry(
    stack: &NetStackHandle,
    target: SocketAddr,
) -> anyhow::Result<TcpConnection> {
    let deadline = Instant::now() + CONNECT_TIMEOUT;
    loop {
        match timeout_at(deadline, stack.connect_tcp(target)).await {
            Ok(Ok(conn)) => return Ok(conn),
            Ok(Err(e)) if Instant::now() < deadline => {
                tracing::debug!(%target, error = %e, "connect failed, retrying");
                sleep(Duration::from_millis(200)).await;
            }
            Ok(Err(e)) => return Err(e).with_context(|| format!("cannot connect to {target}")),
            Err(_) => bail!("cannot connect to {target} within {CONNECT_TIMEOUT:?}"),
        }
    }
}

/// One bulk stream: writes until `deadline`, then returns the byte count the server read.
async fn bulk_stream(mut conn: TcpConnection, deadline: Instant) -> io::Result<u64> {
    let buf = vec![0; 64 * 1024];
    conn.write_u8(OP_BULK).await?;
    while let Ok(written) = timeout_at(deadline, conn.write_all(&buf)).await {
        written?;
    }
    conn.shutdown().await?;
    conn.read_u64().await
}

async fn run_tcp(
    stack: &NetStackHandle,
    target: SocketAddr,
    streams: usize,
    duration: Duration,
) -> anyhow::Result<serde_json::Value> {
    let mut conns = vec![connect_retry(stack, target).await?];
    for _ in 1..streams {
        conns.push(stack.connect_tcp(target).await.context("cannot connect")?);
    }
    let start = Instant::now();
    let tasks: Vec<_> = conns
        .into_iter()
        .map(|conn| tokio::spawn(bulk_stream(conn, start + duration)))
        .collect();
    let mut bytes = 0;
    for task in tasks {
        bytes += task.await?.context("a TCP stream failed")?;
    }
    let elapsed = start.elapsed().as_secs_f64();
    Ok(json!({
        "mode": "tcp",
        "streams": streams,
        "duration_s": elapsed,
        "bytes": bytes,
        "bits_per_second": 8.0 * float(bytes) / elapsed,
    }))
}

async fn run_udp(
    stack: &NetStackHandle,
    target: SocketAddr,
    mtu: u16,
    rate: u64,
    duration: Duration,
) -> anyhow::Result<serde_json::Value> {
    // The control connection also waits out the handshake before the load starts.
    let mut control = connect_retry(stack, target).await?;
    let local = SocketAddr::new(control.local_addr().ip(), 0);
    let socket = stack
        .bind_udp(local)
        .await
        .with_context(|| format!("cannot bind UDP {local}"))?;
    let headers = if target.is_ipv4() { 20 + 8 } else { 40 + 8 };
    let size = UDP_PAYLOAD
        .min(usize::from(mtu).saturating_sub(headers))
        .max(8);
    let mut payload = vec![0; size];
    let datagram_bits = 8 * size as u64;

    let start = Instant::now();
    let mut sent = 0_u64;
    loop {
        let elapsed = start.elapsed();
        let due = elapsed.min(duration).as_nanos() * u128::from(rate)
            / (u128::from(datagram_bits) * 1_000_000_000);
        while u128::from(sent) < due {
            payload[..8].copy_from_slice(&sent.to_be_bytes());
            socket
                .send_to(&payload, target)
                .await
                .context("UDP send failed")?;
            sent += 1;
        }
        if elapsed >= duration {
            break;
        }
        sleep(Duration::from_millis(1)).await;
    }
    let elapsed = start.elapsed().as_secs_f64();
    sleep_until(Instant::now() + UDP_SETTLE).await;

    control.write_u8(OP_UDP).await?;
    control.write_u16(socket.local_addr().port()).await?;
    let received = control.read_u64().await.context("no UDP result")?;
    let loss_pct = if sent == 0 {
        0.0
    } else {
        100.0 * float(sent.saturating_sub(received)) / float(sent)
    };
    Ok(json!({
        "mode": "udp",
        "rate_bps": rate,
        "duration_s": elapsed,
        "sent": sent,
        "received": received,
        "loss_pct": loss_pct,
        "bits_per_second": float(received * datagram_bits) / elapsed,
    }))
}

async fn run_rr(
    stack: &NetStackHandle,
    target: SocketAddr,
    count: usize,
) -> anyhow::Result<serde_json::Value> {
    let mut conn = connect_retry(stack, target).await?;
    conn.write_u8(OP_RR).await?;
    let mut rtts = Vec::with_capacity(count);
    let mut byte = [0];
    for _ in 0..count {
        let start = Instant::now();
        conn.write_all(&byte).await?;
        conn.read_exact(&mut byte).await.context("no response")?;
        rtts.push(start.elapsed().as_secs_f64() * 1e6);
    }
    conn.shutdown().await?;
    rtts.sort_by(f64::total_cmp);
    Ok(json!({
        "mode": "rr",
        "count": count,
        "p50_us": percentile(&rtts, 50),
        "p99_us": percentile(&rtts, 99),
    }))
}

/// `n` as a float, exact below 2^53.
fn float(n: u64) -> f64 {
    let high = u32::try_from(n >> 32).unwrap_or(u32::MAX);
    let low = u32::try_from(n & u64::from(u32::MAX)).unwrap_or(u32::MAX);
    f64::from(high).mul_add(4_294_967_296.0, f64::from(low))
}

/// The nearest-rank `p`th percentile of the sorted `values`, 0 if empty.
fn percentile(values: &[f64], p: usize) -> f64 {
    let rank = (values.len() * p).div_ceil(100).max(1);
    values.get(rank - 1).copied().unwrap_or(0.0)
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args = Args::parse();
    init_logging(&args.node.log)?;
    let addresses = args.address.iter().map(|ip| (ip.addr, ip.cidr)).collect();
    let mut config = NetStackConfig::new(addresses, args.mtu);
    if matches!(args.role, Role::Server { .. }) {
        config.datagram_capacity = SERVER_DATAGRAM_CAPACITY;
    }
    let (stack, handle) = NetStack::new(config);
    let (source, sink) = stack.split();
    let node = build_engine(source, sink, &args.node)?;
    let engine = node.engine.handle();
    configure_peers(&engine, &args.node.peer).await?;
    tracing::info!(listen = %node.transports.listen, "netstack bench node started");

    let wait = node.engine.wait();
    tokio::pin!(wait);
    match args.role {
        Role::Server { port } => {
            serve(&handle, SocketAddr::new(args.address[0].addr, port)).await?;
            tokio::select! {
                signal = tokio::signal::ctrl_c() => {
                    signal.context("cannot watch Ctrl-C")?;
                    tracing::info!("Ctrl-C received, shutting down");
                }
                stopped = &mut wait => {
                    stopped.context("the engine failed")?;
                    bail!("the engine stopped");
                }
            }
        }
        Role::Client {
            target,
            mode,
            streams,
            duration,
            rate,
            count,
        } => {
            let duration = Duration::try_from_secs_f64(duration).context("invalid --duration")?;
            let result = tokio::select! {
                result = async {
                    match mode {
                        Mode::Tcp => run_tcp(&handle, target, streams.max(1), duration).await,
                        Mode::Udp => {
                            let rate = rate.context("--rate is required for udp")?;
                            run_udp(&handle, target, args.mtu, rate, duration).await
                        }
                        Mode::Rr => run_rr(&handle, target, count).await,
                    }
                } => result?,
                stopped = &mut wait => {
                    stopped.context("the engine failed")?;
                    bail!("the engine stopped");
                }
            };
            out::line(format_args!("{result}"));
        }
    }
    let _ = engine.shutdown().await;
    wait.await.context("the engine failed")?;
    Ok(())
}
