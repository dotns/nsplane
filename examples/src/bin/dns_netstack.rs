//! A DNS server on an address no interface owns, served by a transparent netstack.
//!
//! Two userspace stacks are wired back to back in one process, without engines, TUN or root:
//! a client stack (`10.0.0.1`) and a server stack that owns `10.0.0.2` and, in transparent
//! mode, terminates TCP and UDP to any destination in `10.53.0.0/16`. Each new connection or
//! flow is offered for admission: those to the DNS address `10.53.0.53:53` are accepted and
//! handed to an [`nsplane_dns::Server`], every other one is rejected (a RST or an ICMP port
//! unreachable from the dialed address). The resolver is [`StaticRecords`] falling back to a
//! [`FakePool`] on `198.18.0.0/15`, and with `--upstream` the pool hands queries of other
//! types to a [`Forwarder`].
//!
//! The client resolves a static name and a fake one over UDP and a fake one over TCP, maps
//! the fake address back to its name with [`FakePool::lookup`], checks that a connection to
//! another port of the DNS address is refused, and prints one `CHECK` line each, the server
//! counters and `CHECKS PASS` or `CHECKS FAIL`.
//!
//! APIs shown: [`NetStackConfig::transparent`] with [`TransparentConfig`] and
//! [`Admission::Decide`], [`NetStackHandle::incoming_pending`] ([`PendingFlow`]),
//! [`Server::serve_udp_flow`], [`Server::serve_tcp_connection`],
//! [`StaticRecords::with_fallback`], [`FakePool::with_fallback`], [`FakePool::lookup`].
//!
//! [`PendingFlow`]: nsplane_netstack::PendingFlow
//!
//! Usage: `cargo run -p nsplane-examples --bin dns_netstack -- [--upstream <IP:PORT>]`

use std::future::poll_fn;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::pin::Pin;
use std::process::ExitCode;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context as _, bail};
use clap::Parser;
use futures_core::Stream;
use nsplane::{PacketSink as _, PacketSource as _, PeerId};
use nsplane_dns::{
    FakePool, FakePoolConfig, Forwarder, ForwarderConfig, Record, RecordType, Resolver, Server,
    ServerConfig, StaticRecords,
};
use nsplane_examples::node::init_logging;
use nsplane_examples::out;
use nsplane_netstack::{
    Admission, DEFAULT_MTU, NetStack, NetStackConfig, NetStackHandle, NetStackSink, NetStackSource,
    TransparentConfig,
};
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio::time::timeout;

/// A transparent netstack answering DNS on an address it does not own.
#[derive(Debug, Parser)]
#[command(name = "dns_netstack", version)]
struct Args {
    /// Upstream DNS server for queries the fake pool does not answer (types other than A
    /// and AAAA); without it they get NODATA
    #[arg(long, value_name = "IP:PORT")]
    upstream: Option<SocketAddr>,

    /// Name queried through the upstream (TXT) when `--upstream` is given
    #[arg(long, value_name = "NAME", default_value = "example.com")]
    forward_name: String,

    /// Seconds each query waits for its response
    #[arg(long, value_name = "SECS", default_value_t = 5)]
    timeout: u64,

    /// Log filter for stderr
    #[arg(long, value_name = "FILTER", default_value = "warn")]
    log: String,
}

/// Address of the client stack.
const CLIENT_ADDR: IpAddr = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
/// The one address the server stack owns.
const SERVER_ADDR: IpAddr = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));
/// Prefix the server stack terminates transparently.
const TRANSPARENT_PREFIX: (IpAddr, u8) = (IpAddr::V4(Ipv4Addr::new(10, 53, 0, 0)), 16);
/// The DNS address: inside the prefix, not owned by the server stack.
const DNS: SocketAddr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 53, 0, 53)), 53);
/// Prefix of the fake addresses.
const FAKE_PREFIX: (Ipv4Addr, u8) = (Ipv4Addr::new(198, 18, 0, 0), 15);
/// The static record.
const STATIC_NAME: &str = "printer.lan";
const STATIC_ADDR: Ipv4Addr = Ipv4Addr::new(10, 0, 0, 7);

/// Forwards every packet from `from` to `to`.
async fn wire(mut from: NetStackSource, to: NetStackSink) {
    while let Ok(packet) = from.recv().await {
        if to.send(packet, PeerId::new(1)).await.is_err() {
            break;
        }
    }
}

/// The client stack and the transparent server stack, wired back to back.
fn stacks() -> (NetStackHandle, NetStackHandle) {
    let (client_stack, client) =
        NetStack::new(NetStackConfig::new(vec![(CLIENT_ADDR, 24)], DEFAULT_MTU));
    let mut config = NetStackConfig::new(vec![(SERVER_ADDR, 24)], DEFAULT_MTU);
    config.transparent = Some(TransparentConfig {
        prefixes: vec![TRANSPARENT_PREFIX],
        ..TransparentConfig::default()
    });
    config.admission = Admission::Decide {
        timeout: Duration::from_secs(1),
        max_pending: 64,
    };
    let (server_stack, server) = NetStack::new(config);
    let (client_source, client_sink) = client_stack.split();
    let (server_source, server_sink) = server_stack.split();
    tokio::spawn(wire(client_source, server_sink));
    tokio::spawn(wire(server_source, client_sink));
    (client, server)
}

async fn next<S: Stream + Unpin>(stream: &mut S) -> Option<S::Item> {
    poll_fn(|cx| Pin::new(&mut *stream).poll_next(cx)).await
}

/// Admits the connections and flows to [`DNS`] and serves them with `server`; rejects the
/// rest.
fn route<R: Resolver + 'static>(stack: &NetStackHandle, server: &Server<R>) {
    let mut pending = stack.incoming_pending();
    tokio::spawn(async move {
        while let Some(flow) = next(&mut pending).await {
            if flow.local_addr() == DNS {
                flow.accept();
            } else {
                tracing::info!(protocol = ?flow.protocol(), peer = %flow.peer_addr(), dst = %flow.local_addr(), "rejected");
                flow.reject();
            }
        }
    });
    let mut flows = stack.incoming_udp();
    let udp_server = server.clone();
    tokio::spawn(async move {
        while let Some(flow) = next(&mut flows).await {
            let server = udp_server.clone();
            tokio::spawn(async move { server.serve_udp_flow(flow).await });
        }
    });
    let mut connections = stack.incoming_tcp();
    let tcp_server = server.clone();
    tokio::spawn(async move {
        while let Some(conn) = next(&mut connections).await {
            let server = tcp_server.clone();
            tokio::spawn(async move {
                if let Err(err) = server.serve_tcp_connection(conn).await {
                    tracing::debug!(%err, "DNS TCP connection error");
                }
            });
        }
    });
}

/// A query for `name` of type `record_type`, class IN, recursion desired.
fn query(id: u16, name: &str, record_type: RecordType) -> anyhow::Result<Vec<u8>> {
    let mut message = Vec::with_capacity(64);
    message.extend_from_slice(&id.to_be_bytes());
    message.extend_from_slice(&[0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0]);
    for label in name.split('.') {
        let len = u8::try_from(label.len())
            .ok()
            .filter(|len| (1..64).contains(len))
            .with_context(|| format!("invalid label in `{name}`"))?;
        message.push(len);
        message.extend_from_slice(label.as_bytes());
    }
    message.push(0);
    message.extend_from_slice(&record_type.0.to_be_bytes());
    message.extend_from_slice(&nsplane_dns::CLASS_IN.to_be_bytes());
    Ok(message)
}

/// The parts of a response the checks look at.
#[derive(Debug)]
struct Response {
    id: u16,
    rcode: u8,
    answers: usize,
    addrs: Vec<IpAddr>,
}

fn bytes(message: &[u8], at: usize, len: usize) -> anyhow::Result<&[u8]> {
    message.get(at..at + len).context("response cut off")
}

fn u16_at(message: &[u8], at: usize) -> anyhow::Result<u16> {
    let raw = bytes(message, at, 2)?;
    Ok(u16::from_be_bytes([raw[0], raw[1]]))
}

/// The offset after the (possibly compressed) name at `at`.
fn skip_name(message: &[u8], mut at: usize) -> anyhow::Result<usize> {
    loop {
        let len = *message.get(at).context("response cut off")?;
        match len {
            0 => return Ok(at + 1),
            len if len & 0xc0 == 0xc0 => return Ok(at + 2),
            len => at += 1 + usize::from(len),
        }
    }
}

/// Parses the header, skips the question and collects the A and AAAA answers.
fn parse(message: &[u8]) -> anyhow::Result<Response> {
    let header = bytes(message, 0, 12)?;
    let id = u16::from_be_bytes([header[0], header[1]]);
    let rcode = header[3] & 0x0f;
    let questions = u16_at(message, 4)?;
    let answers = usize::from(u16_at(message, 6)?);
    let mut at = 12;
    for _ in 0..questions {
        at = skip_name(message, at)? + 4;
    }
    let mut addrs = Vec::new();
    for _ in 0..answers {
        at = skip_name(message, at)?;
        let record_type = RecordType(u16_at(message, at)?);
        let len = usize::from(u16_at(message, at + 8)?);
        let data = bytes(message, at + 10, len)?;
        if record_type == RecordType::A
            && let Ok(octets) = <[u8; 4]>::try_from(data)
        {
            addrs.push(IpAddr::V4(Ipv4Addr::from(octets)));
        } else if record_type == RecordType::AAAA
            && let Ok(octets) = <[u8; 16]>::try_from(data)
        {
            addrs.push(IpAddr::V6(Ipv6Addr::from(octets)));
        }
        at += 10 + len;
    }
    Ok(Response {
        id,
        rcode,
        answers,
        addrs,
    })
}

/// One query over UDP from the client stack.
async fn udp_exchange(
    client: &NetStackHandle,
    message: &[u8],
    wait: Duration,
) -> anyhow::Result<Response> {
    let mut socket = client.connect_udp(DNS).await?;
    socket.send(message).await?;
    let (response, from) = timeout(wait, socket.recv_from())
        .await
        .context("timed out")?
        .context("client stack stopped")?;
    if from != DNS {
        bail!("response from {from}");
    }
    parse(&response)
}

/// One query over TCP from the client stack, with two-byte length framing.
async fn tcp_exchange(
    client: &NetStackHandle,
    message: &[u8],
    wait: Duration,
) -> anyhow::Result<Response> {
    let mut conn = timeout(wait, client.connect_tcp(DNS))
        .await
        .context("connect timed out")??;
    let len = u16::try_from(message.len())?;
    conn.write_all(&len.to_be_bytes()).await?;
    conn.write_all(message).await?;
    let mut prefix = [0; 2];
    timeout(wait, conn.read_exact(&mut prefix))
        .await
        .context("timed out")??;
    let mut response = vec![0; usize::from(u16::from_be_bytes(prefix))];
    timeout(wait, conn.read_exact(&mut response))
        .await
        .context("timed out")??;
    parse(&response)
}

/// Prints the check line for `result` and returns whether it passed.
fn report(label: &str, result: anyhow::Result<String>) -> bool {
    match result {
        Ok(detail) => {
            out::line(format_args!("CHECK {label} {detail} PASS"));
            true
        }
        Err(err) => {
            out::line(format_args!("CHECK {label} FAIL {err:#}"));
            false
        }
    }
}

/// The single address of a NOERROR response to query `id`.
fn single_addr(response: &Response, id: u16) -> anyhow::Result<IpAddr> {
    if response.id != id || response.rcode != 0 {
        bail!("id={} rcode={}", response.id, response.rcode);
    }
    match response.addrs.as_slice() {
        [addr] => Ok(*addr),
        addrs => bail!("answers {addrs:?}"),
    }
}

/// Runs the server with `pool` behind the static records, then the client checks.
async fn run<F: Resolver + 'static>(args: &Args, pool: FakePool<F>) -> anyhow::Result<bool> {
    let wait = Duration::from_secs(args.timeout);
    let pool = Arc::new(pool);
    let records: StaticRecords =
        std::iter::once(Record::a(STATIC_NAME, 300, STATIC_ADDR)).collect();
    let server = Server::new(
        records.with_fallback(Arc::clone(&pool)),
        ServerConfig::default(),
    );
    let (client, server_stack) = stacks();
    route(&server_stack, &server);
    out::line(format_args!(
        "NODE dns={DNS} owned={SERVER_ADDR} transparent={}/{} fake={}/{}",
        TRANSPARENT_PREFIX.0, TRANSPARENT_PREFIX.1, FAKE_PREFIX.0, FAKE_PREFIX.1
    ));

    let mut passed = true;
    passed &= report(
        &format!("udp A {STATIC_NAME}"),
        async {
            let response =
                udp_exchange(&client, &query(1, STATIC_NAME, RecordType::A)?, wait).await?;
            let addr = single_addr(&response, 1)?;
            if addr != IpAddr::V4(STATIC_ADDR) {
                bail!("{addr}, want {STATIC_ADDR}");
            }
            Ok(addr.to_string())
        }
        .await,
    );

    let fake = async {
        let response =
            udp_exchange(&client, &query(2, "app.example", RecordType::A)?, wait).await?;
        single_addr(&response, 2)
    }
    .await;
    let fake_addr = fake.as_ref().ok().copied();
    passed &= report("udp A app.example", fake.map(|addr| addr.to_string()));

    passed &= report(
        "reverse",
        fake_addr.context("no fake address").and_then(|addr| {
            let name = pool.lookup(addr).context("not in the pool")?;
            if name != "app.example" {
                bail!("{addr} -> {name}");
            }
            Ok(format!("{addr} -> {name}"))
        }),
    );

    passed &= report(
        "tcp A api.example",
        async {
            let response =
                tcp_exchange(&client, &query(3, "api.example", RecordType::A)?, wait).await?;
            let addr = single_addr(&response, 3)?;
            if Some(addr) == fake_addr {
                bail!("{addr} reused");
            }
            Ok(addr.to_string())
        }
        .await,
    );

    let other = SocketAddr::new(DNS.ip(), 80);
    passed &= report(
        &format!("tcp {other} refused"),
        match timeout(wait, client.connect_tcp(other)).await {
            Ok(Err(err)) => Ok(err.kind().to_string()),
            Ok(Ok(_)) => Err(anyhow::anyhow!("connected")),
            Err(_) => Err(anyhow::anyhow!("timed out")),
        },
    );

    if args.upstream.is_some() {
        match udp_exchange(
            &client,
            &query(4, &args.forward_name, RecordType::TXT)?,
            wait,
        )
        .await
        {
            Ok(response) => out::line(format_args!(
                "FORWARD {} TXT rcode={} answers={}",
                args.forward_name, response.rcode, response.answers
            )),
            Err(err) => out::line(format_args!(
                "FORWARD {} TXT error {err:#}",
                args.forward_name
            )),
        }
    }

    let stats = server.stats();
    let net = server_stack.stats();
    out::line(format_args!(
        "STATS queries={} responses={} fake_bindings={} accepted={} rejected={}",
        stats.queries,
        stats.responses,
        pool.len(),
        net.accepted,
        net.rejected_hook
    ));
    Ok(passed)
}

#[tokio::main]
async fn main() -> anyhow::Result<ExitCode> {
    let args = Args::parse();
    init_logging(&args.log)?;
    let config = FakePoolConfig {
        ipv4: Some(FAKE_PREFIX),
        ..FakePoolConfig::default()
    };
    let pool = FakePool::new(config)?;
    let passed = match args.upstream {
        Some(upstream) => {
            let forwarder = Forwarder::new(ForwarderConfig::new(vec![upstream]))?;
            run(&args, pool.with_fallback(forwarder)).await?
        }
        None => run(&args, pool).await?,
    };
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
