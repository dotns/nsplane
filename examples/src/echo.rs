//! TCP and UDP echo servers and checks, on the kernel stack or an `nsplane-netstack`.
//!
//! A node with `--echo-port` echoes TCP and UDP on that port of all its local addresses;
//! each `--check` connects through the tunnel and verifies the echo. The [`Backend`] picks
//! the stack: tokio sockets on the host's kernel stack (TUN nodes), or a
//! [`NetStackHandle`] (netstack nodes).
//!
//! Every check prints one line to stdout, `CHECK <tcp|udp> <ip:port> PASS <ms>ms` or
//! `CHECK <tcp|udp> <ip:port> FAIL <reason>`, and once all ran, `CHECKS PASS` or
//! `CHECKS FAIL`.

use std::fmt;
use std::future::poll_fn;
use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::pin::Pin;
use std::str::FromStr;
use std::time::{Duration, Instant};

use anyhow::{Context as _, anyhow, bail};
use clap::Args;
use futures_core::Stream;
use nsplane_netstack::NetStackHandle;
use tokio::io::{AsyncRead, AsyncReadExt as _, AsyncWrite, AsyncWriteExt as _};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::time::{sleep, timeout};

use crate::out;

/// Bytes a TCP check sends.
pub const TCP_CHECK_LEN: usize = 1024;
/// Bytes of a UDP check datagram.
pub const UDP_CHECK_LEN: usize = 512;
/// Interval between UDP check datagrams and between failed attempts.
pub const RETRY_INTERVAL: Duration = Duration::from_millis(500);

/// Echo and check options, flattened into the node examples.
#[derive(Debug, Clone, Args)]
pub struct EchoArgs {
    /// Serve TCP and UDP echo on this port of all local addresses
    #[arg(long, value_name = "PORT")]
    pub echo_port: Option<u16>,

    /// Check an echo server through the tunnel, repeatable: `tcp:10.0.0.2:7`, `udp:[fd00::2]:7`
    #[arg(long, value_name = "PROTO:IP:PORT")]
    pub check: Vec<Check>,

    /// Seconds each check retries before it fails
    #[arg(long, value_name = "SECS", default_value_t = 30)]
    pub check_timeout: u64,

    /// Exit once all checks ran: code 0 iff all passed
    #[arg(long)]
    pub exit_after_checks: bool,
}

impl EchoArgs {
    /// Starts the echo servers of `--echo-port`, if set, on `backend`.
    pub async fn serve(&self, backend: &Backend) -> anyhow::Result<()> {
        match self.echo_port {
            Some(port) => serve(backend, port).await,
            None => Ok(()),
        }
    }

    /// Runs every `--check`; `None` without checks, otherwise whether all passed.
    pub async fn run_checks(&self, backend: &Backend) -> Option<bool> {
        if self.check.is_empty() {
            return None;
        }
        let limit = Duration::from_secs(self.check_timeout);
        Some(run_checks(backend, &self.check, limit).await)
    }
}

/// The stack echo servers and checks run on.
#[derive(Debug, Clone)]
pub enum Backend {
    /// The host's kernel stack, through tokio sockets (a TUN node).
    Kernel,
    /// A userspace stack.
    NetStack(NetStackHandle),
}

/// The protocol of a [`Check`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Proto {
    /// TCP: connect, write, half close, read the echo to EOF.
    Tcp,
    /// UDP: one datagram every 500 ms until it comes back.
    Udp,
}

impl fmt::Display for Proto {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Tcp => "tcp",
            Self::Udp => "udp",
        })
    }
}

/// One `--check`: `<tcp|udp>:<ip:port>`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Check {
    /// The protocol.
    pub proto: Proto,
    /// The echo server.
    pub target: SocketAddr,
}

impl FromStr for Check {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> anyhow::Result<Self> {
        let (proto, target) = s
            .split_once(':')
            .ok_or_else(|| anyhow!("`{s}` is not `<tcp|udp>:<ip:port>`"))?;
        let proto = match proto {
            "tcp" => Proto::Tcp,
            "udp" => Proto::Udp,
            _ => bail!("unknown protocol `{proto}`, expected tcp or udp"),
        };
        let target = target
            .parse()
            .with_context(|| format!("invalid address `{target}`"))?;
        Ok(Self { proto, target })
    }
}

/// `len` deterministic bytes (period 251, so it does not line up with segment sizes).
pub fn pattern(len: usize) -> Vec<u8> {
    (0..len).map(|i| (i % 251).to_le_bytes()[0]).collect()
}

/// Runs `checks` one after the other, then prints `CHECKS PASS` or `CHECKS FAIL`;
/// returns whether all passed.
pub async fn run_checks(backend: &Backend, checks: &[Check], limit: Duration) -> bool {
    let mut passed = true;
    for check in checks {
        passed &= run_check(backend, check, limit).await;
    }
    out::line(format_args!(
        "CHECKS {}",
        if passed { "PASS" } else { "FAIL" }
    ));
    passed
}

/// Runs one check, retrying until it passes or `limit` elapsed, and prints its line;
/// returns whether it passed.
pub async fn run_check(backend: &Backend, check: &Check, limit: Duration) -> bool {
    let start = Instant::now();
    let deadline = start + limit;
    let result = match check.proto {
        Proto::Tcp => retry(deadline, || tcp_check(backend, check.target)).await,
        Proto::Udp => udp_check(backend, check.target, deadline).await,
    };
    match result {
        Ok(()) => {
            let ms = start.elapsed().as_millis();
            out::line(format_args!(
                "CHECK {} {} PASS {ms}ms",
                check.proto, check.target
            ));
            true
        }
        Err(e) => {
            out::line(format_args!(
                "CHECK {} {} FAIL {e:#}",
                check.proto, check.target
            ));
            false
        }
    }
}

/// Runs `attempt` until it succeeds or `deadline` passes, pausing between attempts.
async fn retry<F, Fut>(deadline: Instant, mut attempt: F) -> anyhow::Result<()>
where
    F: FnMut() -> Fut,
    Fut: Future<Output = anyhow::Result<()>>,
{
    loop {
        let remaining = deadline.saturating_duration_since(Instant::now());
        let error = match timeout(remaining, attempt()).await {
            Ok(Ok(())) => return Ok(()),
            Ok(Err(e)) => e,
            Err(_) => anyhow!("timed out"),
        };
        if Instant::now() + RETRY_INTERVAL >= deadline {
            return Err(error);
        }
        tracing::debug!(
            error = format!("{error:#}"),
            "check attempt failed, retrying"
        );
        sleep(RETRY_INTERVAL).await;
    }
}

/// One TCP attempt: connect, write the pattern, shut the write half down, read to EOF and
/// compare.
async fn tcp_check(backend: &Backend, target: SocketAddr) -> anyhow::Result<()> {
    match backend {
        Backend::Kernel => tcp_round_trip(TcpStream::connect(target).await?).await,
        Backend::NetStack(stack) => tcp_round_trip(stack.connect_tcp(target).await?).await,
    }
}

async fn tcp_round_trip<S: AsyncRead + AsyncWrite>(stream: S) -> anyhow::Result<()> {
    let sent = pattern(TCP_CHECK_LEN);
    let (mut reader, mut writer) = tokio::io::split(stream);
    let write = async {
        writer.write_all(&sent).await?;
        writer.shutdown().await
    };
    let read = async {
        let mut echoed = Vec::with_capacity(TCP_CHECK_LEN);
        reader.read_to_end(&mut echoed).await?;
        Ok::<_, io::Error>(echoed)
    };
    let ((), echoed) = tokio::try_join!(write, read)?;
    if echoed != sent {
        bail!(
            "{} of {TCP_CHECK_LEN} bytes echoed, or changed",
            echoed.len()
        );
    }
    Ok(())
}

/// The unspecified address of `target`'s family, port 0.
const fn any_of(target: SocketAddr) -> SocketAddr {
    match target {
        SocketAddr::V4(_) => SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0),
        SocketAddr::V6(_) => SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 0),
    }
}

/// A bound UDP socket on either backend.
enum CheckSocket {
    Kernel(UdpSocket),
    NetStack(nsplane_netstack::UdpSocket),
}

impl CheckSocket {
    async fn bind(backend: &Backend, target: SocketAddr) -> io::Result<Self> {
        Ok(match backend {
            Backend::Kernel => Self::Kernel(UdpSocket::bind(any_of(target)).await?),
            Backend::NetStack(stack) => Self::NetStack(stack.bind_udp(any_of(target)).await?),
        })
    }

    async fn send_to(&self, payload: &[u8], target: SocketAddr) -> io::Result<()> {
        match self {
            Self::Kernel(socket) => socket.send_to(payload, target).await.map(drop),
            Self::NetStack(socket) => socket.send_to(payload, target).await,
        }
    }

    async fn recv(&mut self) -> io::Result<Vec<u8>> {
        match self {
            Self::Kernel(socket) => {
                let mut buf = vec![0; 65_536];
                let (len, _) = socket.recv_from(&mut buf).await?;
                buf.truncate(len);
                Ok(buf)
            }
            Self::NetStack(socket) => Ok(socket.recv_from().await?.0.to_vec()),
        }
    }
}

/// Sends the pattern datagram every [`RETRY_INTERVAL`] until it comes back or `deadline`
/// passes.
async fn udp_check(backend: &Backend, target: SocketAddr, deadline: Instant) -> anyhow::Result<()> {
    let sent = pattern(UDP_CHECK_LEN);
    let mut last_error = anyhow!("no echo");
    let mut socket = None;
    while Instant::now() < deadline {
        if socket.is_none() {
            match CheckSocket::bind(backend, target).await {
                Ok(bound) => socket = Some(bound),
                Err(e) => last_error = anyhow!(e).context("cannot bind"),
            }
        }
        let Some(bound) = socket.as_mut() else {
            sleep(RETRY_INTERVAL).await;
            continue;
        };
        if let Err(e) = bound.send_to(&sent, target).await {
            last_error = anyhow!(e).context("cannot send");
        }
        let wait = RETRY_INTERVAL.min(deadline.saturating_duration_since(Instant::now()));
        let until = Instant::now() + wait;
        // Read everything that arrives within the interval; stale echoes are skipped.
        while let Ok(received) = timeout(
            until.saturating_duration_since(Instant::now()),
            bound.recv(),
        )
        .await
        {
            match received {
                Ok(echoed) if echoed == sent => return Ok(()),
                Ok(_) => last_error = anyhow!("the echo changed the datagram"),
                Err(e) => {
                    last_error = anyhow!(e).context("cannot receive");
                    sleep(until.saturating_duration_since(Instant::now())).await;
                    break;
                }
            }
        }
    }
    Err(last_error.context("timed out"))
}

/// Starts TCP and UDP echo servers on `port` of all local addresses of `backend`.
///
/// Kernel: binds `[::]:port` (dual stack where the host allows it) and `0.0.0.0:port`
/// unless the IPv6 socket already covers IPv4. Netstack: takes the stack's incoming TCP
/// connections and UDP flows (only one taker per stack) and echoes those to `port`.
pub async fn serve(backend: &Backend, port: u16) -> anyhow::Result<()> {
    match backend {
        Backend::Kernel => serve_kernel(port).await,
        Backend::NetStack(stack) => {
            serve_netstack(stack, port);
            Ok(())
        }
    }
}

async fn serve_kernel(port: u16) -> anyhow::Result<()> {
    let v6 = SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), port);
    let v4 = SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), port);
    let mut bound = 0;
    for addr in [v6, v4] {
        match (TcpListener::bind(addr).await, UdpSocket::bind(addr).await) {
            (Ok(tcp), Ok(udp)) => {
                tokio::spawn(tcp_echo_kernel(tcp));
                tokio::spawn(udp_echo_kernel(udp));
                bound += 1;
            }
            // `[::]` covers IPv4 already, or the host has no IPv6.
            (Err(e), _) | (_, Err(e)) => {
                tracing::debug!(%addr, error = %e, "echo not bound");
            }
        }
    }
    if bound == 0 {
        bail!("cannot bind the echo servers on port {port}");
    }
    tracing::info!(port, "echo serving on the kernel stack");
    Ok(())
}

async fn tcp_echo_kernel(listener: TcpListener) {
    loop {
        match listener.accept().await {
            Ok((stream, from)) => {
                tracing::debug!(%from, "TCP echo connection");
                tokio::spawn(echo_stream(stream));
            }
            Err(e) => tracing::warn!(error = %e, "TCP echo accept failed"),
        }
    }
}

async fn udp_echo_kernel(socket: UdpSocket) {
    let mut buf = vec![0; 65_536];
    loop {
        match socket.recv_from(&mut buf).await {
            Ok((len, from)) => {
                if let Err(e) = socket.send_to(&buf[..len], from).await {
                    tracing::debug!(%from, error = %e, "UDP echo reply failed");
                }
            }
            Err(e) => tracing::debug!(error = %e, "UDP echo receive failed"),
        }
    }
}

/// Copies everything read back to the writer, then closes the write half.
async fn echo_stream<S: AsyncRead + AsyncWrite>(stream: S) {
    let (mut reader, mut writer) = tokio::io::split(stream);
    let copied = async {
        tokio::io::copy(&mut reader, &mut writer).await?;
        writer.shutdown().await
    };
    if let Err(e) = copied.await {
        tracing::debug!(error = %e, "TCP echo failed");
    }
}

/// The next item of `stream`.
async fn next<S: Stream + Unpin>(stream: &mut S) -> Option<S::Item> {
    poll_fn(|cx| Pin::new(&mut *stream).poll_next(cx)).await
}

fn serve_netstack(stack: &NetStackHandle, port: u16) {
    let mut connections = stack.incoming_tcp();
    tokio::spawn(async move {
        while let Some(conn) = next(&mut connections).await {
            if conn.local_addr().port() == port {
                tracing::debug!(from = %conn.peer_addr(), "TCP echo connection");
                tokio::spawn(echo_stream(conn));
            }
        }
    });
    let mut flows = stack.incoming_udp();
    tokio::spawn(async move {
        while let Some(mut flow) = next(&mut flows).await {
            if flow.local_addr().port() != port {
                continue;
            }
            tokio::spawn(async move {
                while let Some(datagram) = flow.recv().await {
                    if let Err(e) = flow.send(&datagram).await {
                        tracing::debug!(error = %e, "UDP echo reply failed");
                    }
                }
            });
        }
    });
    tracing::info!(port, "echo serving on the netstack");
}
