//! [`Forwarder`]: a resolver that asks upstream DNS servers.

use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::atomic::{AtomicU16, AtomicU64, Ordering};
use std::time::Duration;

use bytes::Bytes;
use simple_dns::{Packet, PacketFlag, header_buffer};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};
use tokio::time::{Instant, timeout, timeout_at};

use crate::message::{Answer, Query, ResponseCode, normalize_name};
use crate::resolver::Resolver;

/// Receive buffer for UDP responses: the largest datagram an upstream can send.
const MAX_UDP_RESPONSE: usize = 65535;

/// Upstream servers and retry policy of a [`Forwarder`].
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct ForwarderConfig {
    /// Upstream servers, asked in order. Must not be empty.
    pub upstreams: Vec<SocketAddr>,
    /// Time limit of one attempt (the UDP exchange, then the TCP retry on its own). Default 2 s.
    pub timeout: Duration,
    /// Attempts per query, rotating through `upstreams` in order. Must be at least 1.
    /// Default 2.
    pub attempts: usize,
}

impl ForwarderConfig {
    /// A configuration with the default timeout and attempts.
    pub const fn new(upstreams: Vec<SocketAddr>) -> Self {
        Self {
            upstreams,
            timeout: Duration::from_secs(2),
            attempts: 2,
        }
    }
}

/// Why a [`ForwarderConfig`] is rejected.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum ForwarderError {
    /// `upstreams` is empty.
    #[error("no upstream servers")]
    NoUpstreams,
    /// `attempts` is zero.
    #[error("zero attempts")]
    NoAttempts,
}

/// Counters of a [`Forwarder`] since it was created.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct ForwarderStats {
    /// Queries answered with an upstream response.
    pub forwarded: u64,
    /// Attempts that ran out of time.
    pub timeouts: u64,
    /// Truncated UDP responses retried over TCP.
    pub tcp_retries: u64,
    /// Queries answered `SERVFAIL` because every attempt failed.
    pub failures: u64,
}

#[derive(Debug, Default)]
struct Counters {
    forwarded: AtomicU64,
    timeouts: AtomicU64,
    tcp_retries: AtomicU64,
    failures: AtomicU64,
}

/// Forwards queries to upstream servers and answers with their response ([`Answer::Raw`]).
///
/// Each attempt sends the client's query, under a fresh transaction ID, from a new ephemeral
/// UDP socket connected to the upstream. Only a response with that ID and the query's
/// question (name compared case-insensitively, type and class) is accepted; other datagrams
/// are ignored until the attempt times out. A truncated response (`TC` = 1) is retried over
/// TCP to the same upstream. Attempts rotate through the upstreams in order; when all fail
/// (timeout, ICMP refusal, I/O error) the answer is `SERVFAIL`. Any accepted response is
/// final, whatever its response code.
///
/// The transaction ID mixes a counter with the socket's port and is not cryptographically
/// random: resistance against spoofed responses comes mostly from the random ephemeral
/// source port the system picks for every attempt.
///
/// The forwarder has no cache and no policy: it forwards every query it gets. To answer some
/// names locally, put it behind other resolvers with [`Fallback`](crate::Fallback), for example
/// `StaticRecords::with_fallback(forwarder)`.
#[derive(Debug)]
pub struct Forwarder {
    config: ForwarderConfig,
    next_id: AtomicU16,
    counters: Counters,
}

impl Forwarder {
    /// A forwarder for `config`.
    ///
    /// # Errors
    ///
    /// [`ForwarderError`] when `upstreams` is empty or `attempts` is zero.
    pub fn new(config: ForwarderConfig) -> Result<Self, ForwarderError> {
        if config.upstreams.is_empty() {
            return Err(ForwarderError::NoUpstreams);
        }
        if config.attempts == 0 {
            return Err(ForwarderError::NoAttempts);
        }
        Ok(Self {
            config,
            next_id: AtomicU16::new(0),
            counters: Counters::default(),
        })
    }

    /// The configuration.
    pub const fn config(&self) -> &ForwarderConfig {
        &self.config
    }

    /// A snapshot of the counters.
    pub fn stats(&self) -> ForwarderStats {
        let c = &self.counters;
        ForwarderStats {
            forwarded: c.forwarded.load(Ordering::Relaxed),
            timeouts: c.timeouts.load(Ordering::Relaxed),
            tcp_retries: c.tcp_retries.load(Ordering::Relaxed),
            failures: c.failures.load(Ordering::Relaxed),
        }
    }

    /// One attempt against `upstream`: UDP, then TCP when the response is truncated.
    async fn attempt(
        &self,
        query: &Query,
        upstream: SocketAddr,
        buf: &mut [u8],
    ) -> Result<Bytes, AttemptError> {
        let socket = UdpSocket::bind(unspecified(upstream)).await?;
        socket.connect(upstream).await?;
        let id = self.transaction_id(socket.local_addr()?.port());
        let mut message = query.raw().to_vec();
        message[..2].copy_from_slice(&id.to_be_bytes());

        let deadline = Instant::now() + self.config.timeout;
        let udp = timeout_at(deadline, async {
            socket.send(&message).await?;
            loop {
                let len = socket.recv(buf).await?;
                let response = &buf[..len];
                if matches_query(response, id, query) {
                    if header_buffer::has_flags(response, PacketFlag::TRUNCATION).unwrap_or(false) {
                        return Ok(None);
                    }
                    return Ok::<_, io::Error>(Some(Bytes::copy_from_slice(response)));
                }
            }
        })
        .await??;
        if let Some(response) = udp {
            return Ok(response);
        }

        self.counters.tcp_retries.fetch_add(1, Ordering::Relaxed);
        let response = timeout(self.config.timeout, exchange_tcp(upstream, &message)).await??;
        if matches_query(&response, id, query) {
            Ok(response)
        } else {
            Err(AttemptError::Failed)
        }
    }

    fn transaction_id(&self, port: u16) -> u16 {
        let count = self.next_id.fetch_add(1, Ordering::Relaxed);
        count.wrapping_mul(0x9e37) ^ port.rotate_left(7)
    }
}

impl Resolver for Forwarder {
    async fn resolve(&self, query: &Query, _client: SocketAddr) -> Answer {
        let upstreams = &self.config.upstreams;
        let mut buf = vec![0; MAX_UDP_RESPONSE];
        for attempt in 0..self.config.attempts {
            let upstream = upstreams[attempt % upstreams.len()];
            match self.attempt(query, upstream, &mut buf).await {
                Ok(response) => {
                    self.counters.forwarded.fetch_add(1, Ordering::Relaxed);
                    return Answer::Raw(response);
                }
                Err(AttemptError::Timeout) => {
                    self.counters.timeouts.fetch_add(1, Ordering::Relaxed);
                }
                Err(AttemptError::Failed) => {}
            }
        }
        self.counters.failures.fetch_add(1, Ordering::Relaxed);
        Answer::Code(ResponseCode::ServFail)
    }
}

#[derive(Debug)]
enum AttemptError {
    /// The upstream did not answer in time.
    Timeout,
    /// An I/O error, or a TCP response to another query.
    Failed,
}

impl From<io::Error> for AttemptError {
    fn from(_: io::Error) -> Self {
        Self::Failed
    }
}

impl From<tokio::time::error::Elapsed> for AttemptError {
    fn from(_: tokio::time::error::Elapsed) -> Self {
        Self::Timeout
    }
}

/// The wildcard address of `upstream`'s family, port 0.
const fn unspecified(upstream: SocketAddr) -> SocketAddr {
    match upstream {
        SocketAddr::V4(_) => SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0),
        SocketAddr::V6(_) => SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 0),
    }
}

/// Sends `message` over TCP with two-byte length framing and reads one framed response.
async fn exchange_tcp(upstream: SocketAddr, message: &[u8]) -> io::Result<Bytes> {
    let len = u16::try_from(message.len()).map_err(|_| io::ErrorKind::InvalidInput)?;
    let mut stream = TcpStream::connect(upstream).await?;
    let mut framed = Vec::with_capacity(message.len() + 2);
    framed.extend_from_slice(&len.to_be_bytes());
    framed.extend_from_slice(message);
    stream.write_all(&framed).await?;
    let len = stream.read_u16().await?;
    let mut response = vec![0; usize::from(len)];
    stream.read_exact(&mut response).await?;
    Ok(Bytes::from(response))
}

/// Whether `response` is a response with ID `id` to `query`'s question.
fn matches_query(response: &[u8], id: u16, query: &Query) -> bool {
    if header_buffer::id(response).ok() != Some(id)
        || !header_buffer::has_flags(response, PacketFlag::RESPONSE).unwrap_or(false)
    {
        return false;
    }
    let Ok(packet) = Packet::parse(response) else {
        return false;
    };
    let [question] = packet.questions.as_slice() else {
        return false;
    };
    u16::from(question.qtype) == query.record_type().0
        && u16::from(question.qclass) == query.class()
        && normalize_name(&question.qname.to_string()) == query.name()
}
