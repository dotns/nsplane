//! [`Forwarder`]: a resolver that asks upstream DNS servers, and passes raw messages to them.

use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::time::Duration;

use bytes::Bytes;
use rand_core::{OsRng, RngCore};
use simple_dns::{PacketFlag, PacketView, header_buffer};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};
use tokio::time::{Instant, timeout, timeout_at};

use crate::message::{Answer, Query, ResponseCode, name_text};

/// Length of the fixed DNS header.
const HEADER_LEN: usize = 12;
use crate::resolver::Resolver;

/// Receive buffer for UDP responses: the largest datagram an upstream can send.
const MAX_UDP_RESPONSE: usize = 65535;

/// Upstream servers and retry policy of a [`Forwarder`].
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct ForwarderConfig {
    /// Upstream servers, asked in order from the one that answered last (the first one
    /// until then). Must not be empty.
    pub upstreams: Vec<SocketAddr>,
    /// Time limit of one attempt (the UDP exchange, then the TCP retry on its own). Default 2 s.
    pub timeout: Duration,
    /// Tries per query in total, not per upstream: each try asks the next upstream in
    /// order, wrapping around. With fewer attempts than upstreams one query does not reach
    /// all of them; a query whose attempts all failed leaves the next query to start at the
    /// upstream after the last one it tried. Must be at least 1. Default 2.
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
    /// Queries and raw messages answered with an upstream response.
    pub forwarded: u64,
    /// Attempts that ran out of time.
    pub timeouts: u64,
    /// Truncated UDP responses retried over TCP.
    pub tcp_retries: u64,
    /// Queries answered `SERVFAIL`, and raw messages left without a response, because every
    /// attempt failed.
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
/// The rotation of a query starts at the upstream that answered last, so an upstream that
/// stopped answering costs one query its timeout, not every query; the forwarder stays with
/// the upstream that answers and returns to an earlier one only when that one fails too.
///
/// The transaction ID of every attempt comes from the system's random number generator, so a
/// spoofed response has to guess it together with the ephemeral source port the system picks
/// for the attempt.
///
/// The forwarder has no cache and no policy: it forwards every query it gets. To answer some
/// names locally, put it behind other resolvers with [`Fallback`](crate::Fallback), for example
/// `StaticRecords::with_fallback(forwarder)`.
///
/// [`forward`](Self::forward) passes messages that are not decoded queries (other opcodes,
/// other question counts) the same way; [`Server::with_passthrough`](crate::Server::with_passthrough)
/// uses it.
#[derive(Debug)]
pub struct Forwarder {
    config: ForwarderConfig,
    /// Index of the upstream the next query asks first.
    first: AtomicUsize,
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
            first: AtomicUsize::new(0),
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

    /// Passes the DNS message `message` to the upstreams byte for byte and returns the
    /// response, with the message's ID.
    ///
    /// Attempts, transaction IDs, the TCP retry and the counters work as for queries, but the
    /// message is not decoded: a response is accepted when it has the transaction ID, `QR` = 1
    /// and the message's opcode. When the message's question section is readable and not
    /// empty, a response that carries questions must also carry the same ones (names compared
    /// case-insensitively, types and classes); a response without questions, as servers send
    /// for messages they refuse, or one whose sections are not readable is not compared. Any
    /// accepted response is returned, whatever its response code.
    ///
    /// `None` when `message` is shorter than the DNS header or every attempt failed (timeout,
    /// ICMP refusal, I/O error); the latter counts in [`ForwarderStats::failures`].
    pub async fn forward(&self, message: &[u8]) -> Option<Bytes> {
        if message.len() < HEADER_LEN {
            return None;
        }
        let opcode = header_buffer::opcode(message).ok()?;
        let asked = PacketView::parse(message).map_or_else(|_| Vec::new(), |view| questions(&view));
        let matches = |response: &[u8], id: u16| {
            is_response(response, id)
                && header_buffer::opcode(response).ok() == Some(opcode)
                && echoes_questions(response, &asked)
        };
        let mut response = self.exchange(message, matches).await?.to_vec();
        response[..2].copy_from_slice(&message[..2]);
        Some(Bytes::from(response))
    }

    /// Runs the attempts for `message`; `None` when all failed.
    async fn exchange(
        &self,
        message: &[u8],
        matches: impl Fn(&[u8], u16) -> bool + Sync,
    ) -> Option<Bytes> {
        let upstreams = &self.config.upstreams;
        let mut buf = Vec::with_capacity(MAX_UDP_RESPONSE);
        let first = self.first.load(Ordering::Relaxed);
        for attempt in 0..self.config.attempts {
            let index = first.wrapping_add(attempt) % upstreams.len();
            let upstream = upstreams[index];
            match self.attempt(message, upstream, &mut buf, &matches).await {
                Ok(response) => {
                    self.first.store(index, Ordering::Relaxed);
                    self.counters.forwarded.fetch_add(1, Ordering::Relaxed);
                    return Some(response);
                }
                Err(AttemptError::Timeout) => {
                    self.counters.timeouts.fetch_add(1, Ordering::Relaxed);
                }
                Err(AttemptError::Failed) => {}
            }
        }
        // Later upstreams get their turn even with fewer attempts than upstreams.
        let next = first.wrapping_add(self.config.attempts) % upstreams.len();
        self.first.store(next, Ordering::Relaxed);
        self.counters.failures.fetch_add(1, Ordering::Relaxed);
        None
    }

    /// One attempt against `upstream`: UDP, then TCP when the response is truncated.
    async fn attempt(
        &self,
        message: &[u8],
        upstream: SocketAddr,
        buf: &mut Vec<u8>,
        matches: impl Fn(&[u8], u16) -> bool + Sync,
    ) -> Result<Bytes, AttemptError> {
        let socket = UdpSocket::bind(unspecified(upstream)).await?;
        socket.connect(upstream).await?;
        let id = transaction_id()?;
        let mut message = message.to_vec();
        message[..2].copy_from_slice(&id.to_be_bytes());

        let deadline = Instant::now() + self.config.timeout;
        let udp = timeout_at(deadline, async {
            socket.send(&message).await?;
            loop {
                buf.clear();
                let len = socket.recv_buf(buf).await?;
                let response = &buf[..len];
                if matches(response, id) {
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
        if matches(&response, id) {
            Ok(response)
        } else {
            Err(AttemptError::Failed)
        }
    }
}

/// A transaction ID from the system's random number generator.
fn transaction_id() -> Result<u16, AttemptError> {
    let mut id = [0; 2];
    OsRng
        .try_fill_bytes(&mut id)
        .map_err(|_| AttemptError::Failed)?;
    Ok(u16::from_be_bytes(id))
}

impl Resolver for Forwarder {
    async fn resolve(&self, query: &Query, _client: SocketAddr) -> Answer {
        let matches = |response: &[u8], id: u16| matches_query(response, id, query);
        self.exchange(query.raw(), matches)
            .await
            .map_or(Answer::Code(ResponseCode::ServFail), Answer::Raw)
    }
}

#[derive(Debug)]
enum AttemptError {
    /// The upstream did not answer in time.
    Timeout,
    /// An I/O error, no random transaction ID, or a TCP response to another query.
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

/// Whether `response` is a response (`QR` = 1) with ID `id`.
fn is_response(response: &[u8], id: u16) -> bool {
    header_buffer::id(response).ok() == Some(id)
        && header_buffer::has_flags(response, PacketFlag::RESPONSE).unwrap_or(false)
}

/// Whether `response` is a response with ID `id` to `query`'s question.
fn matches_query(response: &[u8], id: u16, query: &Query) -> bool {
    if !is_response(response, id) {
        return false;
    }
    let Ok(packet) = PacketView::parse(response) else {
        return false;
    };
    let [question] = packet.questions.as_slice() else {
        return false;
    };
    u16::from(question.qtype) == query.record_type().0
        && u16::from(question.qclass) == query.class()
        && name_text(&question.qname) == query.name()
}

/// The questions of `view` as (normalized name, type, class).
fn questions(view: &PacketView<'_>) -> Vec<(String, u16, u16)> {
    view.questions
        .iter()
        .map(|question| {
            (
                name_text(&question.qname),
                u16::from(question.qtype),
                u16::from(question.qclass),
            )
        })
        .collect()
}

/// Whether `response` may answer a message with the questions `asked`: no questions were
/// read from the message, or the response is not readable, has no questions or has the same.
fn echoes_questions(response: &[u8], asked: &[(String, u16, u16)]) -> bool {
    if asked.is_empty() {
        return true;
    }
    let Ok(view) = PacketView::parse(response) else {
        return true;
    };
    view.questions.is_empty() || questions(&view) == asked
}

#[cfg(test)]
mod property_tests;
