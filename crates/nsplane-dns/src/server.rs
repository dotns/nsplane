//! [`Server`]: answers DNS clients over UDP and TCP with a [`Resolver`].
//!
//! [`Server::handle`] is the transport-neutral core: one message in, one response out. The
//! serve functions run it over tokio sockets ([`serve_udp`](Server::serve_udp),
//! [`serve_tcp`](Server::serve_tcp)) or any byte stream ([`serve_stream`](Server::serve_stream));
//! they spawn tasks with `tokio::spawn` and need a tokio runtime.

use std::io;
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use bytes::Bytes;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, UdpSocket};
use tokio::sync::Semaphore;

use crate::message::{
    Answer, DEFAULT_UDP_PAYLOAD_SIZE, EncodeOptions, Query, ResponseCode, encode_error,
    encode_response, max_udp_response_size,
};
use crate::resolver::Resolver;

/// Largest DNS message: the UDP receive buffer and the TCP response limit.
const MAX_MESSAGE_SIZE: usize = 65535;

/// The `TC` bit in the third header byte.
const TC_BIT: u8 = 0x02;

/// The transport a message arrived on; it decides the response size limit.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Transport {
    /// UDP: responses above [`max_udp_response_size`] are truncated (`TC` = 1).
    Udp,
    /// TCP (length-prefixed): responses up to 65535 bytes.
    Tcp,
}

/// [`Server`] settings.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct ServerConfig {
    /// Queries resolved at once, over all transports. Default 256.
    pub max_in_flight: usize,
    /// UDP payload size advertised in the OPT record and upper bound of UDP responses.
    /// Default [`DEFAULT_UDP_PAYLOAD_SIZE`].
    pub udp_payload_size: u16,
    /// Time a resolver may take before the query is answered `SERVFAIL`. Default 5 s.
    pub resolve_timeout: Duration,
    /// Time a TCP connection may wait for the next query, or for the client to read a
    /// response, before it is closed. Default 10 s.
    pub tcp_idle_timeout: Duration,
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            max_in_flight: 256,
            udp_payload_size: DEFAULT_UDP_PAYLOAD_SIZE,
            resolve_timeout: Duration::from_secs(5),
            tcp_idle_timeout: Duration::from_secs(10),
        }
    }
}

impl ServerConfig {
    /// Sets [`max_in_flight`](Self::max_in_flight).
    #[must_use]
    pub const fn with_max_in_flight(mut self, max_in_flight: usize) -> Self {
        self.max_in_flight = max_in_flight;
        self
    }

    /// Sets [`udp_payload_size`](Self::udp_payload_size).
    #[must_use]
    pub const fn with_udp_payload_size(mut self, udp_payload_size: u16) -> Self {
        self.udp_payload_size = udp_payload_size;
        self
    }

    /// Sets [`resolve_timeout`](Self::resolve_timeout).
    #[must_use]
    pub const fn with_resolve_timeout(mut self, resolve_timeout: Duration) -> Self {
        self.resolve_timeout = resolve_timeout;
        self
    }

    /// Sets [`tcp_idle_timeout`](Self::tcp_idle_timeout).
    #[must_use]
    pub const fn with_tcp_idle_timeout(mut self, tcp_idle_timeout: Duration) -> Self {
        self.tcp_idle_timeout = tcp_idle_timeout;
        self
    }
}

/// A snapshot of [`Server`] counters, cumulative since the server was created.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct ServerStats {
    /// Messages passed to [`Server::handle`].
    pub queries: u64,
    /// Responses returned by [`Server::handle`].
    pub responses: u64,
    /// Responses with `TC` = 1.
    pub truncated: u64,
    /// UDP datagrams dropped because [`ServerConfig::max_in_flight`] queries were in flight.
    pub dropped_overload: u64,
    /// Messages that did not decode as a query.
    pub decode_errors: u64,
    /// Queries answered `SERVFAIL` after [`ServerConfig::resolve_timeout`].
    pub timeouts: u64,
}

#[derive(Debug, Default)]
struct Counters {
    queries: AtomicU64,
    responses: AtomicU64,
    truncated: AtomicU64,
    dropped_overload: AtomicU64,
    decode_errors: AtomicU64,
    timeouts: AtomicU64,
}

fn bump(counter: &AtomicU64) {
    counter.fetch_add(1, Ordering::Relaxed);
}

/// A DNS server answering with a [`Resolver`].
///
/// Clones share the resolver, the in-flight bound and the counters. At most
/// [`ServerConfig::max_in_flight`] queries are resolved at once by the serve functions: UDP
/// datagrams above the bound are dropped (clients retry), TCP queries wait. The server answers
/// what the resolver returns, encoded by [`encode_response`]; it does not rewrite names or
/// answers.
#[derive(Debug)]
pub struct Server<R> {
    resolver: Arc<R>,
    config: ServerConfig,
    permits: Arc<Semaphore>,
    counters: Arc<Counters>,
}

impl<R> Clone for Server<R> {
    fn clone(&self) -> Self {
        Self {
            resolver: Arc::clone(&self.resolver),
            config: self.config,
            permits: Arc::clone(&self.permits),
            counters: Arc::clone(&self.counters),
        }
    }
}

impl<R: Resolver> Server<R> {
    /// A server answering with `resolver`.
    pub fn new(resolver: R, config: ServerConfig) -> Self {
        Self {
            resolver: Arc::new(resolver),
            config,
            permits: Arc::new(Semaphore::new(config.max_in_flight)),
            counters: Arc::default(),
        }
    }

    /// The settings.
    pub const fn config(&self) -> &ServerConfig {
        &self.config
    }

    /// The resolver.
    pub fn resolver(&self) -> &R {
        &self.resolver
    }

    /// A snapshot of the counters.
    pub fn stats(&self) -> ServerStats {
        let c = &self.counters;
        ServerStats {
            queries: c.queries.load(Ordering::Relaxed),
            responses: c.responses.load(Ordering::Relaxed),
            truncated: c.truncated.load(Ordering::Relaxed),
            dropped_overload: c.dropped_overload.load(Ordering::Relaxed),
            decode_errors: c.decode_errors.load(Ordering::Relaxed),
            timeouts: c.timeouts.load(Ordering::Relaxed),
        }
    }

    /// Answers one DNS message from `client`, the transport-neutral core of the serve
    /// functions; transport adapters call it with each received message.
    ///
    /// A message that does not decode is answered by [`encode_error`] (`FORMERR`, `NOTIMP`)
    /// when its header is readable, else `None`. A query is resolved under
    /// [`ServerConfig::resolve_timeout`] (`SERVFAIL` when it expires) and encoded with the
    /// size limit of `transport`: [`max_udp_response_size`] over UDP, so larger answers
    /// come back truncated for the client to retry over TCP, and 65535 over TCP.
    ///
    /// It does not take an in-flight permit; callers bound concurrency themselves.
    pub async fn handle(
        &self,
        message: &[u8],
        client: SocketAddr,
        transport: Transport,
    ) -> Option<Bytes> {
        bump(&self.counters.queries);
        let response = match Query::decode(message) {
            Ok(query) => self.answer(&query, client, transport).await,
            Err(err) => {
                bump(&self.counters.decode_errors);
                tracing::debug!(%client, %err, "undecodable DNS message");
                encode_error(err.id()?, err.response_code()?)
            }
        };
        if response.get(2).is_some_and(|flags| flags & TC_BIT != 0) {
            bump(&self.counters.truncated);
        }
        bump(&self.counters.responses);
        Some(response)
    }

    async fn answer(&self, query: &Query, client: SocketAddr, transport: Transport) -> Bytes {
        let resolve = self.resolver.resolve(query, client);
        let answer = tokio::time::timeout(self.config.resolve_timeout, resolve)
            .await
            .unwrap_or_else(|_| {
                bump(&self.counters.timeouts);
                tracing::debug!(%client, name = query.name(), "DNS resolve timed out");
                Answer::Code(ResponseCode::ServFail)
            });
        let options = EncodeOptions {
            udp_payload_size: self.config.udp_payload_size,
        };
        let max_size = match transport {
            Transport::Udp => max_udp_response_size(query, options),
            Transport::Tcp => MAX_MESSAGE_SIZE,
        };
        encode_response(query, &answer, max_size, options)
    }
}

impl<R: Resolver + 'static> Server<R> {
    /// Answers queries arriving on `socket` until it fails.
    ///
    /// Each datagram is handled in its own task holding an in-flight permit; without a free
    /// permit the datagram is dropped and counted in [`ServerStats::dropped_overload`].
    /// Receive errors caused by a single peer (an ICMP-reported reset or unreachable port)
    /// are logged and skipped. Needs a tokio runtime.
    ///
    /// # Errors
    ///
    /// The first other receive error.
    pub async fn serve_udp(&self, socket: UdpSocket) -> io::Result<()> {
        let socket = Arc::new(socket);
        let mut buf = vec![0; MAX_MESSAGE_SIZE];
        loop {
            let (len, client) = match socket.recv_from(&mut buf).await {
                Ok(received) => received,
                Err(err) if is_peer_error(&err) => {
                    tracing::debug!(%err, "DNS UDP receive error");
                    continue;
                }
                Err(err) => return Err(err),
            };
            let Ok(permit) = Arc::clone(&self.permits).try_acquire_owned() else {
                bump(&self.counters.dropped_overload);
                tracing::trace!(%client, "DNS query dropped: in-flight limit");
                continue;
            };
            let message = Bytes::copy_from_slice(&buf[..len]);
            let server = self.clone();
            let socket = Arc::clone(&socket);
            tokio::spawn(async move {
                let response = server.handle(&message, client, Transport::Udp).await;
                drop(permit);
                if let Some(response) = response
                    && let Err(err) = socket.send_to(&response, client).await
                {
                    tracing::debug!(%client, %err, "DNS UDP send error");
                }
            });
        }
    }

    /// Accepts connections on `listener` until it fails, serving each with
    /// [`serve_stream`](Self::serve_stream) in its own task. Needs a tokio runtime.
    ///
    /// # Errors
    ///
    /// The first accept error not tied to a single connection.
    pub async fn serve_tcp(&self, listener: TcpListener) -> io::Result<()> {
        loop {
            let (stream, client) = match listener.accept().await {
                Ok(accepted) => accepted,
                Err(err) if is_peer_error(&err) => {
                    tracing::debug!(%err, "DNS TCP accept error");
                    continue;
                }
                Err(err) => return Err(err),
            };
            let server = self.clone();
            tokio::spawn(async move {
                if let Err(err) = server.serve_stream(stream, client).await {
                    tracing::debug!(%client, %err, "DNS TCP connection error");
                }
            });
        }
    }

    /// Answers queries from `client` on one connection, framed with a two-byte length
    /// prefix (RFC 1035 section 4.2.2, RFC 7766).
    ///
    /// Queries are processed one at a time in arrival order, pipelined ones included; each
    /// waits for an in-flight permit. The connection is closed (`Ok`) on end of stream, a
    /// zero-length or cut-off frame, a message that gets no response, or after
    /// [`ServerConfig::tcp_idle_timeout`] without a query or without the client reading.
    ///
    /// # Errors
    ///
    /// An I/O error of `stream`.
    pub async fn serve_stream<S>(&self, mut stream: S, client: SocketAddr) -> io::Result<()>
    where
        S: AsyncRead + AsyncWrite + Unpin + Send,
    {
        let idle = self.config.tcp_idle_timeout;
        loop {
            let mut prefix = [0; 2];
            if !read_frame_part(&mut stream, &mut prefix, idle).await? {
                return Ok(());
            }
            let len = usize::from(u16::from_be_bytes(prefix));
            if len == 0 {
                return Ok(());
            }
            let mut message = vec![0; len];
            if !read_frame_part(&mut stream, &mut message, idle).await? {
                return Ok(());
            }
            let Ok(permit) = self.permits.acquire().await else {
                return Ok(());
            };
            let response = self.handle(&message, client, Transport::Tcp).await;
            drop(permit);
            let Some(response) = response else {
                return Ok(());
            };
            let Ok(len) = u16::try_from(response.len()) else {
                return Ok(());
            };
            let mut frame = Vec::with_capacity(response.len() + 2);
            frame.extend_from_slice(&len.to_be_bytes());
            frame.extend_from_slice(&response);
            let write = async {
                stream.write_all(&frame).await?;
                stream.flush().await
            };
            match tokio::time::timeout(idle, write).await {
                Ok(result) => result?,
                Err(_) => return Ok(()),
            }
        }
    }
}

/// Fills `buf` from `stream`. `Ok(false)` on end of stream or when `idle` expires first.
async fn read_frame_part<S: AsyncRead + Unpin>(
    stream: &mut S,
    buf: &mut [u8],
    idle: Duration,
) -> io::Result<bool> {
    match tokio::time::timeout(idle, stream.read_exact(buf)).await {
        Ok(Ok(_)) => Ok(true),
        Ok(Err(err)) if err.kind() == io::ErrorKind::UnexpectedEof => Ok(false),
        Ok(Err(err)) => Err(err),
        Err(_) => Ok(false),
    }
}

/// Socket errors that concern one peer or one connection, not the socket.
fn is_peer_error(err: &io::Error) -> bool {
    matches!(
        err.kind(),
        io::ErrorKind::ConnectionReset
            | io::ErrorKind::ConnectionRefused
            | io::ErrorKind::ConnectionAborted
            | io::ErrorKind::HostUnreachable
            | io::ErrorKind::NetworkUnreachable
            | io::ErrorKind::Interrupted
            | io::ErrorKind::WouldBlock
            | io::ErrorKind::TimedOut
    )
}
