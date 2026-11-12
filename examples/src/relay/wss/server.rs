//! The relay side of the WSS carrier: a TLS listener whose WebSocket connections feed the
//! relay's router.
//!
//! [`WsHub`] holds the open connections. [`serve`] accepts them (TLS, then the WebSocket
//! upgrade); each connection gets an id, is a [`Source::Ws`] of the router while it is
//! open ([`Router::connect_ws`]) and is forgotten when it closes
//! ([`Router::disconnect_ws`]). At most [`MAX_CONNECTIONS`] are open at once, and one
//! without a valid frame for [`IDLE_TIMEOUT`] is closed. Its binary messages queue up for
//! [`RelayServerTransport`](crate::relay::server::RelayServerTransport), which routes them
//! like UDP datagrams; what the router sends to a connection leaves as one binary message.
//! The own engine sees a connection as a path on the UDP transport whose address is the
//! connection's TCP peer address; its sends to that address go to the connection.
//!
//! [`Source::Ws`]: crate::relay::router::Source::Ws
//! [`Router::connect_ws`]: crate::relay::router::Router::connect_ws
//! [`Router::disconnect_ws`]: crate::relay::router::Router::disconnect_ws

use std::collections::HashMap;
use std::io;
use std::net::SocketAddr;
use std::pin::pin;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use futures_util::{SinkExt as _, StreamExt as _};
use rustls::ServerConfig;
use serde_json::{Value, json};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::mpsc;
use tokio::task::{JoinHandle, JoinSet};
use tokio::time::Instant;
use tokio_rustls::TlsAcceptor;
use tokio_tungstenite::tungstenite::{Error as WsError, Message};

use super::{MAX_DATAGRAM, ws_config};
use crate::relay::server::{SharedRouter, lock};
use crate::relay::wire::{self, Frame};

/// Time a client has for the TLS and WebSocket handshakes.
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);
/// Connections open at once, those still in their handshakes included; further ones are
/// accepted and closed at once. Each takes a file descriptor: raise both together.
pub const MAX_CONNECTIONS: usize = 256;
/// Closes a connection when no valid frame (a datagram the router takes, a ping or a pong)
/// arrived on it for this long. The relay's clients ping every 10 s.
pub const IDLE_TIMEOUT: Duration = Duration::from_secs(35);
/// Time a message has to be written to a connection, before the connection is closed.
const SEND_TIMEOUT: Duration = Duration::from_secs(10);
/// Datagrams queued from all connections towards the router.
const INBOUND_QUEUE: usize = 1024;
/// Datagrams queued towards one connection.
const OUTBOUND_QUEUE: usize = 256;

/// A datagram received on a connection.
#[derive(Debug)]
pub struct Inbound {
    /// The connection id.
    pub id: u64,
    /// The connection's TCP peer address.
    pub peer: SocketAddr,
    /// The datagram.
    pub data: Vec<u8>,
}

/// The hub's counters.
#[derive(Debug, Default)]
struct Counters {
    accepted: AtomicU64,
    refused: AtomicU64,
    handshake_failures: AtomicU64,
    closed: AtomicU64,
    closed_idle: AtomicU64,
    rx: AtomicU64,
    tx: AtomicU64,
    pings: AtomicU64,
    dropped_text: AtomicU64,
    dropped_oversized: AtomicU64,
    dropped_invalid: AtomicU64,
    dropped_queue_full: AtomicU64,
    dropped_closed: AtomicU64,
}

fn bump(counter: &AtomicU64) {
    counter.fetch_add(1, Ordering::Relaxed);
}

#[derive(Debug)]
struct Conn {
    peer: SocketAddr,
    tx: mpsc::Sender<Vec<u8>>,
}

#[derive(Debug, Default)]
struct Conns {
    by_id: HashMap<u64, Conn>,
    by_addr: HashMap<SocketAddr, u64>,
}

/// The open WebSocket connections of a relay. See the [module documentation](self).
#[derive(Debug)]
pub struct WsHub {
    router: SharedRouter,
    conns: Mutex<Conns>,
    next_id: AtomicU64,
    inbound_tx: mpsc::Sender<Inbound>,
    inbound_rx: tokio::sync::Mutex<mpsc::Receiver<Inbound>>,
    counters: Counters,
}

impl WsHub {
    /// A hub whose connections are sources of `router`.
    pub fn new(router: SharedRouter) -> Arc<Self> {
        let (inbound_tx, inbound_rx) = mpsc::channel(INBOUND_QUEUE);
        Arc::new(Self {
            router,
            conns: Mutex::new(Conns::default()),
            next_id: AtomicU64::new(1),
            inbound_tx,
            inbound_rx: tokio::sync::Mutex::new(inbound_rx),
            counters: Counters::default(),
        })
    }

    /// The next datagram any connection received.
    pub async fn next_inbound(&self) -> Inbound {
        let mut rx = self.inbound_rx.lock().await;
        match rx.recv().await {
            Some(inbound) => inbound,
            // The hub holds a sender, so the channel never closes.
            None => std::future::pending().await,
        }
    }

    /// The connection whose TCP peer address is `addr`.
    pub fn conn_at(&self, addr: SocketAddr) -> Option<u64> {
        lock(&self.conns).by_addr.get(&addr).copied()
    }

    /// Queues `datagram` for connection `id`; dropped (and counted) when the connection is
    /// gone or its queue is full.
    pub fn send_to(&self, id: u64, datagram: &[u8]) {
        let tx = lock(&self.conns).by_id.get(&id).map(|conn| conn.tx.clone());
        let Some(tx) = tx else {
            bump(&self.counters.dropped_closed);
            return;
        };
        if tx.try_send(datagram.to_vec()).is_err() {
            bump(&self.counters.dropped_queue_full);
        }
    }

    /// Counts a received datagram that did not fit the receive buffer.
    pub fn count_oversized(&self) {
        bump(&self.counters.dropped_oversized);
    }

    /// Open connections.
    pub fn connections(&self) -> usize {
        lock(&self.conns).by_id.len()
    }

    /// The status file's `extra.wss` object of a relay:
    ///
    /// ```json
    /// {"connections": 1, "accepted": 2, "refused": 0, "handshake_failures": 0, "closed": 1,
    ///  "closed_idle": 0, "rx": 10, "tx": 9, "pings": 0, "dropped_text": 0, "dropped_oversized": 0,
    ///  "dropped_invalid": 0, "dropped_queue_full": 0, "dropped_closed": 0}
    /// ```
    pub fn status_json(&self) -> Value {
        let c = &self.counters;
        let get = |counter: &AtomicU64| counter.load(Ordering::Relaxed);
        json!({
            "connections": self.connections(),
            "accepted": get(&c.accepted),
            "refused": get(&c.refused),
            "handshake_failures": get(&c.handshake_failures),
            "closed": get(&c.closed),
            "closed_idle": get(&c.closed_idle),
            "rx": get(&c.rx),
            "tx": get(&c.tx),
            "pings": get(&c.pings),
            "dropped_text": get(&c.dropped_text),
            "dropped_oversized": get(&c.dropped_oversized),
            "dropped_invalid": get(&c.dropped_invalid),
            "dropped_queue_full": get(&c.dropped_queue_full),
            "dropped_closed": get(&c.dropped_closed),
        })
    }

    /// Adds a connection; it is removed when the returned guard drops.
    fn open(self: &Arc<Self>, peer: SocketAddr, tx: mpsc::Sender<Vec<u8>>) -> ConnGuard {
        let id = self.next_id.fetch_add(1, Ordering::Relaxed);
        let mut conns = lock(&self.conns);
        conns.by_id.insert(id, Conn { peer, tx });
        conns.by_addr.insert(peer, id);
        drop(conns);
        lock(&self.router).connect_ws(id, peer);
        ConnGuard {
            hub: Arc::clone(self),
            id,
        }
    }

    /// A binary message from connection `id`; whether it is a valid datagram.
    fn on_binary(&self, id: u64, peer: SocketAddr, data: &[u8]) -> bool {
        if data.len() > MAX_DATAGRAM {
            bump(&self.counters.dropped_oversized);
            return false;
        }
        if matches!(wire::classify(data), Frame::Invalid) {
            bump(&self.counters.dropped_invalid);
            return false;
        }
        bump(&self.counters.rx);
        let inbound = Inbound {
            id,
            peer,
            data: data.to_vec(),
        };
        if self.inbound_tx.try_send(inbound).is_err() {
            bump(&self.counters.dropped_queue_full);
        }
        true
    }
}

/// Removes a connection from the hub and the router.
struct ConnGuard {
    hub: Arc<WsHub>,
    id: u64,
}

impl Drop for ConnGuard {
    fn drop(&mut self) {
        let mut conns = lock(&self.hub.conns);
        if let Some(conn) = conns.by_id.remove(&self.id)
            && conns.by_addr.get(&conn.peer) == Some(&self.id)
        {
            conns.by_addr.remove(&conn.peer);
        }
        drop(conns);
        lock(&self.hub.router).disconnect_ws(self.id);
        bump(&self.hub.counters.closed);
        tracing::debug!(id = self.id, "wss connection closed");
    }
}

/// Accepts WSS connections on `listener` for `hub` until the returned task is aborted;
/// aborting it closes every connection.
pub fn serve(listener: TcpListener, tls: Arc<ServerConfig>, hub: Arc<WsHub>) -> JoinHandle<()> {
    let acceptor = TlsAcceptor::from(tls);
    tokio::spawn(async move {
        let mut conns = JoinSet::new();
        loop {
            tokio::select! {
                accepted = listener.accept() => match accepted {
                    // Over the cap the stream is dropped, which closes it.
                    Ok(_) if conns.len() >= MAX_CONNECTIONS => bump(&hub.counters.refused),
                    Ok((stream, peer)) => {
                        conns.spawn(connection(Arc::clone(&hub), acceptor.clone(), stream, peer));
                    }
                    Err(e) => {
                        tracing::warn!(error = %e, "wss accept failed");
                        tokio::time::sleep(Duration::from_millis(100)).await;
                    }
                },
                Some(_) = conns.join_next() => {}
            }
        }
    })
}

/// Binds `listen` and [`serve`]s it; returns the bound address and the task.
pub async fn bind(
    listen: SocketAddr,
    tls: Arc<ServerConfig>,
    hub: Arc<WsHub>,
) -> io::Result<(SocketAddr, JoinHandle<()>)> {
    let listener = TcpListener::bind(listen).await?;
    let addr = listener.local_addr()?;
    Ok((addr, serve(listener, tls, hub)))
}

/// Runs one connection until it closes.
async fn connection(hub: Arc<WsHub>, acceptor: TlsAcceptor, stream: TcpStream, peer: SocketAddr) {
    let _ = stream.set_nodelay(true);
    let handshake = async {
        let tls = acceptor.accept(stream).await?;
        tokio_tungstenite::accept_async_with_config(tls, Some(ws_config()))
            .await
            .map_err(io::Error::other)
    };
    let mut ws = match tokio::time::timeout(HANDSHAKE_TIMEOUT, handshake).await {
        Ok(Ok(ws)) => ws,
        Ok(Err(e)) => {
            bump(&hub.counters.handshake_failures);
            tracing::debug!(%peer, error = %e, "wss handshake failed");
            return;
        }
        Err(_) => {
            bump(&hub.counters.handshake_failures);
            tracing::debug!(%peer, "wss handshake timed out");
            return;
        }
    };
    bump(&hub.counters.accepted);
    let (tx, mut rx) = mpsc::channel(OUTBOUND_QUEUE);
    let guard = hub.open(peer, tx);
    tracing::debug!(%peer, id = guard.id, "wss connection open");
    let mut idle = pin!(tokio::time::sleep(IDLE_TIMEOUT));
    loop {
        tokio::select! {
            message = ws.next() => {
                let valid = match message {
                    Some(Ok(Message::Binary(data))) => hub.on_binary(guard.id, peer, &data),
                    Some(Ok(Message::Text(_))) => {
                        bump(&hub.counters.dropped_text);
                        false
                    }
                    // tungstenite queues the pong and flushes it with the next read or write.
                    Some(Ok(Message::Ping(_))) => {
                        bump(&hub.counters.pings);
                        true
                    }
                    Some(Ok(Message::Pong(_))) => true,
                    Some(Ok(Message::Frame(_))) => false,
                    Some(Ok(Message::Close(_))) | None => break,
                    Some(Err(e)) => {
                        if matches!(e, WsError::Capacity(_)) {
                            bump(&hub.counters.dropped_oversized);
                        }
                        tracing::debug!(%peer, error = %e, "wss connection failed");
                        break;
                    }
                };
                if valid {
                    idle.as_mut().reset(Instant::now() + IDLE_TIMEOUT);
                }
            }
            () = &mut idle => {
                bump(&hub.counters.closed_idle);
                tracing::debug!(%peer, "wss connection idle");
                break;
            }
            datagram = rx.recv() => {
                let Some(datagram) = datagram else { break };
                let send = ws.send(Message::Binary(datagram.into()));
                match tokio::time::timeout(SEND_TIMEOUT, send).await {
                    Ok(Ok(())) => bump(&hub.counters.tx),
                    Ok(Err(e)) => {
                        tracing::debug!(%peer, error = %e, "wss send failed");
                        break;
                    }
                    Err(_) => {
                        tracing::debug!(%peer, "wss send timed out");
                        break;
                    }
                }
            }
        }
    }
    drop(guard);
    let _ = tokio::time::timeout(SEND_TIMEOUT, ws.close(None)).await;
}
