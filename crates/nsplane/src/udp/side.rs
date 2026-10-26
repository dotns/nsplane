//! The side channel: datagrams on the transport's socket that are not the engine's.

use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::{fmt, io};

use bytes::Bytes;
#[cfg(doc)]
use nsplane_packet::Path;
use tokio::net::UdpSocket;
use tokio::sync::mpsc;

use super::SocketErrors;
#[cfg(doc)]
use super::UdpTransport;
use super::send::write_io;
use super::socket::target;
#[cfg(doc)]
use crate::transport::Transport;

/// A datagram the side channel took (see [`UdpTransport::with_side_channel`]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SideDatagram {
    /// The sender, reported as [`Path::addr`] would report it (IPv4 peers of a dual-stack
    /// socket as plain IPv4 addresses).
    pub from: SocketAddr,
    /// The datagram as received; one longer than the receive buffer may be truncated, as
    /// through [`recv`](Transport::recv).
    pub datagram: Bytes,
}

/// Counters of a side channel, from [`SideSender::stats`].
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct SideStats {
    /// Datagrams handed to the side channel's receiver.
    pub received: u64,
    /// Datagrams the side channel took but its receiver could not take (full or closed),
    /// so they were dropped.
    pub dropped: u64,
}

/// Sends datagrams on the socket of a [`UdpTransport`] with a side channel (see
/// [`UdpTransport::with_side_channel`]); cheap to clone.
///
/// [`send_to`](Self::send_to) is synchronous and best effort, so a caller never waits on
/// the engine's traffic: it hands the datagram to the socket at once, or fails with
/// [`io::ErrorKind::WouldBlock`] when the socket's send buffer is full.
/// [`send_to_async`](Self::send_to_async) instead waits until the socket is writable and
/// retries, for datagrams that should not be lost to a full buffer.
#[derive(Debug, Clone)]
pub struct SideSender {
    pub(super) socket: Arc<UdpSocket>,
    pub(super) local: SocketAddr,
    pub(super) counters: Arc<SideCounters>,
    /// The transport's error queue and PMTU reports.
    pub(super) errors: Arc<SocketErrors>,
}

impl SideSender {
    /// Sends `datagram` to `to` from the transport's socket, without an ECN mark and without
    /// segmentation. IPv4 destinations of a dual-stack socket are mapped as the transport
    /// maps them; an IPv6 destination on an IPv4 socket fails with
    /// [`io::ErrorKind::InvalidInput`]. Does not wait: when the socket cannot take the
    /// datagram now this fails with [`io::ErrorKind::WouldBlock`] and the datagram is not
    /// sent.
    pub fn send_to(&self, datagram: &[u8], to: SocketAddr) -> io::Result<()> {
        // Straight to the non-blocking socket: tokio's `try_send_to` also fails while it
        // has not seen the socket writable yet.
        let to = target(self.local, to)?.into();
        self.errors
            .write(&self.socket, || {
                socket2::SockRef::from(&*self.socket).send_to(datagram, &to)
            })
            .map(drop)
    }

    /// Sends `datagram` to `to` as [`send_to`](Self::send_to) does, addressed the same way,
    /// but when the socket's send buffer is full waits until the socket is writable and
    /// tries again, until it is sent or fails with another error.
    ///
    /// Cancel safe: each try hands the whole datagram to the socket or nothing, so dropping
    /// the future sends either nothing or the whole datagram, once.
    ///
    /// The socket is the engine's: this waits on the same writability as the engine's own
    /// sends and takes no lock, so it neither blocks nor delays them. Once the socket is
    /// writable each waiter tries its datagram; the engine's sends and this one go out in
    /// whatever order they reach the socket, and the ones that do not fit wait again.
    pub async fn send_to_async(&self, datagram: &[u8], to: SocketAddr) -> io::Result<()> {
        let to = target(self.local, to)?.into();
        write_io(&self.socket, &self.errors, || {
            socket2::SockRef::from(&*self.socket).send_to(datagram, &to)
        })
        .await
        .map(drop)
    }

    /// The transport's bound address.
    pub const fn local_addr(&self) -> SocketAddr {
        self.local
    }

    /// What the side channel received and dropped so far.
    pub fn stats(&self) -> SideStats {
        SideStats {
            received: self.counters.received.load(Ordering::Relaxed),
            dropped: self.counters.dropped.load(Ordering::Relaxed),
        }
    }
}

/// The counters behind [`SideStats`].
#[derive(Debug, Default)]
pub(super) struct SideCounters {
    received: AtomicU64,
    dropped: AtomicU64,
}

/// The classifier of a side channel.
pub(super) type Classify = dyn Fn(&[u8]) -> bool + Send + Sync;

/// An attached side channel.
pub(super) struct Side {
    pub(super) classify: Box<Classify>,
    pub(super) tx: mpsc::Sender<SideDatagram>,
    pub(super) counters: Arc<SideCounters>,
}

impl Side {
    /// Hands `datagram` from `from` to the receiver if it is classified as a side datagram,
    /// counting it as received or dropped; whether it was.
    pub(super) fn take(&self, datagram: &[u8], from: SocketAddr) -> bool {
        if !(self.classify)(datagram) {
            return false;
        }
        let side = SideDatagram {
            from,
            datagram: Bytes::copy_from_slice(datagram),
        };
        let counter = match self.tx.try_send(side) {
            Ok(()) => &self.counters.received,
            Err(_) => &self.counters.dropped,
        };
        counter.fetch_add(1, Ordering::Relaxed);
        true
    }
}

impl fmt::Debug for Side {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Side")
            .field("tx", &self.tx)
            .field("counters", &self.counters)
            .finish_non_exhaustive()
    }
}
