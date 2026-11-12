//! `recv_from` mapped to the transport contract: truncation instead of `WSAEMSGSIZE`
//! and no `WSAECONNRESET`; and the second socket of a transport bound to `[::]:port`.
//!
//! A dual-stack socket on `[::]:port` does not own the IPv4 side of its port on Windows:
//! anyone may still bind `0.0.0.0:port`, and that socket then gets every IPv4 datagram to
//! the port. `SO_EXCLUSIVEADDRUSE` would refuse that bind, but it has no safe setter. So
//! the transport binds an IPv6-only socket and an IPv4 socket on the same port instead
//! ([`bind_pair`](super::socket::bind_pair)), receives on both and sends on the one of the
//! destination's address family.

use std::future::{Future, poll_fn};
use std::io;
use std::net::SocketAddr;
use std::pin::pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::task::Poll;

use quinn_udp::{UdpSockRef, UdpSocketState};
use tokio::net::UdpSocket;

use super::UdpTransport;
use super::socket::set_up;

/// The IPv4 socket of a transport bound to `[::]:port`.
#[derive(Debug)]
pub(super) struct V4 {
    /// Shared with the [`SideSender`](super::SideSender)s.
    pub(super) socket: Arc<UdpSocket>,
    /// As [`UdpTransport::state`], of this socket.
    pub(super) state: Option<UdpSocketState>,
    /// Whether the next receive looks at this socket first: the two take turns, so
    /// neither address family waits behind a backlog of the other.
    first: AtomicBool,
}

impl V4 {
    /// Sets `socket` up as the transport's other socket is.
    pub(super) fn new(socket: UdpSocket, offload: bool) -> Self {
        let state = offload.then(|| set_up(&socket)).flatten();
        Self {
            socket: Arc::new(socket),
            state,
            first: AtomicBool::new(false),
        }
    }

    /// [`UdpTransport::set_send_buffer_size`] for this socket.
    pub(super) fn set_send_buffer_size(&self, bytes: usize) -> io::Result<()> {
        let Some(state) = &self.state else {
            return socket2::SockRef::from(&self.socket).set_send_buffer_size(bytes);
        };
        state.set_send_buffer_size(UdpSockRef::from(&*self.socket), bytes)
    }
}

/// `WSAEMSGSIZE`: the datagram did not fit; the buffer holds its first bytes and the
/// rest is discarded.
const WSAEMSGSIZE: i32 = 10040;

impl UdpTransport {
    /// Receives one datagram, truncating it to `packet`.
    ///
    /// A truncated `recvfrom` fails without reporting the sender, so the sender is
    /// peeked first. With several tasks receiving on the same transport, another task
    /// may take the peeked datagram in between, and a truncated datagram is then
    /// attributed to the wrong sender; datagrams that fit are always attributed
    /// correctly. `WSAECONNRESET` (an ICMP port-unreachable for an earlier send) is
    /// transient for an unconnected socket: it is skipped and receiving continues,
    /// which needs no `SIO_UDP_CONNRESET` ioctl and so no unsafe code. A truncated
    /// datagram whose sender could not be peeked is dropped.
    ///
    /// A transport with two sockets receives from the one that is readable, and from
    /// each in turn while both are.
    pub(super) async fn recv_from(&self, packet: &mut [u8]) -> io::Result<(usize, SocketAddr)> {
        loop {
            let socket = self.readable().await?;
            let sender = match socket.try_peek_sender() {
                Ok(addr) => Some(addr),
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => continue,
                Err(e) if e.kind() == io::ErrorKind::ConnectionReset => None,
                Err(e) => return Err(e),
            };
            match socket.try_recv_from(packet) {
                Ok(received) => return Ok(received),
                Err(e) if e.raw_os_error() == Some(WSAEMSGSIZE) => {
                    if let Some(addr) = sender {
                        return Ok((packet.len(), addr));
                    }
                }
                Err(e)
                    if matches!(
                        e.kind(),
                        io::ErrorKind::WouldBlock | io::ErrorKind::ConnectionReset
                    ) => {}
                Err(e) => return Err(e),
            }
        }
    }

    /// Waits until a socket of the transport is readable; which one.
    async fn readable(&self) -> io::Result<&UdpSocket> {
        let Some(v4) = &self.v4 else {
            self.socket.readable().await?;
            return Ok(&self.socket);
        };
        let (first, second) = if v4.first.fetch_xor(true, Ordering::Relaxed) {
            (&*v4.socket, &*self.socket)
        } else {
            (&*self.socket, &*v4.socket)
        };
        let mut first_readable = pin!(first.readable());
        let mut second_readable = pin!(second.readable());
        poll_fn(|cx| {
            if let Poll::Ready(ready) = first_readable.as_mut().poll(cx) {
                return Poll::Ready(ready.map(|()| first));
            }
            second_readable
                .as_mut()
                .poll(cx)
                .map(|ready| ready.map(|()| second))
        })
        .await
    }
}
