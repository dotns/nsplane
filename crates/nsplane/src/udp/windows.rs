//! `recv_from` mapped to the transport contract: truncation instead of `WSAEMSGSIZE`
//! and no `WSAECONNRESET`.

use std::io;
use std::net::SocketAddr;

use super::UdpTransport;

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
    pub(super) async fn recv_from(&self, packet: &mut [u8]) -> io::Result<(usize, SocketAddr)> {
        loop {
            self.socket.readable().await?;
            let sender = match self.socket.try_peek_sender() {
                Ok(addr) => Some(addr),
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => continue,
                Err(e) if e.kind() == io::ErrorKind::ConnectionReset => None,
                Err(e) => return Err(e),
            };
            match self.socket.try_recv_from(packet) {
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
}
