//! Receiving through `quinn-udp`, with generic receive offload: one read may return a
//! train of datagrams of one sender, all of one size (the stride) but the last. Without
//! `quinn-udp` state, `recvmsg` / `sendmsg` with TOS and traffic class control messages.
//! With path MTU discovery on, each read attempt first consumes at most 64 queued errors.

mod pmtu;
mod recv;
mod send;

use std::io;
use std::net::{SocketAddr, SocketAddrV4, SocketAddrV6};

use nix::sys::socket::{ControlMessage, ControlMessageOwned, SockaddrStorage};
use nsplane_packet::Ecn;
use quinn_udp::RecvMeta;
use socket2::SockRef;
use tokio::net::UdpSocket;

#[cfg(doc)]
use super::UdpTransport;

pub(super) use self::pmtu::Pmtu;
#[cfg(test)]
pub(super) use self::pmtu::path_mtu_report;
pub(super) use self::recv::Rx;
pub(super) use self::send::mmsg_len;

/// The most path MTU reports waiting for the engine.
const REPORTS: usize = 64;
/// The leading bytes of a datagram read with its error: as many as a report keeps.
const QUOTE: usize = 8;

/// Bytes one coalesced read may fill: the largest datagram, and the most the kernel
/// coalesces into one read.
const READ: usize = 1 << 16;

/// The size of a storage for coalesced reads: twice the read, so small datagrams take
/// many reads per refill.
const STORAGE: usize = 2 * READ;

/// The storages coalesced reads take turns in.
const RING: usize = 4;

/// The most datagrams one segmented send takes straight from their buffers, one `iovec`
/// each: the kernel's segment limit.
pub(super) const IOVS: usize = 64;

/// The most datagrams one `recvmmsg` reads in batches.
const SLOTS: usize = 16;

/// Coalesced reads of one datagram each in a row after which receive offload reads in
/// batches.
const SINGLES: u8 = 4;

/// Control-message space of one batched read: as much as [`CmsgBuf`] holds.
const CMSG: usize = 64;

/// Control-message buffer, aligned for `cmsghdr`; holds one TOS or traffic class
/// message (24 bytes on 64-bit targets) with room to spare.
#[repr(C, align(8))]
struct CmsgBuf([u8; 64]);

/// Control-message buffer for an error-queue entry, aligned for `cmsghdr`: the error
/// with the sender of the ICMP message (64 bytes on 64-bit targets for IPv6) comes
/// last, after the packet info and TOS the socket may also ask for.
#[repr(C, align(8))]
struct ErrCmsgBuf([u8; 256]);

/// Asks for the TOS (IPv4, including IPv4-mapped peers of a dual-stack socket) and
/// traffic class (IPv6) of every received datagram.
pub(super) fn enable_ecn(socket: &UdpSocket, local: SocketAddr) -> io::Result<()> {
    let socket = SockRef::from(socket);
    socket.set_recv_tos_v4(true)?;
    if local.is_ipv6() {
        socket.set_recv_tclass_v6(true)?;
    }
    Ok(())
}

/// The control message that marks a datagram to `to` with `ecn`, as
/// [`UdpTransport::send_msg`] sends it: none for [`Ecn::NotEct`], else `IP_TOS` for
/// IPv4 and IPv4-mapped destinations (even on an IPv6 socket), `IPV6_TCLASS` for IPv6
/// ones.
fn ecn_cmsg<'a>(
    to: SocketAddr,
    ecn: Ecn,
    tos: &'a u8,
    tclass: &'a i32,
) -> Option<ControlMessage<'a>> {
    match to {
        _ if ecn == Ecn::NotEct => None,
        SocketAddr::V6(v6) if v6.ip().to_ipv4_mapped().is_none() => {
            Some(ControlMessage::Ipv6TClass(tclass))
        }
        _ => Some(ControlMessage::Ipv4Tos(tos)),
    }
}

/// The ECN mark among the control messages of a received datagram; [`Ecn::NotEct`]
/// without one.
fn received_ecn(cmsgs: impl IntoIterator<Item = ControlMessageOwned>) -> Ecn {
    cmsgs.into_iter().fold(Ecn::NotEct, |ecn, cmsg| match cmsg {
        ControlMessageOwned::Ipv4Tos(tos) => Ecn::from_bits(tos),
        ControlMessageOwned::Ipv6TClass(tclass) => {
            u8::try_from(tclass & 0xFF).map_or(ecn, Ecn::from_bits)
        }
        _ => ecn,
    })
}

/// The ECN mark of a read.
fn ecn(meta: &RecvMeta) -> Ecn {
    meta.ecn
        .map_or(Ecn::NotEct, |ecn| Ecn::from_bits(ecn as u8))
}

fn socket_addr(addr: &SockaddrStorage) -> Option<SocketAddr> {
    addr.as_sockaddr_in()
        .map(|v4| SocketAddrV4::from(*v4).into())
        .or_else(|| {
            addr.as_sockaddr_in6()
                .map(|v6| SocketAddrV6::from(*v6).into())
        })
}
