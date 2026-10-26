//! Sending with `sendmsg`, segmented sends and batches with `sendmmsg`.

use std::io;
use std::io::IoSlice;
use std::net::SocketAddr;
use std::os::fd::AsRawFd;

use nix::errno::Errno;
use nix::sys::socket::{
    ControlMessage, MsgFlags, MultiHeaders, SockaddrStorage, sendmmsg, sendmsg,
};
use nsplane_packet::{Ecn, MAX_BATCH, PacketBuf, Path};
use quinn_udp::UdpSockRef;
use tokio::io::Interest;

use super::{IOVS, ecn_cmsg};
use crate::udp::UdpTransport;
use crate::udp::send::write_io;

/// How many datagrams from the start of `datagrams` one `sendmmsg` takes: the first one
/// and the ones after it with the same address and ECN mark, up to [`MAX_BATCH`]. `0`
/// for no datagrams.
pub(in crate::udp) fn mmsg_len(datagrams: &[(Path, PacketBuf)]) -> usize {
    let Some((to, _)) = datagrams.first() else {
        return 0;
    };
    datagrams
        .iter()
        .take(MAX_BATCH)
        .take_while(|(path, _)| path.addr == to.addr && path.ecn == to.ecn)
        .count()
}

impl UdpTransport {
    /// Sends one datagram with `sendmsg`, marked with `ecn`.
    pub(in crate::udp) async fn send_to(
        &self,
        datagram: &[u8],
        to: SocketAddr,
        ecn: Ecn,
    ) -> io::Result<()> {
        write_io(&self.socket, &self.errors, || {
            self.send_msg(datagram, to, ecn)
        })
        .await
    }

    /// [`UdpTransport::send_to`] without waiting.
    pub(in crate::udp) fn try_send_to(
        &self,
        datagram: &[u8],
        to: SocketAddr,
        ecn: Ecn,
    ) -> io::Result<()> {
        self.socket.try_io(Interest::WRITABLE, || {
            self.errors
                .write(&self.socket, || self.send_msg(datagram, to, ecn))
        })
    }

    /// One non-blocking `sendmsg` of `datagram` to `to`, marked with `ecn`.
    fn send_msg(&self, datagram: &[u8], to: SocketAddr, ecn: Ecn) -> io::Result<()> {
        let fd = self.socket.as_raw_fd();
        let dest = SockaddrStorage::from(to);
        let tos = ecn.to_bits();
        let tclass = i32::from(tos);
        let cmsg = ecn_cmsg(to, ecn, &tos, &tclass);
        sendmsg(
            fd,
            &[IoSlice::new(datagram)],
            cmsg.as_slice(),
            MsgFlags::empty(),
            Some(&dest),
        )
        .map_err(io::Error::from)
        .map(drop)
    }

    /// One non-blocking `sendmsg` of `run`, at most [`IOVS`] datagrams of the first
    /// one's size (the last may be shorter), to `to` as one segmented send
    /// (`UDP_SEGMENT`) straight from their buffers, one `iovec` each, with the mark
    /// `quinn-udp` sets: `IP_TOS` for IPv4 and IPv4-mapped destinations, `IPV6_TCLASS`
    /// for IPv6 ones, also for [`Ecn::NotEct`].
    pub(in crate::udp) fn send_gso(
        &self,
        run: &[(Path, PacketBuf)],
        to: SocketAddr,
        ecn: Ecn,
    ) -> io::Result<()> {
        let mut iovs = [IoSlice::new(&[]); IOVS];
        for (iov, (_, datagram)) in iovs.iter_mut().zip(run) {
            *iov = IoSlice::new(datagram.as_packet());
        }
        let segment = run.first().map_or(0, |(_, datagram)| datagram.len());
        let segment = u16::try_from(segment).map_err(|_| io::ErrorKind::InvalidInput)?;
        let tos = ecn.to_bits();
        let tclass = i32::from(tos);
        let mark = match to {
            SocketAddr::V6(v6) if v6.ip().to_ipv4_mapped().is_none() => {
                ControlMessage::Ipv6TClass(&tclass)
            }
            _ => ControlMessage::Ipv4Tos(&tos),
        };
        let cmsgs = [ControlMessage::UdpGsoSegments(&segment), mark];
        let dest = SockaddrStorage::from(to);
        loop {
            match sendmsg(
                self.socket.as_raw_fd(),
                &iovs[..run.len().min(IOVS)],
                &cmsgs,
                MsgFlags::empty(),
                Some(&dest),
            ) {
                Ok(_) => return Ok(()),
                Err(Errno::EINTR) => {}
                Err(e) => return Err(e.into()),
            }
        }
    }

    /// One non-blocking `sendmmsg` of `run`, datagrams to `to` with the mark `ecn` that
    /// [`mmsg_len`] put together, each its own message marked as
    /// [`send_msg`](Self::send_msg) marks it; how many of them the socket took, at
    /// least one. When it takes none this fails with the first one's error. Where
    /// `sendmmsg` does not exist, or on `EIO` or `EINVAL` where `quinn-udp` set the
    /// socket up, the first datagram goes out as without batching instead.
    pub(in crate::udp) fn send_mmsg_or_one(
        &self,
        run: &[(Path, PacketBuf)],
        to: SocketAddr,
        ecn: Ecn,
    ) -> io::Result<usize> {
        let Some((_, first)) = run.first() else {
            return Ok(0);
        };
        let run = &run[..run.len().min(MAX_BATCH)];
        let tos = ecn.to_bits();
        let tclass = i32::from(tos);
        let cmsg = ecn_cmsg(to, ecn, &tos, &tclass);
        let mut iovs = [[IoSlice::new(&[])]; MAX_BATCH];
        for (iov, (_, datagram)) in iovs.iter_mut().zip(run) {
            *iov = [IoSlice::new(datagram.as_packet())];
        }
        let dests = [Some(SockaddrStorage::from(to)); MAX_BATCH];
        // Control space only for a mark: unfilled space fails the send.
        let mut headers = MultiHeaders::<SockaddrStorage>::preallocate(
            run.len(),
            cmsg.is_some().then(|| nix::cmsg_space!(i32)),
        );
        let error = loop {
            match sendmmsg(
                self.socket.as_raw_fd(),
                &mut headers,
                &iovs[..run.len()],
                &dests[..run.len()],
                cmsg.as_slice(),
                MsgFlags::empty(),
            ) {
                Ok(sent) => return Ok(sent.count()),
                Err(Errno::EINTR) => {}
                Err(e) => break e,
            }
        };
        let single = self.mmsg_missing(error)
            || (self.state.is_some() && matches!(error, Errno::EIO | Errno::EINVAL));
        if !single {
            return Err(error.into());
        }
        match &self.state {
            Some(state) => {
                let transmit = quinn_udp::Transmit {
                    destination: to,
                    ecn: quinn_udp::EcnCodepoint::from_bits(ecn.to_bits()),
                    contents: first.as_packet(),
                    segment_size: None,
                    src_ip: None,
                };
                state.try_send(UdpSockRef::from(&*self.socket), &transmit)?;
            }
            None => self.send_msg(first.as_packet(), to, ecn)?,
        }
        Ok(1)
    }
}
