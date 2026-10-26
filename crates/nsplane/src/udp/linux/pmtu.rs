//! Path MTU discovery: the socket's error queue and the reports for the engine.

use std::io;
use std::io::IoSliceMut;
use std::os::fd::AsRawFd;
use std::sync::atomic::Ordering;
use std::sync::{Mutex, OnceLock, PoisonError};

use nix::errno::Errno;
use nix::libc::{SO_EE_ORIGIN_ICMP, SO_EE_ORIGIN_ICMP6, sock_extended_err};
use nix::sys::socket::{
    ControlMessageOwned, MsgFlags, SockaddrStorage, getsockopt, recvmsg, setsockopt, sockopt,
};
use nsplane_packet::{Ecn, Path};
use tokio::net::UdpSocket;
use tokio::sync::mpsc;

use super::{ErrCmsgBuf, QUOTE, REPORTS, socket_addr};
use crate::transport::PathMtuReport;
use crate::udp::socket::unmap;
use crate::udp::{SocketErrors, UdpTransport};

/// Path MTU discovery ([`UdpTransport::set_path_mtu_discovery`]).
#[derive(Debug, Default)]
pub(in crate::udp) struct Pmtu {
    /// The reports for the engine, from the first time it is turned on.
    tx: OnceLock<mpsc::Sender<PathMtuReport>>,
    /// The receiving end, until the engine takes it.
    rx: Mutex<Option<mpsc::Receiver<PathMtuReport>>>,
}

impl Pmtu {
    pub(in crate::udp) const fn new() -> Self {
        Self {
            tx: OnceLock::new(),
            rx: Mutex::new(None),
        }
    }

    /// Creates the report queue if it does not exist yet.
    fn open(&self) {
        self.tx.get_or_init(|| {
            let (tx, rx) = mpsc::channel(REPORTS);
            *self.rx.lock().unwrap_or_else(PoisonError::into_inner) = Some(rx);
            tx
        });
    }

    /// Queues `report`; false when the queue is full or closed.
    fn push(&self, report: PathMtuReport) -> bool {
        self.tx.get().is_none_or(|tx| tx.try_send(report).is_ok())
    }

    /// The receiver of the reports, once.
    pub(in crate::udp) fn take(&self) -> Option<mpsc::Receiver<PathMtuReport>> {
        self.rx
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .take()
    }
}

/// The report an error-queue entry makes: `err` is the error about a datagram sent on
/// `path`, `quote` the datagram's leading bytes. `None` unless the error is an ICMP
/// Fragmentation Needed or an `ICMPv6` Packet Too Big; the MTU is the one it carries.
pub(in crate::udp) fn path_mtu_report(
    path: Path,
    err: &sock_extended_err,
    quote: &[u8],
) -> Option<PathMtuReport> {
    let too_big = match err.ee_origin {
        SO_EE_ORIGIN_ICMP => (err.ee_type, err.ee_code) == (3, 4),
        SO_EE_ORIGIN_ICMP6 => (err.ee_type, err.ee_code) == (2, 0),
        _ => false,
    };
    let mtu = u16::try_from(err.ee_info).unwrap_or(u16::MAX);
    too_big.then(|| PathMtuReport::with_quote(path, mtu, quote))
}

impl SocketErrors {
    /// Reads at most 64 queued errors, reporting Packet Too Big. Returns whether an
    /// asynchronous ICMP error was read; locally generated errors do not count.
    pub(in crate::udp) fn drain_errors(&self, socket: &UdpSocket) -> bool {
        let fd = socket.as_raw_fd();
        let mut asynchronous = false;
        for _ in 0..64 {
            let mut quote = [0; QUOTE];
            let mut cmsg = ErrCmsgBuf([0; 256]);
            let mut iov = [IoSliceMut::new(&mut quote)];
            let (len, to, err) = match recvmsg::<SockaddrStorage>(
                fd,
                &mut iov,
                Some(&mut cmsg.0),
                MsgFlags::MSG_ERRQUEUE,
            ) {
                Ok(msg) => (
                    msg.bytes,
                    // The datagram's destination.
                    msg.address.as_ref().and_then(socket_addr),
                    msg.cmsgs()
                        .ok()
                        .into_iter()
                        .flatten()
                        .find_map(|cmsg| match cmsg {
                            ControlMessageOwned::Ipv4RecvErr(err, _)
                            | ControlMessageOwned::Ipv6RecvErr(err, _) => Some(err),
                            _ => None,
                        }),
                ),
                Err(Errno::EAGAIN) => return asynchronous,
                Err(e) => {
                    tracing::debug!(message = "Error queue not read", error = %e);
                    return asynchronous;
                }
            };
            if let Some(err) = err {
                asynchronous |= matches!(err.ee_origin, SO_EE_ORIGIN_ICMP | SO_EE_ORIGIN_ICMP6);
                if let Some(to) = to {
                    let path = Path {
                        transport: self.id,
                        addr: unmap(to),
                        ecn: Ecn::NotEct,
                    };
                    if let Some(report) = path_mtu_report(path, &err, &quote[..len]) {
                        self.push_report(report);
                    }
                }
            }
        }
        asynchronous
    }

    /// Queues `report` for the engine; drops and counts it when the queue is full or
    /// closed.
    pub(in crate::udp) fn push_report(&self, report: PathMtuReport) {
        if !self.pmtu.push(report) {
            self.dropped.fetch_add(1, Ordering::Relaxed);
        }
    }
}

impl UdpTransport {
    /// [`UdpTransport::set_path_mtu_discovery`].
    pub(in crate::udp) fn set_recv_err(&self, on: bool) -> io::Result<()> {
        if self.local.is_ipv4() || !getsockopt(&self.socket, sockopt::Ipv6V6Only)? {
            setsockopt(&self.socket, sockopt::Ipv4RecvErr, &on)?;
        }
        if self.local.is_ipv6() {
            setsockopt(&self.socket, sockopt::Ipv6RecvErr, &on)?;
        }
        if on {
            self.errors.pmtu.open();
        }
        self.errors.discovery.store(on, Ordering::Relaxed);
        Ok(())
    }

    #[cfg(test)]
    pub(in crate::udp) fn push_report(&self, report: PathMtuReport) {
        self.errors.push_report(report);
    }
}
