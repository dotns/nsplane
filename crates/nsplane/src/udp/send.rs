//! Sending: runs of datagrams as one segmented send, and waiting for room in the send
//! buffer.

use std::io;
use std::net::SocketAddr;
use std::sync::atomic::Ordering;
use std::time::Duration;

use nsplane_packet::{Ecn, PacketBuf, Path};
use quinn_udp::{EcnCodepoint, Transmit, UdpSockRef, UdpSocketState};
use tokio::io::Interest;
use tokio::net::UdpSocket;

#[cfg(any(target_os = "linux", target_os = "android"))]
use super::linux;
use super::{MAX_SEND, SocketErrors, UdpTransport};

impl UdpTransport {
    /// The most datagrams one send may carry right now.
    pub(super) fn max_segments(&self) -> usize {
        match &self.state {
            Some(state) if self.offload() => state.max_gso_segments(),
            _ => 1,
        }
    }

    /// Sends `contents` to `to`: one datagram, or with `segment_size` a train of datagrams
    /// of that size (the last may be shorter).
    pub(super) async fn send_segments(
        &self,
        contents: &[u8],
        segment_size: Option<usize>,
        to: &Path,
    ) -> io::Result<()> {
        let destination = self.target(to.addr)?;
        let Some(state) = &self.state else {
            // Without `quinn-udp` state nothing is segmented.
            return self.send_to(contents, destination, to.ecn).await;
        };
        let transmit = Transmit {
            destination,
            ecn: EcnCodepoint::from_bits(to.ecn.to_bits()),
            contents,
            segment_size,
            src_ip: None,
        };
        write_io(&self.socket, &self.errors, || {
            state.try_send(UdpSockRef::from(&*self.socket), &transmit)
        })
        .await
    }

    /// [`UdpTransport::send_segments`] without waiting: [`io::ErrorKind::WouldBlock`] when
    /// the socket cannot take it now.
    pub(super) fn try_send_segments(
        &self,
        contents: &[u8],
        segment_size: Option<usize>,
        to: &Path,
    ) -> io::Result<()> {
        let destination = self.target(to.addr)?;
        let Some(state) = &self.state else {
            return self.try_send_to(contents, destination, to.ecn);
        };
        let transmit = Transmit {
            destination,
            ecn: EcnCodepoint::from_bits(to.ecn.to_bits()),
            contents,
            segment_size,
            src_ip: None,
        };
        self.socket.try_io(Interest::WRITABLE, || {
            self.errors.write(&self.socket, || {
                state.try_send(UdpSockRef::from(&*self.socket), &transmit)
            })
        })
    }

    /// Sends `run`, two or more datagrams to `to` that [`run_len`] put into one run, as
    /// one segmented send (see [`UdpTransport::send_run_now`]).
    pub(super) async fn send_run(
        &self,
        state: &UdpSocketState,
        run: &[(Path, PacketBuf)],
        to: &Path,
    ) -> io::Result<()> {
        let destination = self.target(to.addr)?;
        write_io(&self.socket, &self.errors, || {
            self.send_run_now(state, run, destination, to.ecn)
        })
        .await
    }

    /// [`UdpTransport::send_run`] without waiting: [`io::ErrorKind::WouldBlock`] when the
    /// socket cannot take it now.
    pub(super) fn try_send_run(
        &self,
        state: &UdpSocketState,
        run: &[(Path, PacketBuf)],
        to: &Path,
    ) -> io::Result<()> {
        let destination = self.target(to.addr)?;
        self.socket.try_io(Interest::WRITABLE, || {
            self.errors.write(&self.socket, || {
                self.send_run_now(state, run, destination, to.ecn)
            })
        })
    }

    /// One non-blocking segmented send of `run` to `destination`, marked with `ecn`. On
    /// Linux and Android it goes out straight from the datagrams' buffers (one `iovec`
    /// each); the transport's train buffer takes a copy for `quinn-udp` elsewhere, for a
    /// run of more than [`linux::IOVS`] datagrams, and when that send fails with `EIO` or
    /// `EINVAL`, so that `quinn-udp` meets the error itself and turns segmentation off as
    /// it does for its own sends.
    fn send_run_now(
        &self,
        state: &UdpSocketState,
        run: &[(Path, PacketBuf)],
        destination: SocketAddr,
        ecn: Ecn,
    ) -> io::Result<()> {
        #[cfg(any(target_os = "linux", target_os = "android"))]
        if run.len() <= linux::IOVS {
            match self.send_gso(run, destination, ecn) {
                Err(e) if matches!(e.raw_os_error(), Some(nix::libc::EIO | nix::libc::EINVAL)) => {}
                result => return result,
            }
        }
        let mut train = self
            .train
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        train.clear();
        for (_, datagram) in run {
            train.extend_from_slice(datagram.as_packet());
        }
        let transmit = Transmit {
            destination,
            ecn: EcnCodepoint::from_bits(ecn.to_bits()),
            contents: &train,
            segment_size: run.first().map(|(_, datagram)| datagram.len()),
            src_ip: None,
        };
        state.try_send(UdpSockRef::from(&*self.socket), &transmit)
    }
}

/// How many datagrams from the start of `datagrams` go out in one send of at most
/// `max_segments`: the first one, and the ones after it with the same address and ECN mark
/// and the first one's size, up to one shorter one that ends the run, while the run fits
/// into [`MAX_SEND`] bytes. `0` for no datagrams.
pub(super) fn run_len(datagrams: &[(Path, PacketBuf)], max_segments: usize) -> usize {
    let Some(((to, first), rest)) = datagrams.split_first() else {
        return 0;
    };
    let size = first.len();
    let mut run = 1;
    let mut total = size;
    for (path, datagram) in rest {
        let len = datagram.len();
        if run == max_segments
            || path.addr != to.addr
            || path.ecn != to.ecn
            || len == 0
            || len > size
            || total + len > MAX_SEND
        {
            break;
        }
        run += 1;
        total += len;
        if len < size {
            break;
        }
    }
    run
}

/// The first pause of [`write_io`] after a try that found the send buffer full, and the
/// longest.
const FIRST_PAUSE: Duration = Duration::from_millis(1);
const LONGEST_PAUSE: Duration = Duration::from_millis(8);

/// Waits until `socket` is writable and runs the non-blocking send `io`, until it does not
/// fail with [`io::ErrorKind::WouldBlock`]: [`UdpSocket::async_io`], which is what it does
/// while path MTU discovery (`discovery`) is off.
///
/// While it is on, an ICMP error makes the kernel report the socket in error, which tokio
/// takes for a closed write side and from then on reports writable for good: waiting no
/// longer waits for room in the send buffer. So a try that finds the buffer full while tokio
/// reports that state pauses before the next, first 1 ms, doubling up to 8 ms, instead of
/// spinning.
pub(super) async fn write_io<R>(
    socket: &UdpSocket,
    errors: &SocketErrors,
    mut io: impl FnMut() -> io::Result<R>,
) -> io::Result<R> {
    if !errors.discovery.load(Ordering::Relaxed) {
        return socket.async_io(Interest::WRITABLE, io).await;
    }
    let mut pause = Duration::ZERO;
    loop {
        let ready = socket.ready(Interest::WRITABLE).await?;
        match socket.try_io(Interest::WRITABLE, || errors.write(socket, &mut io)) {
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                if ready.is_write_closed() {
                    pause = (pause * 2).clamp(FIRST_PAUSE, LONGEST_PAUSE);
                    tokio::time::sleep(pause).await;
                }
            }
            result => return result,
        }
    }
}
