//! Linux `AF_PACKET` transport: a raw packet socket bound to an existing interface.
//!
//! It serves a guest whose host-side TAP another process holds (a virtual machine monitor
//! that keeps the TAP's file descriptor itself). Frames the guest sends arrive on the
//! interface as received frames and are read from the socket; frames written to the socket
//! leave through the interface toward the guest. The socket carries a virtio-net header
//! (`PACKET_VNET_HDR`), so frames from a guest with checksum and segmentation offloads
//! arrive with a partial checksum or as one large GSO frame; the reader completes the
//! checksum and splits GSO frames into frames of `gso_size` payload bytes before handing
//! them on.

use std::io::{self, IoSlice, IoSliceMut};
use std::os::fd::{AsRawFd, OwnedFd};
use std::sync::Arc;

use libc::{
    AF_PACKET, ENETDOWN, ENOBUFS, ENOPROTOOPT, ENXIO, ETH_P_ALL, MSG_TRUNC, PACKET_IGNORE_OUTGOING,
    PACKET_OUTGOING, PACKET_VNET_HDR, SOCK_CLOEXEC, SOCK_NONBLOCK, SOCK_RAW, SOL_PACKET, c_int,
    sockaddr_ll, socklen_t,
};
use nsplane_packet::vnet::VirtioNetHdr;
use tokio::io::unix::AsyncFd;

use crate::tap::{if_index, socket};
use crate::transport::{FrameRead, FrameWrite};
use crate::vnet::{self, Segments};

/// An `AF_PACKET` socket bound to one interface, carrying the guest's frames.
#[derive(Debug)]
pub struct PacketSocket {
    fd: Arc<AsyncFd<OwnedFd>>,
    index: u32,
}

impl PacketSocket {
    /// Opens an `AF_PACKET` / `SOCK_RAW` socket for every protocol (`ETH_P_ALL`) with a
    /// virtio-net header (`PACKET_VNET_HDR`), bound to the interface `ifname`, which must
    /// exist.
    ///
    /// The socket does not read back the frames it writes, nor anything else the host sends
    /// out of the interface (`PACKET_IGNORE_OUTGOING`; on kernels without that option the
    /// reader skips outgoing frames itself). It does not change the interface: no
    /// promiscuous mode is needed, since every frame a TAP receives is delivered to the
    /// socket whatever its destination MAC.
    ///
    /// Needs `CAP_NET_RAW`.
    ///
    /// # Errors
    ///
    /// [`io::ErrorKind::InvalidInput`] for a name the kernel would not accept, `ENODEV`
    /// when the interface does not exist, `EPERM` without `CAP_NET_RAW`.
    ///
    /// # Panics
    ///
    /// Panics outside a Tokio runtime with I/O enabled.
    pub fn bind(ifname: &str) -> io::Result<Self> {
        let index = if_index(ifname)?;
        // Protocol 0: the socket receives nothing until it is bound to the interface.
        let fd = socket(AF_PACKET, SOCK_RAW | SOCK_NONBLOCK | SOCK_CLOEXEC, 0)?;
        set_option(&fd, PACKET_VNET_HDR)?;
        match set_option(&fd, PACKET_IGNORE_OUTGOING) {
            Err(e) if e.raw_os_error() == Some(ENOPROTOOPT) => {}
            result => result?,
        }
        let addr = sockaddr_ll {
            sll_family: u16::try_from(AF_PACKET).unwrap_or_default(),
            sll_protocol: u16::try_from(ETH_P_ALL).unwrap_or_default().to_be(),
            sll_ifindex: c_int::try_from(index)
                .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?,
            sll_hatype: 0,
            sll_pkttype: 0,
            sll_halen: 0,
            sll_addr: [0; 8],
        };
        #[allow(unsafe_code, reason = "bind(2) on an owned socket")]
        // SAFETY: `addr` is a `sockaddr_ll` that lives for the duration of the call and the
        // length passed is its size.
        let ret = unsafe {
            libc::bind(
                fd.as_raw_fd(),
                (&raw const addr).cast(),
                socklen_t::try_from(size_of::<sockaddr_ll>()).unwrap_or_default(),
            )
        };
        if ret == -1 {
            return Err(io::Error::last_os_error());
        }
        #[allow(unsafe_code, reason = "registering a raw fd with the reactor")]
        // SAFETY: `fd` is an open descriptor owned by the `OwnedFd`, which the `AsyncFd`
        // owns until it is dropped; `as_raw_fd` keeps returning that same descriptor.
        let fd = unsafe { AsyncFd::register(fd) }?;
        Ok(Self {
            fd: Arc::new(fd),
            index,
        })
    }

    /// The index of the interface the socket is bound to.
    pub const fn index(&self) -> u32 {
        self.index
    }

    /// Splits the socket into a frame reader and writer.
    pub fn split(self) -> (PacketReader, PacketWriter) {
        (
            PacketReader {
                fd: Arc::clone(&self.fd),
                index: self.index,
                segments: Segments::default(),
            },
            PacketWriter { fd: self.fd },
        )
    }
}

/// Reads the guest's frames from a [`PacketSocket`].
#[derive(Debug)]
pub struct PacketReader {
    fd: Arc<AsyncFd<OwnedFd>>,
    index: u32,
    segments: Segments,
}

impl FrameRead for PacketReader {
    /// Returns the next frame the interface received, never `None`: a packet socket has no
    /// end.
    ///
    /// Outgoing frames are skipped. A frame with a partial checksum is completed in place;
    /// a GSO frame (TCP over IPv4 or IPv6, UDP) is split and its frames are returned one per
    /// call. A frame the kernel truncated, or one whose virtio-net header or headers do not
    /// match (unknown GSO type, checksum offset past the end, malformed IP or transport
    /// header), is dropped and logged at debug level. While the interface is down the
    /// reader waits for it to come back up; once the interface is deleted the read fails
    /// with `ENETDOWN`.
    async fn read_frame(&mut self, buf: &mut [u8]) -> io::Result<Option<usize>> {
        loop {
            if let Some(len) = self.segments.next(buf) {
                return Ok(Some(len));
            }
            let mut guard = self.fd.readable().await?;
            let mut hdr = [0; VirtioNetHdr::LEN];
            let received = match guard.try_io(|fd| recv(fd.get_ref(), &mut hdr, buf)) {
                Ok(Ok(received)) => received,
                Ok(Err(e))
                    if e.raw_os_error() == Some(ENETDOWN) && interface_exists(self.index) =>
                {
                    continue;
                }
                Ok(Err(e)) => return Err(e),
                Err(_would_block) => continue,
            };
            if received.outgoing || received.truncated {
                continue;
            }
            let Some(len) = received.len.checked_sub(VirtioNetHdr::LEN) else {
                continue;
            };
            let Ok(hdr) = VirtioNetHdr::parse(&hdr) else {
                continue;
            };
            match vnet::process(&hdr, buf, len, &mut self.segments) {
                Ok(Some(len)) => return Ok(Some(len)),
                Ok(None) => tracing::trace!(len, ?hdr, "splitting a GSO frame"),
                Err(e) => tracing::debug!(?e, ?hdr, "dropping a malformed offload frame"),
            }
        }
    }
}

/// Writes frames to the guest through a [`PacketSocket`].
#[derive(Debug)]
pub struct PacketWriter {
    fd: Arc<AsyncFd<OwnedFd>>,
}

impl FrameWrite for PacketWriter {
    /// Sends one frame behind an empty virtio-net header (no offloads: the frame carries
    /// its complete checksums). A frame the kernel refuses because the interface is down or
    /// gone, it has no buffer space, or the frame exceeds the interface MTU (`ENETDOWN`,
    /// `ENXIO`, `ENOBUFS`, `EMSGSIZE`) is dropped and logged at debug level; the transport
    /// stays open.
    async fn write_frame(&mut self, frame: &[u8]) -> io::Result<()> {
        loop {
            let mut guard = self.fd.writable().await?;
            match guard.try_io(|fd| send(fd.get_ref(), frame)) {
                Ok(Err(e))
                    if matches!(
                        e.raw_os_error(),
                        Some(ENETDOWN | ENXIO | ENOBUFS | libc::EMSGSIZE)
                    ) =>
                {
                    tracing::debug!("dropping a frame for the guest: {e}");
                    return Ok(());
                }
                Ok(result) => return result.map(drop),
                Err(_would_block) => {}
            }
        }
    }
}

/// What one `recvmsg(2)` returned.
struct Received {
    /// Bytes received, the virtio-net header included.
    len: usize,
    /// The frame was sent out of the interface rather than received on it.
    outgoing: bool,
    /// The frame did not fit and was cut.
    truncated: bool,
}

/// Sets the integer socket option `name` at `SOL_PACKET` to 1.
fn set_option(fd: &OwnedFd, name: c_int) -> io::Result<()> {
    let on: c_int = 1;
    #[allow(unsafe_code, reason = "setsockopt(2) on an owned socket")]
    // SAFETY: `on` is a `c_int` that lives for the duration of the call and the length
    // passed is its size.
    let ret = unsafe {
        libc::setsockopt(
            fd.as_raw_fd(),
            SOL_PACKET,
            name,
            (&raw const on).cast(),
            socklen_t::try_from(size_of::<c_int>()).unwrap_or_default(),
        )
    };
    if ret == -1 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// One `recvmsg(2)`: the virtio-net header into `hdr`, the frame into `buf`.
fn recv(fd: &OwnedFd, hdr: &mut [u8; VirtioNetHdr::LEN], buf: &mut [u8]) -> io::Result<Received> {
    let mut iov = [IoSliceMut::new(hdr), IoSliceMut::new(buf)];
    #[allow(unsafe_code, reason = "zeroed C structs")]
    // SAFETY: `sockaddr_ll` and `msghdr` are plain C structs for which all zero bytes is a
    // valid value.
    let (mut addr, mut msg): (sockaddr_ll, libc::msghdr) = unsafe { std::mem::zeroed() };
    msg.msg_name = (&raw mut addr).cast();
    msg.msg_namelen = socklen_t::try_from(size_of::<sockaddr_ll>()).unwrap_or_default();
    // `IoSliceMut` is ABI compatible with `struct iovec` on Unix.
    msg.msg_iov = iov.as_mut_ptr().cast();
    // The two entries of `iov`; a literal, because the type of `msg_iovlen` differs between
    // C libraries (`size_t` on glibc, `int` on musl).
    msg.msg_iovlen = 2;
    #[allow(unsafe_code, reason = "recvmsg(2) on an owned socket")]
    // SAFETY: `msg` points at `addr` and at the two iovecs, which are valid for writes of
    // their lengths and live for the duration of the call.
    let ret = unsafe { libc::recvmsg(fd.as_raw_fd(), &raw mut msg, 0) };
    let len = usize::try_from(ret).map_err(|_| io::Error::last_os_error())?;
    Ok(Received {
        len,
        outgoing: addr.sll_pkttype == PACKET_OUTGOING,
        truncated: msg.msg_flags & MSG_TRUNC != 0,
    })
}

/// One `writev(2)` of an empty virtio-net header and `frame`.
fn send(fd: &OwnedFd, frame: &[u8]) -> io::Result<usize> {
    let hdr = [0; VirtioNetHdr::LEN];
    let iov = [IoSlice::new(&hdr), IoSlice::new(frame)];
    #[allow(unsafe_code, reason = "writev(2) on an owned socket")]
    // SAFETY: `IoSlice` is ABI compatible with `struct iovec` on Unix; both slices are valid
    // for reads of their lengths for the duration of the call.
    let ret = unsafe { libc::writev(fd.as_raw_fd(), iov.as_ptr().cast(), 2) };
    usize::try_from(ret).map_err(|_| io::Error::last_os_error())
}

/// Whether an interface with index `index` still exists.
fn interface_exists(index: u32) -> bool {
    let mut name = [0; libc::IFNAMSIZ];
    #[allow(unsafe_code, reason = "if_indextoname")]
    // SAFETY: `name` holds IFNAMSIZ bytes, as if_indextoname requires.
    let ret = unsafe { libc::if_indextoname(index, name.as_mut_ptr()) };
    !ret.is_null()
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use tokio::time::timeout;

    use super::*;
    use crate::tap::tests::{attach_vnet, net_caps};
    use crate::tap::{TapConfig, TapDevice, ensure_tap};
    use crate::transport::MAX_FRAME_LEN;
    use crate::vnet::tests::{assert_valid, tcp4_gso_frame, udp6_partial_frame};

    const WAIT: Duration = Duration::from_secs(5);

    /// A frame from the guest MAC ending in `src` to the gateway MAC, with a local
    /// experimental `EtherType` the host kernel does not process.
    fn frame(dst: [u8; 6], src: u8, payload: &[u8]) -> Vec<u8> {
        let mut f = dst.to_vec();
        f.extend_from_slice(&[0x52, 0x54, 0, 0, 0, src]);
        f.extend_from_slice(&[0x88, 0xB5]);
        f.extend_from_slice(payload);
        f
    }

    const GW: [u8; 6] = [0x02, 0, 0, 0, 0, 1];

    async fn read(reader: &mut impl FrameRead) -> Vec<u8> {
        let mut buf = vec![0; MAX_FRAME_LEN];
        let len = timeout(WAIT, reader.read_frame(&mut buf))
            .await
            .expect("no frame")
            .unwrap()
            .unwrap();
        buf.truncate(len);
        buf
    }

    /// Frames the guest writes into its TAP are read from the socket, whatever their
    /// destination MAC; frames written to the socket reach the guest and are not read back.
    #[tokio::test]
    async fn carries_frames_both_ways() {
        if !net_caps() {
            return;
        }
        let tap = ensure_tap(&TapConfig::new("nsafp-p1")).unwrap();
        let (mut guest_rx, mut guest_tx) = TapDevice::open(tap.name()).unwrap().split();
        let socket = PacketSocket::bind(tap.name()).unwrap();
        assert_eq!(socket.index(), tap.index());
        let (mut reader, mut writer) = socket.split();

        let unicast = frame(GW, 1, b"to the gateway");
        guest_tx.write_frame(&unicast).await.unwrap();
        assert_eq!(read(&mut reader).await, unicast);
        let other = frame([0x02, 0, 0, 0, 0, 9], 1, b"to another host");
        guest_tx.write_frame(&other).await.unwrap();
        assert_eq!(read(&mut reader).await, other);
        let broadcast = frame([0xFF; 6], 1, b"to everyone");
        guest_tx.write_frame(&broadcast).await.unwrap();
        assert_eq!(read(&mut reader).await, broadcast);

        let to_guest = frame([0x52, 0x54, 0, 0, 0, 1], 0xEE, b"to the guest");
        // The kernel activates the interface's queue asynchronously once the guest attaches
        // and drops frames sent before that, so the first frames may be lost.
        let mut buf = vec![0; MAX_FRAME_LEN];
        let mut got = None;
        for _ in 0..50 {
            writer.write_frame(&to_guest).await.unwrap();
            let read = guest_rx.read_frame(&mut buf);
            if let Ok(len) = timeout(Duration::from_millis(100), read).await {
                got = Some(buf[..len.unwrap().unwrap()].to_vec());
                break;
            }
        }
        assert_eq!(got.as_deref(), Some(&to_guest[..]));
        let after = frame(GW, 1, b"after our own write");
        guest_tx.write_frame(&after).await.unwrap();
        assert_eq!(read(&mut reader).await, after);
    }

    /// A guest with offloads hands the TAP a GSO frame and a frame with a partial checksum,
    /// as a virtual machine monitor does; the reader returns complete frames.
    #[tokio::test]
    async fn completes_guest_offloads() {
        if !net_caps() {
            return;
        }
        let tap = ensure_tap(&TapConfig::new("nsafp-p2")).unwrap();
        let (_, mut guest_tx) = TapDevice::from_fd(attach_vnet(tap.name())).unwrap().split();
        let (mut reader, _) = PacketSocket::bind(tap.name()).unwrap().split();

        let (hdr, frame) = tcp4_gso_frame(2500, 1000);
        guest_tx
            .write_frame(&[&hdr.encode()[..], &frame].concat())
            .await
            .unwrap();
        let mut offset = 0;
        for len in [1000, 1000, 500] {
            let got = read(&mut reader).await;
            assert_valid(&got);
            assert_eq!(got.len(), 54 + len);
            assert_eq!(got[54..], frame[54 + offset..54 + offset + len]);
            offset += len;
        }

        let (hdr, frame) = udp6_partial_frame(b"a query");
        guest_tx
            .write_frame(&[&hdr.encode()[..], &frame].concat())
            .await
            .unwrap();
        let got = read(&mut reader).await;
        assert_valid(&got);
        assert_eq!(got.len(), frame.len());
    }

    /// Frames for the guest are dropped while no process holds the TAP; the writer stays
    /// usable.
    #[tokio::test]
    async fn writes_without_a_guest() {
        if !net_caps() {
            return;
        }
        let tap = ensure_tap(&TapConfig::new("nsafp-noguest")).unwrap();
        let (_reader, mut writer) = PacketSocket::bind(tap.name()).unwrap().split();
        for _ in 0..3 {
            writer.write_frame(&frame(GW, 1, b"nobody")).await.unwrap();
        }
    }

    #[tokio::test]
    async fn bind_errors() {
        let err = PacketSocket::bind("nsafp-missing").unwrap_err();
        assert_eq!(err.raw_os_error(), Some(libc::ENODEV));
        let err = PacketSocket::bind("bad/name").unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidInput);
    }
}
