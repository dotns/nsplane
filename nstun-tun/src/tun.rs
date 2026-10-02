//! The platform-independent TUN device and its source and sink halves.

use std::io;
use std::os::fd::{AsFd, OwnedFd};
use std::sync::Arc;

use nstun::{PacketBuf, PacketPool, PacketSink, PacketSource, PeerId};
use tokio::io::unix::AsyncFd;
use tokio::sync::watch;

#[cfg(any(target_os = "macos", target_os = "ios"))]
use crate::darwin as sys;
#[cfg(any(target_os = "linux", target_os = "android"))]
use crate::linux as sys;
use crate::unix::set_nonblocking;

/// Idle buffers kept by a [`TunSource`]'s pool.
const POOL_FREE: usize = 64;

/// An opened TUN device, not yet registered with the tokio reactor.
#[derive(Debug)]
pub struct Tun {
    fd: OwnedFd,
    mtu: u16,
}

impl Tun {
    /// Creates a TUN device and reads its MTU (`SIOCGIFMTU`).
    ///
    /// Linux/Android: opens `/dev/net/tun` with `IFF_TUN | IFF_NO_PI`; `name` may be
    /// `""` or a pattern such as `"tun%d"` for a kernel-assigned name. macOS/iOS: opens
    /// a utun control socket; `name` is `"utun"` (kernel-assigned unit) or `"utunN"`.
    pub fn create(name: &str) -> io::Result<Self> {
        let fd = sys::create(name)?;
        set_nonblocking(&fd)?;
        let mtu = sys::mtu(&sys::name(fd.as_fd())?)?;
        Ok(Self { fd, mtu })
    }

    /// Adopts an inherited TUN fd (Android `VpnService`, iOS `NEPacketTunnelFlow`
    /// socket) and switches it to non-blocking mode.
    ///
    /// Linux/Android framing: one raw IP packet per read and write. macOS/iOS framing:
    /// a 4-byte utun address-family header in front of every packet. `mtu` is taken as
    /// given; the device is not queried.
    pub fn from_fd(fd: OwnedFd, mtu: u16) -> io::Result<Self> {
        set_nonblocking(&fd)?;
        Ok(Self { fd, mtu })
    }

    /// The interface name, queried from the fd (Linux/Android `TUNGETIFF`, macOS/iOS
    /// `UTUN_OPT_IFNAME`).
    ///
    /// For an adopted fd this works only if it is a real TUN device or utun socket;
    /// anything else yields the OS error of the query.
    pub fn name(&self) -> io::Result<String> {
        sys::name(self.fd.as_fd())
    }

    /// The MTU queried at [`Tun::create`] or given to [`Tun::from_fd`].
    pub const fn mtu(&self) -> u16 {
        self.mtu
    }

    /// Registers the fd with the tokio reactor and splits it into source and sink
    /// halves. Must be called inside a tokio runtime.
    pub fn split(self) -> io::Result<(TunSource, TunSink)> {
        let fd = Arc::new(AsyncFd::new(self.fd)?);
        let (mtu, _) = watch::channel(self.mtu);
        let source = TunSource {
            fd: Arc::clone(&fd),
            pool: PacketPool::new(POOL_FREE),
            capacity: usize::from(self.mtu),
            mtu,
        };
        Ok((source, TunSink { fd }))
    }
}

/// The receiving half of a [`Tun`]: packets the OS routed into the device.
#[derive(Debug)]
pub struct TunSource {
    fd: Arc<AsyncFd<OwnedFd>>,
    pool: PacketPool,
    /// Packet bytes read per call: the MTU. On macOS/iOS the 4-byte header is read
    /// into a separate scratch buffer, so it needs no room here.
    capacity: usize,
    /// Kept alive so receivers never observe a closed channel; Phase 1 has no MTU
    /// watcher, so the value never changes.
    mtu: watch::Sender<u16>,
}

impl PacketSource for TunSource {
    /// Reads exactly one packet into the packet region of a pooled [`PacketBuf`],
    /// leaving the headroom in front free. A packet longer than the MTU is truncated
    /// by the OS. A zero-length read (end of stream) yields
    /// [`io::ErrorKind::BrokenPipe`].
    async fn recv(&mut self) -> io::Result<PacketBuf> {
        let mut packet = self.pool.get(self.capacity);
        // `PacketBuf` exposes only initialised bytes, so the read region is zero-filled
        // first.
        packet.set_len(self.capacity);
        loop {
            let mut guard = self.fd.readable().await?;
            match guard.try_io(|fd| sys::read(fd.get_ref().as_fd(), packet.as_packet_mut())) {
                Ok(Ok(0)) => return Err(io::Error::from(io::ErrorKind::BrokenPipe)),
                Ok(Ok(len)) => {
                    packet.set_len(len);
                    return Ok(packet);
                }
                Ok(Err(e)) => return Err(e),
                Err(_would_block) => {}
            }
        }
    }

    /// The device MTU; it never changes in Phase 1.
    fn mtu(&self) -> watch::Receiver<u16> {
        self.mtu.subscribe()
    }
}

/// The sending half of a [`Tun`]: packets handed to the OS.
#[derive(Debug)]
pub struct TunSink {
    fd: Arc<AsyncFd<OwnedFd>>,
}

impl PacketSink for TunSink {
    /// Writes `packet` as one packet (macOS/iOS: behind the AF header chosen from its IP
    /// version). `from` is unused: the OS device has no notion of peers. A packet that
    /// is neither IPv4 nor IPv6 is dropped with [`io::ErrorKind::InvalidInput`].
    async fn send(&self, packet: PacketBuf, _from: PeerId) -> io::Result<()> {
        let bytes = packet.as_packet();
        if !matches!(bytes.first().map(|b| b >> 4), Some(4 | 6)) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "packet is neither IPv4 nor IPv6",
            ));
        }
        loop {
            let mut guard = self.fd.writable().await?;
            match guard.try_io(|fd| sys::write(fd.get_ref().as_fd(), bytes)) {
                Ok(result) => return result.map(drop),
                Err(_would_block) => {}
            }
        }
    }
}
