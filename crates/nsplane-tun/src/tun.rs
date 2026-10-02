//! The platform-independent TUN device and its source and sink halves.

use std::io;
use std::os::fd::{AsFd, BorrowedFd, OwnedFd, RawFd};
use std::sync::{Arc, Weak};
use std::time::Duration;

use nsplane::{PacketBuf, PacketPool, PacketSink, PacketSource, PeerId};
use tokio::io::unix::AsyncFd;
use tokio::sync::watch;

#[cfg(any(target_os = "macos", target_os = "ios"))]
use crate::darwin as sys;
#[cfg(any(target_os = "linux", target_os = "android"))]
use crate::linux as sys;
use crate::unix::{adopt_fd, set_nonblocking};

/// Idle buffers kept by a [`TunSource`]'s pool.
const POOL_FREE: usize = 64;

/// How often the MTU watcher started by [`Tun::split`] queries the interface MTU.
pub const MTU_POLL_INTERVAL: Duration = Duration::from_secs(1);

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
    /// a 4-byte utun address-family header in front of every packet.
    ///
    /// `mtu` is the initial value; the device is not queried here. If the fd is a real
    /// TUN device (its name can be queried), [`Tun::split`] replaces it with the
    /// interface MTU at once and keeps it up to date; otherwise it stays as given.
    pub fn from_fd(fd: OwnedFd, mtu: u16) -> io::Result<Self> {
        set_nonblocking(&fd)?;
        Ok(Self { fd, mtu })
    }

    /// Adopts the TUN fd numbered `fd` (passed in by a parent process, e.g. the CLI's
    /// `--tun-fd`) through [`adopt_fd`](crate::adopt_fd), then behaves like
    /// [`Tun::from_fd`]: same framing, same `mtu` handling.
    ///
    /// Ownership rules: the call takes ownership of `fd`. It must be an fd the process
    /// inherited or otherwise owns, and nothing else may use or close it afterwards; it
    /// is closed when the [`Tun`] (or the halves of [`Tun::split`]) drops, and also if
    /// this call fails after adoption. A negative number or one that is not an open fd
    /// fails without adopting anything.
    pub fn from_raw_fd(fd: RawFd, mtu: u16) -> io::Result<Self> {
        Self::from_fd(adopt_fd(fd)?, mtu)
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
    /// halves. Must be called inside a tokio runtime with the time driver enabled.
    ///
    /// If the fd is a real TUN device, the interface MTU is queried now and a small
    /// task polls it every [`MTU_POLL_INTERVAL`], publishing changes on
    /// [`TunSource`]'s `mtu` watch. The task ends once the source and every receiver of
    /// that watch are dropped, the device fd is closed, or the query fails (the
    /// interface is gone). If the name cannot be queried (not a TUN device) nothing is
    /// spawned and the MTU stays the value given to [`Tun::from_fd`].
    pub fn split(self) -> io::Result<(TunSource, TunSink)> {
        let watched = sys::name(self.fd.as_fd())
            .and_then(|name| Ok((sys::mtu(&name)?, name)))
            .ok();
        let fd = Arc::new(AsyncFd::new(self.fd)?);
        let (sender, receiver) = watch::channel(watched.as_ref().map_or(self.mtu, |w| w.0));
        let unwatched = match watched {
            Some((_, name)) => {
                tokio::spawn(watch_mtu(name, Arc::downgrade(&fd), sender));
                None
            }
            None => Some(sender),
        };
        let source = TunSource {
            fd: Arc::clone(&fd),
            pool: PacketPool::new(POOL_FREE),
            mtu: receiver,
            _unwatched: unwatched,
        };
        Ok((source, TunSink { fd }))
    }
}

impl AsFd for Tun {
    /// The device fd, e.g. for handing it to a child process; it stays owned by the
    /// [`Tun`].
    fn as_fd(&self) -> BorrowedFd<'_> {
        self.fd.as_fd()
    }
}

/// Polls the MTU of interface `name` every [`MTU_POLL_INTERVAL`] and sends it on `mtu`
/// when it changed. Ends once every receiver is gone, the device fd is closed, or the
/// query fails.
async fn watch_mtu(name: String, fd: Weak<AsyncFd<OwnedFd>>, mtu: watch::Sender<u16>) {
    loop {
        // Every receiver gone: nobody observes the MTU any more.
        if tokio::time::timeout(MTU_POLL_INTERVAL, mtu.closed())
            .await
            .is_ok()
        {
            return;
        }
        // Device closed: the name may already belong to another interface.
        if fd.strong_count() == 0 {
            return;
        }
        let Ok(current) = sys::mtu(&name) else {
            return;
        };
        mtu.send_if_modified(|value| {
            let changed = *value != current;
            *value = current;
            changed
        });
    }
}

/// The receiving half of a [`Tun`]: packets the OS routed into the device.
#[derive(Debug)]
pub struct TunSource {
    fd: Arc<AsyncFd<OwnedFd>>,
    pool: PacketPool,
    /// The current MTU, which is also the number of packet bytes read per call. On
    /// macOS/iOS the 4-byte header is read into a separate scratch buffer, so it needs
    /// no room here.
    mtu: watch::Receiver<u16>,
    /// The watch's sender when no MTU watcher task owns it, kept alive so receivers
    /// never observe a closed channel.
    _unwatched: Option<watch::Sender<u16>>,
}

impl PacketSource for TunSource {
    /// Reads exactly one packet into the packet region of a pooled [`PacketBuf`],
    /// leaving the headroom in front free. A packet longer than the MTU is truncated
    /// by the OS. A zero-length read (end of stream) yields
    /// [`io::ErrorKind::BrokenPipe`].
    async fn recv(&mut self) -> io::Result<PacketBuf> {
        let capacity = usize::from(*self.mtu.borrow());
        let mut packet = self.pool.get(capacity);
        // `PacketBuf` exposes only initialised bytes, so the read region is zero-filled
        // first.
        packet.set_len(capacity);
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

    /// The device MTU. For a real TUN device it follows the interface MTU: the
    /// watcher started by [`Tun::split`] polls `SIOCGIFMTU` every
    /// [`MTU_POLL_INTERVAL`], so a change is observed within about that interval. For
    /// an fd that is not a TUN device it never changes.
    fn mtu(&self) -> watch::Receiver<u16> {
        let mut mtu = self.mtu.clone();
        // Like `Sender::subscribe`: only later changes count as changed.
        mtu.mark_unchanged();
        mtu
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
