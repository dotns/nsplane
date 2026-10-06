//! The platform-independent TUN device and its source and sink halves.

use std::collections::VecDeque;
use std::io;
#[cfg(any(target_os = "linux", target_os = "android"))]
use std::io::IoSlice;
#[cfg(any(target_os = "linux", target_os = "android"))]
use std::mem;
use std::os::fd::{AsFd, BorrowedFd, OwnedFd, RawFd};
#[cfg(any(target_os = "linux", target_os = "android"))]
use std::sync::Mutex;
use std::sync::{Arc, Weak};
use std::time::Duration;

#[cfg(any(target_os = "linux", target_os = "android"))]
use nsplane::{MAX_BATCH, PacketBatch};
use nsplane::{PacketBuf, PacketPool, PacketSink, PacketSource, PeerId, TAILROOM};
use tokio::io::Interest;
use tokio::io::unix::AsyncFd;
use tokio::sync::watch;

#[cfg(any(target_os = "macos", target_os = "ios"))]
use crate::darwin as sys;
#[cfg(any(target_os = "linux", target_os = "android"))]
use crate::linux as sys;
#[cfg(any(target_os = "linux", target_os = "android"))]
use crate::offload::{self, Coalescer, VirtioNetHdr};
use crate::unix::{adopt_fd, set_nonblocking};

/// Idle buffers kept by a [`TunSource`]'s pool.
const POOL_FREE: usize = 64;

/// How often the MTU watcher started by [`Tun::split`] queries the interface MTU.
pub const MTU_POLL_INTERVAL: Duration = Duration::from_secs(1);

/// Options for [`Tun::create_with`]; [`TunOptions::new`] (or `Default`) gives the
/// options [`Tun::create`] uses.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct TunOptions {
    offload: bool,
}

impl TunOptions {
    /// The default options: segmentation offloads on.
    pub const fn new() -> Self {
        Self { offload: true }
    }

    /// Whether to use segmentation offloads (Linux/Android `IFF_VNET_HDR` with TSO and,
    /// if the kernel supports it, USO); on by default. `false` opens a plain device that
    /// reads and writes one raw IP packet at a time. Ignored on macOS/iOS, which have no
    /// TUN offloads.
    #[must_use]
    pub const fn offload(mut self, offload: bool) -> Self {
        self.offload = offload;
        self
    }
}

impl Default for TunOptions {
    fn default() -> Self {
        Self::new()
    }
}

/// The segmentation offloads a [`Tun`] uses, from [`Tun::offload`]. All off on macOS/iOS
/// and for a plain Linux/Android device.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[non_exhaustive]
pub struct Offload {
    /// Every read and write carries a virtio-net header (`IFF_VNET_HDR`). Reads may then
    /// hold TCP or UDP super-packets, which the source splits into packets no larger than
    /// the MTU, and packets with a checksum left for the reader, which the source
    /// completes.
    pub vnet_hdr: bool,
    /// TCP segmentation offload (`TUN_F_TSO4 | TUN_F_TSO6`) is on: the sink coalesces
    /// runs of TCP packets of one flow into one super-packet per write.
    pub tso: bool,
    /// UDP segmentation offload (`TUN_F_USO4 | TUN_F_USO6`) is on: the sink also
    /// coalesces runs of equally sized UDP datagrams of one flow.
    pub uso: bool,
}

/// An opened TUN device, not yet registered with the tokio reactor.
#[derive(Debug)]
pub struct Tun {
    fd: OwnedFd,
    mtu: u16,
    offload: Offload,
}

impl Tun {
    /// Creates a TUN device with the default [`TunOptions`] (segmentation offloads on)
    /// and reads its MTU (`SIOCGIFMTU`).
    ///
    /// Linux/Android: opens `/dev/net/tun` with `IFF_TUN | IFF_NO_PI | IFF_VNET_HDR` and
    /// enables checksum and TCP segmentation offload, plus UDP segmentation offload if
    /// the kernel accepts it; if the kernel supports neither the header nor the offloads,
    /// it falls back to a plain `IFF_TUN | IFF_NO_PI` device. [`Tun::offload`] reports
    /// the outcome. `name` may be `""` or a pattern such as `"tun%d"` for a
    /// kernel-assigned name. macOS/iOS: opens a utun control socket; `name` is `"utun"`
    /// (kernel-assigned unit) or `"utunN"`.
    pub fn create(name: &str) -> io::Result<Self> {
        Self::create_with(name, TunOptions::new())
    }

    /// Like [`Tun::create`], with `options`; `offload(false)` ([`TunOptions::offload`]) opens a
    /// plain device that reads and writes one raw IP packet at a time.
    pub fn create_with(name: &str, options: TunOptions) -> io::Result<Self> {
        let (fd, offload) = open(name, options.offload)?;
        set_nonblocking(&fd)?;
        let mtu = sys::mtu(&sys::name(fd.as_fd())?)?;
        Ok(Self { fd, mtu, offload })
    }

    /// Adopts an inherited TUN fd (Android `VpnService`, iOS `NEPacketTunnelFlow`
    /// socket) and switches it to non-blocking mode.
    ///
    /// Linux/Android framing: one raw IP packet per read and write. If the fd is a TUN
    /// device with `IFF_VNET_HDR` (from `TUNGETIFF`), every packet is preceded by a
    /// virtio-net header instead: reads are split and checksum-completed like those of
    /// a created offload device, while writes carry a header without offloads, since the
    /// offloads the fd's owner enabled are unknown. [`Tun::offload`] then reports only
    /// [`Offload::vnet_hdr`]. macOS/iOS framing: a 4-byte utun address-family header in
    /// front of every packet.
    ///
    /// `mtu` is the initial value; the device is not queried here. If the fd is a real
    /// TUN device (its name can be queried), [`Tun::split`] replaces it with the
    /// interface MTU at once and keeps it up to date; otherwise it stays as given.
    pub fn from_fd(fd: OwnedFd, mtu: u16) -> io::Result<Self> {
        set_nonblocking(&fd)?;
        let offload = adopted_offload(fd.as_fd());
        Ok(Self { fd, mtu, offload })
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

    /// The created interface name, queried from the fd (Linux/Android `TUNGETIFF`,
    /// macOS/iOS `UTUN_OPT_IFNAME`): for a pattern such as `"tun%d"` or `"utun"` it is
    /// the name the kernel assigned, e.g. `tun0` or `utun3`. After [`Tun::split`] the
    /// halves report it through [`TunSource::name`] and [`TunSink::name`].
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

    /// The segmentation offloads the device uses.
    pub const fn offload(&self) -> Offload {
        self.offload
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
            #[cfg(any(target_os = "linux", target_os = "android"))]
            vnet: self.offload.vnet_hdr.then(VnetReader::new),
        };
        let sink = TunSink {
            fd,
            #[cfg(any(target_os = "linux", target_os = "android"))]
            vnet: self.offload.vnet_hdr.then(|| VnetWriter::new(self.offload)),
        };
        Ok((source, sink))
    }
}

/// Opens the device `name`, with segmentation offloads if `offload` and the kernel
/// supports them.
#[cfg(any(target_os = "linux", target_os = "android"))]
fn open(name: &str, offload: bool) -> io::Result<(OwnedFd, Offload)> {
    if offload {
        sys::create_offload(name)
    } else {
        Ok((sys::create(name)?, Offload::default()))
    }
}

/// Opens the device `name`; macOS/iOS have no TUN offloads.
#[cfg(any(target_os = "macos", target_os = "ios"))]
fn open(name: &str, _offload: bool) -> io::Result<(OwnedFd, Offload)> {
    Ok((sys::create(name)?, Offload::default()))
}

/// The offloads of an adopted fd: only the virtio-net header, if the fd is a TUN device
/// that has one.
#[cfg(any(target_os = "linux", target_os = "android"))]
fn adopted_offload(fd: BorrowedFd<'_>) -> Offload {
    Offload {
        vnet_hdr: sys::vnet_hdr(fd).unwrap_or(false),
        ..Offload::default()
    }
}

/// The offloads of an adopted fd; macOS/iOS have no TUN offloads.
#[cfg(any(target_os = "macos", target_os = "ios"))]
fn adopted_offload(_fd: BorrowedFd<'_>) -> Offload {
    Offload::default()
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
    /// Read state of a device with a virtio-net header.
    #[cfg(any(target_os = "linux", target_os = "android"))]
    vnet: Option<VnetReader>,
}

impl TunSource {
    /// The created interface name, queried from the shared fd like [`Tun::name`] on
    /// every call: a caller that created the device with a pattern (`"tun%d"`,
    /// `"utun"`) learns the kernel-assigned name after [`Tun::split`]. For an adopted
    /// fd that is not a TUN device it yields the OS error of the query.
    pub fn name(&self) -> io::Result<String> {
        sys::name(self.fd.get_ref().as_fd())
    }

    /// Room each packet split off a virtio-net read gets: the MTU, the translation slack
    /// and the tail room.
    #[cfg(any(target_os = "linux", target_os = "android"))]
    fn capacity(&self) -> usize {
        usize::from(*self.mtu.borrow()) + TRANSLATION_SLACK + TAILROOM
    }

    /// A pooled buffer for one plain read, its packet region the `mtu` bytes to read into.
    fn plain_buf(&mut self, mtu: usize) -> PacketBuf {
        let mut packet = self.pool.get(mtu + TRANSLATION_SLACK + TAILROOM);
        // `PacketBuf` exposes only initialised bytes; a reused buffer has them already, a
        // fresh one is zero-filled once.
        packet.set_len(mtu);
        packet
    }
}

impl PacketSource for TunSource {
    /// Reads exactly one packet into the packet region of a pooled [`PacketBuf`],
    /// leaving the headroom in front free and room for the MTU plus 28 bytes behind it,
    /// so an IPv4 <-> IPv6 translator can grow a full-size packet in place, plus
    /// [`TAILROOM`], so the grown packet is sealed without reallocating. A packet
    /// longer than the MTU is truncated by the OS. A zero-length read (end of stream)
    /// yields [`io::ErrorKind::BrokenPipe`].
    ///
    /// With a virtio-net header ([`Offload::vnet_hdr`]) one read may yield several
    /// packets; they are queued and returned one per call, before the next read.
    async fn recv(&mut self) -> io::Result<PacketBuf> {
        #[cfg(any(target_os = "linux", target_os = "android"))]
        {
            let capacity = self.capacity();
            if let Some(vnet) = &mut self.vnet {
                return vnet.recv(&self.fd, capacity, &mut self.pool).await;
            }
        }
        let mtu = usize::from(*self.mtu.borrow());
        let mut packet = self.plain_buf(mtu);
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

    /// Waits for one read like [`recv`](Self::recv), then keeps reading without waiting
    /// until the device has nothing more to read or `batch` is full, so a lone packet is
    /// returned at once. With a virtio-net header ([`Offload::vnet_hdr`]) one read of up
    /// to 65535 packet bytes is split into every packet it holds (each no larger than the
    /// MTU), and as many as fit are appended; the rest are appended by the next call
    /// before anything is read, and no further read is made after a split one. A
    /// malformed read is dropped. Packets read before an error stay in `batch`.
    #[cfg(any(target_os = "linux", target_os = "android"))]
    async fn recv_batch(&mut self, batch: &mut PacketBatch) -> io::Result<()> {
        let capacity = self.capacity();
        if let Some(vnet) = &mut self.vnet {
            return vnet
                .recv_batch(&self.fd, capacity, &mut self.pool, batch)
                .await;
        }
        if batch.is_full() {
            return Ok(());
        }
        let packet = self.recv().await?;
        // The batch had room, so the push succeeds.
        let _ = batch.push(packet);
        let mtu = usize::from(*self.mtu.borrow());
        while !batch.is_full() {
            let mut packet = self.plain_buf(mtu);
            // Clears the readiness if the read would block.
            let read = self.fd.try_io(Interest::READABLE, |fd| {
                sys::read(fd.as_fd(), packet.as_packet_mut())
            });
            match read {
                Ok(0) => {
                    self.pool.put(packet);
                    return Err(io::Error::from(io::ErrorKind::BrokenPipe));
                }
                Ok(len) => {
                    packet.set_len(len);
                    let _ = batch.push(packet);
                }
                Err(e) => {
                    self.pool.put(packet);
                    return if e.kind() == io::ErrorKind::WouldBlock {
                        Ok(())
                    } else {
                        Err(e)
                    };
                }
            }
        }
        Ok(())
    }

    /// Returns the buffers to the source's pool, which keeps up to 64 idle ones; the rest
    /// are dropped.
    fn recycle(&mut self, bufs: &mut Vec<PacketBuf>) {
        for buf in bufs.drain(..) {
            self.pool.put(buf);
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
    /// Write state of a device with a virtio-net header.
    #[cfg(any(target_os = "linux", target_os = "android"))]
    vnet: Option<VnetWriter>,
}

impl PacketSink for TunSink {
    /// Writes `packet` as one packet (macOS/iOS: behind the AF header chosen from its IP
    /// version; with [`Offload::vnet_hdr`]: behind a virtio-net header without
    /// offloads). `from` is unused: the OS device has no notion of peers. A packet that
    /// is neither IPv4 nor IPv6 is dropped with [`io::ErrorKind::InvalidInput`].
    async fn send(&self, packet: PacketBuf, _from: PeerId) -> io::Result<()> {
        self.write(packet.as_packet()).await
    }

    /// Like one [`send`](Self::send) per packet, unless the device uses TCP
    /// segmentation offload ([`Offload::tso`]): then up to [`MAX_BATCH`] packets at a
    /// time are coalesced, runs of TCP packets of one flow (and of UDP datagrams if
    /// [`Offload::uso`]) each into one super-packet the kernel splits again, and every
    /// write is one `writev` of the virtio-net header and the packet pieces. A packet
    /// that is neither IPv4 nor IPv6 ends the call with [`io::ErrorKind::InvalidInput`]
    /// once the packets in front of it are written. If a write fails, the packets of
    /// the coalesced chunk are still written and the first error is returned once the
    /// chunk is done; the failed write's packets are dropped. Cancelling drops the chunk
    /// being written.
    #[cfg(any(target_os = "linux", target_os = "android"))]
    async fn send_batch(&self, packets: &mut VecDeque<(PeerId, PacketBuf)>) -> io::Result<()> {
        match &self.vnet {
            Some(vnet) if vnet.tso => vnet.send_batch(&self.fd, packets, None).await,
            _ => {
                while let Some((from, packet)) = packets.pop_front() {
                    self.send(packet, from).await?;
                }
                Ok(())
            }
        }
    }

    /// Like [`send_batch`](Self::send_batch), and appends the buffer of every packet it
    /// took over to `spent` once its write is done, whether it was written or dropped.
    /// With TCP segmentation offload the buffers of a coalesced chunk are appended
    /// together once the chunk is written; a packet that is neither IPv4 nor IPv6 is
    /// dropped there without being appended.
    async fn send_batch_spent(
        &self,
        packets: &mut VecDeque<(PeerId, PacketBuf)>,
        spent: &mut Vec<PacketBuf>,
    ) -> io::Result<()> {
        #[cfg(any(target_os = "linux", target_os = "android"))]
        if let Some(vnet) = &self.vnet
            && vnet.tso
        {
            return vnet.send_batch(&self.fd, packets, Some(spent)).await;
        }
        while let Some((_, packet)) = packets.pop_front() {
            let result = self.write(packet.as_packet()).await;
            spent.push(packet);
            result?;
        }
        Ok(())
    }

    /// Like [`send_batch`](Self::send_batch), but each write is tried once
    /// ([`AsyncFd::try_io`]): a packet the device cannot take now stays in `packets` with
    /// the ones behind it, and the call returns [`io::ErrorKind::WouldBlock`]. With TCP
    /// segmentation offload, a coalesced chunk whose write would block part-way (its
    /// packets are already merged) is kept and written before any later packet by the
    /// next [`send_batch`](Self::send_batch) or `try_send_batch`, so order is kept; a Linux
    /// TUN device blocks a write only when its send buffer was lowered (`TUNSETSNDBUF`).
    fn try_send_batch(&self, packets: &mut VecDeque<(PeerId, PacketBuf)>) -> io::Result<()> {
        #[cfg(any(target_os = "linux", target_os = "android"))]
        if let Some(vnet) = &self.vnet
            && vnet.tso
        {
            return vnet.try_send_batch(&self.fd, packets);
        }
        while let Some((_, packet)) = packets.front() {
            match self.try_write(packet.as_packet()) {
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => return Err(e),
                result => {
                    packets.pop_front();
                    result?;
                }
            }
        }
        Ok(())
    }
}

impl TunSink {
    /// The created interface name, queried from the shared fd like [`Tun::name`] on
    /// every call: a caller that created the device with a pattern (`"tun%d"`,
    /// `"utun"`) learns the kernel-assigned name after [`Tun::split`]. For an adopted
    /// fd that is not a TUN device it yields the OS error of the query.
    pub fn name(&self) -> io::Result<String> {
        sys::name(self.fd.get_ref().as_fd())
    }

    /// Writes `packet` as [`PacketSink::send`] does.
    async fn write(&self, packet: &[u8]) -> io::Result<()> {
        check_ip(packet)?;
        #[cfg(any(target_os = "linux", target_os = "android"))]
        if self.vnet.is_some() {
            let hdr = VirtioNetHdr::default().encode();
            return write_vectored(&self.fd, &[IoSlice::new(&hdr), IoSlice::new(packet)]).await;
        }
        loop {
            let mut guard = self.fd.writable().await?;
            match guard.try_io(|fd| sys::write(fd.get_ref().as_fd(), packet)) {
                Ok(result) => return result.map(drop),
                Err(_would_block) => {}
            }
        }
    }

    /// Writes `packet` as [`PacketSink::send`] does, without waiting.
    fn try_write(&self, packet: &[u8]) -> io::Result<()> {
        check_ip(packet)?;
        #[cfg(any(target_os = "linux", target_os = "android"))]
        if self.vnet.is_some() {
            let hdr = VirtioNetHdr::default().encode();
            return try_write_vectored(&self.fd, &[IoSlice::new(&hdr), IoSlice::new(packet)]);
        }
        self.fd
            .try_io(Interest::WRITABLE, |fd| sys::write(fd.as_fd(), packet))
            .map(drop)
    }
}

/// Fails with [`io::ErrorKind::InvalidInput`] unless `packet` is IPv4 or IPv6.
fn check_ip(packet: &[u8]) -> io::Result<()> {
    if matches!(packet.first().map(|b| b >> 4), Some(4 | 6)) {
        Ok(())
    } else {
        Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "packet is neither IPv4 nor IPv6",
        ))
    }
}

/// Room beyond the MTU each packet read from the device gets: the growth of an IPv4
/// packet translated to IPv6 with a fragment header, so an IPv4 <-> IPv6 translator
/// can rewrite a full-size packet in place.
const TRANSLATION_SLACK: usize = 28;

/// Bytes one read from a device with a virtio-net header may return: the header and the
/// largest IP packet.
#[cfg(any(target_os = "linux", target_os = "android"))]
const VNET_READ: usize = VirtioNetHdr::LEN + 65535;

/// Read state of a [`TunSource`] whose device carries a virtio-net header.
#[cfg(any(target_os = "linux", target_os = "android"))]
#[derive(Debug)]
struct VnetReader {
    /// The last read: a virtio-net header and the packet behind it.
    scratch: Box<[u8]>,
    /// Segments of the packet in `scratch` not produced yet.
    pending: Option<Pending>,
    /// Packets split off by [`TunSource::recv`] and not returned yet.
    ready: VecDeque<PacketBuf>,
    /// The batch [`TunSource::recv`] reads into.
    staging: PacketBatch,
}

/// The rest of a split read: the read's header and length and the next segment index.
#[cfg(any(target_os = "linux", target_os = "android"))]
#[derive(Debug, Clone, Copy)]
struct Pending {
    hdr: VirtioNetHdr,
    len: usize,
    next: usize,
}

#[cfg(any(target_os = "linux", target_os = "android"))]
impl VnetReader {
    fn new() -> Self {
        Self {
            scratch: vec![0; VNET_READ].into_boxed_slice(),
            pending: None,
            ready: VecDeque::new(),
            staging: PacketBatch::new(),
        }
    }

    /// The next packet: a queued one, or the first of the next read. Packets split off
    /// a read get at least `capacity` bytes of capacity.
    async fn recv(
        &mut self,
        fd: &AsyncFd<OwnedFd>,
        capacity: usize,
        pool: &mut PacketPool,
    ) -> io::Result<PacketBuf> {
        loop {
            if let Some(packet) = self.ready.pop_front() {
                return Ok(packet);
            }
            let mut staging = mem::take(&mut self.staging);
            let result = self.recv_batch(fd, capacity, pool, &mut staging).await;
            self.ready.extend(staging.drain());
            self.staging = staging;
            result?;
        }
    }

    /// Appends queued packets and the rest of the last read if there are any; otherwise
    /// reads until a read yields at least one packet, then keeps reading without waiting
    /// until a read would block, one is split (not every segment fit), or `batch` is
    /// full. Packets split off a read get at least `capacity` bytes of capacity.
    async fn recv_batch(
        &mut self,
        fd: &AsyncFd<OwnedFd>,
        capacity: usize,
        pool: &mut PacketPool,
        batch: &mut PacketBatch,
    ) -> io::Result<()> {
        let before = batch.len();
        while !batch.is_full() {
            let Some(packet) = self.ready.pop_front() else {
                break;
            };
            // The batch had room, so the push succeeds.
            let _ = batch.push(packet);
        }
        if let Some(pending) = self.pending.take() {
            self.segment(
                pending.hdr,
                pending.len,
                pending.next,
                capacity,
                pool,
                batch,
            );
        }
        if batch.len() > before || batch.is_full() {
            return Ok(());
        }
        loop {
            let mut guard = fd.readable().await?;
            let len = match guard.try_io(|fd| sys::read(fd.get_ref().as_fd(), &mut self.scratch)) {
                Ok(Ok(0)) => return Err(io::Error::from(io::ErrorKind::BrokenPipe)),
                Ok(Ok(len)) => len,
                Ok(Err(e)) => return Err(e),
                Err(_would_block) => continue,
            };
            self.split(len, capacity, pool, batch);
            if batch.len() > before {
                break;
            }
        }
        // Keep reading without waiting while the last read was not split and there is room.
        while self.pending.is_none() && !batch.is_full() {
            // Clears the readiness if the read would block.
            match fd.try_io(Interest::READABLE, |fd| {
                sys::read(fd.as_fd(), &mut self.scratch)
            }) {
                Ok(0) => return Err(io::Error::from(io::ErrorKind::BrokenPipe)),
                Ok(len) => self.split(len, capacity, pool, batch),
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => break,
                Err(e) => return Err(e),
            }
        }
        Ok(())
    }

    /// Splits the `len`-byte read in `scratch` into `batch` (see [`segment`](Self::segment));
    /// drops a read without a virtio-net header.
    fn split(
        &mut self,
        len: usize,
        capacity: usize,
        pool: &mut PacketPool,
        batch: &mut PacketBatch,
    ) {
        match VirtioNetHdr::parse(&self.scratch[..len]) {
            Ok(hdr) => self.segment(hdr, len, 0, capacity, pool, batch),
            Err(e) => tracing::debug!(?e, "dropping a TUN read without a vnet header"),
        }
    }

    /// Appends the segments of the `len`-byte read in `scratch` from index `first` on to
    /// `batch`, each with at least `capacity` bytes of capacity, and keeps the rest
    /// pending; drops the read if it is malformed.
    fn segment(
        &mut self,
        hdr: VirtioNetHdr,
        len: usize,
        first: usize,
        capacity: usize,
        pool: &mut PacketPool,
        batch: &mut PacketBatch,
    ) {
        let packet = &self.scratch[VirtioNetHdr::LEN..len];
        match offload::segment(&hdr, packet, first, capacity, pool, batch) {
            Ok(next) => self.pending = next.map(|next| Pending { hdr, len, next }),
            Err(e) => tracing::debug!(?e, ?hdr, "dropping a malformed TUN read"),
        }
    }
}

/// Write state of a [`TunSink`] whose device carries a virtio-net header.
#[cfg(any(target_os = "linux", target_os = "android"))]
#[derive(Debug)]
struct VnetWriter {
    /// Whether TCP super-packets may be written.
    tso: bool,
    /// Whether UDP super-packets may be written.
    uso: bool,
    /// Reusable coalescing buffers; taken out for the duration of a write.
    state: Mutex<Option<WriteState>>,
}

/// The coalescer and the chunk of packets it works on.
#[cfg(any(target_os = "linux", target_os = "android"))]
#[derive(Debug)]
struct WriteState {
    coalescer: Coalescer,
    chunk: Vec<PacketBuf>,
    /// Groups of the coalesced chunk written so far; the rest are written before any
    /// later packet.
    written: usize,
    /// The first error of the chunk's writes.
    error: Option<io::Error>,
}

#[cfg(any(target_os = "linux", target_os = "android"))]
impl VnetWriter {
    const fn new(offload: Offload) -> Self {
        Self {
            tso: offload.tso,
            uso: offload.uso,
            state: Mutex::new(None),
        }
    }

    /// [`TunSink::send_batch`] with TCP segmentation offload; with `spent`,
    /// [`TunSink::send_batch_spent`].
    async fn send_batch(
        &self,
        fd: &AsyncFd<OwnedFd>,
        packets: &mut VecDeque<(PeerId, PacketBuf)>,
        spent: Option<&mut Vec<PacketBuf>>,
    ) -> io::Result<()> {
        let mut state = self.take();
        let result = state.send_batch(fd, packets, spent).await;
        self.put(state);
        result
    }

    /// [`TunSink::try_send_batch`] with TCP segmentation offload.
    fn try_send_batch(
        &self,
        fd: &AsyncFd<OwnedFd>,
        packets: &mut VecDeque<(PeerId, PacketBuf)>,
    ) -> io::Result<()> {
        let mut state = self.take();
        let result = state.try_send_batch(fd, packets);
        self.put(state);
        result
    }

    /// The reusable write state, with the chunk an earlier call left unfinished.
    fn take(&self) -> WriteState {
        self.state
            .lock()
            .ok()
            .and_then(|mut state| state.take())
            .unwrap_or_else(|| WriteState {
                coalescer: Coalescer::new(self.uso),
                chunk: Vec::with_capacity(MAX_BATCH),
                written: 0,
                error: None,
            })
    }

    fn put(&self, state: WriteState) {
        if let Ok(mut slot) = self.state.lock() {
            *slot = Some(state);
        }
    }
}

#[cfg(any(target_os = "linux", target_os = "android"))]
impl WriteState {
    async fn send_batch(
        &mut self,
        fd: &AsyncFd<OwnedFd>,
        packets: &mut VecDeque<(PeerId, PacketBuf)>,
        mut spent: Option<&mut Vec<PacketBuf>>,
    ) -> io::Result<()> {
        self.finish(fd, spent.as_deref_mut()).await?;
        while self.load(packets)? {
            self.finish(fd, spent.as_deref_mut()).await?;
        }
        Ok(())
    }

    fn try_send_batch(
        &mut self,
        fd: &AsyncFd<OwnedFd>,
        packets: &mut VecDeque<(PeerId, PacketBuf)>,
    ) -> io::Result<()> {
        self.try_finish(fd)?;
        while self.load(packets)? {
            self.try_finish(fd)?;
        }
        Ok(())
    }

    /// Takes the next chunk, up to [`MAX_BATCH`] IP packets from the front of `packets`,
    /// and coalesces it; `false` without packets. A packet that is neither IPv4 nor IPv6
    /// at the front is dropped with [`io::ErrorKind::InvalidInput`].
    fn load(&mut self, packets: &mut VecDeque<(PeerId, PacketBuf)>) -> io::Result<bool> {
        let Some((_, front)) = packets.front() else {
            return Ok(false);
        };
        if let Err(e) = check_ip(front.as_packet()) {
            packets.pop_front();
            return Err(e);
        }
        while self.chunk.len() < MAX_BATCH
            && packets
                .front()
                .is_some_and(|(_, packet)| check_ip(packet.as_packet()).is_ok())
        {
            if let Some((_, packet)) = packets.pop_front() {
                self.chunk.push(packet);
            }
        }
        self.coalescer.coalesce(&mut self.chunk);
        self.written = 0;
        Ok(true)
    }

    /// Whether groups of the chunk are left to write.
    fn unfinished(&self) -> bool {
        self.written < self.coalescer.groups().len()
    }

    /// Writes every group of the chunk not written yet; returns the chunk's first error
    /// once every group was tried. The chunk's buffers go to `spent`, if given.
    async fn finish(
        &mut self,
        fd: &AsyncFd<OwnedFd>,
        spent: Option<&mut Vec<PacketBuf>>,
    ) -> io::Result<()> {
        while self.unfinished() {
            let result = loop {
                match self.try_write_group(fd) {
                    Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                        // The next try clears the readiness again if the write still would block.
                        fd.writable().await?.retain_ready();
                    }
                    result => break result,
                }
            };
            self.wrote(result);
        }
        self.done(spent)
    }

    /// [`WriteState::finish`] without waiting: a group that would block ends the call
    /// with [`io::ErrorKind::WouldBlock`], and it and the rest stay unfinished.
    fn try_finish(&mut self, fd: &AsyncFd<OwnedFd>) -> io::Result<()> {
        while self.unfinished() {
            match self.try_write_group(fd) {
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => return Err(e),
                result => self.wrote(result),
            }
        }
        self.done(None)
    }

    /// Writes the next group once, as one `writev` of its virtio-net header and pieces.
    fn try_write_group(&self, fd: &AsyncFd<OwnedFd>) -> io::Result<()> {
        let group = &self.coalescer.groups()[self.written];
        let hdr = group.hdr().encode();
        let mut parts = [IoSlice::new(&[]); MAX_BATCH + 1];
        let parts = &mut parts[..=group.len()];
        parts[0] = IoSlice::new(&hdr);
        for (slot, part) in parts[1..]
            .iter_mut()
            .zip(self.coalescer.parts(group, &self.chunk))
        {
            *slot = IoSlice::new(part);
        }
        try_write_vectored(fd, parts)
    }

    /// Counts the next group written, keeping the chunk's first error.
    fn wrote(&mut self, result: io::Result<()>) {
        self.written += 1;
        if let Err(e) = result {
            self.error.get_or_insert(e);
        }
    }

    /// Ends the written chunk, moving its buffers to `spent` if given; its first error,
    /// if any.
    fn done(&mut self, spent: Option<&mut Vec<PacketBuf>>) -> io::Result<()> {
        match spent {
            Some(spent) => spent.append(&mut self.chunk),
            None => self.chunk.clear(),
        }
        self.error.take().map_or(Ok(()), Err)
    }
}

/// Writes the concatenation of `parts` as one packet without waiting.
#[cfg(any(target_os = "linux", target_os = "android"))]
fn try_write_vectored(fd: &AsyncFd<OwnedFd>, parts: &[IoSlice<'_>]) -> io::Result<()> {
    fd.try_io(Interest::WRITABLE, |fd| sys::writev(fd.as_fd(), parts))
        .map(drop)
}

/// Writes the concatenation of `parts` as one packet.
#[cfg(any(target_os = "linux", target_os = "android"))]
async fn write_vectored(fd: &AsyncFd<OwnedFd>, parts: &[IoSlice<'_>]) -> io::Result<()> {
    loop {
        let mut guard = fd.writable().await?;
        if let Ok(result) = guard.try_io(|fd| sys::writev(fd.get_ref().as_fd(), parts)) {
            return result.map(drop);
        }
    }
}

#[cfg(test)]
#[cfg(any(target_os = "linux", target_os = "android"))]
mod tests {
    use std::net::Ipv4Addr;
    use std::os::unix::net::UnixDatagram;

    use nsplane_packet::checksum::{ipv4_header_checksum, transport_checksum_v4};

    use super::*;

    const SRC: Ipv4Addr = Ipv4Addr::new(10, 0, 0, 1);
    const DST: Ipv4Addr = Ipv4Addr::new(10, 0, 0, 2);

    /// An IPv4 packet with a valid checksum: TCP (flags ACK) or UDP.
    fn packet(proto: u8, id: u16, seq: u32, payload: &[u8]) -> Vec<u8> {
        let mut l4 = vec![0u8; if proto == 6 { 20 } else { 8 }];
        l4[0..2].copy_from_slice(&1000u16.to_be_bytes());
        l4[2..4].copy_from_slice(&2000u16.to_be_bytes());
        if proto == 6 {
            l4[4..8].copy_from_slice(&seq.to_be_bytes());
            l4[8..12].copy_from_slice(&1u32.to_be_bytes());
            l4[12] = 5 << 4;
            l4[13] = 0x10;
            l4[14..16].copy_from_slice(&1000u16.to_be_bytes());
        } else {
            let len = u16::try_from(8 + payload.len()).unwrap();
            l4[4..6].copy_from_slice(&len.to_be_bytes());
        }
        l4.extend_from_slice(payload);
        let csum = transport_checksum_v4(SRC, DST, proto, &l4);
        let at = if proto == 6 { 16 } else { 6 };
        l4[at..at + 2].copy_from_slice(&csum.to_be_bytes());
        let len = u16::try_from(20 + l4.len()).unwrap();
        let mut p = vec![0x45, 0];
        p.extend_from_slice(&len.to_be_bytes());
        p.extend_from_slice(&id.to_be_bytes());
        p.extend_from_slice(&[0x40, 0, 64, proto, 0, 0]);
        p.extend_from_slice(&SRC.octets());
        p.extend_from_slice(&DST.octets());
        let csum = ipv4_header_checksum(&p);
        p[10..12].copy_from_slice(&csum.to_be_bytes());
        p.extend_from_slice(&l4);
        p
    }

    /// `count` consecutive full-size TCP segments of one flow.
    fn tcp_run(count: u8) -> Vec<Vec<u8>> {
        (0..count)
            .map(|i| {
                let payload: Vec<u8> = (0..1000u16).map(|b| b.to_le_bytes()[0] ^ i).collect();
                packet(6, 7 + u16::from(i), 100 + 1000 * u32::from(i), &payload)
            })
            .collect()
    }

    /// A device over one end of a datagram socket pair; the other end plays the kernel.
    fn device(offload: Offload) -> (TunSource, TunSink, UnixDatagram) {
        let (ours, kernel) = UnixDatagram::pair().unwrap();
        let fd = OwnedFd::from(ours);
        set_nonblocking(&fd).unwrap();
        let tun = Tun {
            fd,
            mtu: 1500,
            offload,
        };
        let (source, sink) = tun.split().unwrap();
        (source, sink, kernel)
    }

    const TSO: Offload = Offload {
        vnet_hdr: true,
        tso: true,
        uso: false,
    };

    fn recv_datagram(kernel: &UnixDatagram) -> (VirtioNetHdr, Vec<u8>) {
        let mut buf = vec![0; VNET_READ];
        let len = kernel.recv(&mut buf).unwrap();
        let hdr = VirtioNetHdr::parse(&buf[..len]).unwrap();
        (hdr, buf[VirtioNetHdr::LEN..len].to_vec())
    }

    fn batch_of(packets: &[Vec<u8>]) -> VecDeque<(PeerId, PacketBuf)> {
        packets
            .iter()
            .map(|p| (PeerId::new(0), PacketBuf::from_packet(p)))
            .collect()
    }

    #[test]
    fn options_default_to_offload() {
        assert_eq!(TunOptions::default(), TunOptions::new());
        assert!(TunOptions::new().offload);
        assert!(!TunOptions::new().offload(false).offload);
        assert!(!Offload::default().vnet_hdr);
    }

    #[tokio::test]
    async fn send_batch_coalesces_and_recv_batch_splits() {
        let (mut source, sink, kernel) = device(TSO);
        let run = tcp_run(5);
        let udp = packet(17, 1, 0, b"datagram");
        let mut packets = batch_of(&run);
        packets.extend(batch_of(std::slice::from_ref(&udp)));
        sink.send_batch(&mut packets).await.unwrap();
        assert!(packets.is_empty());

        let (hdr, super_packet) = recv_datagram(&kernel);
        assert_eq!(hdr.gso_type, VirtioNetHdr::GSO_TCPV4);
        assert_eq!(hdr.gso_size, 1000);
        assert_eq!(super_packet.len(), 40 + 5000);
        let (hdr_udp, single) = recv_datagram(&kernel);
        assert_eq!(hdr_udp, VirtioNetHdr::default());
        assert_eq!(single, udp);

        // The kernel's view back: the super-packet is split into the original packets.
        let mut framed = hdr.encode().to_vec();
        framed.extend_from_slice(&super_packet);
        kernel.send(&framed).unwrap();
        let mut batch = PacketBatch::new();
        source.recv_batch(&mut batch).await.unwrap();
        let got: Vec<&[u8]> = batch.iter().map(PacketBuf::as_packet).collect();
        assert_eq!(got, run);
        assert!(batch.iter().all(|p| p.headroom() == nsplane::HEADROOM));
    }

    /// The addresses of the packets' buffers, to recognize them in `spent`.
    fn addrs<'a>(packets: impl IntoIterator<Item = &'a PacketBuf>) -> Vec<*const u8> {
        packets
            .into_iter()
            .map(|p| p.as_packet().as_ptr())
            .collect()
    }

    #[tokio::test]
    async fn send_batch_spent_returns_written_buffers() {
        for offload in [
            Offload::default(),
            Offload {
                vnet_hdr: true,
                ..Offload::default()
            },
        ] {
            let (_source, sink, kernel) = device(offload);
            let udp: Vec<Vec<u8>> = (0..3u8).map(|i| packet(17, 1, 0, &[i; 9])).collect();
            let mut packets = batch_of(&udp);
            let sent = addrs(packets.iter().map(|(_, p)| p));
            let mut spent = Vec::new();
            sink.send_batch_spent(&mut packets, &mut spent)
                .await
                .unwrap();
            assert!(packets.is_empty());
            assert_eq!(addrs(&spent), sent);
            let header = if offload.vnet_hdr {
                VirtioNetHdr::LEN
            } else {
                0
            };
            let got: Vec<Vec<u8>> = drain(&kernel)
                .iter()
                .map(|d| d[header..].to_vec())
                .collect();
            assert_eq!(got, udp);

            // A dropped packet's buffer is spent too; the rest stay.
            let mut packets = batch_of(&udp);
            packets.push_front((PeerId::new(0), PacketBuf::from_packet(&[0x10, 0])));
            let mut spent = Vec::new();
            let err = sink
                .send_batch_spent(&mut packets, &mut spent)
                .await
                .unwrap_err();
            assert_eq!(err.kind(), io::ErrorKind::InvalidInput);
            assert_eq!((spent.len(), packets.len()), (1, udp.len()));
        }
    }

    #[tokio::test]
    async fn send_batch_spent_returns_a_coalesced_chunk() {
        let (_source, sink, kernel) = device(TSO);
        let run = tcp_run(5);
        let udp = packet(17, 1, 0, b"datagram");
        let mut packets = batch_of(&run);
        packets.extend(batch_of(std::slice::from_ref(&udp)));
        let sent = addrs(packets.iter().map(|(_, p)| p));
        let mut spent = Vec::new();
        sink.send_batch_spent(&mut packets, &mut spent)
            .await
            .unwrap();
        assert!(packets.is_empty());
        assert_eq!(addrs(&spent), sent);
        let (hdr, super_packet) = recv_datagram(&kernel);
        assert_eq!(hdr.gso_type, VirtioNetHdr::GSO_TCPV4);
        assert_eq!(super_packet.len(), 40 + 5000);
        assert_eq!(recv_datagram(&kernel).1, udp);

        // A non-IP packet ends the call without being spent; the chunk before it is.
        let mut packets = batch_of(&run);
        packets.push_back((PeerId::new(0), PacketBuf::from_packet(&[0x10, 0])));
        let mut spent = Vec::new();
        let err = sink
            .send_batch_spent(&mut packets, &mut spent)
            .await
            .unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidInput);
        assert_eq!((spent.len(), packets.len()), (run.len(), 0));
    }

    #[tokio::test]
    async fn udp_runs_coalesce_only_with_uso() {
        let datagrams: Vec<Vec<u8>> = (0..3u8)
            .map(|i| packet(17, u16::from(i), 0, &[i; 500]))
            .collect();
        for uso in [false, true] {
            let (_source, sink, kernel) = device(Offload { uso, ..TSO });
            sink.send_batch(&mut batch_of(&datagrams)).await.unwrap();
            let (hdr, first) = recv_datagram(&kernel);
            if uso {
                assert_eq!(hdr.gso_type, VirtioNetHdr::GSO_UDP_L4);
                assert_eq!(first.len(), 28 + 1500);
            } else {
                assert_eq!(hdr.gso_type, VirtioNetHdr::GSO_NONE);
                assert_eq!(first, datagrams[0]);
            }
        }
    }

    #[tokio::test]
    async fn recv_returns_queued_segments_one_by_one() {
        let (mut source, sink, kernel) = device(TSO);
        let run = tcp_run(4);
        sink.send_batch(&mut batch_of(&run)).await.unwrap();
        let (hdr, super_packet) = recv_datagram(&kernel);
        let mut framed = hdr.encode().to_vec();
        framed.extend_from_slice(&super_packet);
        kernel.send(&framed).unwrap();
        kernel.send(&framed).unwrap();

        // `recv` hands out the segments of one read one by one.
        for expected in &run {
            assert_eq!(source.recv().await.unwrap().as_packet(), expected);
        }
        // A batch with room for two takes two; the rest come with the next call.
        let mut batch = PacketBatch::new();
        while batch.len() < MAX_BATCH - 2 {
            batch.push(PacketBuf::from_packet(&[])).unwrap();
        }
        source.recv_batch(&mut batch).await.unwrap();
        assert!(batch.is_full());
        let got: Vec<Vec<u8>> = batch
            .drain()
            .skip(MAX_BATCH - 2)
            .map(|p| p.as_packet().to_vec())
            .collect();
        assert_eq!(got, run[..2]);
        source.recv_batch(&mut batch).await.unwrap();
        let got: Vec<&[u8]> = batch.iter().map(PacketBuf::as_packet).collect();
        assert_eq!(got, run[2..]);
    }

    #[tokio::test]
    async fn offload_reads_leave_room_to_grow() {
        let (mut source, sink, kernel) = device(TSO);
        let run = tcp_run(3);
        sink.send_batch(&mut batch_of(&run)).await.unwrap();
        let (hdr, super_packet) = recv_datagram(&kernel);
        let mut framed = hdr.encode().to_vec();
        framed.extend_from_slice(&super_packet);
        kernel.send(&framed).unwrap();
        let udp = packet(17, 1, 0, b"small");
        let mut single = VirtioNetHdr::default().encode().to_vec();
        single.extend_from_slice(&udp);
        kernel.send(&single).unwrap();

        // Segments and `GSO_NONE` packets get the MTU plus the translation slack, like
        // a plain read, so a translator can grow them in place.
        let mut got = Vec::new();
        for _ in 0..=run.len() {
            got.push(source.recv().await.unwrap());
        }
        assert_eq!(got[run.len()].as_packet(), udp);
        for p in &got {
            assert!(p.capacity() >= 1500 + TRANSLATION_SLACK + TAILROOM);
            assert_eq!(p.headroom(), nsplane::HEADROOM);
        }
    }

    #[tokio::test]
    async fn malformed_reads_are_dropped() {
        let (mut source, _sink, kernel) = device(TSO);
        kernel.send(&[1, 2, 3]).unwrap();
        let mut bad = VirtioNetHdr {
            gso_type: VirtioNetHdr::GSO_TCPV4,
            gso_size: 0,
            ..VirtioNetHdr::default()
        }
        .encode()
        .to_vec();
        bad.extend_from_slice(&tcp_run(1)[0]);
        kernel.send(&bad).unwrap();
        let udp = packet(17, 1, 0, b"ok");
        let mut good = VirtioNetHdr::default().encode().to_vec();
        good.extend_from_slice(&udp);
        kernel.send(&good).unwrap();
        assert_eq!(source.recv().await.unwrap().as_packet(), udp);
    }

    #[tokio::test]
    async fn send_writes_a_plain_vnet_header() {
        let (_source, sink, kernel) = device(TSO);
        let udp = packet(17, 1, 0, b"one");
        sink.send(PacketBuf::from_packet(&udp), PeerId::new(0))
            .await
            .unwrap();
        assert_eq!(recv_datagram(&kernel), (VirtioNetHdr::default(), udp));
        let err = sink
            .send(PacketBuf::from_packet(&[0x10, 0]), PeerId::new(0))
            .await
            .unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidInput);
    }

    #[tokio::test]
    async fn send_batch_stops_at_a_non_ip_packet() {
        let (_source, sink, kernel) = device(TSO);
        let run = tcp_run(2);
        let mut packets = batch_of(&run);
        packets.push_back((PeerId::new(0), PacketBuf::from_packet(&[0x10, 0])));
        packets.extend(batch_of(&run));
        let err = sink.send_batch(&mut packets).await.unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidInput);
        assert_eq!(packets.len(), 2);
        let (hdr, _) = recv_datagram(&kernel);
        assert_eq!(hdr.gso_type, VirtioNetHdr::GSO_TCPV4);
        sink.send_batch(&mut packets).await.unwrap();
        assert!(packets.is_empty());
    }

    #[tokio::test]
    async fn adopted_vnet_fd_writes_without_offloads() {
        let (_source, sink, kernel) = device(Offload {
            vnet_hdr: true,
            ..Offload::default()
        });
        let run = tcp_run(3);
        sink.send_batch(&mut batch_of(&run)).await.unwrap();
        for expected in run {
            assert_eq!(recv_datagram(&kernel), (VirtioNetHdr::default(), expected));
        }
    }

    #[tokio::test]
    async fn plain_device_has_no_header() {
        let (mut source, sink, kernel) = device(Offload::default());
        let udp = packet(17, 1, 0, b"plain");
        sink.send_batch(&mut batch_of(std::slice::from_ref(&udp)))
            .await
            .unwrap();
        let mut buf = [0; 100];
        let len = kernel.recv(&mut buf).unwrap();
        assert_eq!(&buf[..len], udp);
        kernel.send(&udp).unwrap();
        let mut batch = PacketBatch::new();
        source.recv_batch(&mut batch).await.unwrap();
        let got: Vec<&[u8]> = batch.iter().map(PacketBuf::as_packet).collect();
        assert_eq!(got, [udp.as_slice()]);
    }

    #[tokio::test]
    async fn plain_reads_leave_room_to_grow() {
        let (mut source, _sink, kernel) = device(Offload::default());
        let full = packet(17, 1, 0, &[0x5a; 1500 - 28]);
        assert_eq!(full.len(), 1500);
        kernel.send(&full).unwrap();
        // Like the virtio-net path, a full-MTU read gets the translation slack.
        let got = source.recv().await.unwrap();
        assert_eq!(got.as_packet(), full);
        assert!(got.capacity() >= 1500 + TRANSLATION_SLACK + TAILROOM);
        assert_eq!(got.headroom(), nsplane::HEADROOM);
    }

    #[tokio::test]
    async fn plain_recv_batch_takes_every_queued_packet() {
        let (mut source, _sink, kernel) = device(Offload::default());
        let udp: Vec<Vec<u8>> = (0..5u8).map(|i| packet(17, 1, 0, &[i; 9])).collect();
        for p in &udp {
            kernel.send(p).unwrap();
        }
        let mut batch = PacketBatch::new();
        source.recv_batch(&mut batch).await.unwrap();
        let got: Vec<&[u8]> = batch.iter().map(PacketBuf::as_packet).collect();
        assert_eq!(got, udp);
        for p in batch.iter() {
            assert!(p.capacity() >= 1500 + TRANSLATION_SLACK + TAILROOM);
        }

        // A lone packet comes back at once.
        let mut batch = PacketBatch::new();
        kernel.send(&udp[0]).unwrap();
        tokio::time::timeout(Duration::from_secs(5), source.recv_batch(&mut batch))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(batch.len(), 1);

        // Never more than the batch has room for; the rest stay for the next call.
        let mut batch = PacketBatch::new();
        while batch.len() < MAX_BATCH - 2 {
            batch.push(PacketBuf::from_packet(&[])).unwrap();
        }
        for p in &udp[..3] {
            kernel.send(p).unwrap();
        }
        source.recv_batch(&mut batch).await.unwrap();
        assert!(batch.is_full());
        let got: Vec<Vec<u8>> = batch
            .drain()
            .skip(MAX_BATCH - 2)
            .map(|p| p.as_packet().to_vec())
            .collect();
        assert_eq!(got, udp[..2]);
        source.recv_batch(&mut batch).await.unwrap();
        let got: Vec<&[u8]> = batch.iter().map(PacketBuf::as_packet).collect();
        assert_eq!(got, [udp[2].as_slice()]);

        // A zero-length read behind a packet ends the batch with the packet kept.
        batch.clear();
        kernel.send(&udp[1]).unwrap();
        kernel.send(&[]).unwrap();
        let err = source.recv_batch(&mut batch).await.unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::BrokenPipe);
        let got: Vec<&[u8]> = batch.iter().map(PacketBuf::as_packet).collect();
        assert_eq!(got, [udp[1].as_slice()]);
    }

    #[tokio::test]
    async fn vnet_recv_batch_reads_on_until_a_read_is_split() {
        let (mut source, sink, kernel) = device(TSO);
        let udp: Vec<Vec<u8>> = (0..3u8).map(|i| packet(17, 1, 0, &[i; 9])).collect();
        let framed = |p: &[u8]| {
            let mut f = VirtioNetHdr::default().encode().to_vec();
            f.extend_from_slice(p);
            f
        };
        for p in &udp {
            kernel.send(&framed(p)).unwrap();
        }
        let mut batch = PacketBatch::new();
        source.recv_batch(&mut batch).await.unwrap();
        let got: Vec<&[u8]> = batch.iter().map(PacketBuf::as_packet).collect();
        assert_eq!(got, udp);

        // A super-packet that does not fit is split; the read behind it waits.
        let run = tcp_run(4);
        sink.send_batch(&mut batch_of(&run)).await.unwrap();
        let (hdr, super_packet) = recv_datagram(&kernel);
        let mut gso = hdr.encode().to_vec();
        gso.extend_from_slice(&super_packet);
        kernel.send(&framed(&udp[0])).unwrap();
        kernel.send(&gso).unwrap();
        kernel.send(&framed(&udp[1])).unwrap();
        let mut batch = PacketBatch::new();
        while batch.len() < MAX_BATCH - 3 {
            batch.push(PacketBuf::from_packet(&[])).unwrap();
        }
        source.recv_batch(&mut batch).await.unwrap();
        let got: Vec<Vec<u8>> = batch
            .drain()
            .skip(MAX_BATCH - 3)
            .map(|p| p.as_packet().to_vec())
            .collect();
        assert_eq!(got, [&udp[..1], &run[..2]].concat());
        source.recv_batch(&mut batch).await.unwrap();
        let got: Vec<&[u8]> = batch.iter().map(PacketBuf::as_packet).collect();
        assert_eq!(got, run[2..]);
        batch.clear();
        source.recv_batch(&mut batch).await.unwrap();
        let got: Vec<&[u8]> = batch.iter().map(PacketBuf::as_packet).collect();
        assert_eq!(got, [udp[1].as_slice()]);
    }

    #[tokio::test]
    async fn recycle_refills_the_pool_up_to_its_bound() {
        let (mut source, _sink, _kernel) = device(Offload::default());
        assert_eq!(source.pool.free_len(), 0);
        let mut bufs: Vec<PacketBuf> = (0..POOL_FREE + 3)
            .map(|_| PacketBuf::with_capacity(1600))
            .collect();
        source.recycle(&mut bufs);
        assert!(bufs.is_empty());
        assert_eq!(source.pool.free_len(), POOL_FREE);

        // The next read goes into a recycled buffer.
        let (mut source, _sink, kernel) = device(Offload::default());
        source.recycle(&mut vec![PacketBuf::with_capacity(1600)]);
        let udp = packet(17, 1, 0, b"reuse");
        kernel.send(&udp).unwrap();
        assert_eq!(source.recv().await.unwrap().as_packet(), udp);
        assert_eq!(source.pool.free_len(), 0);
    }

    /// Writes small UDP packets with `try_send_batch` until the device would block;
    /// returns how many it took.
    fn fill(sink: &TunSink) -> usize {
        let mut written = 0;
        loop {
            let mut packets = batch_of(&[packet(17, 0, 0, b"fill")]);
            match sink.try_send_batch(&mut packets) {
                Ok(()) => written += 1,
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                    assert_eq!(packets.len(), 1, "the blocked packet stays");
                    return written;
                }
                Err(e) => panic!("{e}"),
            }
            assert!(written < 100_000, "the socket never filled");
        }
    }

    /// Drains the kernel side; returns the datagrams read.
    fn drain(kernel: &UnixDatagram) -> Vec<Vec<u8>> {
        kernel.set_nonblocking(true).unwrap();
        let mut buf = vec![0; VNET_READ];
        let mut got = Vec::new();
        while let Ok(len) = kernel.recv(&mut buf) {
            got.push(buf[..len].to_vec());
        }
        kernel.set_nonblocking(false).unwrap();
        got
    }

    #[tokio::test]
    async fn try_send_batch_leaves_what_would_block() {
        for offload in [
            Offload::default(),
            Offload {
                vnet_hdr: true,
                ..Offload::default()
            },
        ] {
            let (_source, sink, kernel) = device(offload);
            let udp: Vec<Vec<u8>> = (0..4u8).map(|i| packet(17, 1, 0, &[i; 9])).collect();
            // The reactor has not reported the new device writable yet.
            let mut packets = batch_of(&udp);
            let err = sink.try_send_batch(&mut packets).unwrap_err();
            assert_eq!(err.kind(), io::ErrorKind::WouldBlock);
            assert_eq!(packets.len(), udp.len());

            sink.fd.writable().await.unwrap().retain_ready();
            sink.try_send_batch(&mut packets).unwrap();
            assert!(packets.is_empty());
            let filled = fill(&sink);
            // Full: a non-IP packet in front is still dropped, the rest stay.
            let mut packets = batch_of(&udp);
            packets.push_front((PeerId::new(0), PacketBuf::from_packet(&[0x10, 0])));
            let err = sink.try_send_batch(&mut packets).unwrap_err();
            assert_eq!(err.kind(), io::ErrorKind::InvalidInput);
            let err = sink.try_send_batch(&mut packets).unwrap_err();
            assert_eq!(err.kind(), io::ErrorKind::WouldBlock);
            assert_eq!(packets.len(), udp.len());

            let header = if offload.vnet_hdr {
                VirtioNetHdr::LEN
            } else {
                0
            };
            let got = drain(&kernel);
            assert_eq!(got.len(), udp.len() + filled);
            sink.fd.writable().await.unwrap().retain_ready();
            sink.try_send_batch(&mut packets).unwrap();
            let got: Vec<Vec<u8>> = drain(&kernel)
                .iter()
                .map(|d| d[header..].to_vec())
                .collect();
            assert_eq!(got, udp);
        }
    }

    #[tokio::test]
    async fn try_send_batch_coalesces_and_keeps_a_blocked_chunk_in_order() {
        let (_source, sink, kernel) = device(TSO);
        sink.fd.writable().await.unwrap().retain_ready();
        let run = tcp_run(5);
        let mut packets = batch_of(&run);
        sink.try_send_batch(&mut packets).unwrap();
        assert!(packets.is_empty());
        let (hdr, super_packet) = recv_datagram(&kernel);
        assert_eq!(hdr.gso_type, VirtioNetHdr::GSO_TCPV4);
        assert_eq!(super_packet.len(), 40 + 5000);

        // Large packets fill the socket buffer part-way through the next chunk: the
        // writes before go out, the rest of the chunk is taken over and kept.
        let big: Vec<Vec<u8>> = (0..MAX_BATCH)
            .map(|i| {
                let i = u8::try_from(i).unwrap();
                packet(17, u16::from(i), 0, &vec![i; 60_000])
            })
            .collect();
        let mut packets = batch_of(&big);
        let err = sink.try_send_batch(&mut packets).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::WouldBlock);
        assert!(packets.is_empty(), "the chunk was taken over");
        let written: Vec<Vec<u8>> = drain(&kernel)
            .iter()
            .map(|d| d[VirtioNetHdr::LEN..].to_vec())
            .collect();
        assert!(!written.is_empty() && written.len() < big.len());
        assert_eq!(written, big[..written.len()]);

        // The next send writes the rest of the chunk first, while the kernel side reads.
        let last = packet(17, 2, 0, b"last");
        let expected = [&big[written.len()..], std::slice::from_ref(&last)].concat();
        let count = expected.len();
        let reader = std::thread::spawn(move || {
            let mut buf = vec![0; VNET_READ];
            (0..count)
                .map(|_| {
                    let len = kernel.recv(&mut buf).unwrap();
                    buf[VirtioNetHdr::LEN..len].to_vec()
                })
                .collect::<Vec<_>>()
        });
        sink.send_batch(&mut batch_of(std::slice::from_ref(&last)))
            .await
            .unwrap();
        assert_eq!(reader.join().unwrap(), expected);
    }
}
