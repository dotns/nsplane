//! The Wintun TUN device and its source and sink halves.
//!
//! Wintun's session API is blocking, so [`Tun::split`] moves receiving onto a dedicated
//! thread that hands packets to the async [`TunSource`] through a bounded channel.
//! Sending uses Wintun's non-blocking allocate-and-send path directly.
//!
//! [`Tun::create_with`] adds the service TUN checks of [`TunOptions`]: the
//! `wintun.dll` pin (verified before the DLL is loaded), an exclusive adapter name and
//! the interface MTU.

use std::collections::VecDeque;
use std::ffi::OsStr;
use std::fmt;
use std::future;
use std::io;
use std::iter;
use std::os::windows::ffi::OsStrExt;
use std::sync::Arc;
use std::sync::mpsc::{self as sync_mpsc, Receiver, SyncSender, TrySendError};
use std::thread::{self, JoinHandle};

use nsplane::{PacketBuf, PacketPool, PacketSink, PacketSource, PeerId, TAILROOM};
use tokio::sync::{mpsc, watch};
use windows_sys::Win32::Foundation::{
    ERROR_FILE_NOT_FOUND, ERROR_INVALID_NAME, ERROR_INVALID_PARAMETER, ERROR_NOT_FOUND, NO_ERROR,
};
use windows_sys::Win32::NetworkManagement::IpHelper::ConvertInterfaceAliasToLuid;
use windows_sys::Win32::NetworkManagement::Ndis::NET_LUID_LH;
use wintun_bindings::{Adapter, MAX_RING_CAPACITY, Session};

use crate::wintun::{self, Plan, WintunError, WintunPin};

/// Idle buffers kept by the reader thread's pool.
const POOL_FREE: usize = 64;

/// Room beyond each received packet: the growth of an IPv4 packet translated to IPv6
/// with a fragment header, so an IPv4 <-> IPv6 translator can rewrite it in place.
const TRANSLATION_SLACK: usize = 28;

/// Packets queued between the reader thread and the [`TunSource`].
const QUEUE_DEPTH: usize = 64;

/// `ERROR_HANDLE_EOF`: the Wintun session is terminating.
const ERROR_HANDLE_EOF: i32 = 38;

/// `ERROR_BUFFER_OVERFLOW`: the Wintun send ring is full.
const ERROR_BUFFER_OVERFLOW: i32 = 111;

/// An opened Wintun adapter with a running session, not yet split.
pub struct Tun {
    session: Arc<Session>,
    mtu: u16,
}

impl fmt::Debug for Tun {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Tun")
            .field("mtu", &self.mtu)
            .finish_non_exhaustive()
    }
}

/// Options for [`Tun::create_with`]; [`TunOptions::new`] (or `Default`) gives the
/// options [`Tun::create`] uses. Every check is off by default and costs nothing then.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct TunOptions {
    wintun_pin: Option<WintunPin>,
    exclusive: bool,
    mtu: Option<u16>,
}

impl TunOptions {
    /// The default options: `wintun.dll` from the loader's search path, an existing
    /// adapter of the same name opened, the MTU left as it is.
    pub const fn new() -> Self {
        Self {
            wintun_pin: None,
            exclusive: false,
            mtu: None,
        }
    }

    /// Accepted for portable code and ignored: Wintun has no segmentation offloads.
    #[must_use]
    pub const fn offload(self, _offload: bool) -> Self {
        self
    }

    /// Loads `wintun.dll` only from [`WintunPin`]'s path and only if its SHA-256 matches;
    /// optionally checks the running driver version. A mismatch fails with
    /// [`WintunError::HashMismatch`] (nothing loaded) or
    /// [`WintunError::DriverVersionMismatch`] (a created adapter is removed again); a
    /// missing file with [`io::ErrorKind::NotFound`] naming the path and how to install
    /// the DLL.
    #[must_use]
    pub fn wintun_pin(mut self, pin: WintunPin) -> Self {
        self.wintun_pin = Some(pin);
        self
    }

    /// With `true`, refuses with [`WintunError::AdapterExists`] when a Wintun adapter or
    /// any interface with the alias `name` already exists, instead of opening it. A
    /// foreign adapter is never touched beyond opening and closing a handle to it.
    #[must_use]
    pub const fn exclusive(mut self, exclusive: bool) -> Self {
        self.exclusive = exclusive;
        self
    }

    /// Sets the interface MTU (IPv4, and IPv6 where the interface has an IPv6 row) once
    /// the adapter is open; [`Tun::mtu`] then reports the value read back. Below 576 (the
    /// IPv4 minimum) [`Tun::create_with`] fails with [`io::ErrorKind::InvalidInput`]
    /// before loading anything.
    #[must_use]
    pub const fn mtu(mut self, mtu: u16) -> Self {
        self.mtu = Some(mtu);
        self
    }
}

impl Tun {
    /// Opens the Wintun adapter `name`, creating it if needed, reads its MTU and starts
    /// a session.
    ///
    /// `wintun.dll` must sit next to the executable or on the DLL search path; without
    /// it (or without the driver) this fails with an [`io::Error`].
    pub fn create(name: &str) -> io::Result<Self> {
        Self::create_with(name, TunOptions::new())
    }

    /// Like [`Tun::create`], with the checks of `options`, in this order: MTU
    /// validation, the `wintun.dll` pin (hash, then load of that same absolute path),
    /// the adapter (refused if exclusive and taken, else opened or created), the running
    /// driver version, the MTU (set, then read back), the session.
    ///
    /// The refusals are [`WintunError`]s inside the [`io::Error`]; see there for the
    /// downcast.
    pub fn create_with(name: &str, options: TunOptions) -> io::Result<Self> {
        let TunOptions {
            wintun_pin,
            exclusive,
            mtu,
        } = options;
        let mtu = mtu.map(wintun::validate_mtu).transpose()?;
        let wintun = match &wintun_pin {
            #[allow(unsafe_code, reason = "loading the verified Wintun driver library")]
            Some(pin) => {
                let path = pin.resolved_path()?;
                wintun::verify(&path, pin.sha256())?;
                // SAFETY: the bytes at this absolute path were just verified against the
                // caller's SHA-256 pin of the signed Wintun library (a replacement between
                // check and load is the documented residual window); loading it runs no
                // code beyond its DLL initialization, and the returned function table is
                // only used through the safe wrappers of `wintun-bindings`.
                unsafe { wintun_bindings::load_from_path(&path) }?
            }
            #[allow(unsafe_code, reason = "loading the Wintun driver library")]
            // SAFETY: `wintun.dll` is the signed Wintun library; loading it runs no code
            // beyond its DLL initialization, and the returned function table is only used
            // through the safe wrappers of `wintun-bindings`.
            None => unsafe { wintun_bindings::load() }?,
        };
        let opened = Adapter::open(&wintun, name).ok();
        let existing = opened.is_some() || (exclusive && interface_alias_exists(name)?);
        let adapter = match (wintun::plan(existing, exclusive), opened) {
            (Plan::Refuse, _) => {
                return Err(WintunError::AdapterExists {
                    name: name.to_owned(),
                }
                .into());
            }
            (Plan::Open, Some(adapter)) => adapter,
            _ => Adapter::create(&wintun, name, "nsplane", None)?,
        };
        if let Some(expected) = wintun_pin
            .as_ref()
            .and_then(WintunPin::expected_driver_version)
        {
            let running = wintun_bindings::get_running_driver_version(&wintun)?;
            let actual = (running.major, running.minor);
            if actual != expected {
                return Err(WintunError::DriverVersionMismatch { expected, actual }.into());
            }
        }
        if let Some(mtu) = mtu {
            adapter.set_mtu(usize::from(mtu))?;
        }
        let mtu = u16::try_from(adapter.get_mtu()?).unwrap_or(u16::MAX);
        let session = adapter.start_session(MAX_RING_CAPACITY)?;
        Ok(Self { session, mtu })
    }

    /// The created adapter's interface alias (friendly name). After [`Tun::split`] the
    /// halves report it through [`TunSource::name`] and [`TunSink::name`].
    pub fn name(&self) -> io::Result<String> {
        Ok(self.session.get_adapter().get_name()?)
    }

    /// The IPv4 MTU of the adapter, queried at [`Tun::create`] (after setting it, if
    /// [`TunOptions::mtu`] asked for that).
    pub const fn mtu(&self) -> u16 {
        self.mtu
    }

    /// Spawns the reader thread (`nsplane-tun-rx`) and splits the session into source and
    /// sink halves.
    ///
    /// Dropping the last half shuts the session down and joins the reader thread.
    pub fn split(self) -> io::Result<(TunSource, TunSink)> {
        let (tx, packets) = mpsc::channel(QUEUE_DEPTH);
        let (recycled, free) = sync_mpsc::sync_channel(POOL_FREE);
        let session = Arc::clone(&self.session);
        let reader = thread::Builder::new()
            .name("nsplane-tun-rx".to_owned())
            .spawn(move || read_loop(&session, &tx, &free))?;
        let shared = Arc::new(Shared {
            session: self.session,
            reader: Some(reader),
        });
        let (mtu, _) = watch::channel(self.mtu);
        let source = TunSource {
            packets,
            recycled,
            mtu,
            shared: Arc::clone(&shared),
        };
        Ok((source, TunSink { shared }))
    }
}

/// Whether IP Helper knows an interface with the alias `name`. Not-found style errors
/// mean absent; any other error is returned.
fn interface_alias_exists(name: &str) -> io::Result<bool> {
    let alias: Vec<u16> = OsStr::new(name)
        .encode_wide()
        .chain(iter::once(0))
        .collect();
    let mut luid = NET_LUID_LH { Value: 0 };
    #[allow(unsafe_code, reason = "IP Helper FFI call")]
    // SAFETY: `alias` is a NUL-terminated UTF-16 string that outlives the call, and
    // `luid` is writable storage for one `NET_LUID_LH`.
    let status = unsafe { ConvertInterfaceAliasToLuid(alias.as_ptr(), &raw mut luid) };
    match status {
        NO_ERROR => Ok(true),
        ERROR_FILE_NOT_FOUND | ERROR_INVALID_NAME | ERROR_INVALID_PARAMETER | ERROR_NOT_FOUND => {
            Ok(false)
        }
        code => Err(io::Error::from_raw_os_error(code.cast_signed())),
    }
}

/// Receives packets until the session shuts down or the [`TunSource`] is gone, reading
/// them into the buffers recycled through `free` when there are any.
fn read_loop(
    session: &Arc<Session>,
    packets: &mpsc::Sender<PacketBuf>,
    free: &Receiver<PacketBuf>,
) {
    let mut pool = PacketPool::new(POOL_FREE);
    while let Ok(received) = session.receive_blocking() {
        refill(&mut pool, free);
        let bytes = received.bytes();
        let mut packet = pool.get(bytes.len() + TRANSLATION_SLACK + TAILROOM);
        packet.extend_from_slice(bytes);
        // Release the ring slot before waiting for room in the channel.
        drop(received);
        if packets.blocking_send(packet).is_err() {
            return;
        }
    }
}

/// Moves the buffers waiting in `free` into `pool`, without waiting; the pool drops what
/// it has no room for.
fn refill(pool: &mut PacketPool, free: &Receiver<PacketBuf>) {
    while let Ok(buf) = free.try_recv() {
        pool.put(buf);
    }
}

/// Hands `bufs` to the reader thread through `free` until it is full, without waiting; the
/// rest stay in `bufs`.
fn hand_back(free: &SyncSender<PacketBuf>, bufs: &mut Vec<PacketBuf>) {
    while let Some(buf) = bufs.pop() {
        match free.try_send(buf) {
            Ok(()) => {}
            Err(TrySendError::Full(buf) | TrySendError::Disconnected(buf)) => {
                bufs.push(buf);
                return;
            }
        }
    }
}

/// The session and reader thread shared by both halves.
struct Shared {
    session: Arc<Session>,
    reader: Option<JoinHandle<()>>,
}

impl fmt::Debug for Shared {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Shared").finish_non_exhaustive()
    }
}

impl Drop for Shared {
    /// Wakes the reader thread out of its blocking receive and waits for it to exit.
    /// The [`TunSource`]'s channel receiver is already gone here, so the thread cannot
    /// be stuck on a full channel.
    fn drop(&mut self) {
        let _ = self.session.shutdown();
        if let Some(reader) = self.reader.take() {
            let _ = reader.join();
        }
    }
}

/// The receiving half of a [`Tun`]: packets the OS routed into the adapter.
#[derive(Debug)]
pub struct TunSource {
    /// Declared before `shared` so the channel closes before the session shuts down.
    packets: mpsc::Receiver<PacketBuf>,
    /// Buffers handed back to the reader thread's pool.
    recycled: SyncSender<PacketBuf>,
    /// Kept alive so receivers never observe a closed channel; the adapter MTU is not
    /// watched on Windows, so the value never changes.
    mtu: watch::Sender<u16>,
    shared: Arc<Shared>,
}

impl TunSource {
    /// The created adapter's interface alias (friendly name), queried from the session
    /// like [`Tun::name`].
    pub fn name(&self) -> io::Result<String> {
        Ok(self.shared.session.get_adapter().get_name()?)
    }
}

impl PacketSource for TunSource {
    /// Returns the next packet read by the reader thread, in the packet region of a
    /// pooled [`PacketBuf`] with the headroom in front free. Once the reader thread has
    /// exited (session shut down or a receive error) this yields
    /// [`io::ErrorKind::BrokenPipe`].
    async fn recv(&mut self) -> io::Result<PacketBuf> {
        self.packets
            .recv()
            .await
            .ok_or_else(|| io::Error::from(io::ErrorKind::BrokenPipe))
    }

    /// Hands the buffers back to the reader thread, which keeps up to 64 idle ones; the
    /// rest are dropped. Up to 64 wait for the thread's next read; beyond that they are
    /// dropped without waiting.
    fn recycle(&mut self, bufs: &mut Vec<PacketBuf>) {
        hand_back(&self.recycled, bufs);
    }

    /// The adapter MTU read at [`Tun::create`]. It is not watched on Windows (that
    /// would need IP Helper notifications), so it never changes.
    fn mtu(&self) -> watch::Receiver<u16> {
        self.mtu.subscribe()
    }
}

/// The sending half of a [`Tun`]: packets handed to the OS.
#[derive(Debug)]
pub struct TunSink {
    shared: Arc<Shared>,
}

impl PacketSink for TunSink {
    /// Copies `packet` into the Wintun send ring without blocking, so the returned
    /// future is already complete. `from` is unused: the OS device has no notion of
    /// peers.
    ///
    /// A packet that is neither IPv4 nor IPv6 is dropped with
    /// [`io::ErrorKind::InvalidInput`]. When the send ring is full the packet is dropped
    /// with [`io::ErrorKind::WouldBlock`]; once the session is terminating it is dropped
    /// with [`io::ErrorKind::BrokenPipe`].
    fn send(
        &self,
        packet: PacketBuf,
        _from: PeerId,
    ) -> impl Future<Output = io::Result<()>> + Send {
        future::ready(self.write(packet.as_packet()))
    }

    /// Like `send_batch`, and appends the buffer of every packet it took over to `spent`
    /// once it is copied into the send ring or dropped. Never waits, so the returned
    /// future is already complete.
    fn send_batch_spent(
        &self,
        packets: &mut VecDeque<(PeerId, PacketBuf)>,
        spent: &mut Vec<PacketBuf>,
    ) -> impl Future<Output = io::Result<()>> + Send {
        future::ready(write_spent(packets, spent, |bytes| self.write(bytes)))
    }
}

/// Writes the packets of `packets` front first with `write`, appending each buffer to
/// `spent` after its write; stops at the first error, the rest staying in `packets`.
fn write_spent(
    packets: &mut VecDeque<(PeerId, PacketBuf)>,
    spent: &mut Vec<PacketBuf>,
    mut write: impl FnMut(&[u8]) -> io::Result<()>,
) -> io::Result<()> {
    while let Some((_, packet)) = packets.pop_front() {
        let result = write(packet.as_packet());
        spent.push(packet);
        result?;
    }
    Ok(())
}

impl TunSink {
    /// The created adapter's interface alias (friendly name), queried from the session
    /// like [`Tun::name`].
    pub fn name(&self) -> io::Result<String> {
        Ok(self.shared.session.get_adapter().get_name()?)
    }

    fn write(&self, bytes: &[u8]) -> io::Result<()> {
        if !matches!(bytes.first().map(|b| b >> 4), Some(4 | 6)) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "packet is neither IPv4 nor IPv6",
            ));
        }
        let len = u16::try_from(bytes.len())
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "packet too long"))?;
        let session = &self.shared.session;
        let mut slot = session
            .allocate_send_packet(len)
            .map_err(|e| send_error(e.into()))?;
        slot.bytes_mut().copy_from_slice(bytes);
        session.send_packet(slot);
        Ok(())
    }
}

/// Maps the Win32 errors of `WintunAllocateSendPacket` to the sink contract.
fn send_error(e: io::Error) -> io::Error {
    match e.raw_os_error() {
        Some(ERROR_BUFFER_OVERFLOW) => {
            io::Error::new(io::ErrorKind::WouldBlock, "Wintun send ring is full")
        }
        Some(ERROR_HANDLE_EOF) => io::Error::from(io::ErrorKind::BrokenPipe),
        _ => e,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The test environment (wine) has no `wintun.dll`.
    #[test]
    fn create_without_driver_fails() {
        assert!(Tun::create("nsplane-test").is_err());
    }

    /// A file under the temp directory, removed on drop.
    struct TempFile(std::path::PathBuf);

    impl TempFile {
        fn new(tag: &str, contents: &[u8]) -> Self {
            let path = std::env::temp_dir().join(format!(
                "nsplane-tun-windows-{}-{tag}.dll",
                std::process::id()
            ));
            std::fs::write(&path, contents).unwrap();
            Self(path)
        }
    }

    impl Drop for TempFile {
        fn drop(&mut self) {
            let _ = std::fs::remove_file(&self.0);
        }
    }

    fn wintun_error(e: &io::Error) -> Option<&WintunError> {
        e.get_ref().and_then(|e| e.downcast_ref::<WintunError>())
    }

    /// The hash check precedes loading: a wrong digest is refused with the typed error
    /// even though the file is no DLL at all.
    #[test]
    fn create_with_refuses_a_wrong_digest_before_loading() {
        let file = TempFile::new("wrong", b"not a dll");
        let options = TunOptions::new().wintun_pin(WintunPin::new([0; 32]).path(&file.0));
        let e = Tun::create_with("nsplane-test", options).unwrap_err();
        assert_eq!(e.kind(), io::ErrorKind::InvalidData);
        assert!(
            matches!(wintun_error(&e), Some(WintunError::HashMismatch { path, .. }) if *path == file.0),
            "{e}"
        );
    }

    /// A matching digest passes the check and the load of that file then fails.
    #[test]
    fn create_with_loads_the_verified_file() {
        use sha2::{Digest, Sha256};

        let file = TempFile::new("right", b"not a dll");
        let pin = WintunPin::new(Sha256::digest(b"not a dll").into()).path(&file.0);
        let e = Tun::create_with("nsplane-test", TunOptions::new().wintun_pin(pin)).unwrap_err();
        assert!(wintun_error(&e).is_none(), "{e}");
        assert_ne!(e.kind(), io::ErrorKind::NotFound, "{e}");
    }

    #[test]
    fn create_with_reports_a_missing_pinned_dll() {
        let path = std::env::temp_dir().join(format!(
            "nsplane-tun-windows-{}-missing.dll",
            std::process::id()
        ));
        let options = TunOptions::new().wintun_pin(WintunPin::new([0; 32]).path(&path));
        let e = Tun::create_with("nsplane-test", options).unwrap_err();
        assert_eq!(e.kind(), io::ErrorKind::NotFound);
        assert!(e.to_string().contains("wintun.net"), "{e}");
    }

    #[test]
    fn create_with_validates_the_mtu_first() {
        let e = Tun::create_with("nsplane-test", TunOptions::new().mtu(575)).unwrap_err();
        assert_eq!(e.kind(), io::ErrorKind::InvalidInput);
    }

    #[test]
    fn options_builder() {
        assert_eq!(TunOptions::default(), TunOptions::new());
        assert_eq!(TunOptions::new().offload(false), TunOptions::new());
        let pin = WintunPin::new([1; 32]).driver_version(0, 14);
        let options = TunOptions::new()
            .wintun_pin(pin.clone())
            .exclusive(true)
            .mtu(1280);
        assert_eq!(options.wintun_pin, Some(pin));
        assert!(options.exclusive);
        assert_eq!(options.mtu, Some(1280));
    }

    #[test]
    fn recycled_buffers_reach_the_reader_pool() {
        let (recycled, free) = sync_mpsc::sync_channel(POOL_FREE);
        let mut pool = PacketPool::new(POOL_FREE);
        let mut bufs: Vec<_> = (0..POOL_FREE + 3)
            .map(|_| PacketBuf::with_capacity(1600))
            .collect();
        // Handed back first, so it is one of those the channel takes.
        let addr = bufs[POOL_FREE + 2].as_packet().as_ptr();
        hand_back(&recycled, &mut bufs);
        // The channel is full; the source drops the rest.
        assert_eq!(bufs.len(), 3);

        refill(&mut pool, &free);
        assert_eq!(pool.free_len(), POOL_FREE);
        // Drained, so the next hand-back fits again; the pool, full, drops it.
        hand_back(&recycled, &mut bufs);
        assert!(bufs.is_empty());
        refill(&mut pool, &free);
        assert_eq!(pool.free_len(), POOL_FREE);

        let packets: Vec<_> = (0..POOL_FREE).map(|_| pool.get(1500)).collect();
        assert!(packets.iter().any(|p| p.as_packet().as_ptr() == addr));
        assert_eq!(pool.free_len(), 0);
    }

    #[test]
    fn hand_back_after_the_reader_exits_keeps_the_buffers() {
        let (recycled, free) = sync_mpsc::sync_channel(POOL_FREE);
        drop(free);
        let mut bufs = vec![PacketBuf::with_capacity(1600)];
        hand_back(&recycled, &mut bufs);
        assert_eq!(bufs.len(), 1);
    }

    #[test]
    fn write_spent_returns_every_buffer_taken_over() {
        let mut packets: VecDeque<_> = (0..4u8)
            .map(|i| (PeerId::new(0), PacketBuf::from_packet(&[0x45, i])))
            .collect();
        let addrs: Vec<_> = packets
            .iter()
            .map(|(_, p)| p.as_packet().as_ptr())
            .collect();
        let mut written = Vec::new();
        let mut spent = Vec::new();
        // The third write fails: its buffer is spent, the fourth packet stays.
        let err = write_spent(&mut packets, &mut spent, |bytes| {
            if bytes[1] == 2 {
                return Err(io::ErrorKind::WouldBlock.into());
            }
            written.push(bytes[1]);
            Ok(())
        })
        .unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::WouldBlock);
        assert_eq!(written, [0, 1]);
        let spent_addrs: Vec<_> = spent.iter().map(|p| p.as_packet().as_ptr()).collect();
        assert_eq!(spent_addrs, addrs[..3]);
        assert_eq!(packets.len(), 1);
    }

    #[test]
    fn send_errors_map_to_sink_contract() {
        let full = send_error(io::Error::from_raw_os_error(ERROR_BUFFER_OVERFLOW));
        assert_eq!(full.kind(), io::ErrorKind::WouldBlock);
        let eof = send_error(io::Error::from_raw_os_error(ERROR_HANDLE_EOF));
        assert_eq!(eof.kind(), io::ErrorKind::BrokenPipe);
        let other = send_error(io::Error::from_raw_os_error(5));
        assert_eq!(other.raw_os_error(), Some(5));
    }
}
