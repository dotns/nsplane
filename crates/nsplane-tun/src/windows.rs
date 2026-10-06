//! The Wintun TUN device and its source and sink halves.
//!
//! Wintun's session API is blocking, so [`Tun::split`] moves receiving onto a dedicated
//! thread that hands packets to the async [`TunSource`] through a bounded channel.
//! Sending uses Wintun's non-blocking allocate-and-send path directly.

use std::fmt;
use std::future;
use std::io;
use std::sync::Arc;
use std::thread::{self, JoinHandle};

use nsplane::{PacketBuf, PacketPool, PacketSink, PacketSource, PeerId, TAILROOM};
use tokio::sync::{mpsc, watch};
use wintun_bindings::{Adapter, MAX_RING_CAPACITY, Session};

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

impl Tun {
    /// Opens the Wintun adapter `name`, creating it if needed, reads its MTU and starts
    /// a session.
    ///
    /// `wintun.dll` must sit next to the executable or on the DLL search path; without
    /// it (or without the driver) this fails with an [`io::Error`].
    pub fn create(name: &str) -> io::Result<Self> {
        #[allow(unsafe_code, reason = "loading the Wintun driver library")]
        // SAFETY: `wintun.dll` is the signed Wintun library; loading it runs no code beyond
        // its DLL initialization, and the returned function table is only used through the
        // safe wrappers of `wintun-bindings`.
        let wintun = unsafe { wintun_bindings::load() }?;
        let adapter = Adapter::open(&wintun, name)
            .or_else(|_| Adapter::create(&wintun, name, "nsplane", None))?;
        let mtu = u16::try_from(adapter.get_mtu()?).unwrap_or(u16::MAX);
        let session = adapter.start_session(MAX_RING_CAPACITY)?;
        Ok(Self { session, mtu })
    }

    /// The created adapter's interface alias (friendly name). After [`Tun::split`] the
    /// halves report it through [`TunSource::name`] and [`TunSink::name`].
    pub fn name(&self) -> io::Result<String> {
        Ok(self.session.get_adapter().get_name()?)
    }

    /// The IPv4 MTU of the adapter, queried at [`Tun::create`].
    pub const fn mtu(&self) -> u16 {
        self.mtu
    }

    /// Spawns the reader thread (`nsplane-tun-rx`) and splits the session into source and
    /// sink halves.
    ///
    /// Dropping the last half shuts the session down and joins the reader thread.
    pub fn split(self) -> io::Result<(TunSource, TunSink)> {
        let (tx, packets) = mpsc::channel(QUEUE_DEPTH);
        let session = Arc::clone(&self.session);
        let reader = thread::Builder::new()
            .name("nsplane-tun-rx".to_owned())
            .spawn(move || read_loop(&session, &tx))?;
        let shared = Arc::new(Shared {
            session: self.session,
            reader: Some(reader),
        });
        let (mtu, _) = watch::channel(self.mtu);
        let source = TunSource {
            packets,
            mtu,
            shared: Arc::clone(&shared),
        };
        Ok((source, TunSink { shared }))
    }
}

/// Receives packets until the session shuts down or the [`TunSource`] is gone.
fn read_loop(session: &Arc<Session>, packets: &mpsc::Sender<PacketBuf>) {
    let mut pool = PacketPool::new(POOL_FREE);
    while let Ok(received) = session.receive_blocking() {
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
