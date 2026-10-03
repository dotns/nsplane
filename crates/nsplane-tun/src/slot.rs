//! A TUN fd the host can swap while the engine runs (Android `VpnService`).
//!
//! [`TunSlot::new`] yields the control handle and a [`SlotSource`] and [`SlotSink`] that do
//! their I/O on whatever fd is installed in the slot at the time.
//!
//! Fencing: every read and write runs under a shared lock that [`TunSlot::replace`] and
//! [`TunSlot::close`] take exclusively, and only if the fd it waited on is still the
//! installed one (a generation counter, bumped by every replace and by close). So once
//! `replace` returned, no syscall runs on the previous fd; a read that completed on it
//! but was not returned yet is discarded, and the call reads from the new fd instead.

use std::fs::File;
use std::future::poll_fn;
use std::io::{self, Read, Write};
use std::os::fd::OwnedFd;
use std::pin::pin;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, PoisonError, RwLock, RwLockReadGuard, RwLockWriteGuard};
use std::task::Poll;

use nsplane::{PacketBuf, PacketPool, PacketSink, PacketSource, PeerId};
use tokio::io::unix::AsyncFd;
use tokio::sync::futures::Notified;
use tokio::sync::{Notify, watch};

use crate::unix::set_nonblocking;

/// Idle buffers kept by a [`SlotSource`]'s pool.
const POOL_FREE: usize = 64;

/// Room beyond the MTU each packet read gets, as `TunSource` gives: the growth of an IPv4
/// packet translated to IPv6 with a fragment header.
const TRANSLATION_SLACK: usize = 28;

/// The installed fd and the switches, guarded by [`Shared::state`].
#[derive(Debug)]
struct State {
    fd: Option<Arc<AsyncFd<File>>>,
    enabled: bool,
    closed: bool,
}

/// What the control handle, the source and the sink share.
#[derive(Debug)]
struct Shared {
    /// Read-locked around every syscall, write-locked to install or remove the fd.
    state: RwLock<State>,
    /// Bumped by every replace and by close, under the write lock of `state`.
    generation: AtomicU64,
    /// Notified after every change that may let waiting I/O proceed or end.
    changed: Notify,
}

impl Shared {
    fn read(&self) -> RwLockReadGuard<'_, State> {
        self.state.read().unwrap_or_else(PoisonError::into_inner)
    }

    fn write(&self) -> RwLockWriteGuard<'_, State> {
        self.state.write().unwrap_or_else(PoisonError::into_inner)
    }

    /// The installed fd and its generation if there is one and I/O is enabled.
    fn current(&self) -> io::Result<Option<(u64, Arc<AsyncFd<File>>)>> {
        let state = self.read();
        if state.closed {
            return Err(closed());
        }
        Ok(state
            .fd
            .as_ref()
            .filter(|_| state.enabled)
            .map(|fd| (self.generation.load(Ordering::Acquire), Arc::clone(fd))))
    }

    /// Runs `syscall` if the fd of `generation` is still installed and I/O is enabled;
    /// `None` otherwise. The read lock keeps replace and close out until it returns.
    fn io<T>(
        &self,
        generation: u64,
        syscall: impl FnOnce() -> io::Result<T>,
    ) -> io::Result<Option<T>> {
        let state = self.read();
        if !state.enabled || self.generation.load(Ordering::Acquire) != generation {
            return Ok(None);
        }
        let result = syscall().map(Some);
        drop(state);
        result
    }

    fn close(&self) {
        let previous = {
            let mut state = self.write();
            state.closed = true;
            self.generation.fetch_add(1, Ordering::AcqRel);
            state.fd.take()
        };
        self.changed.notify_waiters();
        drop(previous);
    }
}

/// Closes the slot when the last [`TunSlot`] handle drops.
#[derive(Debug)]
struct Control(Arc<Shared>);

impl Drop for Control {
    fn drop(&mut self) {
        self.0.close();
    }
}

/// Control handle of a TUN fd that can be swapped while the engine runs, as an Android
/// `VpnService` hands out a new fd on every reconfiguration.
///
/// [`TunSlot::new`] returns the handle with a [`SlotSource`] and a [`SlotSink`]; the
/// engine owns those and the host keeps the handle to [`replace`](Self::replace) the fd,
/// [`disable`](Self::disable) and [`enable`](Self::enable) I/O, and
/// [`close`](Self::close) the slot. The handle is cheap to clone; every clone controls
/// the same slot. Dropping the last clone closes the slot, so the engine's local side
/// ends.
///
/// The slot only installs fds: the caller keeps its own generation numbering,
/// begin/attach/activate ordering and host-claim rules, and decides when to call which
/// method.
#[derive(Debug, Clone)]
pub struct TunSlot {
    control: Arc<Control>,
}

impl TunSlot {
    /// An empty, enabled slot for packets of at most `mtu` bytes, with its source and
    /// sink. I/O waits until the first [`replace`](Self::replace) installs an fd.
    pub fn new(mtu: u16) -> (Self, SlotSource, SlotSink) {
        let shared = Arc::new(Shared {
            state: RwLock::new(State {
                fd: None,
                enabled: true,
                closed: false,
            }),
            generation: AtomicU64::new(0),
            changed: Notify::new(),
        });
        let (mtu_tx, _) = watch::channel(mtu);
        let source = SlotSource {
            shared: Arc::clone(&shared),
            pool: PacketPool::new(POOL_FREE),
            mtu,
            mtu_tx,
            oversize_drops: 0,
        };
        let sink = SlotSink {
            shared: Arc::clone(&shared),
        };
        let slot = Self {
            control: Arc::new(Control(shared)),
        };
        (slot, source, sink)
    }

    fn shared(&self) -> &Shared {
        &self.control.0
    }

    /// Installs `fd`, taking ownership: it is switched to non-blocking mode, registered
    /// with the tokio reactor of the current runtime, and waiting I/O is woken.
    ///
    /// The previous fd is fenced: once this returns, no read or write runs on it, and a
    /// read that completed on it but was not returned yet is discarded and retried on
    /// `fd`. It is closed once no I/O uses it any more. Whether I/O is enabled does not
    /// change.
    ///
    /// Fails with [`io::ErrorKind::BrokenPipe`] after [`close`](Self::close), and with
    /// [`io::ErrorKind::Other`] outside a tokio runtime; `fd` is closed on every error.
    pub fn replace(&self, fd: OwnedFd) -> io::Result<()> {
        if tokio::runtime::Handle::try_current().is_err() {
            return Err(io::Error::other("TunSlot::replace needs a tokio runtime"));
        }
        set_nonblocking(&fd)?;
        let fd = Arc::new(AsyncFd::new(File::from(fd))?);
        let shared = self.shared();
        let previous = {
            let mut state = shared.write();
            if state.closed {
                drop(state);
                return Err(closed());
            }
            shared.generation.fetch_add(1, Ordering::AcqRel);
            state.fd.replace(fd)
        };
        shared.changed.notify_waiters();
        drop(previous);
        Ok(())
    }

    /// Parks I/O: reads and writes wait, nothing is lost or fails, until
    /// [`enable`](Self::enable). A syscall already running completes.
    pub fn disable(&self) {
        self.shared().write().enabled = false;
    }

    /// Lets I/O parked by [`disable`](Self::disable) proceed. A new slot is enabled.
    pub fn enable(&self) {
        self.shared().write().enabled = true;
        self.shared().changed.notify_waiters();
    }

    /// Closes the slot: the installed fd is removed (and closed once no I/O uses it), and
    /// every current and later call of the source and the sink, and every later
    /// [`replace`](Self::replace), fails with [`io::ErrorKind::BrokenPipe`]. Dropping the
    /// last handle does the same.
    pub fn close(&self) {
        self.shared().close();
    }
}

/// The receiving half of a [`TunSlot`]: packets read from the installed fd.
#[derive(Debug)]
pub struct SlotSource {
    shared: Arc<Shared>,
    pool: PacketPool,
    mtu: u16,
    /// Kept so the receivers [`PacketSource::mtu`] hands out never close.
    mtu_tx: watch::Sender<u16>,
    oversize_drops: u64,
}

impl SlotSource {
    /// How many reads were dropped for being longer than the MTU.
    pub const fn oversize_drops(&self) -> u64 {
        self.oversize_drops
    }
}

impl PacketSource for SlotSource {
    /// Reads one packet into the packet region of a pooled [`PacketBuf`], leaving the
    /// headroom in front free and room for the MTU plus 28 bytes behind it.
    ///
    /// Each read gets MTU + 1 bytes of buffer: a read longer than the MTU is dropped and
    /// counted ([`SlotSource::oversize_drops`]) and the next packet is read. A read of 0
    /// bytes fails with [`io::ErrorKind::UnexpectedEof`]. While the slot is empty or
    /// disabled this waits; once it is closed this fails with
    /// [`io::ErrorKind::BrokenPipe`]. A read that completed on an fd that was replaced
    /// meanwhile is discarded (see [`TunSlot::replace`]).
    ///
    /// Cancel-safe: a packet is only taken off the fd in the same poll that returns it.
    async fn recv(&mut self) -> io::Result<PacketBuf> {
        let mtu = usize::from(self.mtu);
        let mut packet = self.pool.get(mtu + TRANSLATION_SLACK);
        // `PacketBuf` exposes only initialised bytes, so the read region is zero-filled
        // first.
        packet.set_len(mtu + 1);
        loop {
            // Created before the check, so a change made after it wakes the wait.
            let changed = self.shared.changed.notified();
            let Some((generation, fd)) = self.shared.current()? else {
                changed.await;
                continue;
            };
            let Some(guard) = ready_or_changed(fd.readable(), changed).await else {
                continue;
            };
            let Ok(result) = guard?.try_io(|fd| {
                self.shared
                    .io(generation, || read(fd.get_ref(), packet.as_packet_mut()))
            }) else {
                continue;
            };
            let Some(len) = result? else { continue };
            // Fenced: the fd was replaced or the slot closed after the read.
            if self.shared.generation.load(Ordering::Acquire) != generation {
                continue;
            }
            if len == 0 {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "TUN fd reached end of stream",
                ));
            }
            if len > mtu {
                self.oversize_drops += 1;
                continue;
            }
            packet.set_len(len);
            return Ok(packet);
        }
    }

    /// The MTU the slot was created with; it never changes.
    fn mtu(&self) -> watch::Receiver<u16> {
        self.mtu_tx.subscribe()
    }
}

/// The sending half of a [`TunSlot`]: packets written to the installed fd.
#[derive(Debug)]
pub struct SlotSink {
    shared: Arc<Shared>,
}

impl PacketSink for SlotSink {
    /// Writes `packet` as one write, without any header or offload. `from` is unused.
    ///
    /// A short write fails with [`io::ErrorKind::WriteZero`]. While the slot is empty or
    /// disabled this waits; once it is closed this fails with
    /// [`io::ErrorKind::BrokenPipe`]. A write never runs on an fd after
    /// [`TunSlot::replace`] removed it: one waiting for that fd is done on the new one.
    async fn send(&self, packet: PacketBuf, _from: PeerId) -> io::Result<()> {
        let bytes = packet.as_packet();
        loop {
            // Created before the check, so a change made after it wakes the wait.
            let changed = self.shared.changed.notified();
            let Some((generation, fd)) = self.shared.current()? else {
                changed.await;
                continue;
            };
            let Some(guard) = ready_or_changed(fd.writable(), changed).await else {
                continue;
            };
            let Ok(result) =
                guard?.try_io(|fd| self.shared.io(generation, || write(fd.get_ref(), bytes)))
            else {
                continue;
            };
            if let Some(written) = result? {
                return check_written(written, bytes.len());
            }
        }
    }
}

/// Waits for `ready`; `None` if `changed` fires first.
async fn ready_or_changed<T>(ready: impl Future<Output = T>, changed: Notified<'_>) -> Option<T> {
    let mut changed = pin!(changed);
    let mut ready = pin!(ready);
    poll_fn(|cx| {
        if let Poll::Ready(value) = ready.as_mut().poll(cx) {
            return Poll::Ready(Some(value));
        }
        if changed.as_mut().poll(cx).is_ready() {
            return Poll::Ready(None);
        }
        Poll::Pending
    })
    .await
}

fn closed() -> io::Error {
    io::Error::new(io::ErrorKind::BrokenPipe, "TUN slot closed")
}

/// One `read`, retried when interrupted by a signal.
fn read(mut fd: &File, buf: &mut [u8]) -> io::Result<usize> {
    loop {
        match fd.read(buf) {
            Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
            result => return result,
        }
    }
}

/// One `write`, retried when interrupted by a signal.
fn write(mut fd: &File, buf: &[u8]) -> io::Result<usize> {
    loop {
        match fd.write(buf) {
            Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
            result => return result,
        }
    }
}

/// Fails with [`io::ErrorKind::WriteZero`] unless all `len` bytes were written.
fn check_written(written: usize, len: usize) -> io::Result<()> {
    if written == len {
        Ok(())
    } else {
        Err(io::Error::new(
            io::ErrorKind::WriteZero,
            format!("short TUN write: {written} of {len} bytes"),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn short_write_is_write_zero() {
        assert!(check_written(60, 60).is_ok());
        let err = check_written(59, 60).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::WriteZero);
    }
}
