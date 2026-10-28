//! Receiving: coalesced reads through `quinn-udp`, batched reads with `recvmmsg` and
//! single reads with `recvmsg`.

use std::collections::VecDeque;
use std::io;
use std::io::IoSliceMut;
use std::net::SocketAddr;
use std::os::fd::AsRawFd;
use std::sync::atomic::Ordering;
use std::sync::{MutexGuard, PoisonError};

use bytes::BytesMut;
use nix::errno::Errno;
use nix::sys::socket::{MsgFlags, MultiHeaders, SockaddrStorage, recvmmsg, recvmsg};
use nsplane_packet::{Ecn, MAX_BATCH, PacketBuf, Path};
use quinn_udp::{RecvMeta, UdpSockRef, UdpSocketState};
use tokio::io::Interest;

use super::{CMSG, CmsgBuf, READ, RING, SINGLES, SLOTS, STORAGE, ecn, received_ecn, socket_addr};
use crate::udp::UdpTransport;

/// What the receiving side keeps between receives.
#[derive(Debug, Default)]
pub(in crate::udp) struct Rx {
    /// Storages for coalesced reads; every read takes its datagrams off the front of the
    /// current one, so they share its allocation, which is freed once all of them are
    /// dropped and the ring has let go of it.
    ring: [BytesMut; RING],
    /// The storage of `ring` reads go to.
    current: usize,
    /// Datagrams read but not handed out yet, oldest first.
    pending: VecDeque<(Path, PacketBuf)>,
    /// The slots of a batched read, as many bytes each as the caller's buffer holds
    /// (a whole read with receive offload).
    slots: Vec<u8>,
    /// Coalesced reads of one datagram each in a row, up to [`SINGLES`].
    singles: u8,
    /// With receive offload, batches go to one `recvmmsg` of several slots: no trains
    /// arrived lately.
    batched: bool,
}

impl Rx {
    /// Makes sure the current storage has room for the next coalesced read: keeps it,
    /// else takes the first storage of the ring, from the current one on, whose
    /// datagrams are all dropped, reclaimed without allocating and zero-filled again.
    /// Only while every storage still has datagrams out it allocates a fresh one, in an
    /// unused place of the ring, else after the current one (the storage there is freed
    /// once its datagrams are).
    fn refill(&mut self) {
        if self.ring[self.current].len() < READ {
            let reclaimed = (0..RING).map(|i| (self.current + i) % RING).find(|&i| {
                let storage = &mut self.ring[i];
                storage.clear();
                storage.try_reclaim(STORAGE)
            });
            if let Some(i) = reclaimed {
                self.current = i;
                self.ring[i].resize(STORAGE, 0);
            } else {
                let next = (self.current + 1) % RING;
                self.current = (1..=RING)
                    .map(|i| (self.current + i) % RING)
                    .find(|&i| self.ring[i].capacity() == 0)
                    .unwrap_or(next);
                self.ring[self.current] = BytesMut::zeroed(STORAGE);
            }
        }
    }
}

impl UdpTransport {
    /// What a read waits for: the socket to be readable, and with path MTU discovery
    /// on also an error.
    fn readiness(&self) -> Interest {
        if self.errors.discovery.load(Ordering::Relaxed) {
            Interest::READABLE | Interest::ERROR
        } else {
            Interest::READABLE
        }
    }

    /// Runs the non-blocking read `read`. With path MTU discovery on, it reads the
    /// first 64 queued errors at most, and retries a failed read: a queued ICMP error also
    /// fails the next read once with its error code, which is not the engine's.
    fn read<T>(&self, mut read: impl FnMut() -> io::Result<T>) -> io::Result<T> {
        if !self.errors.discovery.load(Ordering::Relaxed) {
            return read();
        }
        loop {
            self.errors.drain_errors(&self.socket);
            match read() {
                Err(e) if e.kind() != io::ErrorKind::WouldBlock => {
                    tracing::trace!(message = "Read failed on an ICMP error", error = %e);
                }
                result => return result,
            }
        }
    }

    fn rx(&self) -> MutexGuard<'_, Rx> {
        self.rx.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Whether receive offload reads in batches now.
    #[cfg(test)]
    pub(in crate::udp) fn batched(&self) -> bool {
        self.rx().batched
    }

    /// [`Transport::recv`](crate::Transport::recv).
    pub(in crate::udp) async fn recv_datagram(
        &self,
        buf: &mut PacketBuf,
    ) -> io::Result<(usize, Path)> {
        loop {
            let next = self.rx().pending.pop_front();
            if let Some((path, datagram)) = next {
                let len = datagram.len().min(buf.capacity());
                buf.set_len(len);
                buf.as_packet_mut()
                    .copy_from_slice(&datagram.as_packet()[..len]);
                return Ok((len, path));
            }
            match &self.state {
                Some(state) if self.offload() => self.read_coalesced(state).await?,
                _ => {
                    if let Some(received) = self.read_into(buf).await? {
                        return Ok(received);
                    }
                }
            }
        }
    }

    /// [`Transport::recv_batch`](crate::Transport::recv_batch).
    pub(in crate::udp) async fn recv_datagrams(
        &self,
        buf: &mut PacketBuf,
        datagrams: &mut VecDeque<(Path, PacketBuf)>,
    ) -> io::Result<()> {
        let capacity = buf.capacity();
        loop {
            let room = MAX_BATCH.saturating_sub(datagrams.len());
            {
                let mut rx = self.rx();
                if room == 0 || !rx.pending.is_empty() {
                    let ready = room.min(rx.pending.len());
                    for (path, mut datagram) in rx.pending.drain(..ready) {
                        if datagram.len() > capacity {
                            datagram.set_len(capacity);
                        }
                        datagrams.push_back((path, datagram));
                    }
                    return Ok(());
                }
            }
            match &self.state {
                Some(_) if self.offload() && self.rx().batched => {
                    self.read_batch(READ, room).await?;
                }
                Some(state) if self.offload() => self.read_coalesced(state).await?,
                _ if self.batching() => self.read_batch(capacity, room).await?,
                _ => {
                    if let Some((len, path)) = self.read_into(buf).await? {
                        datagrams
                            .push_back((path, PacketBuf::from_packet(&buf.as_packet()[..len])));
                        return Ok(());
                    }
                }
            }
        }
    }

    /// Reads into `buf` under the [`recv`](crate::Transport::recv) buffer contract;
    /// `None` when the side channel took the datagram. Datagrams after the first of a
    /// train (coalesced before offload was turned off) are copied to the pending queue,
    /// but for those the side channel takes.
    async fn read_into(&self, buf: &mut PacketBuf) -> io::Result<Option<(usize, Path)>> {
        buf.set_len(buf.capacity());
        let Some(state) = &self.state else {
            let (len, addr, ecn) = self
                .recv_from(buf.as_packet_mut())
                .await
                .inspect_err(|_| buf.set_len(0))?;
            buf.set_len(len);
            let path = self.path(addr, ecn);
            return Ok((!self.side_took(buf.as_packet(), path.addr)).then_some((len, path)));
        };
        let meta = self
            .socket
            .async_io(self.readiness(), || {
                self.read(|| {
                    let mut meta = [RecvMeta::default()];
                    let mut bufs = [IoSliceMut::new(buf.as_packet_mut())];
                    state.recv(UdpSockRef::from(&*self.socket), &mut bufs, &mut meta)?;
                    Ok(meta[0])
                })
            })
            .await
            .inspect_err(|_| buf.set_len(0))?;
        let path = self.path(meta.addr, ecn(&meta));
        let len = meta.stride.min(meta.len);
        if len > 0 && len < meta.len {
            let mut rx = self.rx();
            for datagram in buf.as_packet()[len..meta.len].chunks(len) {
                if !self.side_took(datagram, path.addr) {
                    rx.pending
                        .push_back((path, PacketBuf::from_packet(datagram)));
                }
            }
        }
        buf.set_len(len);
        Ok((!self.side_took(buf.as_packet(), path.addr)).then_some((len, path)))
    }

    /// Reads one datagram or train into the shared storage and queues its datagrams,
    /// each a zero-copy slice of the storage at the offset it was read to (no headroom),
    /// but for those the side channel takes.
    async fn read_coalesced(&self, state: &UdpSocketState) -> io::Result<()> {
        self.socket
            .async_io(self.readiness(), || {
                self.read(|| {
                    let mut rx = self.rx();
                    let rx = &mut *rx;
                    rx.refill();
                    let storage = &mut rx.ring[rx.current];
                    let mut meta = [RecvMeta::default()];
                    let mut bufs = [IoSliceMut::new(&mut storage[..READ])];
                    state.recv(UdpSockRef::from(&*self.socket), &mut bufs, &mut meta)?;
                    let meta = meta[0];
                    let path = self.path(meta.addr, ecn(&meta));
                    let stride = meta.stride.clamp(1, READ);
                    let count = meta.len.div_ceil(stride).max(1);
                    rx.singles = if count == 1 {
                        rx.singles.saturating_add(1)
                    } else {
                        0
                    };
                    rx.batched = rx.singles >= SINGLES;
                    let len = |i: usize| stride.min(meta.len - i * stride);
                    let side = self.side.as_ref();
                    for i in 0..count {
                        let slot = storage.split_to(len(i));
                        if side.is_some_and(|side| side.take(&slot, path.addr)) {
                            continue;
                        }
                        match PacketBuf::from_shared(slot, 0, len(i)) {
                            Ok(datagram) => rx.pending.push_back((path, datagram)),
                            Err(e) => {
                                debug_assert!(false, "datagram slice out of bounds: {e}");
                                tracing::debug!(message = "Dropped coalesced datagram", error = %e);
                            }
                        }
                    }
                    Ok(())
                })
            })
            .await
    }
}

impl UdpTransport {
    /// Whether sends and reads go in batches: with offload off, and while `sendmmsg`
    /// and `recvmmsg` are available.
    pub(in crate::udp) fn batching(&self) -> bool {
        !self.offload() && !self.no_mmsg.load(Ordering::Relaxed)
    }

    /// `true` for an error that says `sendmmsg` / `recvmmsg` do not exist, and then
    /// stops batching for good.
    pub(super) fn mmsg_missing(&self, e: Errno) -> bool {
        let missing = e == Errno::ENOSYS;
        if missing {
            tracing::debug!(message = "No sendmmsg / recvmmsg; one datagram per call");
            self.no_mmsg.store(true, Ordering::Relaxed);
        }
        missing
    }

    /// Reads up to `count` datagrams, at most [`SLOTS`], with one `recvmmsg` (through
    /// `quinn-udp` where it set the socket up), each into a slot of `capacity` bytes, so
    /// truncated to it, and queues a copy of each, but for those the side channel
    /// takes. A train (with receive offload, or coalesced before offload was turned off)
    /// is split as [`read_into`](Self::read_into) splits it, and with offload ends the
    /// batched reads.
    pub(in crate::udp) async fn read_batch(&self, capacity: usize, count: usize) -> io::Result<()> {
        let capacity = capacity.max(1);
        let count = count.clamp(1, SLOTS);
        let fd = self.socket.as_raw_fd();
        self.socket
            .async_io(self.readiness(), || {
                self.read(|| {
                    let mut rx = self.rx();
                    let rx = &mut *rx;
                    if rx.slots.len() != SLOTS * capacity {
                        rx.slots = vec![0; SLOTS * capacity];
                    }
                    // Per datagram: its length, sender, mark and stride.
                    let mut received = [(0, None, Ecn::NotEct, 0); SLOTS];
                    let read = {
                        let mut slots = rx.slots.chunks_mut(capacity);
                        if let Some(state) = &self.state {
                            let mut bufs: [IoSliceMut<'_>; SLOTS] = std::array::from_fn(|_| {
                                IoSliceMut::new(slots.next().unwrap_or_default())
                            });
                            let mut meta = [RecvMeta::default(); SLOTS];
                            let read = state.recv(
                                UdpSockRef::from(&*self.socket),
                                &mut bufs[..count],
                                &mut meta[..count],
                            )?;
                            for (received, meta) in received.iter_mut().zip(&meta[..read]) {
                                *received = (meta.len, Some(meta.addr), ecn(meta), meta.stride);
                            }
                            read
                        } else {
                            let mut bufs: [[IoSliceMut<'_>; 1]; SLOTS] =
                                std::array::from_fn(|_| {
                                    [IoSliceMut::new(slots.next().unwrap_or_default())]
                                });
                            let mut headers = MultiHeaders::<SockaddrStorage>::preallocate(
                                count,
                                Some(vec![0; CMSG]),
                            );
                            let msgs = match recvmmsg(
                                fd,
                                &mut headers,
                                bufs[..count].iter_mut(),
                                MsgFlags::empty(),
                                None,
                            ) {
                                Ok(msgs) => msgs,
                                // Read again, one datagram per call.
                                Err(e) if self.mmsg_missing(e) => return Ok(()),
                                Err(e) => return Err(e.into()),
                            };
                            let mut read = 0;
                            for (received, msg) in received.iter_mut().zip(msgs) {
                                // A truncated control buffer only loses the ECN mark.
                                let ecn = received_ecn(msg.cmsgs().into_iter().flatten());
                                let addr = msg.address.as_ref().and_then(socket_addr);
                                *received = (msg.bytes, addr, ecn, msg.bytes);
                                read += 1;
                            }
                            read
                        }
                    };
                    for (slot, &(len, addr, ecn, stride)) in
                        rx.slots.chunks(capacity).zip(&received[..read])
                    {
                        // Never without one; dropped if it were.
                        let Some(addr) = addr else { continue };
                        let path = self.path(addr, ecn);
                        let datagram = &slot[..len.min(capacity)];
                        // An empty datagram is one too.
                        let empty = datagram.is_empty().then_some(datagram);
                        for datagram in datagram.chunks(stride.clamp(1, capacity)).chain(empty) {
                            if !self.side_took(datagram, path.addr) {
                                rx.pending
                                    .push_back((path, PacketBuf::from_packet(datagram)));
                            }
                        }
                    }
                    // A train: back to coalesced reads, without a copy.
                    if received[..read]
                        .iter()
                        .any(|&(len, _, _, stride)| stride < len)
                    {
                        rx.batched = false;
                        rx.singles = 0;
                    }
                    Ok(())
                })
            })
            .await
    }
}

impl UdpTransport {
    /// Receives one datagram with `recvmsg`, truncated to `packet`, and its ECN mark.
    async fn recv_from(&self, packet: &mut [u8]) -> io::Result<(usize, SocketAddr, Ecn)> {
        let fd = self.socket.as_raw_fd();
        self.socket
            .async_io(self.readiness(), || {
                self.read(|| {
                    let mut iov = [IoSliceMut::new(&mut *packet)];
                    let mut cmsg = CmsgBuf([0; 64]);
                    let msg = recvmsg::<SockaddrStorage>(
                        fd,
                        &mut iov,
                        Some(&mut cmsg.0),
                        MsgFlags::empty(),
                    )?;
                    let addr = msg.address.as_ref().and_then(socket_addr).ok_or_else(|| {
                        io::Error::new(io::ErrorKind::InvalidData, "datagram without source")
                    })?;
                    // A truncated control buffer only loses the ECN mark.
                    let ecn = received_ecn(msg.cmsgs().ok().into_iter().flatten());
                    Ok((msg.bytes, addr, ecn))
                })
            })
            .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Where the current storage starts.
    fn start(rx: &mut Rx) -> usize {
        rx.refill();
        rx.ring[rx.current].as_ptr().addr()
    }

    /// Takes all but less than a read off the current storage, as reads do: the
    /// datagrams still out.
    fn fill(rx: &mut Rx) -> BytesMut {
        rx.refill();
        let mut datagrams = rx.ring[rx.current].split_to(STORAGE - READ + 1);
        datagrams.fill(0xAA);
        datagrams
    }

    #[test]
    fn coalesced_storage_is_reclaimed_once_released() {
        let mut rx = Rx::default();
        let first = start(&mut rx);
        let out = fill(&mut rx);
        // The first storage still has datagrams out: another one.
        let second = start(&mut rx);
        assert_ne!(second, first);
        let out_second = fill(&mut rx);
        // Released: the first storage comes back, no new allocation, zero-filled.
        drop(out);
        assert_eq!(start(&mut rx), first);
        assert_eq!(rx.ring[rx.current].len(), STORAGE);
        assert!(rx.ring[rx.current].iter().all(|&b| b == 0));
        // Every storage out: a fresh one; then the second comes back.
        let out = fill(&mut rx);
        let third = start(&mut rx);
        assert!(third != first && third != second);
        let out_third = fill(&mut rx);
        drop(out_second);
        assert_eq!(start(&mut rx), second);
        drop((out, out_third));
    }
}
