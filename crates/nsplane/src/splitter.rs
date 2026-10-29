//! A [`PacketSink`] that routes each packet to one of several sinks.

use std::collections::VecDeque;
use std::fmt;
use std::io;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};

use nsplane_packet::{PacketBuf, PeerId};

use crate::io::PacketSink;
use crate::transport::BoxFuture;

/// The object-safe form of [`PacketSink`], so sinks of different types share one list.
trait DynSink: Send + Sync + 'static {
    fn send_boxed(&self, packet: PacketBuf, from: PeerId) -> BoxFuture<'_, io::Result<()>>;

    fn send_batch_spent_boxed<'a>(
        &'a self,
        packets: &'a mut VecDeque<(PeerId, PacketBuf)>,
        spent: &'a mut Vec<PacketBuf>,
    ) -> BoxFuture<'a, io::Result<()>>;
}

impl<S: PacketSink> DynSink for S {
    fn send_boxed(&self, packet: PacketBuf, from: PeerId) -> BoxFuture<'_, io::Result<()>> {
        Box::pin(PacketSink::send(self, packet, from))
    }

    fn send_batch_spent_boxed<'a>(
        &'a self,
        packets: &'a mut VecDeque<(PeerId, PacketBuf)>,
        spent: &'a mut Vec<PacketBuf>,
    ) -> BoxFuture<'a, io::Result<()>> {
        Box::pin(PacketSink::send_batch_spent(self, packets, spent))
    }
}

/// One routed sink and whether it has returned [`io::ErrorKind::BrokenPipe`].
struct Route {
    sink: Box<dyn DynSink>,
    gone: AtomicBool,
}

/// The routing closure a [`Splitter`] calls for every packet; a [`Splitter::new`] closure is
/// wrapped into this form.
type RouteFn = dyn Fn(PeerId, &mut PacketBuf) -> usize + Send + Sync;

/// A [`PacketSink`] that delivers each packet to one of N sinks picked by a closure.
///
/// For a hybrid local side, e.g. a TUN device next to a userspace netstack, routed by
/// destination address. Build it with [`Splitter::new`] and add sinks, of any types, with
/// [`Splitter::sink`]; the route closure returns an index into the sinks in the order they
/// were added:
///
/// ```
/// # use nsplane::{ChannelSink, Splitter};
/// let (tun, _tun_rx) = ChannelSink::new(64);
/// let (stack, _stack_rx) = ChannelSink::new(64);
/// // IPv4 packets to 100.64.0.1 go to the netstack, everything else to the TUN device.
/// let splitter = Splitter::new(|_peer, packet| {
///     usize::from(packet.as_packet().get(16..20) == Some(&[100, 64, 0, 1][..]))
/// })
/// .sink(tun)
/// .sink(stack);
/// ```
///
/// [`Splitter::new_map`] builds one whose closure may also rewrite each packet in place
/// before it picks the sink, e.g. a Redirect or Masquerade translation that decides the
/// route.
///
/// Semantics of [`PacketSink::send`]:
/// - It awaits only the chosen sink. Backpressure is not isolated: while that sink waits,
///   the engine's next delivery (to any sink) waits too.
/// - An index out of range drops the packet, counts it in [`SplitterStats::misrouted`]
///   (also [`Splitter::misrouted`]), and returns `Ok`, so the engine does not take the
///   local side for gone.
/// - An error from the chosen sink is returned for that packet and counted in
///   [`SplitterStats::failed`].
/// - When the chosen sink returns [`io::ErrorKind::BrokenPipe`], the sink counts as gone;
///   later packets routed to a gone sink get the same error from the sink itself. Once
///   every sink is gone (or none was added), `send` returns [`io::ErrorKind::BrokenPipe`]
///   for every packet without calling the closure, and counts it in
///   [`SplitterStats::failed`].
///
/// [`PacketSink::send_batch`] calls `send` for each packet in order.
/// [`PacketSink::send_batch_spent`] hands packets to the chosen sink's `send_batch_spent`, so
/// that sink's spent buffers reach the caller. A [`Splitter::new`] splitter hands each run of
/// consecutive packets routed to the same sink over as one batch; to find where a run ends it
/// routes the packet behind it, so the route closure may run again for packets left in the
/// batch after an error, when the caller delivers them. A [`Splitter::new_map`] splitter
/// hands over one packet at a time, so its closure rewrites each packet once, also across
/// those retries. Errors and cancellation follow `send_batch`: the packets of a run its sink
/// did not take over stay at the front of the batch, in order. Each packet goes to one sink
/// and is never shared: only that sink may append its buffer, and the splitter appends the
/// buffers of the packets it drops itself (misrouted, or failed because every sink is gone).
///
/// [`Splitter::stats`] reads both counters; a delivered packet costs no counter update.
pub struct Splitter {
    route: Box<RouteFn>,
    routes: Vec<Route>,
    /// Whether `send_batch_spent` hands runs of packets for one sink over together: only
    /// for a closure that does not rewrite packets ([`Splitter::new`]).
    coalesces: bool,
    open: AtomicUsize,
    misrouted: AtomicU64,
    failed: AtomicU64,
}

/// A snapshot of a [`Splitter`]'s drop counters, from [`Splitter::stats`].
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct SplitterStats {
    /// Packets dropped because the route closure returned an index out of range; `send`
    /// returned `Ok` for them.
    pub misrouted: u64,
    /// Packets not delivered because the chosen sink returned an error (of any kind,
    /// [`io::ErrorKind::BrokenPipe`] included) or because every sink was gone; `send`
    /// returned the error for them.
    pub failed: u64,
}

impl Splitter {
    /// Creates a splitter with no sinks, routing every packet by `route`.
    pub fn new<F>(route: F) -> Self
    where
        F: Fn(PeerId, &PacketBuf) -> usize + Send + Sync + 'static,
    {
        Self {
            coalesces: true,
            ..Self::new_map(move |from, packet: &mut PacketBuf| route(from, packet))
        }
    }

    /// Creates a splitter with no sinks whose `route` closure may rewrite each packet in
    /// place before it returns the sink index; the packet, as rewritten, goes to that sink.
    ///
    /// The closure may change the packet's bytes and length (a Redirect or Masquerade
    /// translation, say) and must leave a packet the chosen sink accepts. It is the first to
    /// see the packet as the engine delivered it. Everything else is as [`Splitter::new`]:
    /// a packet routed out of range is dropped already rewritten and counted in
    /// [`SplitterStats::misrouted`], and once every sink is gone (or none was added) the
    /// closure is not called at all.
    ///
    /// ```
    /// # use nsplane::{ChannelSink, Splitter};
    /// let (tun, _tun_rx) = ChannelSink::new(64);
    /// let (stack, _stack_rx) = ChannelSink::new(64);
    /// // IPv4 packets to 10.0.4.4 are redirected to 100.64.0.1 and go to the netstack,
    /// // everything else to the TUN device. (A real translation also fixes the checksums.)
    /// let splitter = Splitter::new_map(|_peer, packet| {
    ///     match packet.as_packet_mut().get_mut(16..20) {
    ///         Some(dst) if *dst == [10, 0, 4, 4] => {
    ///             dst.copy_from_slice(&[100, 64, 0, 1]);
    ///             1
    ///         }
    ///         _ => 0,
    ///     }
    /// })
    /// .sink(tun)
    /// .sink(stack);
    /// ```
    pub fn new_map<F>(route: F) -> Self
    where
        F: Fn(PeerId, &mut PacketBuf) -> usize + Send + Sync + 'static,
    {
        Self {
            route: Box::new(route),
            routes: Vec::new(),
            coalesces: false,
            open: AtomicUsize::new(0),
            misrouted: AtomicU64::new(0),
            failed: AtomicU64::new(0),
        }
    }

    /// Adds `sink` under the next index (the first sink added is index 0).
    ///
    /// Each packet is boxed into one future per delivery; pass a concrete sink to the
    /// engine where only one is needed.
    #[must_use]
    pub fn sink<S: PacketSink>(mut self, sink: S) -> Self {
        self.routes.push(Route {
            sink: Box::new(sink),
            gone: AtomicBool::new(false),
        });
        *self.open.get_mut() += 1;
        self
    }

    /// Packets dropped so far because the route closure returned an index out of range.
    pub fn misrouted(&self) -> u64 {
        self.misrouted.load(Ordering::Relaxed)
    }

    /// The drop counters so far.
    pub fn stats(&self) -> SplitterStats {
        SplitterStats {
            misrouted: self.misrouted(),
            failed: self.failed.load(Ordering::Relaxed),
        }
    }

    /// The sink index the route closure picks for the packet at `at` in `packets`.
    fn route_at(&self, packets: &mut VecDeque<(PeerId, PacketBuf)>, at: usize) -> usize {
        let (from, packet) = &mut packets[at];
        (self.route)(*from, packet)
    }

    /// Counts a packet failed because every sink is gone and returns its error.
    fn all_closed(&self) -> io::Error {
        self.failed.fetch_add(1, Ordering::Relaxed);
        io::Error::new(io::ErrorKind::BrokenPipe, "all splitter sinks closed")
    }

    /// Counts a packet `route` failed with `err`, and the sink as gone on a broken pipe.
    fn failed(&self, route: &Route, err: &io::Error) {
        self.failed.fetch_add(1, Ordering::Relaxed);
        if err.kind() == io::ErrorKind::BrokenPipe && !route.gone.swap(true, Ordering::AcqRel) {
            self.open.fetch_sub(1, Ordering::AcqRel);
        }
    }
}

impl PacketSink for Splitter {
    async fn send(&self, mut packet: PacketBuf, from: PeerId) -> io::Result<()> {
        if self.open.load(Ordering::Acquire) == 0 {
            return Err(self.all_closed());
        }
        let Some(route) = self.routes.get((self.route)(from, &mut packet)) else {
            self.misrouted.fetch_add(1, Ordering::Relaxed);
            return Ok(());
        };
        let result = route.sink.send_boxed(packet, from).await;
        if let Err(err) = &result {
            self.failed(route, err);
        }
        result
    }

    async fn send_batch_spent(
        &self,
        packets: &mut VecDeque<(PeerId, PacketBuf)>,
        spent: &mut Vec<PacketBuf>,
    ) -> io::Result<()> {
        // The packets handed to one sink together.
        let mut run = VecDeque::new();
        // The route of the front packet, if the previous run already took it.
        let mut next = None;
        while !packets.is_empty() {
            if self.open.load(Ordering::Acquire) == 0 {
                if let Some((_, packet)) = packets.pop_front() {
                    spent.push(packet);
                }
                return Err(self.all_closed());
            }
            let index = next.take().unwrap_or_else(|| self.route_at(packets, 0));
            let mut len = 1;
            // A rewriting closure only sees a packet once it is next to be delivered, so a
            // packet left after an error is not rewritten again by the caller's retry.
            if self.coalesces {
                while len < packets.len() {
                    let other = self.route_at(packets, len);
                    if other != index {
                        next = Some(other);
                        break;
                    }
                    len += 1;
                }
            }
            let Some(route) = self.routes.get(index) else {
                self.misrouted.fetch_add(len as u64, Ordering::Relaxed);
                spent.extend(packets.drain(..len).map(|(_, packet)| packet));
                continue;
            };
            run.extend(packets.drain(..len));
            let run = Run {
                packets: &mut *packets,
                run: &mut run,
            };
            let result = route.sink.send_batch_spent_boxed(run.run, spent).await;
            drop(run);
            if let Err(err) = result {
                self.failed(route, &err);
                return Err(err);
            }
        }
        Ok(())
    }
}

/// Packets taken from the front of a batch for one sink. Dropped, once the sink returned or
/// with its call cancelled, it puts the packets the sink did not take over back at the front
/// of the batch, in order.
struct Run<'a> {
    packets: &'a mut VecDeque<(PeerId, PacketBuf)>,
    run: &'a mut VecDeque<(PeerId, PacketBuf)>,
}

impl Drop for Run<'_> {
    fn drop(&mut self) {
        while let Some(entry) = self.run.pop_back() {
            self.packets.push_front(entry);
        }
    }
}

impl fmt::Debug for Splitter {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Splitter")
            .field("sinks", &self.routes.len())
            .field("open", &self.open.load(Ordering::Relaxed))
            .field("misrouted", &self.misrouted())
            .field("failed", &self.failed.load(Ordering::Relaxed))
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    use crate::ChannelSink;
    use crate::io::test_sinks::{SpentSink, bytes};

    type TestResult = Result<(), Box<dyn std::error::Error>>;

    /// Routes by the first packet byte.
    fn by_first_byte(_from: PeerId, packet: &PacketBuf) -> usize {
        packet.as_packet().first().copied().map_or(0, usize::from)
    }

    async fn send(splitter: &Splitter, byte: u8) -> io::Result<()> {
        splitter
            .send(
                PacketBuf::from_packet(&[byte]),
                PeerId::new(u32::from(byte)),
            )
            .await
    }

    #[tokio::test]
    async fn routes_by_closure() -> TestResult {
        let (a, mut a_rx) = ChannelSink::new(4);
        let (b, mut b_rx) = ChannelSink::new(4);
        let splitter = Splitter::new(by_first_byte).sink(a).sink(b);

        send(&splitter, 1).await?;
        send(&splitter, 0).await?;
        let (peer, packet) = b_rx.recv().await.ok_or("b closed")?;
        assert_eq!((peer, packet.as_packet()), (PeerId::new(1), &[1][..]));
        let (peer, packet) = a_rx.recv().await.ok_or("a closed")?;
        assert_eq!((peer, packet.as_packet()), (PeerId::new(0), &[0][..]));
        assert!(a_rx.is_empty() && b_rx.is_empty());
        assert_eq!(splitter.misrouted(), 0);
        assert_eq!(splitter.stats(), SplitterStats::default());
        Ok(())
    }

    #[tokio::test]
    async fn out_of_range_is_counted() -> TestResult {
        let (a, mut a_rx) = ChannelSink::new(4);
        let splitter = Splitter::new(by_first_byte).sink(a);

        send(&splitter, 5).await?;
        send(&splitter, 9).await?;
        send(&splitter, 0).await?;
        assert_eq!(splitter.misrouted(), 2);
        assert_eq!(
            splitter.stats(),
            SplitterStats {
                misrouted: 2,
                failed: 0
            }
        );
        assert_eq!(a_rx.recv().await.ok_or("a closed")?.1.as_packet(), [0]);
        assert!(a_rx.is_empty());
        Ok(())
    }

    #[tokio::test]
    async fn broken_pipe_per_sink_then_all() -> TestResult {
        let (a, a_rx) = ChannelSink::new(4);
        let (b, b_rx) = ChannelSink::new(4);
        let splitter = Splitter::new(by_first_byte).sink(a).sink(b);

        drop(a_rx);
        for _ in 0..2 {
            let err = send(&splitter, 0).await.err().ok_or("expected an error")?;
            assert_eq!(err.kind(), io::ErrorKind::BrokenPipe);
        }
        send(&splitter, 1).await?;
        send(&splitter, 7).await?;
        assert_eq!(splitter.misrouted(), 1);

        drop(b_rx);
        let err = send(&splitter, 1).await.err().ok_or("expected an error")?;
        assert_eq!(err.kind(), io::ErrorKind::BrokenPipe);
        // Every sink is gone: even an out-of-range packet reports the local side gone.
        let err = send(&splitter, 7).await.err().ok_or("expected an error")?;
        assert_eq!(err.kind(), io::ErrorKind::BrokenPipe);
        assert_eq!(splitter.misrouted(), 1);
        // Two to the gone sink a, one to b, one with every sink gone.
        assert_eq!(
            splitter.stats(),
            SplitterStats {
                misrouted: 1,
                failed: 4
            }
        );
        Ok(())
    }

    #[tokio::test]
    async fn no_sinks_is_broken_pipe() -> TestResult {
        let splitter = Splitter::new(by_first_byte);
        assert_eq!(splitter.stats(), SplitterStats::default());
        let err = send(&splitter, 0).await.err().ok_or("expected an error")?;
        assert_eq!(err.kind(), io::ErrorKind::BrokenPipe);
        assert_eq!(splitter.stats().failed, 1);
        Ok(())
    }

    /// A sink that refuses every packet with `kind`.
    struct Failing(io::ErrorKind);

    impl PacketSink for Failing {
        fn send(
            &self,
            _packet: PacketBuf,
            _from: PeerId,
        ) -> impl Future<Output = io::Result<()>> + Send {
            std::future::ready(Err(self.0.into()))
        }
    }

    #[tokio::test]
    async fn every_sink_error_is_counted() -> TestResult {
        let (a, mut a_rx) = ChannelSink::new(4);
        let splitter = Splitter::new(by_first_byte)
            .sink(a)
            .sink(Failing(io::ErrorKind::Other));

        for _ in 0..3 {
            let err = send(&splitter, 1).await.err().ok_or("expected an error")?;
            assert_eq!(err.kind(), io::ErrorKind::Other);
        }
        send(&splitter, 0).await?;
        assert_eq!(a_rx.recv().await.ok_or("a closed")?.1.as_packet(), [0]);
        assert_eq!(
            splitter.stats(),
            SplitterStats {
                misrouted: 0,
                failed: 3
            }
        );
        Ok(())
    }

    /// Adds one to the first packet byte, then routes by the new first byte.
    fn increment_then_route(from: PeerId, packet: &mut PacketBuf) -> usize {
        if let Some(byte) = packet.as_packet_mut().first_mut() {
            *byte = byte.wrapping_add(1);
        }
        by_first_byte(from, packet)
    }

    #[tokio::test]
    async fn map_rewrite_reaches_the_chosen_sink() -> TestResult {
        let (a, a_rx) = ChannelSink::new(4);
        let (b, mut b_rx) = ChannelSink::new(4);
        let (c, mut c_rx) = ChannelSink::new(4);
        let splitter = Splitter::new_map(|from, packet: &mut PacketBuf| {
            packet.set_len(2);
            packet.as_packet_mut()[1] = 0xAA;
            increment_then_route(from, packet)
        })
        .sink(a)
        .sink(b)
        .sink(c);

        // Routed on the rewritten byte: 0 -> 1 goes to b, 1 -> 2 to c, never to a.
        send(&splitter, 0).await?;
        send(&splitter, 1).await?;
        let (peer, packet) = b_rx.recv().await.ok_or("b closed")?;
        assert_eq!((peer, packet.as_packet()), (PeerId::new(0), &[1, 0xAA][..]));
        let (peer, packet) = c_rx.recv().await.ok_or("c closed")?;
        assert_eq!((peer, packet.as_packet()), (PeerId::new(1), &[2, 0xAA][..]));
        assert!(a_rx.is_empty() && b_rx.is_empty() && c_rx.is_empty());
        assert_eq!(splitter.stats(), SplitterStats::default());
        Ok(())
    }

    #[tokio::test]
    async fn map_out_of_range_after_rewrite_is_counted() -> TestResult {
        let (a, a_rx) = ChannelSink::new(4);
        let (b, mut b_rx) = ChannelSink::new(4);
        let splitter = Splitter::new_map(increment_then_route).sink(a).sink(b);

        // 1 would be in range before the rewrite, 2 is not after it.
        send(&splitter, 1).await?;
        send(&splitter, 4).await?;
        send(&splitter, 0).await?;
        assert_eq!(splitter.misrouted(), 2);
        assert_eq!(
            splitter.stats(),
            SplitterStats {
                misrouted: 2,
                failed: 0
            }
        );
        assert_eq!(b_rx.recv().await.ok_or("b closed")?.1.as_packet(), [1]);
        assert!(a_rx.is_empty() && b_rx.is_empty());
        Ok(())
    }

    #[tokio::test]
    async fn map_broken_pipe_per_sink_then_all() -> TestResult {
        let calls = Arc::new(AtomicU64::new(0));
        let (a, a_rx) = ChannelSink::new(4);
        let (b, b_rx) = ChannelSink::new(4);
        let splitter = Splitter::new_map({
            let calls = Arc::clone(&calls);
            move |from, packet: &mut PacketBuf| {
                calls.fetch_add(1, Ordering::Relaxed);
                increment_then_route(from, packet)
            }
        })
        .sink(a)
        .sink(b);

        // A packet starting with 0 is routed to b, one starting with 255 to a.
        drop(b_rx);
        for _ in 0..2 {
            let err = send(&splitter, 0).await.err().ok_or("expected an error")?;
            assert_eq!(err.kind(), io::ErrorKind::BrokenPipe);
        }
        assert_eq!(splitter.stats().failed, 2);
        drop(a_rx);
        let err = send(&splitter, 255)
            .await
            .err()
            .ok_or("expected an error")?;
        assert_eq!(err.kind(), io::ErrorKind::BrokenPipe);
        assert_eq!(calls.load(Ordering::Relaxed), 3);

        // Every sink is gone: the closure is no longer called.
        for byte in [0, 255, 7] {
            let err = send(&splitter, byte)
                .await
                .err()
                .ok_or("expected an error")?;
            assert_eq!(err.kind(), io::ErrorKind::BrokenPipe);
        }
        assert_eq!(calls.load(Ordering::Relaxed), 3);
        assert_eq!(
            splitter.stats(),
            SplitterStats {
                misrouted: 0,
                failed: 6
            }
        );
        Ok(())
    }

    #[tokio::test]
    async fn map_no_sinks_does_not_call_the_closure() -> TestResult {
        let splitter = Splitter::new_map(|_from, _packet: &mut PacketBuf| -> usize {
            panic!("the closure ran without sinks")
        });
        let err = send(&splitter, 0).await.err().ok_or("expected an error")?;
        assert_eq!(err.kind(), io::ErrorKind::BrokenPipe);
        assert_eq!(splitter.stats().failed, 1);
        Ok(())
    }

    /// Packets of `bytes`, each from the peer of its byte.
    fn batch(bytes: &[u8]) -> VecDeque<(PeerId, PacketBuf)> {
        bytes
            .iter()
            .map(|&byte| {
                (
                    PeerId::new(u32::from(byte)),
                    PacketBuf::from_packet(&[byte]),
                )
            })
            .collect()
    }

    /// Routes odd first bytes to sink 1, even ones to sink 0.
    fn by_parity(_from: PeerId, packet: &PacketBuf) -> usize {
        usize::from(packet.as_packet().first().is_some_and(|byte| byte % 2 == 1))
    }

    #[tokio::test]
    async fn spent_returns_delivered_and_misrouted_buffers_in_order() -> TestResult {
        let (a, b) = (SpentSink::default(), SpentSink::default());
        let splitter = Splitter::new(by_first_byte).sink(a.clone()).sink(b.clone());
        let mut packets = batch(&[0, 1, 5, 0]);
        let mut spent = Vec::new();
        splitter.send_batch_spent(&mut packets, &mut spent).await?;
        assert!(packets.is_empty());
        assert_eq!(bytes(&spent), [[0], [1], [5], [0]]);
        assert_eq!(a.taken(), [[0], [0]]);
        assert_eq!(b.taken(), [[1]]);
        assert_eq!(
            splitter.stats(),
            SplitterStats {
                misrouted: 1,
                failed: 0
            }
        );
        Ok(())
    }

    #[tokio::test]
    async fn spent_stops_at_a_sink_error() -> TestResult {
        let (a, b) = (SpentSink::default(), SpentSink::default());
        let splitter = Splitter::new(by_parity).sink(a.clone()).sink(b.clone());
        let mut packets = batch(&[2, 3, SpentSink::FAIL, 5]);
        let mut spent = Vec::new();
        let err = splitter
            .send_batch_spent(&mut packets, &mut spent)
            .await
            .err()
            .ok_or("expected an error")?;
        assert_eq!(err.kind(), io::ErrorKind::Other);
        assert_eq!(bytes(&spent), [[2], [3]]);
        assert_eq!(packets.len(), 1);
        assert_eq!(splitter.stats().failed, 1);

        // The caller delivers the rest with another call.
        splitter.send_batch_spent(&mut packets, &mut spent).await?;
        assert_eq!(bytes(&spent), [[2], [3], [5]]);
        assert_eq!(b.taken(), [[3], [5]]);
        Ok(())
    }

    /// A [`SpentSink`] that also records the length of every `send_batch_spent` batch.
    #[derive(Clone, Default)]
    struct Batches {
        inner: SpentSink,
        lens: Arc<std::sync::Mutex<Vec<usize>>>,
    }

    impl Batches {
        fn lens(&self) -> Vec<usize> {
            self.lens
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .clone()
        }
    }

    impl PacketSink for Batches {
        async fn send(&self, packet: PacketBuf, from: PeerId) -> io::Result<()> {
            self.inner.send(packet, from).await
        }

        async fn send_batch_spent(
            &self,
            packets: &mut VecDeque<(PeerId, PacketBuf)>,
            spent: &mut Vec<PacketBuf>,
        ) -> io::Result<()> {
            self.lens
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .push(packets.len());
            self.inner.send_batch_spent(packets, spent).await
        }
    }

    /// The first byte of each packet left in `packets`, in order.
    fn left(packets: &VecDeque<(PeerId, PacketBuf)>) -> Vec<u8> {
        packets
            .iter()
            .map(|(_, packet)| packet.as_packet()[0])
            .collect()
    }

    #[tokio::test]
    async fn spent_hands_runs_to_a_sink_as_one_batch() -> TestResult {
        let (a, b) = (Batches::default(), Batches::default());
        let splitter = Splitter::new(by_first_byte).sink(a.clone()).sink(b.clone());
        let mut packets = batch(&[0, 0, 0, 1, 1, 7, 7, 0]);
        let mut spent = Vec::new();
        splitter.send_batch_spent(&mut packets, &mut spent).await?;
        assert!(packets.is_empty());
        assert_eq!(bytes(&spent), [[0], [0], [0], [1], [1], [7], [7], [0]]);
        assert_eq!(a.lens(), [3, 1]);
        assert_eq!(b.lens(), [2]);
        assert_eq!(a.inner.taken(), [[0], [0], [0], [0]]);
        assert_eq!(
            splitter.stats(),
            SplitterStats {
                misrouted: 2,
                failed: 0
            }
        );
        Ok(())
    }

    #[tokio::test]
    async fn spent_run_error_leaves_the_rest_in_order() -> TestResult {
        let (a, b) = (Batches::default(), Batches::default());
        let splitter = Splitter::new(by_parity).sink(a.clone()).sink(b.clone());
        let mut packets = batch(&[2, 4, SpentSink::FAIL, 6, 3, 8]);
        let mut spent = Vec::new();
        let err = splitter
            .send_batch_spent(&mut packets, &mut spent)
            .await
            .err()
            .ok_or("expected an error")?;
        assert_eq!(err.kind(), io::ErrorKind::Other);
        assert_eq!(bytes(&spent), [[2], [4]]);
        // The rest of the run, the packet that ended it and the ones behind.
        assert_eq!(left(&packets), [6, 3, 8]);
        assert_eq!(splitter.stats().failed, 1);

        splitter.send_batch_spent(&mut packets, &mut spent).await?;
        assert_eq!(bytes(&spent), [[2], [4], [6], [3], [8]]);
        assert_eq!(a.inner.taken(), [[2], [4], [6], [8]]);
        assert_eq!(b.inner.taken(), [[3]]);
        Ok(())
    }

    #[tokio::test]
    async fn spent_new_routes_again_what_an_error_left() -> TestResult {
        let calls = Arc::new(AtomicU64::new(0));
        let splitter = Splitter::new({
            let calls = Arc::clone(&calls);
            move |from, packet: &PacketBuf| {
                calls.fetch_add(1, Ordering::Relaxed);
                by_parity(from, packet)
            }
        })
        .sink(SpentSink::default())
        .sink(SpentSink::default());
        let mut packets = batch(&[2, SpentSink::FAIL, 6, 3]);
        let mut spent = Vec::new();
        assert!(
            splitter
                .send_batch_spent(&mut packets, &mut spent)
                .await
                .is_err()
        );
        // The run 2, FAIL, 6 and the 3 that ended it.
        assert_eq!(calls.load(Ordering::Relaxed), 4);
        splitter.send_batch_spent(&mut packets, &mut spent).await?;
        // 6 and 3 are routed again, once each.
        assert_eq!(calls.load(Ordering::Relaxed), 6);
        assert_eq!(bytes(&spent), [[2], [6], [3]]);
        Ok(())
    }

    #[tokio::test]
    async fn spent_new_map_maps_each_packet_once_across_retries() -> TestResult {
        let calls = Arc::new(AtomicU64::new(0));
        let (a, b) = (Batches::default(), Batches::default());
        let splitter = Splitter::new_map({
            let calls = Arc::clone(&calls);
            move |from, packet: &mut PacketBuf| {
                calls.fetch_add(1, Ordering::Relaxed);
                if let Some(byte) = packet.as_packet_mut().first_mut() {
                    *byte = byte.wrapping_add(1);
                }
                by_parity(from, packet)
            }
        })
        .sink(a.clone())
        .sink(b.clone());
        // Rewritten to 2, 4, FAIL, 6, 8, all for sink 0.
        let mut packets = batch(&[1, 3, SpentSink::FAIL - 1, 5, 7]);
        let mut spent = Vec::new();
        assert!(
            splitter
                .send_batch_spent(&mut packets, &mut spent)
                .await
                .is_err()
        );
        assert_eq!(calls.load(Ordering::Relaxed), 3);
        assert_eq!(left(&packets), [5, 7]);
        splitter.send_batch_spent(&mut packets, &mut spent).await?;
        assert_eq!(calls.load(Ordering::Relaxed), 5);
        assert_eq!(bytes(&spent), [[2], [4], [6], [8]]);
        assert_eq!(a.lens(), [1; 5]);
        assert_eq!(b.lens(), [0_usize; 0]);
        Ok(())
    }

    #[tokio::test]
    async fn spent_cancel_keeps_the_packets_not_taken_over() -> TestResult {
        let (a, b) = (SpentSink::default(), SpentSink::default());
        let splitter = Splitter::new(by_parity).sink(a.clone()).sink(b.clone());
        let mut packets = batch(&[3, SpentSink::HOLD, 5, 2, 7]);
        let mut spent = Vec::new();
        {
            let mut pending = Box::pin(splitter.send_batch_spent(&mut packets, &mut spent));
            let pending_for = std::time::Duration::from_millis(50);
            assert!(
                tokio::time::timeout(pending_for, &mut pending)
                    .await
                    .is_err()
            );
        }
        // The held packet was being delivered and is dropped; the rest stay in order.
        assert_eq!(left(&packets), [5, 2, 7]);
        assert_eq!(bytes(&spent), [[3]]);
        splitter.send_batch_spent(&mut packets, &mut spent).await?;
        assert_eq!(bytes(&spent), [[3], [5], [2], [7]]);
        assert_eq!(b.taken(), [[3], [5], [7]]);
        Ok(())
    }

    #[tokio::test]
    async fn spent_without_open_sinks_is_broken_pipe() -> TestResult {
        let splitter = Splitter::new(by_first_byte);
        let mut packets = batch(&[1, 2]);
        let mut spent = Vec::new();
        let err = splitter
            .send_batch_spent(&mut packets, &mut spent)
            .await
            .err()
            .ok_or("expected an error")?;
        assert_eq!(err.kind(), io::ErrorKind::BrokenPipe);
        assert_eq!(bytes(&spent), [[1]]);
        assert_eq!(packets.len(), 1);
        assert_eq!(splitter.stats().failed, 1);
        Ok(())
    }
}
