//! A [`PacketSink`] that routes each packet to one of several sinks.

use std::fmt;
use std::io;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};

use nsplane_packet::{PacketBuf, PeerId};

use crate::io::PacketSink;
use crate::transport::BoxFuture;

/// The object-safe form of [`PacketSink`], so sinks of different types share one list.
trait DynSink: Send + Sync + 'static {
    fn send_boxed(&self, packet: PacketBuf, from: PeerId) -> BoxFuture<'_, io::Result<()>>;
}

impl<S: PacketSink> DynSink for S {
    fn send_boxed(&self, packet: PacketBuf, from: PeerId) -> BoxFuture<'_, io::Result<()>> {
        Box::pin(PacketSink::send(self, packet, from))
    }
}

/// One routed sink and whether it has returned [`io::ErrorKind::BrokenPipe`].
struct Route {
    sink: Box<dyn DynSink>,
    gone: AtomicBool,
}

/// The routing closure a [`Splitter`] calls for every packet.
type RouteFn = dyn Fn(PeerId, &PacketBuf) -> usize + Send + Sync;

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
/// [`Splitter::stats`] reads both counters; a delivered packet costs no counter update.
pub struct Splitter {
    route: Box<RouteFn>,
    routes: Vec<Route>,
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
            route: Box::new(route),
            routes: Vec::new(),
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
}

impl PacketSink for Splitter {
    async fn send(&self, packet: PacketBuf, from: PeerId) -> io::Result<()> {
        if self.open.load(Ordering::Acquire) == 0 {
            self.failed.fetch_add(1, Ordering::Relaxed);
            return Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "all splitter sinks closed",
            ));
        }
        let Some(route) = self.routes.get((self.route)(from, &packet)) else {
            self.misrouted.fetch_add(1, Ordering::Relaxed);
            return Ok(());
        };
        let result = route.sink.send_boxed(packet, from).await;
        if let Err(err) = &result {
            self.failed.fetch_add(1, Ordering::Relaxed);
            if err.kind() == io::ErrorKind::BrokenPipe && !route.gone.swap(true, Ordering::AcqRel) {
                self.open.fetch_sub(1, Ordering::AcqRel);
            }
        }
        result
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
    use crate::ChannelSink;

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
}
