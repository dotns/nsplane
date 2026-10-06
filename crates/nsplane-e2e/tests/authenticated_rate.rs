//! The rate of `Event::Authenticated`: a peer pinned to its path by a policy that never
//! adopts reports an off-path source once per change of source, not once per message, while
//! the policy still sees every message.
//!
//! Two engines are linked three times over channel transports: link 1 carries the peers'
//! paths, links 2 and 3 are the other sources `b` sends from.

use std::net::SocketAddr;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};

use nsplane::{ChannelTransport, Event, Path, PathPolicy, PeerId, TransportId};
use nsplane_core::{MessageKind, Roam};
use nsplane_e2e::{Events, Family, Node, Options, TestResult, exchange, introduce, transfer};

const A1: TransportId = TransportId::new(1);
const B1: TransportId = TransportId::new(2);
const A2: TransportId = TransportId::new(3);
const B2: TransportId = TransportId::new(4);
const A3: TransportId = TransportId::new(5);
const B3: TransportId = TransportId::new(6);

/// Packets sent from each source.
const PACKETS: usize = 20;

/// Address of node `last` on link `link`.
fn addr(last: u8, link: u16) -> SocketAddr {
    SocketAddr::from(([192, 0, 2, last], 1000 * u16::from(last) + link))
}

const fn path(transport: TransportId, addr: SocketAddr) -> Path {
    Path {
        transport,
        addr,
        ecn: nsplane::Ecn::NotEct,
    }
}

fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(PoisonError::into_inner)
}

/// Keeps every peer on its path; records the sources of the data it is told about.
#[derive(Debug, Default)]
struct Keeper(Mutex<Vec<Path>>);

#[derive(Debug)]
struct SharedKeeper(Arc<Keeper>);

impl PathPolicy for SharedKeeper {
    fn select(&self, _peer: PeerId, _kind: MessageKind) -> Option<Path> {
        None
    }

    fn on_authenticated(&self, _peer: PeerId, from: &Path, kind: MessageKind) -> Roam {
        if kind == MessageKind::Data {
            lock(&self.0.0).push(*from);
        }
        Roam::Keep
    }
}

/// Has `b` send [`PACKETS`] packets to `a` from `b`'s link `via` and checks that `a` reports
/// the source `from` exactly once and its policy saw every packet.
async fn send_from(
    a: &mut Node<ChannelTransport>,
    b: &Node<ChannelTransport>,
    events: &mut Events,
    keeper: &Keeper,
    via: Path,
    from: Path,
) -> TestResult {
    b.handle.set_path(a.public(), via).await?;
    lock(&keeper.0).clear();
    for _ in 0..PACKETS {
        transfer(b, a, Family::V4, 100).await?;
    }
    assert_eq!(*lock(&keeper.0), [from; PACKETS]);
    events
        .expect(|e| matches!(e, Event::Authenticated { from: f, .. } if *f == from))
        .await?;
    events
        .expect_none(|e| matches!(e, Event::Authenticated { .. }))
        .await
}

#[tokio::test]
async fn an_off_path_source_is_reported_once_per_change() -> TestResult {
    let links = [(A1, B1, 1), (A2, B2, 2), (A3, B3, 3)].map(|(ta, tb, link)| {
        ChannelTransport::pair(256, (ta, addr(1, link)), (tb, addr(2, link)))
    });
    let [(a1, b1), (a2, b2), (a3, b3)] = links;
    let keeper = Arc::new(Keeper::default());
    let policy = Arc::clone(&keeper);
    let mut a = Node::with_builder(1, A1, addr(1, 1), Options::default(), |builder| {
        builder
            .transport(a1)
            .transport(a2)
            .transport(a3)
            .policy(Box::new(SharedKeeper(policy)))
    })?;
    let mut b = Node::with_builder(2, B1, addr(2, 1), Options::default(), |builder| {
        builder.transport(b1).transport(b2).transport(b3)
    })?;
    introduce(&a, &b, None).await?;
    exchange(&mut a, &mut b).await?;
    let from_b = a.peer_of(&b).await?;
    let pinned = path(A1, addr(2, 1));
    let mut events = a.subscribe().await?;

    let (via2, from2) = (path(B2, addr(1, 2)), path(A2, addr(2, 2)));
    let (via3, from3) = (path(B3, addr(1, 3)), path(A3, addr(2, 3)));
    send_from(&mut a, &b, &mut events, &keeper, via2, from2).await?;
    send_from(&mut a, &b, &mut events, &keeper, via3, from3).await?;
    send_from(&mut a, &b, &mut events, &keeper, via2, from2).await?;

    // Setting the path, even to the same one, reports the next source again.
    a.handle.set_path(b.public(), pinned).await?;
    send_from(&mut a, &b, &mut events, &keeper, via2, from2).await?;

    // The current path reports nothing.
    b.handle.set_path(a.public(), path(B1, addr(1, 1))).await?;
    for _ in 0..PACKETS {
        transfer(&b, &mut a, Family::V4, 100).await?;
    }
    events
        .expect_none(|e| matches!(e, Event::Authenticated { .. }))
        .await?;

    let stats = a.handle.peer_stats(from_b).await?.ok_or("peer")?;
    assert_eq!(stats.path, Some(pinned));
    Ok(())
}
