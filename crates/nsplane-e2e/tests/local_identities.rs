//! Local identities over `UdpTransport`s on the loopback interface: one engine holding
//! several static keys, each with its own peers.
//!
//! - two identities with peers of the same remote key, each packet attributed to its peer;
//! - an identity removed under traffic: its peer is gone, the other identity's traffic goes
//!   on, and initiations for the removed key are dropped without a reply;
//! - an initiation for a key the engine does not hold gets no reply;
//! - an identity restricted to one of two transports answers nothing on the other, not even
//!   a cookie reply under load, and handshakes on its own;
//! - a peer of an identity restricted to two transports roams between them;
//! - the first two again with crypto workers.
//!
//! Raw initiations are captured from a remote engine with `force_handshake_on` towards a
//! socket of the test and replayed from other sockets, so a missing reply is observed on the
//! wire.

use std::cmp::Ordering;
use std::io;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};

use nsplane::reasons::{UNKNOWN_LOCAL_IDENTITY, UNKNOWN_SESSION};
use nsplane::x25519::{PublicKey, StaticSecret};
use nsplane::{Ecn, Event, LocalIdentityId, Path, Peer, PeerId, TransportId, UdpTransport};
use nsplane_e2e::{Family, Node, Options, QUIET, TestResult, WAIT, payload};
use tokio::net::UdpSocket;
use tokio::time::{Instant, timeout, timeout_at};

/// The id of every node's first transport, and of the only one of single-transport nodes.
const T1: TransportId = TransportId::new(1);
/// The id of a node's second transport.
const T2: TransportId = TransportId::new(2);
/// The key seed of the remote engines; every one of them holds this key.
const REMOTE: u8 = 2;
/// Packets each remote sends per round in [`removal_under_traffic`].
const BURST: usize = 8;
/// Rounds of [`removal_under_traffic`]; the identity is removed in the middle one.
const ROUNDS: usize = 10;
/// Copies of a captured initiation sent to each transport: well above the per-source budget
/// of 100 handshakes per second, so the engine is under load.
const FLOOD: usize = 300;
/// Wire size and message type of a handshake initiation and of a cookie reply.
const INITIATION: (usize, u8) = (148, 1);
const COOKIE_REPLY: (usize, u8) = (64, 3);

/// A UDP transport on the loopback interface with an OS-chosen port.
fn udp(id: TransportId) -> io::Result<UdpTransport> {
    UdpTransport::bind(id, SocketAddr::from((Ipv4Addr::LOCALHOST, 0)))
}

const fn at(transport: TransportId, addr: SocketAddr) -> Path {
    Path {
        transport,
        addr,
        ecn: Ecn::NotEct,
    }
}

/// A node with key seed `seed` on one UDP transport `T1`, with `workers` crypto workers.
fn node(seed: u8, workers: usize) -> TestResult<Node<UdpTransport>> {
    let transport = udp(T1)?;
    let addr = transport.local_addr();
    Node::with_builder(seed, T1, addr, Options::default(), |b| {
        b.transport(transport).crypto_workers(workers)
    })
}

/// A node with key seed `seed` on two UDP transports, `T1` (its own path) and `T2`, and the
/// address of `T2`.
fn two_transport_node(seed: u8) -> TestResult<(Node<UdpTransport>, SocketAddr)> {
    let (t1, t2) = (udp(T1)?, udp(T2)?);
    let (addr1, addr2) = (t1.local_addr(), t2.local_addr());
    let node = Node::with_builder(seed, T1, addr1, Options::default(), |b| {
        b.transport(t1).transport(t2)
    })?;
    Ok((node, addr2))
}

/// The key of a second local identity.
fn second_key() -> StaticSecret {
    StaticSecret::from([11; 32])
}

/// A remote engine (key seed [`REMOTE`]) answering to tunnel addresses `10.0.0.<ip>` and
/// `fd00::<ip>`, so several remotes sharing one key stay apart in the routing table.
fn remote(ip: u8, workers: usize) -> TestResult<Node<UdpTransport>> {
    let mut node = node(REMOTE, workers)?;
    node.ip4 = Ipv4Addr::new(10, 0, 0, ip);
    node.ip6 = Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, u16::from(ip));
    Ok(node)
}

/// Makes `remote` a peer of `node`'s identity `identity` (reached on `node`'s transport
/// `via`) and the identity's key `key` a peer of `remote` at `node`'s path; returns the peer
/// id on each side, `node`'s first.
async fn pair(
    node: &Node<UdpTransport>,
    identity: LocalIdentityId,
    key: PublicKey,
    via: TransportId,
    remote: &Node<UdpTransport>,
) -> TestResult<(PeerId, PeerId)> {
    let local_identity = (identity != LocalIdentityId::DEFAULT).then_some(identity);
    node.handle
        .add_or_update_peer(Peer {
            local_identity,
            ..remote.as_peer(via)
        })
        .await?;
    remote
        .handle
        .add_or_update_peer(Peer {
            public_key: key,
            ..node.as_peer(remote.path.transport)
        })
        .await?;
    let on_node = node
        .handle
        .peer_id_in(identity, remote.public())
        .await?
        .ok_or("no peer on the node")?;
    let on_remote = remote
        .handle
        .peer_id(key)
        .await?
        .ok_or("no peer on the remote")?;
    Ok((on_node, on_remote))
}

/// Sends a packet with a payload of `len` bytes from `from` to `to` and checks that it
/// arrives intact and attributed to `peer`.
async fn deliver(
    from: &Node<UdpTransport>,
    to: &mut Node<UdpTransport>,
    len: usize,
    peer: PeerId,
) -> TestResult {
    let packet = from.packet_to(to, Family::V4, &payload(len));
    from.send(&packet).await?;
    let (got, delivered) = to.expect_delivery().await?;
    if got != peer {
        return Err(format!("packet attributed to {got:?}, not {peer:?}").into());
    }
    if delivered != packet {
        return Err(format!("packet of {len} bytes changed in transit").into());
    }
    Ok(())
}

/// Node `x` (seed 1) with a second local identity `i1` and a third one without peers (so
/// more than one identity remains when `i1` is removed), and two remote engines sharing one
/// key: `y0` (10.0.0.2) is a peer of `x`'s default identity, `y1` (10.0.0.3) of `i1`.
struct Twins {
    x: Node<UdpTransport>,
    y0: Node<UdpTransport>,
    y1: Node<UdpTransport>,
    i1: LocalIdentityId,
    spare: LocalIdentityId,
    x_to_y0: PeerId,
    x_to_y1: PeerId,
    y0_to_x: PeerId,
    y1_to_x: PeerId,
}

async fn twins(workers: usize) -> TestResult<Twins> {
    let x = node(1, workers)?;
    let i1 = x
        .handle
        .add_local_identity(second_key())
        .await?
        .ok_or("second identity refused")?;
    let spare = x
        .handle
        .add_local_identity(StaticSecret::from([12; 32]))
        .await?
        .ok_or("third identity refused")?;
    let (y0, y1) = (remote(2, workers)?, remote(3, workers)?);
    let (x_to_y0, y0_to_x) = pair(&x, LocalIdentityId::DEFAULT, x.public(), T1, &y0).await?;
    let i1_public = PublicKey::from(&second_key());
    let (x_to_y1, y1_to_x) = pair(&x, i1, i1_public, T1, &y1).await?;
    Ok(Twins {
        x,
        y0,
        y1,
        i1,
        spare,
        x_to_y0,
        x_to_y1,
        y0_to_x,
        y1_to_x,
    })
}

async fn two_identities_with_one_remote_key(workers: usize) -> TestResult {
    let mut t = twins(workers).await?;
    assert_ne!(t.x_to_y0, t.x_to_y1);
    for len in [64, 1300] {
        deliver(&t.y0, &mut t.x, len, t.x_to_y0).await?;
        deliver(&t.y1, &mut t.x, len, t.x_to_y1).await?;
        deliver(&t.x, &mut t.y0, len, t.y0_to_x).await?;
        deliver(&t.x, &mut t.y1, len, t.y1_to_x).await?;
    }

    for (peer, identity) in [(t.x_to_y0, LocalIdentityId::DEFAULT), (t.x_to_y1, t.i1)] {
        let stats = t.x.handle.peer_stats(peer).await?.ok_or("unknown peer")?;
        assert_eq!(stats.local_identity, identity);
        assert_eq!(stats.public_key, t.y0.public());
        assert!(stats.last_handshake.is_some());
    }
    let status = t.x.handle.status().await?;
    let identities: Vec<_> = status
        .local_identities
        .iter()
        .map(|i| (i.id, i.public_key, i.peers, i.transports.clone()))
        .collect();
    assert_eq!(
        identities,
        [
            (LocalIdentityId::DEFAULT, Some(t.x.public()), 1, None),
            (t.i1, Some(PublicKey::from(&second_key())), 1, None),
            (
                t.spare,
                Some(PublicKey::from(&StaticSecret::from([12; 32]))),
                0,
                None
            ),
        ]
    );
    assert_eq!(t.x.drops(UNKNOWN_LOCAL_IDENTITY).await?, 0);
    Ok(())
}

#[tokio::test]
async fn two_identities_carry_peers_of_one_remote_key() -> TestResult {
    two_identities_with_one_remote_key(0).await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn two_identities_carry_peers_of_one_remote_key_with_crypto_workers() -> TestResult {
    two_identities_with_one_remote_key(4).await
}

/// Receives deliveries until `y0_packets` from `x_to_y0` have arrived; packets of
/// `x_to_y1` are counted if `y1_allowed`, an error otherwise. Returns the `x_to_y1` count.
async fn collect(t: &mut Twins, y0_packets: usize, y1_allowed: bool) -> TestResult<usize> {
    let (mut from_y0, mut from_y1) = (0, 0);
    while from_y0 < y0_packets {
        let (peer, _) = t.x.expect_delivery().await?;
        if peer == t.x_to_y0 {
            from_y0 += 1;
        } else if peer == t.x_to_y1 && y1_allowed {
            from_y1 += 1;
        } else {
            return Err(format!("unexpected delivery from {peer:?}").into());
        }
    }
    Ok(from_y1)
}

async fn removal_under_traffic(workers: usize) -> TestResult {
    let mut t = twins(workers).await?;
    deliver(&t.y0, &mut t.x, 64, t.x_to_y0).await?;
    deliver(&t.y1, &mut t.x, 64, t.x_to_y1).await?;
    let from_y0 = t.y0.packet_to(&t.x, Family::V4, &payload(256));
    let from_y1 = t.y1.packet_to(&t.x, Family::V4, &payload(256));
    let middle = ROUNDS / 2;

    for round in 0..ROUNDS {
        for _ in 0..BURST {
            t.y0.send(&from_y0).await?;
            t.y1.send(&from_y1).await?;
        }
        match round.cmp(&middle) {
            Ordering::Less => {
                // Both identities: every packet of both remotes arrives.
                let mut from_y1 = collect(&mut t, BURST, true).await?;
                while from_y1 < BURST {
                    let (peer, _) = t.x.expect_delivery().await?;
                    if peer != t.x_to_y1 {
                        return Err(format!("unexpected delivery from {peer:?}").into());
                    }
                    from_y1 += 1;
                }
            }
            Ordering::Equal => {
                // Removed with `y1`'s burst in flight: whatever of it got through before is
                // still delivered, `y0`'s burst is not affected.
                assert!(t.x.handle.remove_local_identity(t.i1).await?);
                collect(&mut t, BURST, true).await?;
                while let Ok(Some((peer, _))) = timeout(QUIET, t.x.delivered.recv()).await {
                    if peer != t.x_to_y1 {
                        return Err(format!("unexpected delivery from {peer:?}").into());
                    }
                }
            }
            Ordering::Greater => {
                collect(&mut t, BURST, false).await?;
            }
        }
    }
    t.x.expect_no_delivery().await?;

    assert_eq!(t.x.handle.peer_stats(t.x_to_y1).await?, None);
    assert_eq!(t.x.handle.peer_id_in(t.i1, t.y1.public()).await?, None);
    assert!(t.x.handle.peer_stats(t.x_to_y0).await?.is_some());
    let identities: Vec<_> =
        t.x.handle
            .local_identities()
            .await?
            .iter()
            .map(|i| i.id)
            .collect();
    assert_eq!(identities, [LocalIdentityId::DEFAULT, t.spare]);
    assert!(!t.x.handle.remove_local_identity(t.i1).await?);

    // `y1` starts over: its initiation for the removed key is dropped.
    let mut events = t.x.subscribe().await?;
    t.y1.handle.force_handshake(t.y1_to_x, None).await?;
    events
        .expect(|e| matches!(e, Event::Dropped { reason, .. } if *reason == UNKNOWN_LOCAL_IDENTITY))
        .await?;
    assert!(t.x.drops(UNKNOWN_LOCAL_IDENTITY).await? >= 1);
    deliver(&t.y0, &mut t.x, 64, t.x_to_y0).await?;
    deliver(&t.x, &mut t.y0, 64, t.y0_to_x).await?;
    Ok(())
}

#[tokio::test]
async fn an_identity_removed_under_traffic_leaves_the_other_untouched() -> TestResult {
    removal_under_traffic(0).await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_identity_removed_under_traffic_leaves_the_other_untouched_with_crypto_workers()
-> TestResult {
    removal_under_traffic(4).await
}

/// The handshake initiation `from` sends to its peer `key`, captured on a socket of the
/// test instead of reaching the peer.
async fn initiation(from: &Node<UdpTransport>, key: PublicKey) -> TestResult<Vec<u8>> {
    let tap = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await?;
    let peer = from.handle.peer_id(key).await?.ok_or("unknown peer")?;
    from.handle
        .force_handshake_on(peer, at(from.path.transport, tap.local_addr()?))
        .await?;
    let mut buf = [0; 2048];
    let (len, _) = timeout(WAIT, tap.recv_from(&mut buf)).await??;
    if (len, buf[0]) != INITIATION {
        return Err(format!("captured {len} bytes of type {}", buf[0]).into());
    }
    Ok(buf[..len].to_vec())
}

/// A socket of the test on the loopback interface.
async fn probe() -> io::Result<UdpSocket> {
    UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await
}

/// Succeeds if nothing arrives at `socket` within [`QUIET`].
async fn expect_silence(socket: &UdpSocket) -> TestResult {
    let mut buf = [0; 2048];
    match timeout(QUIET, socket.recv_from(&mut buf)).await {
        Ok(Ok((len, from))) => Err(format!("{len} bytes of type {} from {from}", buf[0]).into()),
        Ok(Err(e)) => Err(e.into()),
        Err(_) => Ok(()),
    }
}

#[tokio::test]
async fn an_initiation_for_an_unknown_identity_gets_no_reply() -> TestResult {
    let t = twins(0).await?;
    // `z` has a peer whose key no identity of `x` holds, at `x`'s address.
    let z = node(5, 0)?;
    let stranger = PublicKey::from(&StaticSecret::from([42; 32]));
    z.handle
        .add_or_update_peer(Peer {
            public_key: stranger,
            ..t.x.as_peer(T1)
        })
        .await?;
    let init = initiation(&z, stranger).await?;

    let mut events = t.x.subscribe().await?;
    let socket = probe().await?;
    socket.send_to(&init, t.x.path.addr).await?;
    events
        .expect(|e| matches!(e, Event::Dropped { reason, .. } if *reason == UNKNOWN_LOCAL_IDENTITY))
        .await?;
    expect_silence(&socket).await?;
    assert_eq!(t.x.drops(UNKNOWN_LOCAL_IDENTITY).await?, 1);
    Ok(())
}

#[tokio::test]
async fn a_restricted_identity_answers_nothing_on_other_transports() -> TestResult {
    let (mut x, t2_addr) = two_transport_node(1)?;
    let i1 = x
        .handle
        .add_local_identity_on(second_key(), [T1])
        .await?
        .ok_or("identity refused")?;
    let i1_public = PublicKey::from(&second_key());
    let mut y = remote(2, 0)?;
    let (x_to_y, y_to_x) = pair(&x, i1, i1_public, T1, &y).await?;
    let restricted: Vec<_> = x
        .handle
        .local_identities()
        .await?
        .into_iter()
        .filter(|i| i.id == i1)
        .map(|i| i.transports)
        .collect();
    assert_eq!(restricted, [Some(vec![T1])]);

    // On `T1` the identity handshakes and carries traffic.
    deliver(&y, &mut x, 64, x_to_y).await?;
    deliver(&x, &mut y, 1300, y_to_x).await?;

    // Its peer's data on `T2` is dropped before decryption.
    y.handle.set_path(i1_public, at(T1, t2_addr)).await?;
    y.send(&y.packet_to(&x, Family::V4, &payload(64))).await?;
    x.expect_no_delivery().await?;
    assert!(x.drops(UNKNOWN_SESSION).await? >= 1);

    // A flood of one initiation for the identity on both transports: on `T1` the engine
    // comes under load and answers with cookie replies, on `T2` it answers nothing at all.
    let init = initiation(&y, i1_public).await?;
    let (on_t1, on_t2) = (probe().await?, probe().await?);
    for _ in 0..FLOOD {
        on_t1.send_to(&init, x.path.addr).await?;
        on_t2.send_to(&init, t2_addr).await?;
    }
    let deadline = Instant::now() + WAIT;
    let mut buf = [0; 2048];
    loop {
        let (len, _) = timeout_at(deadline, on_t1.recv_from(&mut buf))
            .await
            .map_err(|_| "no cookie reply on T1")??;
        if (len, buf[0]) == COOKIE_REPLY {
            break;
        }
    }
    expect_silence(&on_t2).await?;
    assert!(x.drops(UNKNOWN_LOCAL_IDENTITY).await? >= 1);
    Ok(())
}

#[tokio::test]
async fn a_peer_roams_between_the_transports_of_its_identity() -> TestResult {
    let (mut x, t2_addr) = two_transport_node(1)?;
    let i1 = x
        .handle
        .add_local_identity_on(second_key(), [T1, T2])
        .await?
        .ok_or("identity refused")?;
    let i1_public = PublicKey::from(&second_key());
    let mut y = remote(2, 0)?;
    let (x_to_y, y_to_x) = pair(&x, i1, i1_public, T1, &y).await?;
    deliver(&y, &mut x, 64, x_to_y).await?;
    deliver(&x, &mut y, 64, y_to_x).await?;
    let stats = x.handle.peer_stats(x_to_y).await?.ok_or("unknown peer")?;
    assert_eq!(stats.path, Some(at(T1, y.path.addr)));

    // `y` switches to `x`'s second transport; `x` adopts the path and answers on it.
    let mut events = x.subscribe().await?;
    y.handle.set_path(i1_public, at(T1, t2_addr)).await?;
    deliver(&y, &mut x, 1300, x_to_y).await?;
    let moved = at(T2, y.path.addr);
    events
        .expect(
            |e| matches!(e, Event::PathAdopted { peer, path } if *peer == x_to_y && *path == moved),
        )
        .await?;
    let stats = x.handle.peer_stats(x_to_y).await?.ok_or("unknown peer")?;
    assert_eq!(stats.path, Some(moved));
    assert_eq!(stats.local_identity, i1);
    deliver(&x, &mut y, 1300, y_to_x).await?;
    deliver(&y, &mut x, 64, x_to_y).await?;
    assert_eq!(x.drops(UNKNOWN_SESSION).await?, 0);
    Ok(())
}
