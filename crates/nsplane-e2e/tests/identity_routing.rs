//! Per-identity routing over `UdpTransport`s on the loopback interface: one engine holding
//! three local identities (the default one and two more), each with a peer of the same
//! remote key and the same allowed IPs, told apart by a source set per identity.
//!
//! - traffic in both directions through every identity at once, each remote receiving only
//!   its own identity's packets, and Fragmentation Needed going back through the identity
//!   of the packet's source;
//! - either non-default identity removed under traffic: the others' traffic goes on;
//! - the sets in `EngineStatus::local_identities`, and the refusals of `set_local_sources`;
//! - the first two again with crypto workers.

use std::net::{IpAddr, Ipv4Addr, SocketAddr};

use nsplane::reasons::NO_ROUTE;
use nsplane::x25519::{PublicKey, StaticSecret};
use nsplane::{
    AllowedIp, EngineStatus, FragmentConfig, LocalIdentityId, Peer, PeerId, TransportId,
    UdpTransport,
};
use nsplane_e2e::{Node, Options, QUIET, TestResult, payload, udp4};
use nsplane_packet::protocol;
use tokio::time::timeout;

/// The id of every node's transport.
const T1: TransportId = TransportId::new(1);
/// The key seed of the remote engines; every one of them holds this key and the tunnel
/// address `10.0.0.2`.
const REMOTE: u8 = 2;
/// Local identities of the node, the default one included.
const LANES: usize = 3;
/// Packets each side sends per identity and round.
const BURST: usize = 8;
/// Rounds of [`removal_under_traffic`]; the identity is removed in the middle one.
const ROUNDS: usize = 10;
/// Payload bytes of the packets of a round.
const LEN: usize = 256;

/// A node with key seed `seed` on one UDP transport `T1` on the loopback interface, with
/// `workers` crypto workers and the fragmentation stage.
fn node(seed: u8, workers: usize) -> TestResult<Node<UdpTransport>> {
    let transport = UdpTransport::bind(T1, SocketAddr::from((Ipv4Addr::LOCALHOST, 0)))?;
    let addr = transport.local_addr();
    Node::with_builder(seed, T1, addr, Options::default(), |b| {
        b.transport(transport)
            .crypto_workers(workers)
            .fragmenter(FragmentConfig::default())
    })
}

/// The key of local identity `index`; the default identity (0) holds the node's own key.
fn identity_key(x: &Node<UdpTransport>, index: u8) -> StaticSecret {
    match index {
        0 => x.secret.clone(),
        _ => StaticSecret::from([10 + index; 32]),
    }
}

const fn host(addr: Ipv4Addr) -> AllowedIp {
    AllowedIp {
        addr: IpAddr::V4(addr),
        cidr: 32,
    }
}

/// One identity of the node with its remote engine.
struct Lane {
    identity: LocalIdentityId,
    /// The identity's local address: the only network of its source set.
    source: Ipv4Addr,
    remote: Node<UdpTransport>,
    /// The remote's peer id on the node.
    on_node: PeerId,
    /// The identity's peer id on the remote.
    on_remote: PeerId,
}

impl Lane {
    /// A packet of the node from the identity's address to the remote.
    fn outbound(&self, remote: Ipv4Addr, len: usize) -> Vec<u8> {
        udp4(self.source, remote, &payload(len))
    }

    /// A packet of the remote to the identity's address.
    fn inbound(&self) -> Vec<u8> {
        udp4(self.remote.ip4, self.source, &payload(LEN))
    }
}

/// Node `x` (seed 1) with identities 0 (default), 1 and 2, the identity `k` with the local
/// address `10.1.<k>.1` as its source set and a peer at its own remote engine; every
/// remote holds the key [`REMOTE`] and is known to `x` with the allowed IPs `10.0.0.2/32`
/// and `fd00::2/128`, so without the sets each packet to `10.0.0.2` would go to the last
/// peer added.
struct Setup {
    x: Node<UdpTransport>,
    lanes: Vec<Lane>,
}

async fn setup(workers: usize) -> TestResult<Setup> {
    let x = node(1, workers)?;
    let mut lanes = Vec::new();
    for index in 0..LANES {
        let index = u8::try_from(index)?;
        let key = identity_key(&x, index);
        let identity = match index {
            0 => LocalIdentityId::DEFAULT,
            _ => x
                .handle
                .add_local_identity(key.clone())
                .await?
                .ok_or("identity refused")?,
        };
        let source = Ipv4Addr::new(10, 1, index, 1);
        let remote = node(REMOTE, workers)?;
        let local_identity = (identity != LocalIdentityId::DEFAULT).then_some(identity);
        x.handle
            .add_or_update_peer(Peer {
                local_identity,
                ..remote.as_peer(T1)
            })
            .await?;
        remote
            .handle
            .add_or_update_peer(Peer {
                public_key: PublicKey::from(&key),
                allowed_ips: vec![host(source)],
                ..x.as_peer(T1)
            })
            .await?;
        assert!(x.handle.set_local_sources(identity, [host(source)]).await?);
        let on_node = x
            .handle
            .peer_id_in(identity, remote.public())
            .await?
            .ok_or("no peer on the node")?;
        let on_remote = remote
            .handle
            .peer_id(PublicKey::from(&key))
            .await?
            .ok_or("no peer on the remote")?;
        lanes.push(Lane {
            identity,
            source,
            remote,
            on_node,
            on_remote,
        });
    }
    Ok(Setup { x, lanes })
}

/// The next delivery of `node`, which must be `expected` from `peer`.
async fn expect(node: &mut Node<UdpTransport>, peer: PeerId, expected: &[u8]) -> TestResult {
    let (got, packet) = node.expect_delivery().await?;
    if got != peer {
        return Err(format!("packet attributed to {got:?}, not {peer:?}").into());
    }
    if packet != expected {
        return Err(format!("unexpected packet of {} bytes from {got:?}", packet.len()).into());
    }
    Ok(())
}

/// One packet each way through every lane, one lane after the other.
async fn ping(s: &mut Setup) -> TestResult {
    for lane in &mut s.lanes {
        lane.remote.send(&lane.inbound()).await?;
        expect(&mut s.x, lane.on_node, &lane.inbound()).await?;
        let packet = lane.outbound(lane.remote.ip4, LEN);
        s.x.send(&packet).await?;
        expect(&mut lane.remote, lane.on_remote, &packet).await?;
    }
    Ok(())
}

/// Receives the node's deliveries until `counts[k]` packets of lane `k` have arrived, each
/// the lane's inbound packet; packets of lane `extra` beyond its count are accepted too. A
/// packet of no lane is an error.
async fn collect_on_node(
    s: &mut Setup,
    mut counts: Vec<usize>,
    extra: Option<usize>,
) -> TestResult {
    while counts.iter().any(|&c| c > 0) {
        let (peer, packet) = s.x.expect_delivery().await?;
        let k = s
            .lanes
            .iter()
            .position(|l| l.on_node == peer)
            .ok_or_else(|| format!("delivery from {peer:?}"))?;
        if (counts[k] == 0 && extra != Some(k)) || packet != s.lanes[k].inbound() {
            return Err(format!("unexpected delivery from lane {k}").into());
        }
        counts[k] = counts[k].saturating_sub(1);
    }
    Ok(())
}

/// Receives the deliveries of `node` until it is quiet for [`QUIET`]; each must be
/// `expected` from `peer`.
async fn drain(node: &mut Node<UdpTransport>, peer: PeerId, expected: &[u8]) -> TestResult {
    while let Ok(Some((got, packet))) = timeout(QUIET, node.delivered.recv()).await {
        if got != peer || packet.as_packet() != expected {
            return Err(format!("unexpected delivery from {got:?}").into());
        }
    }
    Ok(())
}

async fn every_identity_carries_its_own_traffic(workers: usize) -> TestResult {
    let mut s = setup(workers).await?;
    ping(&mut s).await?;
    for _ in 0..ROUNDS {
        for _ in 0..BURST {
            for lane in &s.lanes {
                s.x.send(&lane.outbound(lane.remote.ip4, LEN)).await?;
                lane.remote.send(&lane.inbound()).await?;
            }
        }
        collect_on_node(&mut s, vec![BURST; LANES], None).await?;
        for lane in &mut s.lanes {
            let packet = lane.outbound(lane.remote.ip4, LEN);
            for _ in 0..BURST {
                expect(&mut lane.remote, lane.on_remote, &packet).await?;
            }
        }
    }

    // A DF packet above the MTU: the Fragmentation Needed goes back through the peer of the
    // identity whose address sent it, not through the last peer added.
    for lane in &s.lanes {
        s.x.send(&lane.outbound(lane.remote.ip4, 1450)).await?;
        let (peer, reply) = s.x.expect_delivery().await?;
        assert_eq!(peer, lane.on_node);
        assert_eq!(reply[9], protocol::ICMP);
        assert_eq!(reply[16..20], lane.source.octets());
    }
    for lane in &mut s.lanes {
        lane.remote.expect_no_delivery().await?;
    }
    s.x.expect_no_delivery().await?;
    Ok(())
}

#[tokio::test]
async fn every_identity_carries_its_own_traffic_to_one_remote_key() -> TestResult {
    every_identity_carries_its_own_traffic(0).await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn every_identity_carries_its_own_traffic_to_one_remote_key_with_crypto_workers() -> TestResult
{
    every_identity_carries_its_own_traffic(4).await
}

/// Traffic through every lane in both directions, lane `removed` (not the default one)
/// removed in the middle round; from then on the node sends nothing from its address, as
/// a consumer removing the identity together with its local addresses does, while its
/// remote keeps sending.
async fn removal_under_traffic(workers: usize, removed: usize) -> TestResult {
    let mut s = setup(workers).await?;
    ping(&mut s).await?;
    let middle = ROUNDS / 2;
    for round in 0..ROUNDS {
        for _ in 0..BURST {
            for (k, lane) in s.lanes.iter().enumerate() {
                if k != removed || round <= middle {
                    s.x.send(&lane.outbound(lane.remote.ip4, LEN)).await?;
                }
                lane.remote.send(&lane.inbound()).await?;
            }
        }
        let mut counts = vec![BURST; LANES];
        if round >= middle {
            counts[removed] = 0;
        }
        if round == middle {
            // Removed with its lane's bursts in flight: whatever of them got through before
            // is still delivered, the other lanes are not affected.
            let identity = s.lanes[removed].identity;
            assert!(s.x.handle.remove_local_identity(identity).await?);
            collect_on_node(&mut s, counts, Some(removed)).await?;
            let lane = &s.lanes[removed];
            let (peer, packet) = (lane.on_node, lane.inbound());
            drain(&mut s.x, peer, &packet).await?;
        } else {
            collect_on_node(&mut s, counts, None).await?;
        }
        for (k, lane) in s.lanes.iter_mut().enumerate() {
            let packet = lane.outbound(lane.remote.ip4, LEN);
            if k != removed || round < middle {
                for _ in 0..BURST {
                    expect(&mut lane.remote, lane.on_remote, &packet).await?;
                }
            } else if round == middle {
                drain(&mut lane.remote, lane.on_remote, &packet).await?;
            }
        }
    }
    s.x.expect_no_delivery().await?;
    for lane in &mut s.lanes {
        lane.remote.expect_no_delivery().await?;
    }

    let lane = &s.lanes[removed];
    assert_eq!(s.x.handle.peer_stats(lane.on_node).await?, None);
    let status = s.x.handle.status().await?;
    let sources: Vec<_> = status
        .local_identities
        .iter()
        .map(|i| (i.id, i.sources.clone()))
        .collect();
    let expected: Vec<_> = s
        .lanes
        .iter()
        .enumerate()
        .filter(|&(k, _)| k != removed)
        .map(|(_, l)| (l.identity, vec![host(l.source)]))
        .collect();
    assert_eq!(sources, expected);
    // The removed identity's set is gone with it: its network may be taken again.
    let survivor = s.lanes[LANES - removed].identity;
    assert!(
        s.x.handle
            .set_local_sources(
                survivor,
                [host(s.lanes[LANES - removed].source), host(lane.source)]
            )
            .await?
    );
    Ok(())
}

#[tokio::test]
async fn removing_the_first_identity_under_traffic_leaves_the_others_untouched() -> TestResult {
    removal_under_traffic(0, 1).await
}

#[tokio::test]
async fn removing_the_second_identity_under_traffic_leaves_the_others_untouched() -> TestResult {
    removal_under_traffic(0, 2).await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn removing_the_first_identity_under_traffic_with_crypto_workers() -> TestResult {
    removal_under_traffic(4, 1).await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn removing_the_second_identity_under_traffic_with_crypto_workers() -> TestResult {
    removal_under_traffic(4, 2).await
}

#[tokio::test]
async fn the_status_reports_the_sets_and_conflicting_sets_are_refused() -> TestResult {
    let mut s = setup(0).await?;
    let sets: Vec<_> = s
        .lanes
        .iter()
        .map(|l| (l.identity, vec![host(l.source)]))
        .collect();
    let reported = |status: EngineStatus| -> Vec<(LocalIdentityId, Vec<AllowedIp>)> {
        status
            .local_identities
            .into_iter()
            .map(|i| (i.id, i.sources))
            .collect()
    };
    assert_eq!(reported(s.x.handle.status().await?), sets);

    // A network another identity's set holds is refused, also within a longer list, and
    // changes nothing.
    let i2 = s.lanes[2].identity;
    let taken = host(s.lanes[1].source);
    assert!(!s.x.handle.set_local_sources(i2, [taken]).await?);
    assert!(
        !s.x.handle
            .set_local_sources(i2, [host(s.lanes[2].source), taken])
            .await?
    );
    assert_eq!(reported(s.x.handle.status().await?), sets);
    // An unknown identity: one that was added and removed.
    let gone =
        s.x.handle
            .add_local_identity(StaticSecret::from([42; 32]))
            .await?
            .ok_or("identity refused")?;
    assert!(s.x.handle.remove_local_identity(gone).await?);
    let unused = host(Ipv4Addr::new(10, 1, 9, 1));
    assert!(!s.x.handle.set_local_sources(gone, [unused]).await?);
    assert_eq!(reported(s.x.handle.status().await?), sets);

    // A destination only the default identity's peer allows: reached from the default
    // identity's address, dropped from `i2`'s, whose peers have no route to it.
    let other = Ipv4Addr::new(10, 0, 0, 9);
    let mut allowed = s.lanes[0].remote.as_peer(T1).allowed_ips;
    allowed.push(host(other));
    s.x.handle
        .set_allowed_ips(s.lanes[0].remote.public(), allowed)
        .await?;
    ping(&mut s).await?;
    let packet = s.lanes[0].outbound(other, LEN);
    s.x.send(&packet).await?;
    let lane = &mut s.lanes[0];
    expect(&mut lane.remote, lane.on_remote, &packet).await?;
    let before = s.x.drops(NO_ROUTE).await?;
    s.x.send(&s.lanes[2].outbound(other, LEN)).await?;
    for lane in &mut s.lanes {
        lane.remote.expect_no_delivery().await?;
    }
    assert_eq!(s.x.drops(NO_ROUTE).await?, before + 1);
    Ok(())
}
