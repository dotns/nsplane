//! Shared setup of the ACL tests: packet nodes where `b` filters with an `AclFilter`.

use std::fmt::Write as _;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;

use nsplane::x25519::PublicKey;
use nsplane::{ChannelTransport, Event, TransportId};
use nsplane_acl::{AclEngine, AclFilter, Label, LabelSet, NamespaceMember, PeerLabelMap};
use nsplane_packet::PeerId;

use crate::{Events, Node, Options, TestResult, introduce, udp};

/// Capacity of every channel link.
pub const CAPACITY: usize = 1024;
/// The port the peers' packets come from.
pub const SRC_PORT: u16 = 40000;
/// The port the "quick" namespace allows on `b`.
pub const QUICK_PORT: u16 = 7000;
/// The port of the app sessions' pinholes.
pub const APP_PORT: u16 = 9000;
/// The app kind of every pinhole.
pub const TRANSFER_KIND: &str = "transfer";

/// A node of the ACL packet tests.
pub type AclNode = Node<ChannelTransport>;

/// The ACL state of `b` the tests keep.
#[derive(Debug)]
pub struct Acl {
    /// The policy engine.
    pub engine: Arc<AclEngine>,
    /// The labels of `b`'s peers.
    pub identities: Arc<PeerLabelMap>,
    /// The filter `b` runs.
    pub filter: AclFilter,
}

impl Acl {
    /// The ACL state around `engine`, with no peer labelled yet.
    pub fn new(engine: AclEngine) -> Self {
        let engine = Arc::new(engine);
        let identities = Arc::new(PeerLabelMap::new());
        let filter = AclFilter::new(Arc::clone(&engine), Arc::clone(&identities));
        Self {
            engine,
            identities,
            filter,
        }
    }

    /// Labels the peer `peer` of `b` by its WireGuard key.
    pub fn identify(&self, peer: PeerId, key: &PublicKey) {
        self.identities.insert(peer, LabelSet::new([label(key)]));
    }
}

/// The endpoint `host` of a channel link: transport id and address.
pub fn end(id: u16, host: u8) -> (TransportId, SocketAddr) {
    (
        TransportId::new(id),
        SocketAddr::from(([192, 0, 2, host], 1000 + id)),
    )
}

/// The label of a node's key: `key:` and the lowercase hex of the key.
pub fn label(key: &PublicKey) -> Label {
    Label::from(
        key.to_bytes()
            .iter()
            .fold(String::from("key:"), |mut text, b| {
                let _ = write!(text, "{b:02x}");
                text
            }),
    )
}

/// A namespace member with both tunnel addresses of a node.
pub fn member(key: &PublicKey, ip4: Ipv4Addr, ip6: Ipv6Addr) -> TestResult<NamespaceMember> {
    Ok(NamespaceMember {
        label: label(key),
        addresses: vec![format!("{ip4}/32").parse()?, format!("{ip6}/128").parse()?],
    })
}

/// Packet nodes `a` (seed 1) and `b` (seed 2) linked and introduced, `b` filtering with
/// `acl`; `a` is identified by its key.
pub async fn packet_pair(acl: &Acl) -> TestResult<(AclNode, AclNode)> {
    let (a_end, b_end) = (end(1, 1), end(2, 2));
    let (link_a, link_b) = ChannelTransport::pair(CAPACITY, a_end, b_end);
    let a = Node::with_builder(1, a_end.0, a_end.1, Options::default(), |builder| {
        builder.transport(link_a)
    })?;
    let filter = acl.filter.clone();
    let b = Node::with_builder(2, b_end.0, b_end.1, Options::default(), |builder| {
        builder.transport(link_b).filter(Box::new(filter))
    })?;
    introduce(&a, &b, None).await?;
    acl.identify(b.peer_of(&a).await?, &a.public());
    Ok((a, b))
}

/// A UDP packet from `from`'s IPv4 address and `src_port` to `to` port `dst_port`.
pub fn udp_to(from: &AclNode, src_port: u16, to: Ipv4Addr, dst_port: u16) -> Vec<u8> {
    udp(
        SocketAddr::from((from.ip4, src_port)),
        SocketAddr::from((to, dst_port)),
        b"datagram",
    )
}

/// Sends `packet` from `from` and checks that `to` delivers it unchanged.
pub async fn delivered(from: &AclNode, to: &mut AclNode, packet: &[u8]) -> TestResult {
    from.send(packet).await?;
    let (_, got) = to.expect_delivery().await?;
    if got != packet {
        return Err("packet changed in transit".into());
    }
    Ok(())
}

/// Sends `packet` from `from` and checks that `b` drops it with `reason`.
pub async fn dropped(
    from: &AclNode,
    b: &mut AclNode,
    events: &mut Events,
    packet: &[u8],
    reason: &'static str,
) -> TestResult {
    from.send(packet).await?;
    events
        .expect(|e| matches!(e, Event::Dropped { reason: r, .. } if *r == reason))
        .await?;
    b.expect_no_delivery().await
}

/// Sends `packet` from `from` to the hub `b`, which forwards what it delivers back into the
/// tunnel (as its kernel would route it), and checks that `to` delivers it unchanged.
pub async fn relayed(
    from: &AclNode,
    b: &mut AclNode,
    to: &mut AclNode,
    packet: &[u8],
) -> TestResult {
    delivered(from, b, packet).await?;
    b.send(packet).await?;
    let (_, got) = to.expect_delivery().await?;
    if got != packet {
        return Err("packet changed in the hub".into());
    }
    Ok(())
}
