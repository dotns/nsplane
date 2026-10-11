//! Several local identities in one core: peers keyed by identity and remote key, handshake
//! initiations dispatched by mac1, removal, cookies over one shared budget, and identities
//! restricted to a set of transports.

#![allow(clippy::unwrap_used, clippy::panic, reason = "test harness")]

mod common;

use std::net::{Ipv4Addr, SocketAddr};
use std::time::Duration;

use common::{Fate, InFlight, Net, Sent, packet_buf, udp4};
use nsplane_core::x25519::{PublicKey, StaticSecret};
use nsplane_core::{
    AllowedIp, ConfigChange, Core, CoreConfig, Event, Input, LocalIdentityId, Path, PeerConfig,
    PeerId, TransportId, reasons,
};
use rand_core::OsRng;

/// Handshakes per second and source the local core tolerates in the load tests.
const LIMIT: u64 = 2;
/// A transport inside the restricted identity's set besides the remote core's.
const INSIDE: TransportId = TransportId::new(7);
/// A transport outside the restricted identity's set.
const FOREIGN: TransportId = TransportId::new(9);

/// Which identity of the local core a packet goes through.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Side {
    /// The default identity: tunnel addresses `10.0.0.1` (local) and `10.0.0.2` (remote).
    Default,
    /// The added identity: tunnel addresses `10.100.0.1` (local) and `10.100.0.2` (remote).
    Added,
}

impl Side {
    /// Tunnel address of core `i` (0 = local, 1 = remote) on this side.
    fn ip(self, i: usize) -> Ipv4Addr {
        let i = u8::try_from(i + 1).unwrap();
        match self {
            Self::Default => Ipv4Addr::new(10, 0, 0, i),
            Self::Added => Ipv4Addr::new(10, 100, 0, i),
        }
    }
}

/// How the transport set of the added identity is chosen.
#[derive(Debug, Clone, Copy)]
enum Restrict {
    /// Every transport.
    No,
    /// The remote core's transport and [`INSIDE`].
    Yes,
}

type Rewrite = Box<dyn FnMut(&mut InFlight) -> Fate>;

/// Core 0 (local) with the default identity and one added identity; core 1 (remote) with
/// one key and a peer for each local identity. Core 0 has the same remote key as a peer
/// under both identities.
struct Fixture {
    net: Net,
    /// Whether core 0 receives datagrams through crypto jobs.
    deferred: bool,
    /// The added identity of core 0.
    identity: LocalIdentityId,
    /// Its key.
    own: StaticSecret,
    /// Core 0's peer for core 1 under the default identity.
    a: PeerId,
    /// Core 0's peer for core 1 under the added identity.
    b: PeerId,
    /// Core 1's peer for core 0's default key.
    ra: PeerId,
    /// Core 1's peer for core 0's added key.
    rb: PeerId,
    rewrite: Option<Rewrite>,
}

fn allowed(ip: Ipv4Addr) -> AllowedIp {
    AllowedIp {
        addr: ip.into(),
        cidr: 32,
    }
}

impl Fixture {
    fn new(deferred: bool, restrict: Restrict, limit: u64) -> Self {
        let mut net = Net::unpeered(2, |_| CoreConfig {
            handshake_rate_limit: limit,
            crypto_jobs: deferred,
            ..CoreConfig::default()
        });
        let own = StaticSecret::random_from_rng(OsRng);
        let identity = match restrict {
            Restrict::No => net.cores[0].add_local_identity(own.clone()),
            Restrict::Yes => {
                net.cores[0].add_local_identity_on(own.clone(), [net.paths[1].transport, INSIDE])
            }
        }
        .unwrap();

        let remote = net.public_key(1);
        let mut config = PeerConfig::new(remote);
        config.allowed_ips = vec![allowed(Side::Default.ip(1))];
        config.path = Some(net.paths[1]);
        net.configure(0, ConfigChange::AddOrUpdatePeer(config.clone()));
        config.allowed_ips = vec![allowed(Side::Added.ip(1))];
        config.local_identity = Some(identity);
        net.configure(0, ConfigChange::AddOrUpdatePeer(config));

        let mut config = PeerConfig::new(net.public_key(0));
        config.allowed_ips = vec![allowed(Side::Default.ip(0))];
        config.path = Some(net.paths[0]);
        net.configure(1, ConfigChange::AddOrUpdatePeer(config.clone()));
        config.public_key = PublicKey::from(&own);
        config.allowed_ips = vec![allowed(Side::Added.ip(0))];
        net.configure(1, ConfigChange::AddOrUpdatePeer(config));

        let a = net.cores[0].peer_id(&remote).unwrap();
        let b = net.cores[0].peer_id_in(identity, &remote).unwrap();
        let ra = net.cores[1].peer_id(&net.public_key(0)).unwrap();
        let rb = net.cores[1].peer_id(&PublicKey::from(&own)).unwrap();
        let mut f = Self {
            net,
            deferred,
            identity,
            own,
            a,
            b,
            ra,
            rb,
            rewrite: None,
        };
        f.pump();
        f
    }

    /// Core `i`'s peer on `side`.
    const fn peer(&self, i: usize, side: Side) -> PeerId {
        match (i, side) {
            (0, Side::Default) => self.a,
            (0, Side::Added) => self.b,
            (_, Side::Default) => self.ra,
            (_, Side::Added) => self.rb,
        }
    }

    /// Feeds a datagram to core `to`; core 0 opens transport data through a crypto job
    /// when deferred.
    fn receive(&mut self, to: usize, arrival: Path, data: nsplane_core::PacketBuf) {
        let input = Input::Datagram {
            path: arrival,
            data,
        };
        if self.deferred && to == 0 {
            if let Some(mut job) = self.net.cores[0].handle_input_deferred(input, self.net.now) {
                job.run();
                self.net.cores[0].complete_job(job);
            }
        } else {
            self.net.cores[to].handle_input(input, self.net.now);
        }
    }

    /// Moves datagrams through [`Fixture::rewrite`] until none is left in flight.
    fn pump(&mut self) {
        loop {
            let in_flight = self.net.drain();
            if in_flight.is_empty() {
                return;
            }
            for mut datagram in in_flight {
                if let Some(rewrite) = self.rewrite.as_mut()
                    && rewrite(&mut datagram) == Fate::Drop
                {
                    continue;
                }
                match self
                    .net
                    .paths
                    .iter()
                    .position(|p| p.addr == datagram.path.addr)
                {
                    Some(to) => self.receive(to, datagram.arrival, datagram.data),
                    None => self.net.lost.push(datagram),
                }
            }
        }
    }

    /// Lets datagrams from core 1 arrive at core 0 on `arrival` instead of core 1's path.
    fn arrive_on(&mut self, arrival: Path) {
        self.rewrite = Some(Box::new(move |d| {
            if d.from == 1 {
                d.arrival = arrival;
            }
            Fate::Pass
        }));
    }

    /// Core 1's path with transport `transport`.
    fn remote_on(&self, transport: TransportId) -> Path {
        Path {
            transport,
            ..self.net.paths[1]
        }
    }

    /// Starts a handshake from core `i` on `side` and pumps.
    fn handshake(&mut self, i: usize, side: Side) {
        let peer = self.peer(i, side);
        self.net.cores[i].force_handshake(peer, None, self.net.now);
        self.pump();
    }

    /// Moves the clock by `d`, runs every core's timers and pumps.
    fn advance(&mut self, d: Duration) {
        self.net.now += d;
        for core in &mut self.net.cores {
            core.handle_timeout(self.net.now);
        }
        self.pump();
    }

    /// Sends a UDP packet from core `i` to the other core on `side` and pumps.
    fn ping(&mut self, i: usize, side: Side, payload: &[u8]) -> Vec<u8> {
        let packet = udp4(side.ip(i), side.ip(1 - i), payload);
        self.net.send_local(i, &packet);
        self.pump();
        packet
    }

    /// A handshake initiation from core `i` on `side` that never reached the network.
    fn captured_init(&mut self, i: usize, side: Side) -> Vec<u8> {
        let peer = self.peer(i, side);
        self.net.cores[i].force_handshake(peer, None, self.net.now);
        let mut in_flight = self.net.drain();
        assert_eq!(in_flight.len(), 1, "{in_flight:?}");
        in_flight.pop().unwrap().data.as_packet().to_vec()
    }

    /// Feeds `datagram` to core 0 on `arrival` `copies` times; returns what core 0 sent
    /// back, which reaches nobody.
    fn flood(&mut self, datagram: &[u8], arrival: Path, copies: usize) -> Vec<Sent> {
        for _ in 0..copies {
            self.receive(0, arrival, packet_buf(datagram));
        }
        drop(self.net.drain());
        self.net.take_transmits(0)
    }
}

fn is_cookie_reply(t: &Sent) -> bool {
    t.data.len() == 64 && t.data[0] == 3
}

fn handshakes_of(events: &[Event], peer: PeerId) -> usize {
    events
        .iter()
        .filter(|e| matches!(e, Event::HandshakeCompleted { peer: p, .. } if *p == peer))
        .count()
}

fn drops(events: &[Event], reason: &str) -> usize {
    events
        .iter()
        .filter(|e| matches!(e, Event::Dropped { reason: r, .. } if *r == reason))
        .count()
}

/// Runs the test function `$name(deferred: bool)` with and without crypto jobs.
macro_rules! both_paths {
    ($($name:ident),* $(,)?) => {$(
        mod $name {
            #[test]
            fn direct() {
                super::$name(false);
            }

            #[test]
            fn deferred() {
                super::$name(true);
            }
        }
    )*};
}

both_paths!(
    same_remote_key_under_two_identities,
    removal_under_traffic_drops_only_that_identitys_peers,
    restricted_peer_data_on_a_foreign_transport_is_unknown,
    restricted_peer_roams_inside_its_set,
);

/// The same remote key under two identities: both handshakes complete (one initiated by
/// each side) and every packet is delivered from the right peer.
fn same_remote_key_under_two_identities(deferred: bool) {
    let mut f = Fixture::new(deferred, Restrict::No, 100);
    assert_ne!(f.a, f.b);
    f.handshake(1, Side::Default);
    f.handshake(0, Side::Added);
    let events = f.net.take_events(0);
    assert_eq!(handshakes_of(&events, f.a), 1, "{events:?}");
    assert_eq!(handshakes_of(&events, f.b), 1, "{events:?}");

    for side in [Side::Default, Side::Added] {
        let packet = f.ping(1, side, b"to the local core");
        assert_eq!(f.net.take_delivered(0), [(f.peer(0, side), packet)]);
        let packet = f.ping(0, side, b"to the remote core");
        assert_eq!(f.net.take_delivered(1), [(f.peer(1, side), packet)]);
    }

    let core = &f.net.cores[0];
    assert_eq!(
        core.peer_stats(f.a).unwrap().local_identity,
        LocalIdentityId::DEFAULT
    );
    assert_eq!(core.peer_stats(f.b).unwrap().local_identity, f.identity);
    let identities: Vec<_> = core.local_identities().collect();
    assert_eq!(identities.len(), 2);
    assert_eq!(identities[0].id, LocalIdentityId::DEFAULT);
    assert_eq!(identities[0].public_key, Some(f.net.public_key(0)));
    assert_eq!(identities[1].id, f.identity);
    assert_eq!(identities[1].public_key, Some(PublicKey::from(&f.own)));
    assert!(
        identities
            .iter()
            .all(|i| i.peers == 1 && i.transports.is_none())
    );
}

/// Removing an identity under traffic removes its peers (keeping their unanswered
/// handshakes in the total), while the other identity keeps flowing.
fn removal_under_traffic_drops_only_that_identitys_peers(deferred: bool) {
    let mut f = Fixture::new(deferred, Restrict::No, 100);
    f.handshake(1, Side::Default);
    f.handshake(1, Side::Added);
    f.ping(1, Side::Added, b"before");
    assert_eq!(f.net.take_delivered(0).len(), 1);

    // Two initiations to the added identity's peer that never arrive: one is unanswered.
    f.rewrite = Some(Box::new(
        |d| if d.from == 0 { Fate::Drop } else { Fate::Pass },
    ));
    f.handshake(0, Side::Added);
    f.handshake(0, Side::Added);
    f.rewrite = None;
    assert_eq!(f.net.cores[0].unanswered_handshakes(f.b), Some(1));
    let total = f.net.cores[0].total_unanswered_handshakes();
    f.net.clear_logs();

    let remote = f.net.public_key(1);
    let core = &mut f.net.cores[0];
    assert!(!core.remove_local_identity(LocalIdentityId::DEFAULT));
    assert!(core.remove_local_identity(f.identity));
    assert!(!core.remove_local_identity(f.identity), "already removed");
    assert_eq!(core.peer_id_in(f.identity, &remote), None);
    assert!(core.peer_stats(f.b).is_none());
    assert_eq!(core.peers().collect::<Vec<_>>(), [f.a]);
    assert_eq!(core.total_unanswered_handshakes(), total);
    assert_eq!(
        core.local_identities().map(|i| i.id).collect::<Vec<_>>(),
        [LocalIdentityId::DEFAULT]
    );

    f.ping(1, Side::Added, b"after");
    assert_eq!(f.net.take_delivered(0), Vec::new());
    assert_eq!(
        f.net.take_events(0),
        [Event::Dropped {
            peer: None,
            reason: reasons::UNKNOWN_SESSION
        }]
    );
    let packet = f.ping(1, Side::Default, b"still flowing");
    assert_eq!(f.net.take_delivered(0), [(f.a, packet)]);
    let packet = f.ping(0, Side::Default, b"both ways");
    assert_eq!(f.net.take_delivered(1), [(f.ra, packet)]);

    // A config naming the removed identity adds nothing.
    let mut config = PeerConfig::new(remote);
    config.local_identity = Some(f.identity);
    f.net.configure(0, ConfigChange::AddOrUpdatePeer(config));
    f.pump();
    assert_eq!(
        f.net.take_events(0),
        [Event::Dropped {
            peer: None,
            reason: reasons::UNKNOWN_LOCAL_IDENTITY
        }]
    );
    assert_eq!(f.net.cores[0].peers().count(), 1);
}

/// Transport data from a restricted identity's peer on a transport outside its set is
/// dropped as an unknown session: not delivered, not authenticated, not adopted.
fn restricted_peer_data_on_a_foreign_transport_is_unknown(deferred: bool) {
    let mut f = Fixture::new(deferred, Restrict::Yes, 100);
    f.handshake(1, Side::Added);
    let packet = f.ping(1, Side::Added, b"on its transport");
    assert_eq!(f.net.take_delivered(0), [(f.b, packet)]);
    f.net.clear_logs();

    let foreign = Path {
        transport: FOREIGN,
        addr: SocketAddr::from((Ipv4Addr::new(198, 51, 100, 7), 4500)),
        ..f.net.paths[1]
    };
    f.arrive_on(foreign);
    f.ping(1, Side::Added, b"elsewhere");
    assert_eq!(f.net.take_delivered(0), Vec::new());
    assert_eq!(
        f.net.take_events(0),
        [Event::Dropped {
            peer: None,
            reason: reasons::UNKNOWN_SESSION
        }]
    );
    assert_eq!(
        f.net.cores[0].peer_stats(f.b).unwrap().path,
        Some(f.net.paths[1])
    );

    // The default identity is unrestricted.
    let foreign = f.remote_on(FOREIGN);
    f.arrive_on(foreign);
    f.handshake(1, Side::Default);
    f.net.clear_logs();
    let packet = f.ping(1, Side::Default, b"unrestricted");
    assert_eq!(f.net.take_delivered(0), [(f.a, packet)]);
}

/// A restricted identity's peer roams between the transports inside its set.
fn restricted_peer_roams_inside_its_set(deferred: bool) {
    let mut f = Fixture::new(deferred, Restrict::Yes, 100);
    f.handshake(1, Side::Added);
    f.net.clear_logs();

    let inside = f.remote_on(INSIDE);
    f.arrive_on(inside);
    let packet = f.ping(1, Side::Added, b"roamed");
    assert_eq!(f.net.take_delivered(0), [(f.b, packet)]);
    let events = f.net.take_events(0);
    assert!(
        events.contains(&Event::PathAdopted {
            peer: f.b,
            path: inside
        }),
        "{events:?}"
    );
    assert_eq!(f.net.cores[0].peer_stats(f.b).unwrap().path, Some(inside));

    // Traffic continues on the adopted path.
    let packet = f.ping(0, Side::Added, b"back on the new path");
    assert_eq!(f.net.take_delivered(1), [(f.rb, packet)]);
    assert_eq!(f.net.take_transmits(0).last().unwrap().path, inside);
    let packet = f.ping(1, Side::Added, b"and again");
    assert_eq!(f.net.take_delivered(0), [(f.b, packet)]);
}

/// An initiation whose mac1 matches no local key is dropped without an answer and counts
/// against no budget, even with the core under load.
#[test]
fn initiation_for_an_unknown_identity_is_dropped() {
    let mut f = Fixture::new(false, Restrict::No, LIMIT);
    let stranger = PublicKey::from(&StaticSecret::random_from_rng(OsRng));
    let mut config = PeerConfig::new(stranger);
    config.allowed_ips = vec![allowed(Ipv4Addr::new(10, 200, 0, 1))];
    config.path = Some(f.net.paths[0]);
    f.net.configure(1, ConfigChange::AddOrUpdatePeer(config));
    let peer = f.net.cores[1].peer_id(&stranger).unwrap();

    f.net.cores[1].force_handshake(peer, None, f.net.now);
    let init = f.net.drain().pop().unwrap().data.as_packet().to_vec();
    let arrival = f.net.paths[1];
    let replies = f.flood(&init, arrival, 10);
    assert_eq!(replies, Vec::new());
    let events = f.net.take_events(0);
    assert_eq!(events.len(), 10, "{events:?}");
    assert_eq!(drops(&events, reasons::UNKNOWN_LOCAL_IDENTITY), 10);

    // No budget was consumed: both identities answer without cookies.
    f.handshake(1, Side::Default);
    f.handshake(1, Side::Added);
    assert!(!f.net.take_transmits(0).iter().any(is_cookie_reply));
    let events = f.net.take_events(0);
    assert_eq!(handshakes_of(&events, f.a), 1, "{events:?}");
    assert_eq!(handshakes_of(&events, f.b), 1, "{events:?}");
}

/// Under load each identity answers with its own cookie, which gets the initiator's retry
/// through; the budget is shared, so a flood against one identity loads the other.
#[test]
fn cookies_per_identity_over_one_shared_budget() {
    let mut f = Fixture::new(false, Restrict::No, LIMIT);
    let init = f.captured_init(1, Side::Added);
    let arrival = f.net.paths[1];
    let replies = f.flood(&init, arrival, 10);
    assert!(replies.iter().any(is_cookie_reply), "{replies:?}");
    f.net.clear_logs();

    for side in [Side::Default, Side::Added] {
        // A fresh initiation gets a cookie reply, which the initiator accepts.
        f.advance(Duration::from_millis(1));
        f.net.clear_logs();
        f.handshake(1, side);
        let replies = f.net.take_transmits(0);
        assert!(
            replies.len() == 1 && is_cookie_reply(&replies[0]),
            "{side:?}: {replies:?}"
        );
        assert_eq!(f.net.take_events(1), Vec::new(), "{side:?}");

        // The retry carries the identity's cookie and completes.
        f.advance(Duration::from_millis(1));
        f.handshake(1, side);
        assert!(!f.net.take_transmits(0).iter().any(is_cookie_reply));
        assert_eq!(
            handshakes_of(&f.net.take_events(0), f.peer(0, side)),
            1,
            "{side:?}"
        );
        let packet = f.ping(1, side, b"under load");
        assert_eq!(f.net.take_delivered(0), [(f.peer(0, side), packet)]);
    }
}

/// A restricted identity says nothing on a transport outside its set, even under load
/// (no cookie reply), and answers on its own transports.
#[test]
fn restricted_identity_is_silent_on_a_foreign_transport() {
    let mut f = Fixture::new(false, Restrict::Yes, LIMIT);
    // Load the core from the remote's address through the default identity.
    let init = f.captured_init(1, Side::Default);
    let arrival = f.net.paths[1];
    assert!(f.flood(&init, arrival, 10).iter().any(is_cookie_reply));
    f.net.clear_logs();

    let init = f.captured_init(1, Side::Added);
    let foreign = f.remote_on(FOREIGN);
    assert_eq!(f.flood(&init, foreign, 10), Vec::new());
    let events = f.net.take_events(0);
    assert_eq!(
        drops(&events, reasons::UNKNOWN_LOCAL_IDENTITY),
        10,
        "{events:?}"
    );
    assert_eq!(events.len(), 10);

    // On its own transport it answers, here with a cookie reply.
    let replies = f.flood(&init, arrival, 1);
    assert!(
        replies.len() == 1 && is_cookie_reply(&replies[0]),
        "{replies:?}"
    );

    // Without load it completes handshakes on its transports, but not elsewhere.
    f.advance(Duration::from_secs(1));
    f.net.clear_logs();
    f.arrive_on(foreign);
    f.handshake(1, Side::Added);
    assert_eq!(f.net.take_transmits(0), Vec::new());
    assert_eq!(
        drops(&f.net.take_events(0), reasons::UNKNOWN_LOCAL_IDENTITY),
        1
    );
    let inside = f.remote_on(INSIDE);
    f.arrive_on(inside);
    f.handshake(1, Side::Added);
    assert_eq!(handshakes_of(&f.net.take_events(0), f.b), 1);
}

/// A handshake response or cookie reply for a restricted identity's peer on a transport
/// outside its set is dropped as for an unknown peer, before the gate could ask for a cookie.
#[test]
fn replayed_response_and_cookie_reply_on_a_foreign_transport_are_dropped() {
    let mut f = Fixture::new(false, Restrict::Yes, LIMIT);
    let own_transport = f.net.paths[1];
    let foreign = f.remote_on(FOREIGN);

    // A response from the remote core to core 0's initiation, kept off the network.
    let init = f.captured_init(0, Side::Added);
    f.receive(1, f.net.paths[0], packet_buf(&init));
    let mut in_flight = f.net.drain();
    let response = in_flight.pop().unwrap().data.as_packet().to_vec();
    assert_eq!(response[0], 2);

    // A cookie reply of the remote core under load to core 0's next initiation.
    let init = f.captured_init(0, Side::Added);
    for _ in 0..10 {
        f.receive(1, f.net.paths[0], packet_buf(&init));
    }
    let cookie = f
        .net
        .drain()
        .into_iter()
        .map(|d| d.data.as_packet().to_vec())
        .find(|d| d.len() == 64 && d[0] == 3)
        .unwrap();

    // Load core 0 from the remote's address.
    let flood = f.captured_init(1, Side::Default);
    assert!(
        f.flood(&flood, own_transport, 10)
            .iter()
            .any(is_cookie_reply)
    );
    f.net.clear_logs();

    for datagram in [&response, &cookie] {
        f.receive(0, foreign, packet_buf(datagram));
        drop(f.net.drain());
        assert_eq!(f.net.take_transmits(0), Vec::new());
        assert_eq!(
            f.net.take_events(0),
            [Event::Dropped {
                peer: None,
                reason: reasons::UNKNOWN_PEER
            }]
        );
    }

    // On its own transport the response meets the loaded gate, and the cookie reply is
    // accepted.
    f.receive(0, own_transport, packet_buf(&response));
    drop(f.net.drain());
    let replies = f.net.take_transmits(0);
    assert!(
        replies.len() == 1 && is_cookie_reply(&replies[0]),
        "{replies:?}"
    );
    f.net.clear_logs();
    f.receive(0, own_transport, packet_buf(&cookie));
    drop(f.net.drain());
    assert_eq!(f.net.take_events(0), Vec::new());
}

/// A single identity with a key that is restricted is dispatched like several: it answers
/// on its transports only.
#[test]
fn a_sole_restricted_identity_answers_on_its_transports_only() {
    let mut f = Fixture::new(false, Restrict::Yes, 100);
    // Core 0 again, without a default key: the added identity is its only key.
    let mut core = Core::new(CoreConfig::default());
    let identity = core
        .add_local_identity_on(f.own.clone(), [f.net.paths[1].transport])
        .unwrap();
    let mut config = PeerConfig::new(f.net.public_key(1));
    config.allowed_ips = vec![allowed(Side::Added.ip(1))];
    config.path = Some(f.net.paths[1]);
    config.local_identity = Some(identity);
    core.handle_input(
        Input::Config(ConfigChange::AddOrUpdatePeer(config)),
        f.net.now,
    );
    f.b = core.peer_id_in(identity, &f.net.public_key(1)).unwrap();
    f.net.cores[0] = core;

    let foreign = f.remote_on(FOREIGN);
    f.arrive_on(foreign);
    f.handshake(1, Side::Added);
    assert_eq!(f.net.take_transmits(0), Vec::new());
    assert_eq!(
        f.net.take_events(0),
        [Event::Dropped {
            peer: None,
            reason: reasons::UNKNOWN_LOCAL_IDENTITY
        }]
    );

    f.rewrite = None;
    f.handshake(1, Side::Added);
    assert_eq!(handshakes_of(&f.net.take_events(0), f.b), 1);
    let packet = f.ping(1, Side::Added, b"sole identity");
    assert_eq!(f.net.take_delivered(0), [(f.b, packet)]);
}

/// `ConfigChange::InLocalIdentity` addresses the identity's peer; the plain change the
/// default identity's.
#[test]
fn in_local_identity_changes_and_removes_the_right_peer() {
    let mut f = Fixture::new(false, Restrict::No, 100);
    let remote = f.net.public_key(1);
    let identity = f.identity;
    let in_identity = move |change| ConfigChange::InLocalIdentity {
        identity,
        change: Box::new(change),
    };

    f.net.configure(
        0,
        in_identity(ConfigChange::SetKeepalive {
            peer: remote,
            interval: Some(25),
        }),
    );
    f.net.configure(
        0,
        in_identity(ConfigChange::SetAllowedIps {
            peer: remote,
            allowed_ips: vec![allowed(Ipv4Addr::new(10, 100, 0, 9))],
        }),
    );
    f.net.configure(
        0,
        in_identity(ConfigChange::SetPresharedKey {
            peer: remote,
            key: Some([7; 32]),
        }),
    );
    let b = f.net.cores[0].peer_stats(f.b).unwrap();
    assert_eq!(b.persistent_keepalive, Some(25));
    assert_eq!(b.allowed_ips, [allowed(Ipv4Addr::new(10, 100, 0, 9))]);
    assert_eq!(b.preshared_key, Some([7; 32]));
    let a = f.net.cores[0].peer_stats(f.a).unwrap();
    assert_eq!(a.persistent_keepalive, None);
    assert_eq!(a.allowed_ips, [allowed(Side::Default.ip(1))]);
    assert_eq!(a.preshared_key, None);

    // The plain change addresses the default identity's peer.
    f.net.configure(
        0,
        ConfigChange::SetKeepalive {
            peer: remote,
            interval: Some(5),
        },
    );
    assert_eq!(
        f.net.cores[0].peer_stats(f.a).unwrap().persistent_keepalive,
        Some(5)
    );
    assert_eq!(
        f.net.cores[0].peer_stats(f.b).unwrap().persistent_keepalive,
        Some(25)
    );

    // Changes other than peer-keyed ones are ignored, as are unknown peers.
    let stranger = PublicKey::from(&StaticSecret::random_from_rng(OsRng));
    f.net.configure(
        0,
        in_identity(ConfigChange::AddOrUpdatePeer(PeerConfig::new(stranger))),
    );
    f.net
        .configure(0, in_identity(ConfigChange::RemoveAllPeers));
    f.net.configure(
        0,
        in_identity(ConfigChange::SetPrivateKey(StaticSecret::random_from_rng(
            OsRng,
        ))),
    );
    f.net.configure(
        0,
        in_identity(ConfigChange::SetKeepalive {
            peer: stranger,
            interval: Some(1),
        }),
    );
    assert_eq!(f.net.cores[0].peers().collect::<Vec<_>>(), [f.a, f.b]);
    assert_eq!(f.net.cores[0].public_key(), Some(f.net.public_key(0)));
    assert_eq!(f.net.take_events(0), Vec::new());

    f.net
        .configure(0, in_identity(ConfigChange::RemovePeer(remote)));
    assert_eq!(f.net.cores[0].peers().collect::<Vec<_>>(), [f.a]);
    assert_eq!(f.net.cores[0].peer_id_in(f.identity, &remote), None);
    assert_eq!(f.net.cores[0].peer_id(&remote), Some(f.a));
}

/// A key held by any identity cannot be added again; `RemoveAllPeers` keeps the identities.
#[test]
fn identity_keys_are_unique_and_remove_all_peers_keeps_identities() {
    let mut f = Fixture::new(false, Restrict::No, 100);
    let core = &mut f.net.cores[0];
    assert_eq!(core.add_local_identity(f.own.clone()), None);
    assert_eq!(core.add_local_identity(f.net.keys[0].clone()), None);
    assert_eq!(
        core.add_local_identity_on(f.net.keys[0].clone(), [FOREIGN]),
        None
    );

    let restricted = core
        .add_local_identity_on(StaticSecret::random_from_rng(OsRng), [INSIDE, FOREIGN])
        .unwrap();
    assert!(restricted > f.identity);
    let info = core.local_identities().last().unwrap();
    assert_eq!(info.id, restricted);
    assert_eq!(info.transports, Some(vec![INSIDE, FOREIGN]));
    assert_eq!(info.peers, 0);

    core.handle_input(Input::Config(ConfigChange::RemoveAllPeers), f.net.now);
    assert_eq!(core.peers().count(), 0);
    assert_eq!(core.local_identities().count(), 3);
    assert!(core.local_identities().all(|i| i.peers == 0));
}
