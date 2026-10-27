use std::net::IpAddr;

use nsplane_noise::x25519;
use nsplane_packet::{Ecn, TAILROOM};

use super::*;
use crate::peer_table::Destinations;
use crate::policy::Roam;
use crate::reasons;
use crate::types::{AllowedIp, ConfigChange, LocalIdentityId, PeerConfig};

#[test]
fn cookie_replies_do_not_roam() {
    let mut reply = [0u8; 64];
    reply[0] = 3;
    let kind = message_kind(&reply);
    assert_eq!(kind, MessageKind::CookieReply);
    assert!(!roams(kind));

    let mut data = [0u8; 32];
    data[0] = 4;
    let kind = message_kind(&data);
    assert_eq!(kind, MessageKind::Keepalive);
    assert!(roams(kind));
}

#[test]
fn layout_for_sealing_fits_a_buffer_with_tailroom() {
    let mut core = Core::new(CoreConfig::default());
    for len in [40, 1500] {
        // As a TUN source hands a read over: headroom in front, room for a full-size
        // packet and the tail room behind it.
        let mut packet = PacketBuf::with_capacity(1500 + TAILROOM);
        packet.set_len(len);
        let capacity = packet.capacity();
        let ptr = packet.as_packet().as_ptr();
        let (packet, got) = core.layout_for_sealing(packet);
        assert_eq!(got, len);
        // The data header went into the headroom, nothing was reallocated.
        assert_eq!(packet.capacity(), capacity + DATA_HEADER_SZ);
        assert_eq!(
            packet.as_packet().as_ptr(),
            ptr.wrapping_sub(DATA_HEADER_SZ)
        );
        assert_eq!(
            packet.len(),
            (DATA_HEADER_SZ + len + TAILROOM).max(HANDSHAKE_INIT_SZ)
        );
    }
}

#[test]
fn peers_need_a_private_key() {
    let mut core = Core::new(CoreConfig::default());
    assert_eq!(core.poll_timeout(), None);
    let key = x25519::PublicKey::from([7; 32]);

    let now = Instant::now();
    core.handle_input(
        Input::Config(ConfigChange::AddOrUpdatePeer(PeerConfig::new(key))),
        now,
    );
    assert_eq!(core.poll_timeout(), Some(now + TICK));
    assert!(matches!(
        core.poll_output(),
        Some(Output::Event(Event::Dropped {
            peer: None,
            reason: reasons::NO_PRIVATE_KEY
        }))
    ));
    assert!(core.poll_output().is_none());
    assert_eq!(core.peers().count(), 0);
}

#[test]
fn changes_to_unknown_peers_are_ignored() {
    let mut core = Core::new(CoreConfig {
        private_key: Some(x25519::StaticSecret::from([1; 32])),
        ..CoreConfig::default()
    });
    let key = x25519::PublicKey::from([7; 32]);
    core.handle_input(
        Input::Config(ConfigChange::SetKeepalive {
            peer: key,
            interval: Some(25),
        }),
        Instant::now(),
    );
    assert!(core.poll_output().is_none());
    assert_eq!(core.peer_id(&key), None);

    core.handle_input(
        Input::Config(ConfigChange::AddOrUpdatePeer(PeerConfig::new(key))),
        Instant::now(),
    );
    let id = core.peer_id(&key).unwrap();
    assert_eq!(core.peers().collect::<Vec<_>>(), [id]);
    assert_eq!(core.peer_stats(id).unwrap().public_key, key);
}

#[test]
fn inbound_destinations_of_unknown_peers_are_ignored() {
    let mut core = Core::new(CoreConfig {
        private_key: Some(x25519::StaticSecret::from([1; 32])),
        ..CoreConfig::default()
    });
    let key = x25519::PublicKey::from([7; 32]);
    let change = ConfigChange::SetInboundDestinations {
        peer: key,
        destinations: Some(vec!["10.1.0.0/16".parse().unwrap()]),
    };
    assert!(format!("{change:?}").contains("10.1.0.0"));
    core.handle_input(Input::Config(change), Instant::now());
    assert!(core.poll_output().is_none());
    assert_eq!(core.peer_id(&key), None);

    let mut config = PeerConfig::new(key);
    assert!(format!("{config:?}").contains("inbound_destinations: None"));
    config.inbound_destinations = Some(Vec::new());
    core.handle_input(
        Input::Config(ConfigChange::AddOrUpdatePeer(config)),
        Instant::now(),
    );
    let id = core.peer_id(&key).unwrap();
    let slot = core.peers.slot(id).unwrap();
    assert!(core.peers.inbound_destinations(slot).is_some());
    core.handle_input(
        Input::Config(ConfigChange::SetInboundDestinations {
            peer: key,
            destinations: None,
        }),
        Instant::now(),
    );
    assert!(core.peers.inbound_destinations(slot).is_none());
}

#[test]
fn inbound_destination_sources_of_unknown_peers_are_ignored() {
    let mut core = Core::new(CoreConfig {
        private_key: Some(x25519::StaticSecret::from([1; 32])),
        ..CoreConfig::default()
    });
    let key = x25519::PublicKey::from([7; 32]);
    let source: std::sync::Arc<dyn crate::InboundDestinations> =
        std::sync::Arc::new(|_: IpAddr| false);
    let change = ConfigChange::SetInboundDestinationSource {
        peer: key,
        source: Some(std::sync::Arc::clone(&source)),
    };
    assert!(format!("{change:?}").contains("<source>"));
    core.handle_input(Input::Config(change), Instant::now());
    assert!(core.poll_output().is_none());
    assert_eq!(core.peer_id(&key), None);

    core.handle_input(
        Input::Config(ConfigChange::AddOrUpdatePeer(PeerConfig::new(key))),
        Instant::now(),
    );
    let slot = core.peers.slot(core.peer_id(&key).unwrap()).unwrap();
    core.handle_input(
        Input::Config(ConfigChange::SetInboundDestinationSource {
            peer: key,
            source: Some(source),
        }),
        Instant::now(),
    );
    assert!(matches!(
        core.peers.inbound_destinations(slot),
        Some(Destinations::Shared(_))
    ));
    core.handle_input(
        Input::Config(ConfigChange::SetInboundDestinationSource {
            peer: key,
            source: None,
        }),
        Instant::now(),
    );
    assert!(core.peers.inbound_destinations(slot).is_none());
}

#[test]
fn routes_by_the_longest_allowed_ip_match() {
    let mut core = Core::new(CoreConfig {
        private_key: Some(x25519::StaticSecret::from([1; 32])),
        ..CoreConfig::default()
    });
    let mut add = |key: [u8; 32], allowed: &[&str]| {
        let key = x25519::PublicKey::from(key);
        let mut config = PeerConfig::new(key);
        config.allowed_ips = allowed.iter().map(|a| a.parse().unwrap()).collect();
        core.handle_input(
            Input::Config(ConfigChange::AddOrUpdatePeer(config)),
            Instant::now(),
        );
        key
    };
    let wide = add([7; 32], &["10.0.0.0/8", "fd00::/8"]);
    let narrow = add([8; 32], &["10.1.0.0/16"]);
    let wide = core.peer_id(&wide).unwrap();
    let narrow = core.peer_id(&narrow).unwrap();

    assert_eq!(core.route("10.2.0.1".parse().unwrap()), Some(wide));
    assert_eq!(core.route("10.1.0.1".parse().unwrap()), Some(narrow));
    assert_eq!(core.route("fd00::1".parse().unwrap()), Some(wide));
    assert_eq!(core.route("192.0.2.1".parse().unwrap()), None);
}

#[test]
fn the_route_cache_answers_like_the_peer_table() {
    // splitmix64
    let mut state = 0x6e73_706c_616e_6533_u64;
    let mut next = move || {
        state = state.wrapping_add(0x9e37_79b9_7f4a_7c15);
        let mut z = state;
        z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        z ^ (z >> 31)
    };
    let nets: Vec<AllowedIp> = [
        "0.0.0.0/0",
        "10.0.0.0/8",
        "10.1.0.0/16",
        "10.1.2.0/24",
        "10.1.2.3/32",
        "10.1.2.4/32",
        "192.0.2.0/24",
        "::/0",
        "fd00::/8",
        "fd00::1/128",
        "fd00::2/128",
    ]
    .iter()
    .map(|n| n.parse().unwrap())
    .collect();
    let addrs: Vec<IpAddr> = [
        "10.1.2.3",
        "10.1.2.4",
        "10.1.2.5",
        "10.1.3.1",
        "10.2.0.1",
        "192.0.2.9",
        "198.51.100.1",
        "fd00::1",
        "fd00::2",
        "fd00::3",
        "2001:db8::1",
    ]
    .iter()
    .map(|a| a.parse().unwrap())
    .collect();
    let now = Instant::now();
    let mut core = Core::new(CoreConfig {
        private_key: Some(x25519::StaticSecret::from([1; 32])),
        ..CoreConfig::default()
    });
    let mut identities = vec![LocalIdentityId::DEFAULT];
    let keys: Vec<x25519::PublicKey> = (2..8u8)
        .map(|k| x25519::PublicKey::from(&x25519::StaticSecret::from([k; 32])))
        .collect();
    let mut pick = |n: usize| usize::try_from(next()).unwrap() % n;
    for step in 0..3000u32 {
        let identity = identities[pick(identities.len())];
        let key = keys[pick(keys.len())];
        let change = match pick(10) {
            0..=4 => {
                let mut config = PeerConfig::new(key);
                config.local_identity = Some(identity);
                config.replace_allowed_ips = pick(2) == 0;
                config.allowed_ips = (0..pick(3)).map(|_| nets[pick(nets.len())]).collect();
                Some(ConfigChange::AddOrUpdatePeer(config))
            }
            5 => Some(ConfigChange::InLocalIdentity {
                identity,
                change: Box::new(ConfigChange::RemovePeer(key)),
            }),
            6 if pick(8) == 0 => Some(ConfigChange::RemoveAllPeers),
            7 => {
                let sources: Vec<AllowedIp> =
                    (0..pick(3)).map(|_| nets[pick(nets.len())]).collect();
                core.set_local_sources(identity, &sources);
                None
            }
            8 if identities.len() < 4 => {
                let secret =
                    x25519::StaticSecret::from([u8::try_from(100 + step % 100).unwrap(); 32]);
                identities.extend(core.add_local_identity(secret));
                None
            }
            9 if identity != LocalIdentityId::DEFAULT => {
                if core.remove_local_identity(identity) {
                    identities.retain(|&i| i != identity);
                }
                None
            }
            _ => None,
        };
        if let Some(change) = change {
            core.handle_input(Input::Config(change), now);
        }
        // Twice: the second round answers from the cache.
        for _ in 0..2 {
            for &dst in &addrs {
                for &src in &addrs {
                    assert_routes_like_the_peer_table(&mut core, src, dst);
                }
            }
        }
    }
}

/// Asserts that the route cache of `core` answers the route of `dst`, the route from
/// `src` to `dst` and whether each peer may send from `src` like the peer table.
fn assert_routes_like_the_peer_table(core: &mut Core, src: IpAddr, dst: IpAddr) {
    let slot = |id: PeerId| Some((id, core.peers.slot(id)?));
    let route = core.peers.by_destination(dst).and_then(slot);
    let route_from = core.peers.route_from(src, dst).and_then(slot);
    assert_eq!(core.routes.route(&core.peers, dst), route, "{dst}");
    let selected = if core.peers.has_sources() {
        core.routes.route_from(&core.peers, Some(src), dst)
    } else {
        core.routes.route(&core.peers, dst)
    };
    assert_eq!(selected, route_from, "{src} -> {dst}");
    let peers: Vec<PeerId> = core.peers().collect();
    for id in peers {
        assert_eq!(
            core.routes.source_allowed(&core.peers, src, id),
            core.peers.routes_to(src, id),
            "{src} from {id:?}"
        );
    }
}

/// Fills the route cache with the routes between `addrs`, runs `change` and asserts that
/// the next answers are the peer table's and that the generation moved.
fn assert_change_drops_the_route_cache(
    core: &mut Core,
    addrs: &[&str],
    change: impl FnOnce(&mut Core),
) {
    let addrs: Vec<IpAddr> = addrs.iter().map(|a| a.parse().unwrap()).collect();
    let check = |core: &mut Core| {
        for &src in &addrs {
            for &dst in &addrs {
                assert_routes_like_the_peer_table(core, src, dst);
            }
        }
    };
    check(core);
    let generation = core.peers.generation();
    change(core);
    check(core);
    assert_ne!(core.peers.generation(), generation);
}

/// Adds (or updates) the peer `[key; 32]` of `identity` with `allowed` IPs.
fn add_peer_in(core: &mut Core, identity: LocalIdentityId, key: u8, allowed: &[&str]) {
    let mut config = PeerConfig::new(x25519::PublicKey::from([key; 32]));
    config.local_identity = Some(identity);
    config.allowed_ips = allowed.iter().map(|a| a.parse().unwrap()).collect();
    core.handle_input(
        Input::Config(ConfigChange::AddOrUpdatePeer(config)),
        Instant::now(),
    );
}

/// A core with the peer `[7; 32]` routing 10.0.0.0/8.
fn core_routing_ten() -> Core {
    let mut core = Core::new(CoreConfig {
        private_key: Some(x25519::StaticSecret::from([1; 32])),
        ..CoreConfig::default()
    });
    add_peer_in(&mut core, LocalIdentityId::DEFAULT, 7, &["10.0.0.0/8"]);
    core
}

#[test]
fn adding_a_peer_drops_the_cached_routes() {
    let mut core = core_routing_ten();
    assert_change_drops_the_route_cache(&mut core, &["10.1.2.3"], |core| {
        add_peer_in(core, LocalIdentityId::DEFAULT, 8, &["10.1.0.0/16"]);
    });
    let narrow = core.peer_id(&x25519::PublicKey::from([8; 32]));
    assert_eq!(
        core.routes
            .route(&core.peers, "10.1.2.3".parse().unwrap())
            .map(|r| r.0),
        narrow
    );
}

#[test]
fn removing_a_peer_drops_the_cached_routes() {
    let mut core = core_routing_ten();
    add_peer_in(&mut core, LocalIdentityId::DEFAULT, 8, &["10.1.0.0/16"]);
    assert_change_drops_the_route_cache(&mut core, &["10.1.2.3"], |core| {
        core.handle_input(
            Input::Config(ConfigChange::RemovePeer(x25519::PublicKey::from([8; 32]))),
            Instant::now(),
        );
    });
}

#[test]
fn removing_all_peers_drops_the_cached_routes() {
    let mut core = core_routing_ten();
    assert_change_drops_the_route_cache(&mut core, &["10.1.2.3"], |core| {
        core.handle_input(Input::Config(ConfigChange::RemoveAllPeers), Instant::now());
    });
    assert_eq!(
        core.routes.route(&core.peers, "10.1.2.3".parse().unwrap()),
        None
    );
}

#[test]
fn setting_source_sets_drops_the_cached_routes() {
    let mut core = Core::new(CoreConfig {
        private_key: Some(x25519::StaticSecret::from([1; 32])),
        ..CoreConfig::default()
    });
    let other = core
        .add_local_identity(x25519::StaticSecret::from([2; 32]))
        .unwrap();
    // The other identity routes 10.0.0.0/8 to its peer, the fallback to the default's.
    add_peer_in(&mut core, other, 8, &["10.0.0.0/8"]);
    add_peer_in(&mut core, LocalIdentityId::DEFAULT, 7, &["10.0.0.0/8"]);
    assert!(core.set_local_sources(other, &["192.0.2.0/24".parse().unwrap()]));
    assert_change_drops_the_route_cache(&mut core, &["192.0.2.1", "10.1.2.3"], |core| {
        assert!(core.set_local_sources(other, &["198.51.100.0/24".parse().unwrap()]));
    });
}

#[test]
fn adding_and_removing_an_identity_moves_the_generation() {
    let mut core = core_routing_ten();
    let mut added = None;
    assert_change_drops_the_route_cache(&mut core, &["10.1.2.3"], |core| {
        added = core.add_local_identity(x25519::StaticSecret::from([2; 32]));
    });
    let added = added.unwrap();
    assert!(core.set_local_sources(added, &["192.0.2.0/24".parse().unwrap()]));
    assert_change_drops_the_route_cache(&mut core, &["192.0.2.1", "10.1.2.3"], |core| {
        assert!(core.remove_local_identity(added));
    });
}

/// A core with private key `own` and peer `peer` at `path`.
fn core_with_peer(own: u8, peer: u8, path: Path, now: Instant) -> (Core, PeerId) {
    let mut core = Core::new(CoreConfig {
        private_key: Some(x25519::StaticSecret::from([own; 32])),
        ..CoreConfig::default()
    });
    let key = x25519::PublicKey::from(&x25519::StaticSecret::from([peer; 32]));
    let mut config = PeerConfig::new(key);
    config.path = Some(path);
    core.handle_input(Input::Config(ConfigChange::AddOrUpdatePeer(config)), now);
    let id = core.peer_id(&key).unwrap();
    (core, id)
}

fn path(port: u16) -> Path {
    Path {
        transport: nsplane_packet::TransportId::new(0),
        addr: std::net::SocketAddr::from(([192, 0, 2, 1], port)),
        ecn: Ecn::NotEct,
    }
}

/// The datagrams `core` queued, its other outputs discarded.
fn transmits(core: &mut Core) -> Vec<PacketBuf> {
    let mut sent = Vec::new();
    while let Some(output) = core.poll_output() {
        if let Output::Transmit { data, .. } = output {
            sent.push(data);
        }
    }
    sent
}

/// More than `REKEY_TIMEOUT` plus the largest retry jitter.
const RETRY: Duration = Duration::from_millis(5_400);

#[test]
fn unanswered_initiations_count_once_per_retry() {
    let now = Instant::now();
    let (mut core, id) = core_with_peer(1, 2, path(2), now);
    assert_eq!(core.unanswered_handshakes(id), Some(0));

    core.force_handshake(id, None, now);
    assert_eq!(transmits(&mut core).len(), 1);
    assert_eq!(core.unanswered_handshakes(id), Some(0));

    for retry in 1..=3 {
        core.handle_timeout(now + RETRY * retry);
        assert_eq!(transmits(&mut core).len(), 1);
        assert_eq!(core.unanswered_handshakes(id), Some(u64::from(retry)));
    }
    assert_eq!(core.total_unanswered_handshakes(), 3);

    // The handshake attempt gives up: the last initiation is unanswered too, once.
    core.handle_timeout(now + Duration::from_secs(95));
    assert_eq!(core.unanswered_handshakes(id), Some(4));
    core.handle_timeout(now + Duration::from_secs(100));
    assert_eq!(core.unanswered_handshakes(id), Some(4));
    // A new attempt starts with nothing outstanding.
    core.force_handshake(id, None, now + Duration::from_secs(101));
    assert_eq!(core.unanswered_handshakes(id), Some(4));
}

#[test]
fn answered_initiations_do_not_count() {
    let now = Instant::now();
    let (mut a, b_id) = core_with_peer(1, 2, path(2), now);
    let (mut b, a_id) = core_with_peer(2, 1, path(1), now);

    a.force_handshake(b_id, None, now);
    for init in transmits(&mut a) {
        b.handle_input(
            Input::Datagram {
                path: path(1),
                data: init,
            },
            now,
        );
    }
    for response in transmits(&mut b) {
        a.handle_input(
            Input::Datagram {
                path: path(2),
                data: response,
            },
            now,
        );
    }
    assert_eq!(a.unanswered_handshakes(b_id), Some(0));

    // The answer cleared the outstanding initiation: a new one does not count it.
    a.force_handshake(b_id, None, now);
    assert_eq!(a.unanswered_handshakes(b_id), Some(0));
    a.handle_timeout(now + RETRY);
    assert_eq!(a.unanswered_handshakes(b_id), Some(1));

    // The responder never counts.
    assert_eq!(b.unanswered_handshakes(a_id), Some(0));
    assert_eq!(b.total_unanswered_handshakes(), 0);
}

#[test]
fn the_total_survives_peer_removal() {
    let now = Instant::now();
    let (mut core, id) = core_with_peer(1, 2, path(2), now);
    core.force_handshake(id, None, now);
    core.handle_timeout(now + RETRY);
    core.handle_timeout(now + RETRY * 2);
    assert_eq!(core.total_unanswered_handshakes(), 2);

    let key = x25519::PublicKey::from(&x25519::StaticSecret::from([2; 32]));
    core.handle_input(
        Input::Config(ConfigChange::RemovePeer(key)),
        now + RETRY * 2,
    );
    assert_eq!(core.unanswered_handshakes(id), None);
    assert_eq!(core.total_unanswered_handshakes(), 2);

    let (mut other, id) = core_with_peer(1, 3, path(3), now);
    other.force_handshake(id, None, now);
    other.handle_timeout(now + RETRY);
    other.handle_input(Input::Config(ConfigChange::RemoveAllPeers), now + RETRY);
    assert_eq!(other.total_unanswered_handshakes(), 1);
    assert_eq!(other.unanswered_handshakes(id), None);
}

/// Sends data on a fixed path, everything else on the current one.
struct DataOn(Path);

impl PathPolicy for DataOn {
    fn select(&self, _peer: PeerId, kind: MessageKind) -> Option<Path> {
        (kind == MessageKind::Data).then_some(self.0)
    }

    fn on_authenticated(&self, _peer: PeerId, _from: &Path, _kind: MessageKind) -> Roam {
        Roam::Keep
    }
}

#[test]
fn data_path_follows_the_policy_then_the_current_path() {
    let path = |port| Path {
        transport: nsplane_packet::TransportId::new(1),
        addr: std::net::SocketAddr::from(([192, 0, 2, 1], port)),
        ecn: Ecn::NotEct,
    };
    let add = |core: &mut Core, with_path: bool| {
        let key = x25519::PublicKey::from([7; 32]);
        let mut config = PeerConfig::new(key);
        config.path = with_path.then(|| path(1));
        core.handle_input(
            Input::Config(ConfigChange::AddOrUpdatePeer(config)),
            Instant::now(),
        );
        core.peer_id(&key).unwrap()
    };
    let private_key = Some(x25519::StaticSecret::from([1; 32]));

    let mut core = Core::new(CoreConfig {
        private_key: private_key.clone(),
        ..CoreConfig::default()
    });
    assert_eq!(core.data_path(PeerId::new(99)), None);
    let id = add(&mut core, false);
    assert_eq!(core.data_path(id), None);
    let id = add(&mut core, true);
    assert_eq!(core.data_path(id), Some(path(1)));
    assert!(!core.is_remote_index(id, 0));
    assert!(!core.is_remote_index(PeerId::new(99), 0));

    let mut core = Core::new(CoreConfig {
        private_key,
        policy: Box::new(DataOn(path(2))),
        ..CoreConfig::default()
    });
    let id = add(&mut core, true);
    assert_eq!(core.data_path(id), Some(path(2)));
}

/// Two cores, `0` at `10.0.0.1` and `1` at `10.0.0.2`, peered with each other.
fn core_pair(crypto_jobs: bool) -> [Core; 2] {
    let secrets = [[1; 32], [2; 32]].map(x25519::StaticSecret::from);
    let path = |i: u8| Path {
        transport: nsplane_packet::TransportId::new(u16::from(i)),
        addr: std::net::SocketAddr::from(([192, 0, 2, i + 1], 51820)),
        ecn: Ecn::NotEct,
    };
    [0u8, 1].map(|i| {
        let other = usize::from(1 - i);
        let mut core = Core::new(CoreConfig {
            private_key: Some(secrets[usize::from(i)].clone()),
            crypto_jobs,
            ..CoreConfig::default()
        });
        let mut config = PeerConfig::new(x25519::PublicKey::from(&secrets[other]));
        config.allowed_ips = vec![format!("10.0.0.{}/32", other + 1).parse().unwrap()];
        config.path = Some(path(1 - i));
        core.handle_input(
            Input::Config(ConfigChange::AddOrUpdatePeer(config)),
            Instant::now(),
        );
        core
    })
}

/// Moves datagrams between the cores until both are quiet; returns what each delivered.
fn pump(cores: &mut [Core; 2]) -> [Vec<Vec<u8>>; 2] {
    let mut delivered = [Vec::new(), Vec::new()];
    loop {
        let mut quiet = true;
        for i in 0..2 {
            while let Some(output) = cores[i].poll_output() {
                match output {
                    Output::Transmit { data, .. } => {
                        quiet = false;
                        // It arrives on the path the receiver has for the sender.
                        let sender = cores[1 - i].peers().next().unwrap();
                        let path = cores[1 - i].data_path(sender).unwrap();
                        cores[1 - i].handle_input(Input::Datagram { path, data }, Instant::now());
                    }
                    Output::Deliver { packet, .. } => {
                        delivered[i].push(packet.as_packet().to_vec());
                    }
                    Output::Event(_) | Output::Plaintext { .. } | Output::Tracked { .. } => {}
                }
            }
        }
        if quiet {
            return delivered;
        }
    }
}

/// An IPv4 packet of `len` bytes from `10.0.0.1` to `10.0.0.2`.
fn local_packet(len: usize) -> PacketBuf {
    let mut buf = PacketBuf::with_capacity(2048);
    buf.set_len(len);
    let p = buf.as_packet_mut();
    p[0] = 0x45;
    p[2..4].copy_from_slice(&u16::try_from(len).unwrap().to_be_bytes());
    p[8] = 64;
    p[9] = 17;
    p[12..16].copy_from_slice(&[10, 0, 0, 1]);
    p[16..20].copy_from_slice(&[10, 0, 0, 2]);
    buf
}

#[test]
fn padding_stops_at_the_peer_pad_limit() {
    for crypto_jobs in [false, true] {
        let mut cores = core_pair(crypto_jobs);
        // The first packet waits for the handshake.
        cores[0].handle_input(
            Input::Local {
                packet: local_packet(100),
            },
            Instant::now(),
        );
        assert_eq!(pump(&mut cores)[1].len(), 1);
        let peer = cores[0].peers().next().unwrap();

        // (limit, packet length, padded plaintext)
        for (limit, len, padded) in [
            (None, 1001, 1008),
            (Some(1003), 1001, 1003),
            (Some(1003), 1003, 1003),
            (Some(1003), 1010, 1010),
            (Some(1280), 1001, 1008),
            (None, 1003, 1008),
            // A peer at the source MTU: 1420 bytes would pad to 1424.
            (Some(1420), 1420, 1420),
            (None, 1420, 1424),
        ] {
            cores[0].set_peer_pad_limit(peer, limit);
            let packet = local_packet(len);
            let sent = packet.as_packet().to_vec();
            let input = Input::Local { packet };
            if crypto_jobs {
                let mut job = cores[0]
                    .handle_input_deferred(input, Instant::now())
                    .unwrap();
                job.run();
                cores[0].complete_job(job);
            } else {
                cores[0].handle_input(input, Instant::now());
            }
            let Some(Output::Transmit { path, data }) = cores[0].poll_output() else {
                unreachable!();
            };
            assert_eq!(data.len(), DATA_HEADER_SZ + padded + 16, "{limit:?} {len}");
            cores[0].outputs.push_front(Output::Transmit { path, data });
            assert_eq!(pump(&mut cores)[1], [sent], "{limit:?} {len}");
        }
    }
}

/// An IPv4 packet of 100 bytes from `src` to `dst`.
fn packet_between(src: [u8; 4], dst: [u8; 4]) -> PacketBuf {
    let mut buf = local_packet(100);
    let p = buf.as_packet_mut();
    p[12..16].copy_from_slice(&src);
    p[16..20].copy_from_slice(&dst);
    buf
}

/// Feeds `input` to `core`, through a crypto job with `crypto_jobs`.
fn feed(core: &mut Core, input: Input, crypto_jobs: bool) {
    if crypto_jobs {
        if let Some(mut job) = core.handle_input_deferred(input, Instant::now()) {
            job.run();
            core.complete_job(job);
        }
    } else {
        core.handle_input(input, Instant::now());
    }
}

/// Moves datagrams between the cores until both are quiet, a datagram from core `i`
/// arriving on `path(i)`; returns what each delivered, with the peer it came from.
fn pump_from(cores: &mut [Core; 2], crypto_jobs: bool) -> [Vec<(PeerId, Vec<u8>)>; 2] {
    let mut delivered = [Vec::new(), Vec::new()];
    loop {
        let mut quiet = true;
        for i in 0..2 {
            while let Some(output) = cores[i].poll_output() {
                match output {
                    Output::Transmit { data, .. } => {
                        quiet = false;
                        let path = path(u16::try_from(i).unwrap());
                        feed(
                            &mut cores[1 - i],
                            Input::Datagram { path, data },
                            crypto_jobs,
                        );
                    }
                    Output::Deliver { from, packet } => {
                        delivered[i].push((from, packet.as_packet().to_vec()));
                    }
                    Output::Event(_) | Output::Plaintext { .. } | Output::Tracked { .. } => {}
                }
            }
        }
        if quiet {
            return delivered;
        }
    }
}

/// Core `0` with the default identity and a second one, each with a peer of core `1`'s
/// key allowing `10.0.0.2/32`, and with the sources `10.0.0.1/32` and `10.0.1.1/32`;
/// core `1`, at `10.0.0.2`, with a peer for each, allowing one of the sources. Returns
/// the second identity and the peers of core `0` and of core `1`, default identity first.
fn identity_pair(crypto_jobs: bool) -> ([Core; 2], LocalIdentityId, [PeerId; 2], [PeerId; 2]) {
    let secrets = [[1; 32], [2; 32], [3; 32]].map(x25519::StaticSecret::from);
    let [own, remote, second] = secrets.each_ref().map(x25519::PublicKey::from);
    let new = |key: &x25519::StaticSecret| {
        Core::new(CoreConfig {
            private_key: Some(key.clone()),
            crypto_jobs,
            ..CoreConfig::default()
        })
    };
    let add = |core: &mut Core, identity, key, allowed: &str, at: u16| {
        let mut config = PeerConfig::new(key);
        config.local_identity = Some(identity);
        config.allowed_ips = vec![allowed.parse().unwrap()];
        config.path = Some(path(at));
        core.handle_input(
            Input::Config(ConfigChange::AddOrUpdatePeer(config)),
            Instant::now(),
        );
        core.peer_id_in(identity, &key).unwrap()
    };

    let mut a = new(&secrets[0]);
    let identity = a.add_local_identity(secrets[2].clone()).unwrap();
    let a_peers =
        [LocalIdentityId::DEFAULT, identity].map(|id| add(&mut a, id, remote, "10.0.0.2/32", 1));
    assert!(a.set_local_sources(LocalIdentityId::DEFAULT, &["10.0.0.1/32".parse().unwrap()]));
    assert!(a.set_local_sources(identity, &["10.0.1.1/32".parse().unwrap()]));

    let mut b = new(&secrets[1]);
    let b_peers = [(own, "10.0.0.1/32"), (second, "10.0.1.1/32")]
        .map(|(key, allowed)| add(&mut b, LocalIdentityId::DEFAULT, key, allowed, 0));
    ([a, b], identity, a_peers, b_peers)
}

#[test]
fn two_identities_with_the_same_remote_key_and_ranges_exchange_traffic() {
    for crypto_jobs in [false, true] {
        let (mut cores, identity, a_peers, b_peers) = identity_pair(crypto_jobs);
        for _ in 0..2 {
            // Out by source, to the identity's own peer.
            for src in [[10, 0, 0, 1], [10, 0, 1, 1]] {
                let packet = packet_between(src, [10, 0, 0, 2]);
                feed(&mut cores[0], Input::Local { packet }, crypto_jobs);
            }
            let delivered = pump_from(&mut cores, crypto_jobs);
            let from: Vec<PeerId> = delivered[1].iter().map(|(from, _)| *from).collect();
            assert_eq!(from, b_peers, "{crypto_jobs}");

            // In, each checked against its own identity's allowed IPs.
            for dst in [[10, 0, 0, 1], [10, 0, 1, 1]] {
                let packet = packet_between([10, 0, 0, 2], dst);
                feed(&mut cores[1], Input::Local { packet }, crypto_jobs);
            }
            let delivered = pump_from(&mut cores, crypto_jobs);
            let from: Vec<PeerId> = delivered[0].iter().map(|(from, _)| *from).collect();
            assert_eq!(from, a_peers, "{crypto_jobs}");
        }

        // The second identity goes; the default one keeps working both ways.
        assert!(cores[0].remove_local_identity(identity));
        let packet = packet_between([10, 0, 0, 1], [10, 0, 0, 2]);
        feed(&mut cores[0], Input::Local { packet }, crypto_jobs);
        assert_eq!(pump_from(&mut cores, crypto_jobs)[1].len(), 1);
        let packet = packet_between([10, 0, 0, 2], [10, 0, 0, 1]);
        feed(&mut cores[1], Input::Local { packet }, crypto_jobs);
        let delivered = pump_from(&mut cores, crypto_jobs);
        assert_eq!(
            delivered[0]
                .iter()
                .map(|(from, _)| *from)
                .collect::<Vec<_>>(),
            [a_peers[0]]
        );
    }
}

/// The drops `core` reported, its other outputs discarded.
fn drops(core: &mut Core) -> Vec<&'static str> {
    drain(core)
        .1
        .into_iter()
        .filter_map(|event| match event {
            Event::Dropped { reason, .. } => Some(reason),
            _ => None,
        })
        .collect()
}

/// A core with the default identity and a second one, each with a peer allowing `ranges`.
fn two_identity_core(ranges: &[&str]) -> (Core, LocalIdentityId, [PeerId; 2]) {
    let mut core = Core::new(CoreConfig {
        private_key: Some(x25519::StaticSecret::from([1; 32])),
        ..CoreConfig::default()
    });
    let identity = core
        .add_local_identity(x25519::StaticSecret::from([3; 32]))
        .unwrap();
    let peers = [LocalIdentityId::DEFAULT, identity].map(|id| {
        let key = x25519::PublicKey::from([7; 32]);
        let mut config = PeerConfig::new(key);
        config.local_identity = Some(id);
        config.allowed_ips = ranges.iter().map(|r| r.parse().unwrap()).collect();
        config.path = Some(path(2));
        core.handle_input(
            Input::Config(ConfigChange::AddOrUpdatePeer(config)),
            Instant::now(),
        );
        core.peer_id_in(id, &key).unwrap()
    });
    (core, identity, peers)
}

#[test]
fn a_selected_identity_without_a_route_drops_and_no_set_falls_back() {
    let (mut core, identity, peers) = two_identity_core(&["10.0.0.0/24"]);
    let ip = |s: &str| s.parse::<IpAddr>().unwrap();
    assert!(core.set_local_sources(identity, &["100.64.0.0/16".parse().unwrap()]));
    // Unmatched source: the fallback trie, where the last insert owns the range.
    assert_eq!(
        core.route_from(ip("192.0.2.1"), ip("10.0.0.1")),
        Some(peers[1])
    );
    assert_eq!(core.route(ip("10.0.0.1")), Some(peers[1]));
    assert_eq!(
        core.route_from(ip("100.64.0.1"), ip("10.0.0.1")),
        Some(peers[1])
    );

    // The default identity's peer is reached through its own set only.
    assert!(core.set_local_sources(
        LocalIdentityId::DEFAULT,
        &["100.64.1.0/24".parse().unwrap()]
    ));
    assert_eq!(
        core.route_from(ip("100.64.1.1"), ip("10.0.0.1")),
        Some(peers[0])
    );

    // A matched identity without a route: dropped, though the fallback has one.
    assert_eq!(core.route_from(ip("100.64.0.1"), ip("10.0.1.1")), None);
    let packet = packet_between([100, 64, 0, 1], [10, 0, 1, 1]);
    core.handle_input(Input::Local { packet }, Instant::now());
    assert_eq!(drops(&mut core), [reasons::NO_ROUTE]);
    // A routed packet starts a handshake with its peer.
    let packet = packet_between([100, 64, 1, 1], [10, 0, 0, 1]);
    core.handle_locals([packet], Instant::now());
    assert_eq!(drops(&mut core), Vec::<&str>::new());
    assert_eq!(
        core.peer_stats(peers[0]).unwrap().tx,
        HANDSHAKE_INIT_SZ as u64
    );
    assert_eq!(core.peer_stats(peers[1]).unwrap().tx, 0);
}

#[test]
fn a_shared_range_stays_routed_after_either_holder_goes() {
    let ip = |s: &str| s.parse::<IpAddr>().unwrap();
    let key = x25519::PublicKey::from([7; 32]);
    for removed in [0, 1] {
        let (mut core, identity, peers) = two_identity_core(&["10.0.0.0/24"]);
        let ids = [LocalIdentityId::DEFAULT, identity];
        core.handle_input(
            Input::Config(ConfigChange::InLocalIdentity {
                identity: ids[removed],
                change: Box::new(ConfigChange::RemovePeer(key)),
            }),
            Instant::now(),
        );
        assert_eq!(core.route(ip("10.0.0.1")), Some(peers[1 - removed]));
        let stats = core.peer_stats(peers[1 - removed]).unwrap();
        assert_eq!(stats.allowed_ips, vec!["10.0.0.0/24".parse().unwrap()]);
    }

    let (mut core, identity, peers) = two_identity_core(&["10.0.0.0/24"]);
    assert!(core.remove_local_identity(identity));
    assert_eq!(core.route(ip("10.0.0.1")), Some(peers[0]));
    assert_eq!(
        core.route_from(ip("192.0.2.1"), ip("10.0.0.1")),
        Some(peers[0])
    );
}

#[test]
fn one_identity_routes_from_any_source_as_without_sets() {
    let (mut core, peer) = core_with_peer(1, 2, path(2), Instant::now());
    let mut config = PeerConfig::new(x25519::PublicKey::from(&x25519::StaticSecret::from(
        [2; 32],
    )));
    config.allowed_ips = vec!["10.0.0.0/24".parse().unwrap()];
    core.handle_input(
        Input::Config(ConfigChange::AddOrUpdatePeer(config)),
        Instant::now(),
    );
    assert!(!core.peers.merged());
    for dst in ["10.0.0.1", "10.0.1.1"] {
        let dst = dst.parse().unwrap();
        assert_eq!(
            core.route_from("192.0.2.1".parse().unwrap(), dst),
            core.route(dst)
        );
    }
    assert_eq!(core.route("10.0.0.1".parse().unwrap()), Some(peer));
}

#[test]
fn local_identities_report_their_sources_and_remove_all_peers_keeps_them() {
    let (mut core, identity, _) = two_identity_core(&["10.0.0.0/24"]);
    let set: Vec<AllowedIp> = vec!["100.64.0.0/16".parse().unwrap()];
    assert!(core.set_local_sources(identity, &set));
    let sources = |core: &Core| {
        core.local_identities()
            .map(|i| i.sources)
            .collect::<Vec<_>>()
    };
    assert_eq!(sources(&core), [Vec::new(), set.clone()]);
    // An identical network of another identity, or an unknown identity: refused.
    assert!(!core.set_local_sources(LocalIdentityId::DEFAULT, &set));
    assert!(!core.set_local_sources(LocalIdentityId::new(99), &[]));
    assert_eq!(sources(&core), [Vec::new(), set.clone()]);

    core.handle_input(Input::Config(ConfigChange::RemoveAllPeers), Instant::now());
    assert_eq!(sources(&core), [Vec::new(), set]);
    assert!(core.remove_local_identity(identity));
    assert_eq!(sources(&core), [Vec::<AllowedIp>::new()]);
    assert!(!core.peers.has_sources());
}

/// Keeps the current path unless told to adopt; counts what it is told about.
#[derive(Default, Clone)]
struct Counting {
    calls: std::sync::Arc<std::sync::atomic::AtomicUsize>,
    adopt: std::sync::Arc<std::sync::atomic::AtomicBool>,
}

impl Counting {
    fn calls(&self) -> usize {
        self.calls.load(std::sync::atomic::Ordering::Relaxed)
    }
}

impl PathPolicy for Counting {
    fn select(&self, _peer: PeerId, _kind: MessageKind) -> Option<Path> {
        None
    }

    fn on_authenticated(&self, _peer: PeerId, _from: &Path, _kind: MessageKind) -> Roam {
        self.calls
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        if self.adopt.load(std::sync::atomic::Ordering::Relaxed) {
            Roam::Adopt
        } else {
            Roam::Keep
        }
    }
}

/// The datagrams and events `core` queued, its deliveries discarded.
fn drain(core: &mut Core) -> (Vec<PacketBuf>, Vec<Event>) {
    let (mut sent, mut events) = (Vec::new(), Vec::new());
    while let Some(output) = core.poll_output() {
        match output {
            Output::Transmit { data, .. } => sent.push(data),
            Output::Event(event) => events.push(event),
            Output::Deliver { .. } | Output::Plaintext { .. } | Output::Tracked { .. } => {}
        }
    }
    (sent, events)
}

/// Hands `datagrams` to `core` as arriving on `on`.
fn arrive(core: &mut Core, datagrams: Vec<PacketBuf>, on: Path) {
    for data in datagrams {
        core.handle_input(Input::Datagram { path: on, data }, Instant::now());
    }
}

/// The sources of the `Authenticated` events among `events`.
fn reported(events: &[Event]) -> Vec<Path> {
    events
        .iter()
        .filter_map(|event| match event {
            Event::Authenticated { from, .. } => Some(*from),
            _ => None,
        })
        .collect()
}

/// `a` (with peer `b` at `path(2)`) and `b` (with `policy` and peer `a` at `path(1)`)
/// after a handshake and the first data on `b`'s path for `a`.
fn pinned_pair(policy: Counting) -> (Core, Core, PeerId) {
    let now = Instant::now();
    let (mut a, _) = core_with_peer(1, 2, path(2), now);
    let mut config = PeerConfig::new(x25519::PublicKey::from(&x25519::StaticSecret::from(
        [2; 32],
    )));
    config.allowed_ips = vec!["10.0.0.2/32".parse().unwrap()];
    a.handle_input(Input::Config(ConfigChange::AddOrUpdatePeer(config)), now);

    let mut b = Core::new(CoreConfig {
        private_key: Some(x25519::StaticSecret::from([2; 32])),
        policy: Box::new(policy),
        ..CoreConfig::default()
    });
    let key = x25519::PublicKey::from(&x25519::StaticSecret::from([1; 32]));
    let mut config = PeerConfig::new(key);
    config.path = Some(path(1));
    b.handle_input(Input::Config(ConfigChange::AddOrUpdatePeer(config)), now);
    let a_id = b.peer_id(&key).unwrap();

    a.handle_input(
        Input::Local {
            packet: local_packet(100),
        },
        now,
    );
    let (init, _) = drain(&mut a);
    arrive(&mut b, init, path(1));
    let (response, _) = drain(&mut b);
    arrive(&mut a, response, path(2));
    let (data, _) = drain(&mut a);
    arrive(&mut b, data, path(1));
    assert_eq!(reported(&drain(&mut b).1), []);
    (a, b, a_id)
}

/// Sends `n` data packets from `a` to `b`, arriving on `on`; returns `b`'s events.
fn data(a: &mut Core, b: &mut Core, on: Path, n: usize) -> Vec<Event> {
    for _ in 0..n {
        a.handle_input(
            Input::Local {
                packet: local_packet(100),
            },
            Instant::now(),
        );
        let (sent, _) = drain(a);
        assert_eq!(sent.len(), 1);
        arrive(b, sent, on);
    }
    drain(b).1
}

#[test]
fn an_off_path_source_is_reported_once_per_change() {
    let policy = Counting::default();
    let (mut a, mut b, a_id) = pinned_pair(policy.clone());

    // A path the policy keeps: one event, but every message reaches the policy.
    let calls = policy.calls();
    assert_eq!(reported(&data(&mut a, &mut b, path(3), 10)), [path(3)]);
    assert_eq!(policy.calls() - calls, 10);
    assert_eq!(b.data_path(a_id), Some(path(1)));

    // Each change of source is reported once, back to an earlier one included.
    assert_eq!(reported(&data(&mut a, &mut b, path(4), 5)), [path(4)]);
    assert_eq!(reported(&data(&mut a, &mut b, path(3), 5)), [path(3)]);
    // ECN marks do not make a new source.
    let marked = Path {
        ecn: Ecn::Ect0,
        ..path(3)
    };
    assert_eq!(reported(&data(&mut a, &mut b, marked, 3)), []);

    // The current path reports nothing and does not reach this policy.
    let calls = policy.calls();
    assert_eq!(reported(&data(&mut a, &mut b, path(1), 5)), []);
    assert_eq!(policy.calls(), calls);
    assert_eq!(reported(&data(&mut a, &mut b, path(3), 5)), []);
}

#[test]
fn a_path_change_or_handshake_reports_the_source_again() {
    let policy = Counting::default();
    let (mut a, mut b, a_id) = pinned_pair(policy.clone());
    let a_key = x25519::PublicKey::from(&x25519::StaticSecret::from([1; 32]));
    assert_eq!(reported(&data(&mut a, &mut b, path(3), 2)), [path(3)]);

    // A path set by configuration, even the same one.
    b.handle_input(
        Input::Config(ConfigChange::SetPath {
            peer: a_key,
            path: path(1),
        }),
        Instant::now(),
    );
    assert_eq!(reported(&data(&mut a, &mut b, path(3), 2)), [path(3)]);
    let mut config = PeerConfig::new(a_key);
    config.path = Some(path(1));
    b.handle_input(
        Input::Config(ConfigChange::AddOrUpdatePeer(config)),
        Instant::now(),
    );
    assert_eq!(reported(&data(&mut a, &mut b, path(3), 2)), [path(3)]);

    // A forced handshake with a path.
    b.force_handshake(a_id, Some(path(1)), Instant::now());
    let (init, _) = drain(&mut b);
    assert_eq!(reported(&data(&mut a, &mut b, path(3), 2)), [path(3)]);

    // A completed handshake, its response arriving from the reported source.
    arrive(&mut a, init, path(2));
    let (response, _) = drain(&mut a);
    arrive(&mut b, response, path(3));
    let events = drain(&mut b).1;
    assert!(
        events
            .iter()
            .any(|event| matches!(event, Event::HandshakeCompleted { .. }))
    );
    assert_eq!(reported(&events), [path(3)]);
    assert_eq!(reported(&data(&mut a, &mut b, path(3), 2)), []);

    // An adoption is reported even from the reported source, then the new path's
    // sources start over.
    policy
        .adopt
        .store(true, std::sync::atomic::Ordering::Relaxed);
    let events = data(&mut a, &mut b, path(3), 1);
    policy
        .adopt
        .store(false, std::sync::atomic::Ordering::Relaxed);
    assert_eq!(reported(&events), [path(3)]);
    assert!(matches!(
        events.get(1),
        Some(Event::PathAdopted { path: adopted, .. }) if *adopted == path(3)
    ));
    assert_eq!(b.data_path(a_id), Some(path(3)));
    assert_eq!(reported(&data(&mut a, &mut b, path(3), 2)), []);
    assert_eq!(reported(&data(&mut a, &mut b, path(1), 2)), [path(1)]);
}

mod plaintext {
    use std::sync::{Arc, Mutex};

    use super::*;
    use crate::filter::Verdict;
    use crate::types::InboundDestinations;

    const FILTER_DROP: &str = "test filter drop";

    /// What the recording filter saw: the peer, the arrival path and the packet.
    type Seen = Vec<(PeerId, Path, Vec<u8>)>;

    /// Records every inbound packet; drops one whose last byte is 1 and handles one whose
    /// last byte is 2.
    #[derive(Default, Clone)]
    struct Recording(Arc<Mutex<Seen>>);

    impl Recording {
        fn take(&self) -> Seen {
            std::mem::take(&mut *self.0.lock().unwrap())
        }
    }

    impl PacketFilter for Recording {
        fn inbound(&self, _peer: PeerId, _packet: &mut PacketBuf) -> Verdict {
            unreachable!("the core calls inbound_from")
        }

        fn inbound_from(&self, peer: PeerId, from: &Path, packet: &mut PacketBuf) -> Verdict {
            let bytes = packet.as_packet().to_vec();
            let last = bytes.last().copied();
            self.0.lock().unwrap().push((peer, *from, bytes));
            match last {
                Some(1) => Verdict::Drop {
                    reason: FILTER_DROP,
                },
                Some(2) => Verdict::Handled,
                _ => Verdict::Accept,
            }
        }

        fn outbound(&self, _peer: PeerId, _packet: &mut PacketBuf) -> Verdict {
            Verdict::Accept
        }
    }

    /// What a receiving core did with one packet.
    #[derive(Debug, PartialEq, Eq)]
    struct Fate {
        delivered: Vec<(PeerId, Vec<u8>)>,
        drops: Vec<&'static str>,
        seen: Seen,
    }

    /// Outputs of `core` since the last call, as a [`Fate`] with what `filter` saw; also
    /// returns the other events.
    fn fate(core: &mut Core, filter: &Recording) -> (Fate, Vec<Event>) {
        let (mut delivered, mut drops, mut events) = (Vec::new(), Vec::new(), Vec::new());
        while let Some(output) = core.poll_output() {
            match output {
                Output::Deliver { from, packet } => {
                    delivered.push((from, packet.as_packet().to_vec()));
                }
                Output::Event(Event::Dropped { reason, .. }) => drops.push(reason),
                Output::Event(event) => events.push(event),
                Output::Transmit { .. } | Output::Plaintext { .. } | Output::Tracked { .. } => {}
            }
        }
        let seen = filter.take();
        (
            Fate {
                delivered,
                drops,
                seen,
            },
            events,
        )
    }

    /// An IP packet of 100 bytes from `src` to `dst` (both of one family) whose last
    /// byte is `last`.
    fn ip(src: &str, dst: &str, last: u8) -> PacketBuf {
        let (src, dst): (IpAddr, IpAddr) = (src.parse().unwrap(), dst.parse().unwrap());
        let mut buf = PacketBuf::with_capacity(2048);
        buf.set_len(100);
        let p = buf.as_packet_mut();
        match (src, dst) {
            (IpAddr::V4(src), IpAddr::V4(dst)) => {
                p[0] = 0x45;
                p[2..4].copy_from_slice(&100u16.to_be_bytes());
                p[8] = 64;
                p[9] = 17;
                p[12..16].copy_from_slice(&src.octets());
                p[16..20].copy_from_slice(&dst.octets());
            }
            (IpAddr::V6(src), IpAddr::V6(dst)) => {
                p[0] = 0x60;
                p[4..6].copy_from_slice(&60u16.to_be_bytes());
                p[6] = 17;
                p[7] = 64;
                p[8..24].copy_from_slice(&src.octets());
                p[24..40].copy_from_slice(&dst.octets());
            }
            _ => unreachable!("one family"),
        }
        p[99] = last;
        buf
    }

    /// Sender `a` (`10.0.0.1`, `fd00::1`, routing `10.0.0.0/24` and `fd00::/64` to `b`)
    /// and receiver `b` with the recording filter, whose peer `a` may send from `a`'s
    /// addresses to `10.0.0.2` and `fd00::2` only; after a handshake, `b` reaching `a`
    /// on `path(1)`. Returns `a`'s id in `b`.
    fn sender_and_receiver(filter: &Recording) -> (Core, Core, PeerId) {
        let now = Instant::now();
        let keys = [1u8, 2].map(|k| x25519::StaticSecret::from([k; 32]));
        let mut a = Core::new(CoreConfig {
            private_key: Some(keys[0].clone()),
            ..CoreConfig::default()
        });
        let mut to_b = PeerConfig::new(x25519::PublicKey::from(&keys[1]));
        to_b.allowed_ips = vec!["10.0.0.0/24".parse().unwrap(), "fd00::/64".parse().unwrap()];
        to_b.path = Some(path(2));
        a.handle_input(Input::Config(ConfigChange::AddOrUpdatePeer(to_b)), now);

        let mut b = Core::new(CoreConfig {
            private_key: Some(keys[1].clone()),
            filters: vec![Box::new(filter.clone())],
            ..CoreConfig::default()
        });
        let a_key = x25519::PublicKey::from(&keys[0]);
        let mut to_a = PeerConfig::new(a_key);
        to_a.allowed_ips = vec![
            "10.0.0.1/32".parse().unwrap(),
            "fd00::1/128".parse().unwrap(),
        ];
        to_a.inbound_destinations = Some(vec![
            "10.0.0.2/32".parse().unwrap(),
            "fd00::2/128".parse().unwrap(),
        ]);
        to_a.path = Some(path(1));
        b.handle_input(Input::Config(ConfigChange::AddOrUpdatePeer(to_a)), now);
        let a_id = b.peer_id(&a_key).unwrap();

        let (fate_of_first, _) = decrypted(&mut a, &mut b, filter, ip("10.0.0.1", "10.0.0.2", 0));
        assert_eq!(fate_of_first.delivered.len(), 1);
        (a, b, a_id)
    }

    /// Sends `packet` from `a` to `b`, every datagram arriving on `path(1)`; returns what
    /// `b` did with it.
    fn decrypted(
        a: &mut Core,
        b: &mut Core,
        filter: &Recording,
        packet: PacketBuf,
    ) -> (Fate, Vec<Event>) {
        a.handle_input(Input::Local { packet }, Instant::now());
        loop {
            let (sent, _) = drain(a);
            if sent.is_empty() {
                break;
            }
            arrive(b, sent, path(1));
            let mut replies = Vec::new();
            let mut kept = VecDeque::new();
            while let Some(output) = b.poll_output() {
                match output {
                    Output::Transmit { data, .. } => replies.push(data),
                    other => kept.push_back(other),
                }
            }
            b.outputs = kept;
            arrive(a, replies, path(2));
        }
        fate(b, filter)
    }

    fn cases() -> Vec<(&'static str, PacketBuf, PacketBuf)> {
        let pair = |src, dst, last| (ip(src, dst, last), ip(src, dst, last));
        [
            ("accepted v4", pair("10.0.0.1", "10.0.0.2", 0)),
            ("accepted v6", pair("fd00::1", "fd00::2", 0)),
            ("source not allowed v4", pair("10.0.0.9", "10.0.0.2", 0)),
            ("source not allowed v6", pair("fd00::9", "fd00::2", 0)),
            (
                "destination not allowed v4",
                pair("10.0.0.1", "10.0.0.3", 0),
            ),
            ("destination not allowed v6", pair("fd00::1", "fd00::3", 0)),
            ("filter drop v4", pair("10.0.0.1", "10.0.0.2", 1)),
            ("filter drop v6", pair("fd00::1", "fd00::2", 1)),
            ("handled v4", pair("10.0.0.1", "10.0.0.2", 2)),
            ("handled v6", pair("fd00::1", "fd00::2", 2)),
        ]
        .into_iter()
        .map(|(name, (x, y))| (name, x, y))
        .collect()
    }

    #[test]
    fn plaintext_meets_the_checks_of_decrypted_data() {
        let filter = Recording::default();
        let (mut a, mut b, a_id) = sender_and_receiver(&filter);
        for (name, sealed, plain) in cases() {
            let (by_tunnel, _) = decrypted(&mut a, &mut b, &filter, sealed);
            b.receive_plaintext(a_id, path(1), plain);
            let (by_plaintext, _) = fate(&mut b, &filter);
            assert_eq!(by_plaintext, by_tunnel, "{name}");
        }
        // Each verdict was met: delivered, dropped by the checks and the filter, handled.
        let filter = Recording::default();
        let (_, mut b, a_id) = sender_and_receiver(&filter);
        let mut delivered = 0;
        let mut drops = Vec::new();
        let mut seen = 0;
        for (_, _, plain) in cases() {
            b.receive_plaintext(a_id, path(1), plain);
            let (fate, _) = fate(&mut b, &filter);
            delivered += fate.delivered.len();
            drops.extend(fate.drops);
            seen += fate.seen.len();
        }
        assert_eq!(delivered, 2);
        assert_eq!(
            drops,
            [
                reasons::SOURCE_NOT_ALLOWED,
                reasons::SOURCE_NOT_ALLOWED,
                reasons::DESTINATION_NOT_ALLOWED,
                reasons::DESTINATION_NOT_ALLOWED,
                FILTER_DROP,
                FILTER_DROP,
            ]
        );
        assert_eq!(
            seen, 6,
            "accepted, filter drops and handled reach the filter"
        );
    }

    #[test]
    fn a_shared_destination_source_is_consulted_for_plaintext() {
        #[derive(Debug)]
        struct Only(IpAddr);
        impl InboundDestinations for Only {
            fn allows(&self, dst: IpAddr) -> bool {
                dst == self.0
            }
        }
        let filter = Recording::default();
        let (_, mut b, a_id) = sender_and_receiver(&filter);
        let a_key = x25519::PublicKey::from(&x25519::StaticSecret::from([1; 32]));
        b.handle_input(
            Input::Config(ConfigChange::SetInboundDestinationSource {
                peer: a_key,
                source: Some(Arc::new(Only("10.0.0.3".parse().unwrap()))),
            }),
            Instant::now(),
        );
        b.receive_plaintext(a_id, path(1), ip("10.0.0.1", "10.0.0.2", 0));
        assert_eq!(
            fate(&mut b, &filter).0.drops,
            [reasons::DESTINATION_NOT_ALLOWED]
        );
        b.receive_plaintext(a_id, path(1), ip("10.0.0.1", "10.0.0.3", 0));
        assert_eq!(fate(&mut b, &filter).0.delivered.len(), 1);
    }

    #[test]
    fn the_filters_see_the_given_path_and_nothing_is_authenticated() {
        let filter = Recording::default();
        let (_, mut b, a_id) = sender_and_receiver(&filter);
        let before = b.peer_stats(a_id).unwrap();
        let packet = ip("10.0.0.1", "10.0.0.2", 0);
        let bytes = packet.as_packet().to_vec();
        b.receive_plaintext(a_id, path(7), packet);
        let (fate, events) = fate(&mut b, &filter);
        assert_eq!(fate.delivered, [(a_id, bytes.clone())]);
        assert_eq!(fate.seen, [(a_id, path(7), bytes)]);
        assert!(
            events.is_empty(),
            "no authentication, path or handshake event: {events:?}"
        );
        assert_eq!(b.data_path(a_id), Some(path(1)));
        let after = b.peer_stats(a_id).unwrap();
        assert_eq!(after.path, before.path);
        assert_eq!(after.rx, before.rx, "no datagram arrived");
        assert_eq!(after.data_rx, before.data_rx + 100);
        assert_eq!(after.last_handshake, before.last_handshake);
    }

    #[test]
    fn unknown_and_removed_peers_are_dropped() {
        let filter = Recording::default();
        let (_, mut b, a_id) = sender_and_receiver(&filter);
        b.receive_plaintext(
            PeerId::new(a_id.get() + 100),
            path(1),
            ip("10.0.0.1", "10.0.0.2", 0),
        );
        let (unknown, _) = fate(&mut b, &filter);
        assert_eq!(unknown.drops, [reasons::UNKNOWN_PLAINTEXT_PEER]);
        assert!(unknown.delivered.is_empty() && unknown.seen.is_empty());

        let a_key = x25519::PublicKey::from(&x25519::StaticSecret::from([1; 32]));
        b.handle_input(
            Input::Config(ConfigChange::RemovePeer(a_key)),
            Instant::now(),
        );
        let _ = fate(&mut b, &filter);
        b.receive_plaintext(a_id, path(1), ip("10.0.0.1", "10.0.0.2", 0));
        let (removed, _) = fate(&mut b, &filter);
        assert_eq!(removed.drops, [reasons::UNKNOWN_PLAINTEXT_PEER]);
        assert!(removed.delivered.is_empty() && removed.seen.is_empty());

        // The same key again is a new peer: the old id stays unknown.
        let mut config = PeerConfig::new(a_key);
        config.allowed_ips = vec!["10.0.0.1/32".parse().unwrap()];
        b.handle_input(
            Input::Config(ConfigChange::AddOrUpdatePeer(config)),
            Instant::now(),
        );
        assert_ne!(b.peer_id(&a_key), Some(a_id));
        b.receive_plaintext(a_id, path(1), ip("10.0.0.1", "10.0.0.2", 0));
        assert_eq!(
            fate(&mut b, &filter).0.drops,
            [reasons::UNKNOWN_PLAINTEXT_PEER]
        );
    }

    #[test]
    fn packets_are_read_like_decrypted_data() {
        let filter = Recording::default();
        let (mut a, mut b, a_id) = sender_and_receiver(&filter);
        // Bytes behind the IP length are cut, as the tunnel cuts its padding.
        let long = || {
            let mut packet = ip("10.0.0.1", "10.0.0.2", 0);
            packet.as_packet_mut()[2..4].copy_from_slice(&60u16.to_be_bytes());
            packet
        };
        let (by_tunnel, _) = decrypted(&mut a, &mut b, &filter, long());
        assert_eq!(by_tunnel.delivered[0].1.len(), 60);
        b.receive_plaintext(a_id, path(1), long());
        assert_eq!(fate(&mut b, &filter).0, by_tunnel);

        // No readable IPv4 or IPv6 source: dropped as a source not allowed.
        let short_v6 = PacketBuf::from_packet(&ip("fd00::1", "fd00::2", 0).as_packet()[..39]);
        let mut overlong = ip("10.0.0.1", "10.0.0.2", 0);
        overlong.as_packet_mut()[2..4].copy_from_slice(&101u16.to_be_bytes());
        let mut version = ip("10.0.0.1", "10.0.0.2", 0);
        version.as_packet_mut()[0] = 0x55;
        for (name, packet) in [
            ("empty", PacketBuf::from_packet(&[])),
            ("short v4", PacketBuf::from_packet(&[0x45; 19])),
            ("short v6", short_v6),
            ("length beyond the packet", overlong),
            ("version 5", version),
        ] {
            b.receive_plaintext(a_id, path(1), packet);
            let (fate, _) = fate(&mut b, &filter);
            assert_eq!(fate.drops, [reasons::SOURCE_NOT_ALLOWED], "{name}");
            assert!(fate.delivered.is_empty() && fate.seen.is_empty(), "{name}");
        }
    }
}
