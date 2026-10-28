#![allow(clippy::unwrap_used, clippy::panic, reason = "benchmark harness")]

//! Handshake initiations at a responder `Core` with several local identities.
//!
//! `initiation/N` times one valid initiation at a responder holding `N` keyed identities,
//! from the datagram to the handshake response: `N = 1` is the default identity alone (no
//! dispatch), otherwise the default identity and `N - 1` added ones, with the initiator's
//! peer bound to the last added identity, so that every identity is tried before it.
//! `no_match/16` times the drop of an initiation whose mac1 matches none of 16 identities.
//!
//! Initiations are built outside the timed section; each one carries a fresh timestamp.

use std::net::{Ipv4Addr, SocketAddr};
use std::time::Instant;

use criterion::{BatchSize, BenchmarkId, Criterion};
use nsplane_core::x25519::{PublicKey, StaticSecret};
use nsplane_core::{
    ConfigChange, Core, CoreConfig, Ecn, Event, Input, Output, PacketBuf, Path, PeerConfig, PeerId,
    TransportId, reasons,
};
use rand_core::OsRng;

/// Handshakes per second the responder tolerates: high enough that it never sends cookies.
const RATE_LIMIT: u64 = 1_000_000_000;

/// Path of core `i` (0 = initiator, 1 = responder).
fn path(i: u8) -> Path {
    Path {
        transport: TransportId::new(u16::from(i)),
        addr: SocketAddr::from((Ipv4Addr::new(192, 0, 2, i + 1), 51820)),
        ecn: Ecn::NotEct,
    }
}

/// A core with `key` as its default identity.
fn core(key: StaticSecret) -> Core {
    Core::new(CoreConfig {
        private_key: Some(key),
        handshake_rate_limit: RATE_LIMIT,
        ..CoreConfig::default()
    })
}

/// A responder with `n` keyed identities that knows `initiator` as a peer of the last one;
/// returns the responder and the public key of that identity.
fn responder(n: usize, initiator: PublicKey) -> (Core, PublicKey) {
    let key = StaticSecret::random_from_rng(OsRng);
    let mut own = PublicKey::from(&key);
    let mut core = core(key);
    let mut config = PeerConfig::new(initiator);
    for _ in 1..n {
        let key = StaticSecret::random_from_rng(OsRng);
        own = PublicKey::from(&key);
        config.local_identity = Some(core.add_local_identity(key).unwrap());
    }
    core.handle_input(
        Input::Config(ConfigChange::AddOrUpdatePeer(config)),
        Instant::now(),
    );
    assert_eq!(core.local_identities().count(), n);
    (core, own)
}

/// An initiator with `key` and a peer for `responder` at `path(1)`, and that peer's id.
fn initiator(key: StaticSecret, responder: PublicKey) -> (Core, PeerId) {
    let mut core = core(key);
    let mut config = PeerConfig::new(responder);
    config.path = Some(path(1));
    core.handle_input(
        Input::Config(ConfigChange::AddOrUpdatePeer(config)),
        Instant::now(),
    );
    let peer = core.peer_id(&responder).unwrap();
    (core, peer)
}

/// A fresh handshake initiation from `core` to `peer`.
fn initiation(core: &mut Core, peer: PeerId) -> PacketBuf {
    core.force_handshake(peer, None, Instant::now());
    let mut datagram = None;
    while let Some(output) = core.poll_output() {
        if let Output::Transmit { data, .. } = output {
            assert!(datagram.replace(data).is_none(), "one initiation");
        }
    }
    datagram.unwrap()
}

/// Feeds `data` to `core` from `path(0)` and returns what it answers: the response, or the
/// reason it dropped the datagram.
fn receive(core: &mut Core, data: PacketBuf) -> Result<PacketBuf, &'static str> {
    core.handle_input(
        Input::Datagram {
            path: path(0),
            data,
        },
        Instant::now(),
    );
    let mut answer = Err("no output");
    while let Some(output) = core.poll_output() {
        match output {
            Output::Transmit { data, .. } => answer = Ok(data),
            Output::Event(Event::Dropped { reason, .. }) => answer = Err(reason),
            Output::Deliver { packet, .. } => core.recycle(packet),
            _ => {}
        }
    }
    answer
}

fn bench_handshake(c: &mut Criterion) {
    let mut group = c.benchmark_group("handshake");

    for n in [1, 4, 16] {
        group.bench_function(BenchmarkId::new("initiation", n), |b| {
            let key = StaticSecret::random_from_rng(OsRng);
            let (mut rx, own) = responder(n, PublicKey::from(&key));
            let (mut tx, peer) = initiator(key, own);
            b.iter_batched(
                || initiation(&mut tx, peer),
                |data| {
                    let response = receive(&mut rx, data).unwrap();
                    rx.recycle(response);
                },
                BatchSize::SmallInput,
            );
        });
    }

    group.bench_function(BenchmarkId::new("no_match", 16), |b| {
        let key = StaticSecret::random_from_rng(OsRng);
        let (mut rx, _) = responder(16, PublicKey::from(&key));
        let stranger = PublicKey::from(&StaticSecret::random_from_rng(OsRng));
        let (mut tx, peer) = initiator(key, stranger);
        let data = initiation(&mut tx, peer);
        b.iter_batched(
            || PacketBuf::from_packet(data.as_packet()),
            |data| {
                assert_eq!(
                    receive(&mut rx, data).err(),
                    Some(reasons::UNKNOWN_LOCAL_IDENTITY)
                );
            },
            BatchSize::SmallInput,
        );
    });

    group.finish();
}

criterion::criterion_group!(handshake, bench_handshake);
criterion::criterion_main!(handshake);
