//! The batched data path: `Core::handle_datagrams` and `Core::handle_locals` (and their
//! deferred variants) behave exactly like feeding every packet to `Core::handle_input` (or
//! `Core::handle_input_deferred`) one by one.

#![allow(clippy::unwrap_used, clippy::panic, reason = "test harness")]

mod common;

use std::collections::VecDeque;
use std::net::Ipv4Addr;
use std::time::Duration;

use common::{InFlight, Net, ip4, ip6, packet_buf, udp4, udp6};
use nsplane_core::x25519::PublicKey;
use nsplane_core::{
    Core, CoreConfig, CryptoJob, Event, Input, PacketBuf, Path, PeerId, PeerStats, reasons,
};

/// How a scenario feeds datagrams and local packets to the cores.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Mode {
    /// `handle_input`, one packet at a time.
    PerPacket,
    /// `handle_datagrams` and `handle_locals`.
    Batch,
    /// `handle_input_deferred`, one packet at a time, on cores with crypto jobs.
    PerPacketDeferred,
    /// `handle_datagrams_deferred` and `handle_locals_deferred`, on cores with crypto jobs.
    BatchDeferred,
}

impl Mode {
    const fn deferred(self) -> bool {
        matches!(self, Self::PerPacketDeferred | Self::BatchDeferred)
    }
}

/// What a scenario produced on each core, without the ciphertexts.
#[derive(Debug, PartialEq, Eq)]
struct Trace {
    delivered: Vec<Vec<(PeerId, Vec<u8>)>>,
    /// Events, with the measured handshake round trip times (taken on the real clock)
    /// cleared.
    events: Vec<Vec<Event>>,
    /// Paths and lengths of the transmitted datagrams.
    transmits: Vec<Vec<(Path, usize)>>,
    /// Stats of every peer of every core, with the (random) public keys cleared.
    stats: Vec<PeerStats>,
}

/// Runs the jobs, then completes them in order.
fn complete(core: &mut Core, mut jobs: Vec<CryptoJob>) {
    jobs.iter_mut().for_each(CryptoJob::run);
    for job in jobs {
        core.complete_job(job);
    }
}

/// Feeds `batch` to core `i` as received datagrams.
fn feed_datagrams(net: &mut Net, i: usize, batch: Vec<(Path, PacketBuf)>, mode: Mode) {
    let now = net.now;
    let core = &mut net.cores[i];
    match mode {
        Mode::PerPacket => {
            for (path, data) in batch {
                core.handle_input(Input::Datagram { path, data }, now);
            }
        }
        Mode::Batch => core.handle_datagrams(batch, now),
        Mode::PerPacketDeferred => {
            let jobs = batch
                .into_iter()
                .filter_map(|(path, data)| {
                    core.handle_input_deferred(Input::Datagram { path, data }, now)
                })
                .collect();
            complete(core, jobs);
        }
        Mode::BatchDeferred => {
            let mut jobs = Vec::new();
            core.handle_datagrams_deferred(batch, now, &mut jobs);
            complete(core, jobs);
        }
    }
}

/// Feeds `packets` to core `i` as local packets.
fn feed_locals(net: &mut Net, i: usize, packets: &[Vec<u8>], mode: Mode) {
    let now = net.now;
    let core = &mut net.cores[i];
    let batch = packets.iter().map(|p| packet_buf(p));
    match mode {
        Mode::PerPacket => {
            for packet in batch {
                core.handle_input(Input::Local { packet }, now);
            }
        }
        Mode::Batch => core.handle_locals(batch, now),
        Mode::PerPacketDeferred => {
            let jobs = batch
                .filter_map(|packet| core.handle_input_deferred(Input::Local { packet }, now))
                .collect();
            complete(core, jobs);
        }
        Mode::BatchDeferred => {
            let mut jobs = Vec::new();
            core.handle_locals_deferred(batch, now, &mut jobs);
            complete(core, jobs);
        }
    }
}

/// Hands the datagrams in flight to their receivers, one batch per receiver with the senders
/// interleaved round-robin.
fn deliver(net: &mut Net, in_flight: Vec<InFlight>, mode: Mode) {
    let n = net.cores.len();
    let mut queues: Vec<Vec<VecDeque<(Path, PacketBuf)>>> = (0..n)
        .map(|_| (0..n).map(|_| VecDeque::new()).collect())
        .collect();
    for InFlight {
        from,
        path,
        arrival,
        data,
    } in in_flight
    {
        let to = net.paths.iter().position(|p| p.addr == path.addr).unwrap();
        queues[to][from].push_back((arrival, data));
    }
    for (to, mut senders) in queues.into_iter().enumerate() {
        let mut batch = Vec::new();
        while senders.iter().any(|q| !q.is_empty()) {
            batch.extend(senders.iter_mut().filter_map(VecDeque::pop_front));
        }
        if !batch.is_empty() {
            feed_datagrams(net, to, batch, mode);
        }
    }
}

/// Moves datagrams until none is left in flight.
fn pump(net: &mut Net, mode: Mode) {
    loop {
        let in_flight = net.drain();
        if in_flight.is_empty() {
            return;
        }
        deliver(net, in_flight, mode);
    }
}

/// A numbered UDP/IPv4 packet from `src` to `dst`.
fn numbered(src: Ipv4Addr, dst: Ipv4Addr, n: u32) -> Vec<u8> {
    udp4(src, dst, &n.to_be_bytes())
}

/// Three cores; core 0 receives handshakes and data from cores 1 and 2 interleaved, with an
/// invalid datagram, an unknown session, a forbidden source and a re-handshake mixed in, and
/// sends to both peers with a packet that has no route.
fn scenario(mode: Mode) -> Trace {
    let mut net = Net::with_configs(3, |_| CoreConfig {
        crypto_jobs: mode.deferred(),
        ..CoreConfig::default()
    });
    let now = net.now;
    let peer = net.peer_id(1, 0);
    net.cores[1].force_handshake(peer, None, now);
    pump(&mut net, mode);

    // Data from core 1 (one packet from core 2's address), core 2's first handshake, an
    // invalid datagram and a datagram of an unknown session, all in one batch for core 0.
    let mut locals: Vec<Vec<u8>> = (0..4).map(|n| numbered(ip4(1), ip4(0), n)).collect();
    locals.insert(2, numbered(ip4(2), ip4(0), 99));
    feed_locals(&mut net, 1, &locals, mode);
    let peer = net.peer_id(2, 0);
    net.cores[2].force_handshake(peer, None, now);
    let mut in_flight = net.drain();
    let mut unknown = in_flight[0].data.as_packet().to_vec();
    // The receiver index without its session bits names no peer.
    unknown[6] ^= 0xff;
    for data in [&[9u8; 40][..], &unknown] {
        in_flight.insert(
            2,
            InFlight {
                from: 1,
                path: net.paths[0],
                arrival: net.paths[1],
                data: packet_buf(data),
            },
        );
    }
    deliver(&mut net, in_flight, mode);
    pump(&mut net, mode);

    // Core 0 sends to both peers, over IPv4 and IPv6, with a packet nobody owns.
    let locals = [
        numbered(ip4(0), ip4(1), 10),
        numbered(ip4(0), ip4(2), 11),
        numbered(ip4(0), ip4(1), 12),
        numbered(ip4(0), ip4(1), 13),
        numbered(ip4(0), Ipv4Addr::new(10, 9, 9, 9), 14),
        numbered(ip4(0), ip4(2), 15),
        udp6(ip6(0), ip6(1), b"v6"),
        numbered(ip4(0), ip4(2), 16),
    ];
    feed_locals(&mut net, 0, &locals, mode);
    pump(&mut net, mode);

    // Both peers send at once; core 1 starts a new handshake in the middle of its packets.
    let first: Vec<_> = (20..23).map(|n| numbered(ip4(1), ip4(0), n)).collect();
    feed_locals(&mut net, 1, &first, mode);
    let peer = net.peer_id(1, 0);
    net.cores[1].force_handshake(peer, None, now);
    let second: Vec<_> = (23..26).map(|n| numbered(ip4(1), ip4(0), n)).collect();
    feed_locals(&mut net, 1, &second, mode);
    let from_2: Vec<_> = (30..35).map(|n| numbered(ip4(2), ip4(0), n)).collect();
    feed_locals(&mut net, 2, &from_2, mode);
    pump(&mut net, mode);

    // Keepalives in both directions.
    net.advance(Duration::from_secs(11));
    pump(&mut net, mode);
    assert!(net.lost.is_empty());

    let mut stats = Vec::new();
    for i in 0..3 {
        for j in (0..3).filter(|&j| j != i) {
            stats.push(PeerStats {
                public_key: PublicKey::from([0; 32]),
                ..net.cores[i].peer_stats(net.peer_id(i, j)).unwrap()
            });
        }
    }
    Trace {
        delivered: (0..3).map(|i| net.take_delivered(i)).collect(),
        events: (0..3)
            .map(|i| {
                let mut events = net.take_events(i);
                for event in &mut events {
                    if let Event::HandshakeCompleted { rtt, .. } = event {
                        *rtt = None;
                    }
                }
                events
            })
            .collect(),
        transmits: (0..3)
            .map(|i| {
                net.take_transmits(i)
                    .iter()
                    .map(|t| (t.path, t.data.len()))
                    .collect()
            })
            .collect(),
        stats,
    }
}

/// Asserts that the scenario took every path it is meant to.
fn assert_covers(trace: &Trace) {
    let drops: Vec<_> = trace
        .events
        .iter()
        .flatten()
        .filter_map(|e| match e {
            Event::Dropped { reason, .. } => Some(*reason),
            _ => None,
        })
        .collect();
    for reason in [
        reasons::INVALID_PACKET,
        reasons::UNKNOWN_SESSION,
        reasons::SOURCE_NOT_ALLOWED,
        reasons::NO_ROUTE,
    ] {
        assert!(drops.contains(&reason), "{reason}: {drops:?}");
    }
    let senders: Vec<_> = trace.delivered[0].iter().map(|(from, _)| *from).collect();
    assert!(senders.len() > 10, "{senders:?}");
    assert!(
        senders.windows(2).any(|w| w[0] != w[1]),
        "interleaved peers: {senders:?}"
    );
    assert_eq!(trace.delivered[1].len(), 4);
    assert_eq!(trace.delivered[2].len(), 3);
    let keepalives = trace
        .transmits
        .iter()
        .flatten()
        .filter(|(_, len)| *len == 32)
        .count();
    assert!(keepalives > 0, "{:?}", trace.transmits);
}

#[test]
fn batches_behave_like_single_packets() {
    let single = scenario(Mode::PerPacket);
    assert_covers(&single);
    assert_eq!(single, scenario(Mode::Batch));
}

#[test]
fn deferred_batches_behave_like_deferred_single_packets() {
    let single = scenario(Mode::PerPacketDeferred);
    assert_covers(&single);
    assert_eq!(single, scenario(Mode::BatchDeferred));
}

#[test]
fn empty_batches_do_nothing() {
    for crypto_jobs in [false, true] {
        let mut core = Core::new(CoreConfig {
            crypto_jobs,
            ..CoreConfig::default()
        });
        let now = std::time::Instant::now();
        let mut jobs = Vec::new();
        core.handle_datagrams(Vec::new(), now);
        core.handle_locals(Vec::new(), now);
        core.handle_datagrams_deferred(Vec::new(), now, &mut jobs);
        core.handle_locals_deferred(Vec::new(), now, &mut jobs);
        assert!(jobs.is_empty());
        assert!(core.poll_output().is_none());
        assert_eq!(core.poll_timeout(), None, "the schedule did not start");

        let mut net = Net::with_configs(2, |_| CoreConfig {
            crypto_jobs,
            ..CoreConfig::default()
        });
        net.ping4(0, 1, b"hello");
        net.clear_logs();
        let peer = net.peer_id(1, 0);
        let stats = net.cores[1].peer_stats(peer);
        let later = net.now + Duration::from_secs(5);
        let core = &mut net.cores[1];
        core.handle_datagrams(Vec::new(), later);
        core.handle_locals(Vec::new(), later);
        core.handle_datagrams_deferred(Vec::new(), later, &mut jobs);
        core.handle_locals_deferred(Vec::new(), later, &mut jobs);
        assert!(jobs.is_empty());
        assert!(core.poll_output().is_none());
        assert_eq!(core.peer_stats(peer), stats, "the clock did not move");
    }
}
