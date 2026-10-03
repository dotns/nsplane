//! The deferred data path: `Core::handle_input_deferred` hands out the cryptography of data
//! packets as jobs that run on other threads, `Core::complete_job` finishes them.

#![allow(clippy::unwrap_used, clippy::panic, reason = "test harness")]

mod common;

use std::collections::BTreeMap;
use std::thread;

use common::{InFlight, Net, ip4, packet_buf, udp4};
use nsplane_core::{ConfigChange, CryptoJob, Event, Input, PeerId, reasons};

const fn assert_send<T: Send>() {}
const _: () = assert_send::<CryptoJob>();

/// Feeds `inputs` to core `i` deferred, runs the jobs of each peer on a thread of its own,
/// in order, and completes them peer by peer.
fn run_deferred(net: &mut Net, i: usize, inputs: Vec<Input>) {
    let now = net.now;
    let mut by_peer: BTreeMap<PeerId, Vec<CryptoJob>> = BTreeMap::new();
    for input in inputs {
        if let Some(job) = net.cores[i].handle_input_deferred(input, now) {
            by_peer.entry(job.peer()).or_default().push(job);
        }
    }
    thread::scope(|scope| {
        for jobs in by_peer.values_mut() {
            scope.spawn(|| jobs.iter_mut().for_each(CryptoJob::run));
        }
    });
    for job in by_peer.into_values().flatten() {
        net.cores[i].complete_job(job);
    }
}

/// Moves datagrams like `Net::pump`, every core receiving deferred.
fn pump_deferred(net: &mut Net) {
    loop {
        let in_flight = net.drain();
        if in_flight.is_empty() {
            return;
        }
        let mut inputs: Vec<Vec<Input>> = (0..net.cores.len()).map(|_| Vec::new()).collect();
        for InFlight {
            path,
            arrival,
            data,
            ..
        } in in_flight
        {
            let to = net.paths.iter().position(|p| p.addr == path.addr).unwrap();
            inputs[to].push(Input::Datagram {
                path: arrival,
                data,
            });
        }
        for (i, inputs) in inputs.into_iter().enumerate() {
            run_deferred(net, i, inputs);
        }
    }
}

/// A numbered packet from core `i` to core `j`.
fn numbered(i: usize, j: usize, n: u32) -> Vec<u8> {
    udp4(ip4(i), ip4(j), &n.to_be_bytes())
}

#[test]
fn deferred_jobs_keep_every_peer_in_order() {
    let mut net = Net::new(3);
    net.handshake(0, 1);
    net.handshake(0, 2);
    net.clear_logs();

    let mut sent = Vec::new();
    let inputs = (0..64)
        .flat_map(|n| [1, 2].map(|j| (j, numbered(0, j, n))))
        .map(|(j, packet)| {
            sent.push((j, packet.clone()));
            Input::Local {
                packet: packet_buf(&packet),
            }
        })
        .collect();
    run_deferred(&mut net, 0, inputs);
    pump_deferred(&mut net);

    for j in [1, 2] {
        let expected: Vec<_> = sent
            .iter()
            .filter(|(to, _)| *to == j)
            .map(|(_, packet)| (net.peer_id(j, 0), packet.clone()))
            .collect();
        assert_eq!(net.take_delivered(j), expected, "core {j}");
        assert_eq!(net.take_events(j), [], "the data path is event-free");
        let stats = net.cores[j].peer_stats(net.peer_id(j, 0)).unwrap();
        let bytes: usize = expected.iter().map(|(_, p)| p.len()).sum();
        assert_eq!(stats.data_rx, bytes as u64);
        let sender = net.cores[0].peer_stats(net.peer_id(0, j)).unwrap();
        assert_eq!(sender.data_tx, bytes as u64);
    }
    assert_eq!(net.take_events(0), []);
}

#[test]
fn a_deferred_packet_without_session_starts_the_handshake() {
    let mut net = Net::new(2);
    let packet = numbered(0, 1, 7);
    run_deferred(
        &mut net,
        0,
        vec![Input::Local {
            packet: packet_buf(&packet),
        }],
    );
    pump_deferred(&mut net);
    assert_eq!(net.take_delivered(1), [(net.peer_id(1, 0), packet)]);
    for i in [0, 1] {
        let events = net.take_events(i);
        assert!(
            events
                .iter()
                .any(|e| matches!(e, Event::HandshakeCompleted { .. })),
            "core {i}: {events:?}"
        );
    }
}

#[test]
fn complete_job_runs_a_job_that_did_not_run() {
    let mut net = Net::new(2);
    net.handshake(0, 1);
    net.clear_logs();
    let packet = numbered(0, 1, 1);
    let now = net.now;
    let job = net.cores[0]
        .handle_input_deferred(
            Input::Local {
                packet: packet_buf(&packet),
            },
            now,
        )
        .unwrap();
    assert_eq!(job.peer(), net.peer_id(0, 1));
    net.cores[0].complete_job(job);
    net.pump();
    assert_eq!(net.take_delivered(1), [(net.peer_id(1, 0), packet)]);
}

#[test]
fn drops_before_the_cryptography_need_no_job() {
    let mut net = Net::new(2);
    net.handshake(0, 1);
    net.clear_logs();
    let now = net.now;
    let unrouted = udp4(ip4(0), ip4(9), b"nowhere");
    let job = net.cores[0].handle_input_deferred(
        Input::Local {
            packet: packet_buf(&unrouted),
        },
        now,
    );
    assert!(job.is_none());
    net.drain();
    assert_eq!(
        net.take_events(0),
        [Event::Dropped {
            peer: None,
            reason: reasons::NO_ROUTE
        }]
    );
}

#[test]
fn a_job_of_a_removed_peer_is_discarded() {
    let mut net = Net::new(2);
    net.handshake(0, 1);
    net.clear_logs();
    let now = net.now;
    let mut job = net.cores[0]
        .handle_input_deferred(
            Input::Local {
                packet: packet_buf(&numbered(0, 1, 1)),
            },
            now,
        )
        .unwrap();
    job.run();
    let key = net.public_key(1);
    net.configure(0, ConfigChange::RemovePeer(key));
    net.cores[0].complete_job(job);
    assert_eq!(net.drain().len(), 0);
    assert_eq!(net.take_events(0), []);
}
