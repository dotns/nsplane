//! The deferred data path: `Core::handle_input_deferred` hands out the cryptography of data
//! packets as jobs that run on other threads, `Core::complete_job` finishes them.

#![allow(clippy::unwrap_used, clippy::panic, reason = "test harness")]

mod common;

use std::collections::BTreeMap;
use std::thread;

use common::{InFlight, Net, ip4, packet_buf, udp4};
use nsplane_core::{ConfigChange, CoreConfig, CryptoJob, Event, Input, PeerId, reasons};

const fn assert_send<T: Send>() {}
const _: () = assert_send::<CryptoJob>();

/// `n` peered cores that hand out crypto jobs.
fn deferred_net(n: usize) -> Net {
    Net::with_configs(n, |_| CoreConfig {
        crypto_jobs: true,
        ..CoreConfig::default()
    })
}

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
    let mut net = deferred_net(3);
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
    let mut net = deferred_net(2);
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
    let mut net = deferred_net(2);
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
    let mut net = deferred_net(2);
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
    let mut net = deferred_net(2);
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

#[test]
fn a_core_without_crypto_jobs_processes_deferred_inputs_at_once() {
    let mut net = Net::new(2);
    net.handshake(0, 1);
    net.clear_logs();
    let now = net.now;
    let packet = numbered(0, 1, 1);
    let job = net.cores[0].handle_input_deferred(
        Input::Local {
            packet: packet_buf(&packet),
        },
        now,
    );
    assert!(job.is_none());
    let in_flight = net.drain();
    assert_eq!(in_flight.len(), 1, "sealed at once");
    for datagram in in_flight {
        let job = net.cores[1].handle_input_deferred(
            Input::Datagram {
                path: datagram.arrival,
                data: datagram.data,
            },
            now,
        );
        assert!(job.is_none());
    }
    net.drain();
    assert_eq!(net.take_delivered(1), [(net.peer_id(1, 0), packet)]);
    assert_eq!(net.take_events(0), []);
    assert_eq!(net.take_events(1), []);
}

/// Feeds `inputs` to core `i` deferred and returns the jobs, in the order handed out.
fn hand_out(net: &mut Net, i: usize, inputs: Vec<Input>) -> Vec<CryptoJob> {
    let now = net.now;
    inputs
        .into_iter()
        .filter_map(|input| net.cores[i].handle_input_deferred(input, now))
        .collect()
}

/// Runs `jobs` on four threads, each job on thread `n % 4` and every thread backwards, so
/// they finish out of order whatever the scheduling.
fn run_out_of_order(jobs: &mut [CryptoJob]) {
    let mut shares: Vec<Vec<&mut CryptoJob>> = (0..4).map(|_| Vec::new()).collect();
    for (n, job) in jobs.iter_mut().enumerate() {
        shares[n % 4].push(job);
    }
    thread::scope(|scope| {
        for share in &mut shares {
            scope.spawn(|| share.iter_mut().rev().for_each(|job| job.run()));
        }
    });
}

/// Hands out the datagrams in flight to their cores as jobs, runs them out of order and
/// completes them in order.
fn deliver_out_of_order(net: &mut Net) {
    let in_flight = net.drain();
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
        let mut jobs = hand_out(net, i, inputs);
        run_out_of_order(&mut jobs);
        for job in jobs {
            net.cores[i].complete_job(job);
        }
    }
    net.drain();
}

/// The counter (nonce) of every transport data message core `i` transmitted so far.
fn sent_counters(net: &mut Net, i: usize) -> Vec<u64> {
    net.take_transmits(i)
        .iter()
        .map(|sent| u64::from_le_bytes(sent.data[8..16].try_into().unwrap()))
        .collect()
}

fn locals(packets: &[Vec<u8>]) -> Vec<Input> {
    packets
        .iter()
        .map(|packet| Input::Local {
            packet: packet_buf(packet),
        })
        .collect()
}

#[test]
fn jobs_that_run_out_of_order_complete_in_order() {
    let mut net = deferred_net(2);
    net.handshake(0, 1);
    net.clear_logs();
    let packets: Vec<_> = (0..64).map(|n| numbered(0, 1, n)).collect();

    let mut jobs = hand_out(&mut net, 0, locals(&packets));
    run_out_of_order(&mut jobs);
    for job in jobs {
        net.cores[0].complete_job(job);
    }
    deliver_out_of_order(&mut net);

    let counters = sent_counters(&mut net, 0);
    assert!(
        counters.windows(2).all(|w| w[1] == w[0] + 1),
        "{counters:?}"
    );
    let from = net.peer_id(1, 0);
    let expected: Vec<_> = packets.into_iter().map(|p| (from, p)).collect();
    assert_eq!(net.take_delivered(1), expected);
    assert_eq!(net.take_events(0), []);
    assert_eq!(net.take_events(1), []);
}

#[test]
fn a_duplicate_opened_alongside_the_original_is_rejected() {
    let mut net = deferred_net(2);
    net.handshake(0, 1);
    net.clear_logs();
    let packet = numbered(0, 1, 1);
    net.send_local(0, &packet);
    let datagram = net.drain().pop().unwrap();
    let copy = packet_buf(datagram.data.as_packet());
    let inputs = vec![
        Input::Datagram {
            path: datagram.arrival,
            data: datagram.data,
        },
        Input::Datagram {
            path: datagram.arrival,
            data: copy,
        },
    ];
    // Both are handed out before either is completed, so both pass the replay check.
    let mut jobs = hand_out(&mut net, 1, inputs);
    assert_eq!(jobs.len(), 2);
    run_out_of_order(&mut jobs);
    for job in jobs {
        net.cores[1].complete_job(job);
    }
    net.drain();
    assert_eq!(net.take_delivered(1), [(net.peer_id(1, 0), packet)]);
    assert_eq!(
        net.take_events(1),
        [Event::Dropped {
            peer: Some(net.peer_id(1, 0)),
            reason: reasons::DECAPSULATE_ERROR
        }]
    );
}

#[test]
fn jobs_in_flight_during_a_rekey_keep_their_session() {
    let mut net = deferred_net(2);
    net.handshake(0, 1);
    net.clear_logs();
    let packets: Vec<_> = (0..16).map(|n| numbered(0, 1, n)).collect();
    let mut jobs = hand_out(&mut net, 0, locals(&packets));
    let mut back = hand_out(&mut net, 1, locals(&[numbered(1, 0, 0)]));
    // Both sides rekey while the jobs are out.
    net.handshake(0, 1);
    net.handshake(1, 0);
    net.clear_logs();
    run_out_of_order(&mut jobs);
    run_out_of_order(&mut back);
    for job in jobs {
        net.cores[0].complete_job(job);
    }
    for job in back {
        net.cores[1].complete_job(job);
    }
    deliver_out_of_order(&mut net);
    let expected: Vec<_> = packets
        .into_iter()
        .map(|p| (net.peer_id(1, 0), p))
        .collect();
    assert_eq!(net.take_delivered(1), expected);
    assert_eq!(
        net.take_delivered(0),
        [(net.peer_id(0, 1), numbered(1, 0, 0))]
    );
    assert_eq!(net.take_events(0), []);
    assert_eq!(net.take_events(1), []);
}

#[test]
fn jobs_of_a_cleared_session_are_dropped_and_counted() {
    let mut net = deferred_net(2);
    net.handshake(0, 1);
    net.clear_logs();
    let mut seal = hand_out(&mut net, 0, locals(&[numbered(0, 1, 1)]));
    net.send_local(1, &numbered(1, 0, 1));
    let inputs = net
        .drain()
        .into_iter()
        .map(|d| Input::Datagram {
            path: d.arrival,
            data: d.data,
        })
        .collect();
    let mut open = hand_out(&mut net, 0, inputs);
    run_out_of_order(&mut seal);
    run_out_of_order(&mut open);
    // A new private key clears every session while the jobs are out.
    let key = nsplane_core::x25519::StaticSecret::from([42; 32]);
    net.configure(0, ConfigChange::SetPrivateKey(key));
    net.clear_logs();
    for job in seal.into_iter().chain(open) {
        net.cores[0].complete_job(job);
    }
    let in_flight = net.drain();
    assert!(in_flight.is_empty());
    assert_eq!(net.take_delivered(0), []);
    let peer = Some(net.peer_id(0, 1));
    assert_eq!(
        net.take_events(0),
        [
            Event::Dropped {
                peer,
                reason: reasons::ENCAPSULATE_ERROR
            },
            Event::Dropped {
                peer,
                reason: reasons::DECAPSULATE_ERROR
            }
        ]
    );
}

#[test]
fn a_cancelled_job_skips_its_counter() {
    let mut net = deferred_net(2);
    net.handshake(0, 1);
    net.clear_logs();
    let packets: Vec<_> = (0..6).map(|n| numbered(0, 1, n)).collect();
    let mut jobs = hand_out(&mut net, 0, locals(&packets[..3]));
    // Dropped instead of completed, e.g. when its worker is gone.
    drop(jobs.remove(1));
    jobs.extend(hand_out(&mut net, 0, locals(&packets[3..])));
    run_out_of_order(&mut jobs);
    for job in jobs {
        net.cores[0].complete_job(job);
    }
    // An inline packet takes the next counter too.
    net.send_local(0, &numbered(0, 1, 6));
    deliver_out_of_order(&mut net);

    let counters = sent_counters(&mut net, 0);
    let first = counters[0];
    assert_eq!(
        counters,
        [first, first + 2, first + 3, first + 4, first + 5, first + 6]
    );
    let delivered: Vec<_> = net.take_delivered(1).into_iter().map(|(_, p)| p).collect();
    let mut expected = packets;
    expected.remove(1);
    expected.push(numbered(0, 1, 6));
    assert_eq!(delivered, expected);
    assert_eq!(net.take_events(1), []);
}
