//! The packet filter chain in both directions: verdicts, chain order, in-place rewrites and
//! the inbound source check that runs before it.

#![allow(clippy::unwrap_used, clippy::panic, reason = "test harness")]

mod common;

use std::net::Ipv4Addr;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use common::{Net, ip4, udp4};
use nstun_core::{CoreConfig, Event, PacketBuf, PacketFilter, PeerId, Verdict};
use nstun_packet::checksum;

/// Calls seen by a [`Fixed`] filter.
#[derive(Debug, Default)]
struct Calls {
    inbound: AtomicUsize,
    outbound: AtomicUsize,
}

impl Calls {
    fn get(&self) -> (usize, usize) {
        (
            self.inbound.load(Ordering::Relaxed),
            self.outbound.load(Ordering::Relaxed),
        )
    }
}

/// Returns the same verdict for every packet and counts its calls.
#[derive(Debug)]
struct Fixed {
    verdict: Verdict,
    calls: Arc<Calls>,
}

impl Fixed {
    fn boxed(verdict: Verdict) -> (Box<dyn PacketFilter>, Arc<Calls>) {
        let calls = Arc::new(Calls::default());
        let filter = Self {
            verdict,
            calls: Arc::clone(&calls),
        };
        (Box::new(filter), calls)
    }
}

impl PacketFilter for Fixed {
    fn inbound(&self, _peer: PeerId, _packet: &mut PacketBuf) -> Verdict {
        self.calls.inbound.fetch_add(1, Ordering::Relaxed);
        self.verdict
    }

    fn outbound(&self, _peer: PeerId, _packet: &mut PacketBuf) -> Verdict {
        self.calls.outbound.fetch_add(1, Ordering::Relaxed);
        self.verdict
    }
}

const DROP: Verdict = Verdict::Drop {
    reason: "test filter",
};

/// Two cores; core `on` runs `filters`.
fn net_with_filters(on: usize, mut filters: Vec<Box<dyn PacketFilter>>) -> Net {
    Net::with_configs(2, |i| CoreConfig {
        filters: if i == on {
            std::mem::take(&mut filters)
        } else {
            Vec::new()
        },
        ..CoreConfig::default()
    })
}

fn dropped(events: &[Event]) -> Vec<Event> {
    events
        .iter()
        .filter(|e| matches!(e, Event::Dropped { .. }))
        .cloned()
        .collect()
}

#[test]
fn inbound_verdicts() {
    for verdict in [Verdict::Accept, DROP, Verdict::Handled] {
        let (filter, calls) = Fixed::boxed(verdict);
        let mut net = net_with_filters(1, vec![filter]);
        let b_to_a = net.peer_id(1, 0);

        let packet = net.ping4(0, 1, b"inbound");
        let (delivered, drops) = match verdict {
            Verdict::Accept => (vec![(b_to_a, packet)], vec![]),
            Verdict::Drop { reason } => (
                vec![],
                vec![Event::Dropped {
                    peer: Some(b_to_a),
                    reason,
                }],
            ),
            Verdict::Handled => (vec![], vec![]),
        };
        assert_eq!(net.take_delivered(1), delivered, "{verdict:?}");
        assert_eq!(dropped(&net.take_events(1)), drops, "{verdict:?}");
        assert_eq!(calls.get(), (1, 0), "{verdict:?}");
    }
}

#[test]
fn outbound_verdicts() {
    for verdict in [Verdict::Accept, DROP, Verdict::Handled] {
        let (filter, calls) = Fixed::boxed(verdict);
        let mut net = net_with_filters(0, vec![filter]);
        let a_to_b = net.peer_id(0, 1);

        let packet = net.ping4(0, 1, b"outbound");
        let drops = match verdict {
            Verdict::Accept => {
                assert_ne!(net.take_transmits(0), [], "{verdict:?}");
                assert_eq!(net.take_delivered(1)[0].1, packet);
                vec![]
            }
            Verdict::Drop { reason } => vec![Event::Dropped {
                peer: Some(a_to_b),
                reason,
            }],
            Verdict::Handled => vec![],
        };
        if verdict != Verdict::Accept {
            // Not even a handshake: the packet never reached the tunnel.
            assert_eq!(net.take_transmits(0), [], "{verdict:?}");
            assert_eq!(net.take_delivered(1), [], "{verdict:?}");
        }
        assert_eq!(dropped(&net.take_events(0)), drops, "{verdict:?}");
        assert_eq!(calls.get(), (0, 1), "{verdict:?}");
    }
}

#[test]
fn the_first_verdict_other_than_accept_ends_the_chain() {
    for stop in [DROP, Verdict::Handled] {
        let (first, first_calls) = Fixed::boxed(Verdict::Accept);
        let (second, second_calls) = Fixed::boxed(stop);
        let (third, third_calls) = Fixed::boxed(Verdict::Accept);
        // Core 0 runs the chain outbound on its own packets and inbound on core 1's.
        let filters = vec![first, second, third];
        let mut net = net_with_filters(0, filters);

        net.ping4(0, 1, b"outbound");
        assert_eq!(first_calls.get(), (0, 1), "{stop:?}");
        assert_eq!(second_calls.get(), (0, 1), "{stop:?}");
        assert_eq!(third_calls.get(), (0, 0), "{stop:?}");
        assert_eq!(net.take_delivered(1), [], "{stop:?}");

        net.ping4(1, 0, b"inbound");
        assert_eq!(first_calls.get(), (1, 1), "{stop:?}");
        assert_eq!(second_calls.get(), (1, 1), "{stop:?}");
        assert_eq!(third_calls.get(), (0, 0), "{stop:?}");
        assert_eq!(net.take_delivered(0), [], "{stop:?}");
    }
}

/// Rewrites the UDP destination port of outbound IPv4 packets and decrements the TTL of
/// inbound ones, fixing the checksums.
#[derive(Debug)]
struct Rewrite;

const NEW_PORT: u16 = 9999;

fn set_dst_port(packet: &mut [u8], port: u16) {
    let src = Ipv4Addr::from(<[u8; 4]>::try_from(&packet[12..16]).unwrap());
    let dst = Ipv4Addr::from(<[u8; 4]>::try_from(&packet[16..20]).unwrap());
    packet[22..24].copy_from_slice(&port.to_be_bytes());
    packet[26..28].fill(0);
    let sum = checksum::transport_checksum_v4(src, dst, 17, &packet[20..]);
    packet[26..28].copy_from_slice(&sum.to_be_bytes());
}

fn decrement_ttl(packet: &mut [u8]) {
    packet[8] -= 1;
    let sum = checksum::ipv4_header_checksum(&packet[..20]);
    packet[10..12].copy_from_slice(&sum.to_be_bytes());
}

impl PacketFilter for Rewrite {
    fn inbound(&self, _peer: PeerId, packet: &mut PacketBuf) -> Verdict {
        decrement_ttl(packet.as_packet_mut());
        Verdict::Accept
    }

    fn outbound(&self, _peer: PeerId, packet: &mut PacketBuf) -> Verdict {
        set_dst_port(packet.as_packet_mut(), NEW_PORT);
        Verdict::Accept
    }
}

#[test]
fn outbound_filters_rewrite_in_place() {
    let mut net = net_with_filters(0, vec![Box::new(Rewrite)]);
    let mut expected = net.ping4(0, 1, b"rewritten on the way out");
    set_dst_port(&mut expected, NEW_PORT);

    let delivered = net.take_delivered(1);
    assert_eq!(delivered[0].1, expected);
    assert_eq!(delivered[0].1[22..24], NEW_PORT.to_be_bytes());
}

#[test]
fn inbound_filters_rewrite_in_place() {
    let mut net = net_with_filters(1, vec![Box::new(Rewrite)]);
    let mut expected = net.ping4(0, 1, b"rewritten on the way in");
    decrement_ttl(&mut expected);

    let delivered = net.take_delivered(1);
    assert_eq!(delivered[0].1, expected);
    assert_eq!(delivered[0].1[8], 63);
}

#[test]
fn spoofed_sources_are_dropped_before_the_filters() {
    let (filter, calls) = Fixed::boxed(Verdict::Accept);
    let mut net = net_with_filters(1, vec![filter]);
    let b_to_a = net.peer_id(1, 0);
    net.handshake(0, 1);
    net.clear_logs();

    // Core 0 routes by destination only; core 1 checks the source against core 0's allowed IPs.
    net.send_local(0, &udp4(Ipv4Addr::new(10, 0, 9, 9), ip4(1), b"spoofed"));
    net.pump();
    assert_eq!(net.take_delivered(1), []);
    assert_eq!(
        net.take_events(1),
        [Event::Dropped {
            peer: Some(b_to_a),
            reason: "source not allowed"
        }]
    );
    assert_eq!(calls.get(), (0, 0));
}
