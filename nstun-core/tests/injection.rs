//! Packet injection: `inject_inbound` delivers without filters, `inject_outbound` encrypts
//! without them, before and after a session exists.

#![allow(clippy::unwrap_used, clippy::panic, reason = "test harness")]

mod common;

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use common::{Net, ip4, ip6, packet_buf, udp4, udp6};
use nstun_core::{CoreConfig, Event, PacketBuf, PacketFilter, PeerId, Verdict};

/// Drops every packet in both directions and counts its calls.
#[derive(Debug)]
struct DropAll(Arc<AtomicUsize>);

impl PacketFilter for DropAll {
    fn inbound(&self, _peer: PeerId, _packet: &mut PacketBuf) -> Verdict {
        self.0.fetch_add(1, Ordering::Relaxed);
        Verdict::Drop { reason: "drop all" }
    }

    fn outbound(&self, _peer: PeerId, _packet: &mut PacketBuf) -> Verdict {
        self.0.fetch_add(1, Ordering::Relaxed);
        Verdict::Drop { reason: "drop all" }
    }
}

/// Two cores; core `on` drops every packet that goes through its filters.
fn net_dropping_on(on: usize) -> (Net, Arc<AtomicUsize>) {
    let calls = Arc::new(AtomicUsize::new(0));
    let net = Net::with_configs(2, |i| CoreConfig {
        filters: if i == on {
            vec![Box::new(DropAll(Arc::clone(&calls)))]
        } else {
            Vec::new()
        },
        ..CoreConfig::default()
    });
    (net, calls)
}

#[test]
fn inject_inbound_delivers_without_filters() {
    let (mut net, calls) = net_dropping_on(1);
    let b_to_a = net.peer_id(1, 0);

    let packet = udp4(ip4(0), ip4(1), b"injected");
    net.cores[1].inject_inbound(b_to_a, packet_buf(&packet));
    net.pump();
    assert_eq!(net.take_delivered(1), [(b_to_a, packet)]);
    assert_eq!(net.take_events(1), []);
    assert_eq!(net.take_transmits(1), []);
    assert_eq!(calls.load(Ordering::Relaxed), 0);
}

#[test]
fn inject_outbound_bypasses_the_filters() {
    let (mut net, calls) = net_dropping_on(0);
    let b_to_a = net.peer_id(1, 0);
    net.handshake(0, 1);
    net.clear_logs();

    // The filter is in place: a regular local packet goes nowhere.
    net.ping4(0, 1, b"filtered");
    assert_eq!(net.take_delivered(1), []);
    assert_eq!(calls.load(Ordering::Relaxed), 1);
    net.clear_logs();

    for packet in [
        udp4(ip4(0), ip4(1), b"injected over v4"),
        udp6(ip6(0), ip6(1), b"injected over v6"),
    ] {
        net.cores[0].inject_outbound(packet_buf(&packet), net.now);
        net.pump();
        assert_eq!(net.take_transmits(0).len(), 1);
        assert_eq!(net.take_delivered(1), [(b_to_a, packet)]);
    }
    assert_eq!(net.take_events(0), []);
    assert_eq!(calls.load(Ordering::Relaxed), 1);
}

#[test]
fn inject_outbound_without_a_session_starts_a_handshake() {
    let (mut net, calls) = net_dropping_on(0);
    let b_to_a = net.peer_id(1, 0);

    let packet = udp4(ip4(0), ip4(1), b"queued behind the handshake");
    net.cores[0].inject_outbound(packet_buf(&packet), net.now);
    net.pump();
    assert_eq!(
        net.take_transmits(0)[0].data[0],
        1,
        "a handshake initiation"
    );
    assert_eq!(net.take_delivered(1), [(b_to_a, packet)]);
    assert!(
        net.take_events(0)
            .iter()
            .any(|e| matches!(e, Event::HandshakeCompleted { .. }))
    );
    assert_eq!(calls.load(Ordering::Relaxed), 0);
}
