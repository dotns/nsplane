//! Two cores on the fake clock: handshake, data in both directions, keepalives, drops and
//! buffer reuse.

#![allow(clippy::unwrap_used, clippy::panic, reason = "test harness")]

mod common;

use std::net::Ipv4Addr;
use std::time::Duration;

use common::{Net, ip4, packet_buf, udp4};
use nsplane_core::{Event, Input, Output, PacketBuf};

/// Start of the buffer behind `buf`, to tell allocations apart.
fn base(buf: &mut PacketBuf) -> *const u8 {
    buf.with_headroom_mut().as_ptr()
}

fn handshakes(events: &[Event]) -> Vec<&Event> {
    events
        .iter()
        .filter(|e| matches!(e, Event::HandshakeCompleted { .. }))
        .collect()
}

#[test]
fn handshake_and_data_in_both_directions() {
    let mut net = Net::new(2);
    let (a_to_b, b_to_a) = (net.peer_id(0, 1), net.peer_id(1, 0));

    // The first packet is queued behind the handshake and flushed once it completes.
    let packet = net.ping4(0, 1, b"hello over v4");
    assert_eq!(net.take_delivered(1), [(b_to_a, packet)]);

    let events = net.take_events(0);
    let [Event::HandshakeCompleted { peer, path, rtt }] = handshakes(&events)[..] else {
        panic!("one handshake on the initiator: {events:?}");
    };
    assert_eq!((*peer, *path), (a_to_b, Some(net.paths[1])));
    assert!(rtt.is_some(), "the initiator measures the rtt");
    let events = net.take_events(1);
    let [Event::HandshakeCompleted { peer, path, .. }] = handshakes(&events)[..] else {
        panic!("one handshake on the responder: {events:?}");
    };
    assert_eq!((*peer, *path), (b_to_a, Some(net.paths[0])));
    // The configured paths match the arrival paths: no roaming, no drops.
    assert_eq!(handshakes(&events).len(), events.len(), "{events:?}");

    let packet = net.ping4(1, 0, b"and back");
    assert_eq!(net.take_delivered(0), [(a_to_b, packet)]);
    let packet = net.ping6(0, 1, b"hello over v6");
    assert_eq!(net.take_delivered(1), [(b_to_a, packet)]);
    let packet = net.ping6(1, 0, b"and back over v6");
    assert_eq!(net.take_delivered(0), [(a_to_b, packet)]);

    for (i, j) in [(0, 1), (1, 0)] {
        assert!(net.take_events(i).is_empty(), "the data path is event-free");
        let transmits = net.take_transmits(i);
        assert_ne!(transmits.len(), 0);
        assert!(transmits.iter().all(|t| t.path == net.paths[j]));
    }

    let stats = net.cores[1].peer_stats(b_to_a).unwrap();
    assert_eq!(stats.path, Some(net.paths[0]));
    assert!(stats.data_rx > 0 && stats.rx > 0 && stats.tx > 0);
    assert!(stats.last_handshake.is_some());
}

#[test]
fn keepalives_are_not_delivered() {
    let mut net = Net::new(2);
    net.handshake(0, 1);

    // The initiator confirms the handshake with a keepalive.
    let transmits = net.take_transmits(0);
    assert_eq!(transmits.last().unwrap().data.len(), 32);
    assert_eq!(net.take_delivered(1), Vec::new());
    assert_eq!(handshakes(&net.take_events(0)).len(), 1);
    assert_eq!(handshakes(&net.take_events(1)).len(), 1);

    // Data left unanswered is acknowledged by a passive keepalive.
    net.ping4(0, 1, b"ping");
    assert_eq!(net.take_delivered(1).len(), 1);
    net.clear_logs();
    net.run_for(Duration::from_secs(11));
    let transmits = net.take_transmits(1);
    assert!(
        transmits.iter().any(|t| t.data.len() == 32),
        "{transmits:?}"
    );
    assert_eq!(net.take_delivered(0), Vec::new());
    assert_eq!(net.take_delivered(1), Vec::new());
}

#[test]
fn packets_without_a_route_are_dropped() {
    let mut net = Net::new(2);
    net.send_local(0, &udp4(ip4(0), Ipv4Addr::new(10, 9, 9, 9), b"nowhere"));
    net.pump();

    assert_eq!(
        net.take_events(0),
        [Event::Dropped {
            peer: None,
            reason: "no route"
        }]
    );
    assert_eq!(net.take_transmits(0), Vec::new());
}

#[test]
fn steady_state_reuses_buffers() {
    let mut net = Net::new(2);
    net.ping4(0, 1, b"warm up");
    net.ping4(1, 0, b"warm up");
    net.clear_logs();
    let now = net.now;

    // Outbound: the local packet is sealed in its own buffer.
    let send = |net: &mut Net| {
        let mut packet = packet_buf(&udp4(ip4(0), ip4(1), b"steady"));
        let local = base(&mut packet);
        net.cores[0].handle_input(Input::Local { packet }, now);
        let Some(Output::Transmit { mut data, .. }) = net.cores[0].poll_output() else {
            panic!("expected a transmit");
        };
        assert_eq!(base(&mut data), local);
        data
    };

    // Inbound: the datagram is opened in its buffer and delivered from it.
    let mut datagram = send(&mut net);
    let wire = base(&mut datagram);
    let arrival = net.paths[0];
    net.cores[1].handle_input(
        Input::Datagram {
            path: arrival,
            data: &mut datagram,
        },
        now,
    );
    let Some(Output::Deliver { mut packet, .. }) = net.cores[1].poll_output() else {
        panic!("expected a deliver");
    };
    let delivered = base(&mut packet);
    assert_eq!(delivered, wire);
    assert_ne!(base(&mut datagram), wire, "the caller got a fresh buffer");

    // A recycled buffer is what the next datagram is swapped for.
    net.cores[1].recycle(packet);
    let mut datagram = send(&mut net);
    net.cores[1].handle_input(
        Input::Datagram {
            path: arrival,
            data: &mut datagram,
        },
        now,
    );
    assert_eq!(base(&mut datagram), delivered);
    assert!(matches!(
        net.cores[1].poll_output(),
        Some(Output::Deliver { .. })
    ));
}
