//! Receiving is headroom-agnostic: datagrams sliced out of a shared receive buffer (one GRO
//! read) with any headroom, or none, are opened and delivered in place.

#![allow(clippy::unwrap_used, clippy::panic, reason = "test harness")]

mod common;

use std::time::Duration;

use common::{Net, ip4, udp4};
use nsplane_core::noise::DATA_HEADER_SZ;
use nsplane_core::{Event, Output, PacketBuf, reasons};
use nsplane_packet::HEADROOM;

/// Two peered cores past their handshake, with empty logs.
fn warm_net() -> Net {
    let mut net = Net::new(2);
    net.ping4(0, 1, b"warm up");
    net.ping4(1, 0, b"warm up");
    net.clear_logs();
    net
}

/// Seals `packet` on core 0 and returns the datagram it transmits.
fn seal(net: &mut Net, packet: &[u8]) -> Vec<u8> {
    net.send_local(0, packet);
    let Some(Output::Transmit { data, .. }) = net.cores[0].poll_output() else {
        panic!("expected a transmit");
    };
    data.as_packet().to_vec()
}

/// Feeds `datagram` to core 1 as a datagram from core 0 and returns its outputs.
fn open(net: &mut Net, datagram: PacketBuf) -> Vec<Output> {
    let arrival = net.paths[0];
    net.receive(1, arrival, datagram);
    std::iter::from_fn(|| net.cores[1].poll_output()).collect()
}

#[test]
fn any_headroom_is_opened_in_place() {
    let mut net = warm_net();
    let b_to_a = net.peer_id(1, 0);

    for headroom in [0, 16, HEADROOM] {
        let ip = udp4(ip4(0), ip4(1), format!("headroom {headroom}").as_bytes());
        let wire = seal(&mut net, &ip);

        // The datagram sits behind `headroom` bytes of a buffer it does not own alone.
        let mut raw = PacketBuf::with_capacity(headroom + wire.len()).into_bytes();
        raw.resize(headroom, 0xAA);
        raw.extend_from_slice(&wire);
        let datagram = PacketBuf::from_shared(raw, headroom, wire.len()).unwrap();
        assert_eq!(datagram.headroom(), headroom);
        let start = datagram.as_packet().as_ptr();

        let outputs = open(&mut net, datagram);
        let [Output::Deliver { from, packet }] = &outputs[..] else {
            panic!("headroom {headroom}: expected one deliver: {outputs:?}");
        };
        assert_eq!(*from, b_to_a);
        assert_eq!(packet.as_packet(), ip, "headroom {headroom}");
        assert_eq!(
            packet.as_packet().as_ptr(),
            start.wrapping_add(DATA_HEADER_SZ),
            "headroom {headroom}: delivered in place"
        );
    }
}

#[test]
fn gro_train_is_opened_in_place() {
    let mut net = warm_net();
    let b_to_a = net.peer_id(1, 0);

    let packets: Vec<Vec<u8>> = [1, 64, 1000, 1420]
        .into_iter()
        .map(|n| udp4(ip4(0), ip4(1), &vec![u8::try_from(n % 251).unwrap(); n]))
        .collect();
    let wires: Vec<Vec<u8>> = packets.iter().map(|p| seal(&mut net, p)).collect();

    // One GRO read: the datagrams back to back in one allocation, split into slices
    // without headroom.
    let total = wires.iter().map(Vec::len).sum();
    let mut train = PacketBuf::with_capacity(total).into_bytes();
    for wire in &wires {
        train.extend_from_slice(wire);
    }
    let base = train.as_ptr();
    let mut offset = 0;
    for (wire, ip) in wires.iter().zip(&packets) {
        let datagram = PacketBuf::from_shared(train.split_to(wire.len()), 0, wire.len()).unwrap();
        assert_eq!(datagram.headroom(), 0);
        assert_eq!(datagram.as_packet().as_ptr(), base.wrapping_add(offset));

        let outputs = open(&mut net, datagram);
        let [Output::Deliver { from, packet }] = &outputs[..] else {
            panic!("expected one deliver: {outputs:?}");
        };
        assert_eq!(*from, b_to_a);
        assert_eq!(packet.as_packet(), *ip);
        assert_eq!(
            packet.as_packet().as_ptr(),
            base.wrapping_add(offset + DATA_HEADER_SZ),
            "delivered in place in the train"
        );
        offset += wire.len();
    }
    assert!(train.is_empty());
}

#[test]
fn gro_train_drops_only_the_corrupt_datagram() {
    let mut net = warm_net();
    let b_to_a = net.peer_id(1, 0);

    // Core 0 received data and sent nothing since: its timers send a passive keepalive.
    net.now += Duration::from_secs(11);
    net.cores[0].handle_timeout(net.now);
    let mut keepalive = None;
    while let Some(output) = net.cores[0].poll_output() {
        if let Output::Transmit { data, .. } = output {
            keepalive = Some(data.as_packet().to_vec());
        }
    }
    let Some(keepalive) = keepalive else {
        panic!("expected a passive keepalive");
    };
    assert_eq!(keepalive.len(), 32);

    let first = udp4(ip4(0), ip4(1), b"before");
    let last = udp4(ip4(0), ip4(1), b"after");
    let first_wire = seal(&mut net, &first);
    let mut corrupt = seal(&mut net, &udp4(ip4(0), ip4(1), b"corrupt"));
    let last_wire = seal(&mut net, &last);
    *corrupt.last_mut().unwrap() ^= 0x01;

    let wires = [first_wire, keepalive, corrupt, last_wire];
    let total = wires.iter().map(Vec::len).sum();
    let mut train = PacketBuf::with_capacity(total).into_bytes();
    for wire in &wires {
        train.extend_from_slice(wire);
    }
    let mut outputs = Vec::new();
    for wire in &wires {
        let datagram = PacketBuf::from_shared(train.split_to(wire.len()), 0, wire.len()).unwrap();
        outputs.extend(open(&mut net, datagram));
    }

    let [
        Output::Deliver {
            from: from_first,
            packet: delivered_first,
        },
        Output::Event(dropped),
        Output::Deliver {
            from: from_last,
            packet: delivered_last,
        },
    ] = &outputs[..]
    else {
        panic!("expected deliver, drop, deliver: {outputs:?}");
    };
    assert_eq!((*from_first, *from_last), (b_to_a, b_to_a));
    assert_eq!(delivered_first.as_packet(), first);
    assert_eq!(delivered_last.as_packet(), last);
    assert_eq!(
        *dropped,
        Event::Dropped {
            peer: Some(b_to_a),
            reason: reasons::DECAPSULATE_ERROR
        }
    );
}

/// A datagram truncated below the data header, sliced out of a train, is dropped as invalid
/// without disturbing the rest of the train.
#[test]
fn gro_train_tolerates_short_slices() {
    let mut net = warm_net();
    let ip = udp4(ip4(0), ip4(1), b"intact");
    let wire = seal(&mut net, &ip);

    let mut train = PacketBuf::with_capacity(DATA_HEADER_SZ + wire.len()).into_bytes();
    train.extend_from_slice(&wire[..DATA_HEADER_SZ]);
    train.extend_from_slice(&wire);
    let short = PacketBuf::from_shared(train.split_to(DATA_HEADER_SZ), 0, DATA_HEADER_SZ).unwrap();
    let outputs = open(&mut net, short);
    assert!(
        matches!(
            &outputs[..],
            [Output::Event(Event::Dropped {
                peer: None,
                reason: reasons::INVALID_PACKET
            })]
        ),
        "{outputs:?}"
    );

    let datagram = PacketBuf::from_shared(train, 0, wire.len()).unwrap();
    let outputs = open(&mut net, datagram);
    let [Output::Deliver { packet, .. }] = &outputs[..] else {
        panic!("expected one deliver: {outputs:?}");
    };
    assert_eq!(packet.as_packet(), ip);
}
