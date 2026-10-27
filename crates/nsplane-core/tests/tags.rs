//! The packet tag and the receipt marker through the core: moves keep them, the copy for a
//! packet without headroom copies them, a handshake initiation written into a packet's
//! buffer carries neither, and filters may read and set the tag.

#![allow(clippy::unwrap_used, clippy::panic, reason = "test harness")]

mod common;

use std::num::NonZeroU64;
use std::sync::{Arc, Mutex};

use common::{Net, ip4, packet_buf, path, udp4};
use nsplane_core::{CoreConfig, Input, PacketBuf, PacketFilter, PeerId, Verdict};

fn tag(value: u64) -> Option<NonZeroU64> {
    NonZeroU64::new(value)
}

/// A local packet from core 0 to core 1 with room to seal in place, tagged and marked.
fn tagged_local(value: u64) -> PacketBuf {
    let mut packet = packet_buf(&udp4(ip4(0), ip4(1), b"tagged"));
    packet.set_tag(tag(value));
    packet.set_tracked(true);
    packet
}

/// The same packet as a slice of a shared buffer without headroom, tagged and marked.
fn tagged_shared(value: u64) -> PacketBuf {
    let bytes = udp4(ip4(0), ip4(1), b"shared");
    let mut whole = PacketBuf::with_capacity(bytes.len()).into_bytes();
    whole.extend_from_slice(&bytes);
    let mut packet = PacketBuf::from_shared(whole, 0, bytes.len()).unwrap();
    assert_eq!(packet.headroom(), 0);
    packet.set_tag(tag(value));
    packet.set_tracked(true);
    packet
}

/// Records the tags its outbound and inbound sides see; tags the packets that have none
/// with `set_out` and `set_in`.
#[derive(Debug, Default)]
struct Recording {
    outbound: Mutex<Vec<Option<NonZeroU64>>>,
    inbound: Mutex<Vec<Option<NonZeroU64>>>,
    set_out: Option<NonZeroU64>,
    set_in: Option<NonZeroU64>,
}

/// A [`Recording`] installed as a filter.
#[derive(Debug)]
struct Installed(Arc<Recording>);

impl PacketFilter for Installed {
    fn inbound(&self, _peer: PeerId, packet: &mut PacketBuf) -> Verdict {
        self.0.inbound.lock().unwrap().push(packet.tag());
        if packet.tag().is_none() {
            packet.set_tag(self.0.set_in);
        }
        Verdict::Accept
    }

    fn outbound(&self, _peer: PeerId, packet: &mut PacketBuf) -> Verdict {
        self.0.outbound.lock().unwrap().push(packet.tag());
        if packet.tag().is_none() {
            packet.set_tag(self.0.set_out);
        }
        Verdict::Accept
    }
}

/// Two cores, `crypto_jobs` on core 0, each with `filter` installed; the session is up.
fn net(filter: &Arc<Recording>, crypto_jobs: bool) -> Net {
    let mut net = Net::with_configs(2, |i| CoreConfig {
        filters: vec![Box::new(Installed(Arc::clone(filter)))],
        crypto_jobs: crypto_jobs && i == 0,
        ..CoreConfig::default()
    });
    net.handshake(0, 1);
    net.clear_logs();
    net
}

/// Feeds `packet` to core 0 as a local packet, through a crypto job with `crypto_jobs`.
fn send(net: &mut Net, packet: PacketBuf, crypto_jobs: bool) {
    let input = Input::Local { packet };
    feed(net, 0, input, crypto_jobs);
}

/// Feeds `input` to core `i`, through a crypto job with `crypto_jobs`.
fn feed(net: &mut Net, i: usize, input: Input, crypto_jobs: bool) {
    if crypto_jobs {
        if let Some(mut job) = net.cores[i].handle_input_deferred(input, net.now) {
            job.run();
            net.cores[i].complete_job(job);
        }
    } else {
        net.cores[i].handle_input(input, net.now);
    }
}

/// The datagrams core `i` transmits now, with their tags and markers.
fn transmitted(net: &mut Net, i: usize) -> Vec<(u8, Option<NonZeroU64>, bool)> {
    net.drain()
        .into_iter()
        .filter(|d| d.from == i)
        .map(|d| (d.data.as_packet()[0], d.data.tag(), d.data.is_tracked()))
        .collect()
}

#[test]
fn local_packets_carry_the_tag_to_the_filter_and_the_datagram() {
    for crypto_jobs in [false, true] {
        let filter = Arc::new(Recording {
            set_out: tag(99),
            ..Recording::default()
        });
        let mut net = net(&filter, crypto_jobs);
        send(&mut net, tagged_local(7), crypto_jobs);
        // A data message (type 4) with the tag and the marker.
        assert_eq!(transmitted(&mut net, 0), [(4, tag(7), true)]);
        // A filter may set the tag of an untagged packet.
        send(
            &mut net,
            packet_buf(&udp4(ip4(0), ip4(1), b"x")),
            crypto_jobs,
        );
        assert_eq!(transmitted(&mut net, 0), [(4, tag(99), false)]);
        assert_eq!(*filter.outbound.lock().unwrap(), [tag(7), None]);
    }
}

#[test]
fn a_packet_without_headroom_keeps_its_tag_and_marker_through_the_copy() {
    for crypto_jobs in [false, true] {
        let filter = Arc::new(Recording::default());
        let mut net = net(&filter, crypto_jobs);
        send(&mut net, tagged_shared(11), crypto_jobs);
        let datagram = net.drain().pop().unwrap();
        let data = &datagram.data;
        assert_eq!(
            (data.as_packet()[0], data.tag(), data.is_tracked()),
            (4, tag(11), true)
        );
        // The copy sealed the packet's bytes.
        net.receive(1, datagram.arrival, datagram.data);
        net.pump();
        let delivered = net.take_delivered(1);
        assert_eq!(delivered.len(), 1);
        assert_eq!(&delivered[0].1[28..], b"shared");
    }
}

#[test]
fn a_handshake_initiation_written_into_a_packet_carries_neither() {
    for crypto_jobs in [false, true] {
        let mut net = Net::with_configs(2, |i| CoreConfig {
            crypto_jobs: crypto_jobs && i == 0,
            ..CoreConfig::default()
        });
        net.clear_logs();
        // No session: the packet is queued and an initiation (type 1) goes out in its buffer.
        send(&mut net, tagged_local(5), crypto_jobs);
        let sent = net.drain();
        assert_eq!(sent.len(), 1);
        let initiation = &sent[0].data;
        assert_eq!(initiation.as_packet()[0], 1);
        assert_eq!((initiation.tag(), initiation.is_tracked()), (None, false));

        // The queued packet goes out once the session is up, untagged: the tunnel's queue
        // keeps bytes only.
        let data = Arc::new(Mutex::new(Vec::new()));
        let seen = Arc::clone(&data);
        net.set_interceptor(move |datagram| {
            if datagram.from == 0 && datagram.data.as_packet()[0] == 4 {
                let data = &datagram.data;
                seen.lock().unwrap().push((data.tag(), data.is_tracked()));
            }
            common::Fate::Pass
        });
        let initiation = sent.into_iter().next().unwrap();
        net.receive(1, initiation.arrival, initiation.data);
        net.pump();
        let data = data.lock().unwrap();
        assert!(!data.is_empty());
        assert!(data.iter().all(|seen| *seen == (None, false)), "{data:?}");
        assert_eq!(net.take_delivered(1).len(), 1);
    }
}

#[test]
fn inject_calls_and_plaintext_keep_the_tag() {
    let filter = Arc::new(Recording::default());
    let mut net = net(&filter, false);
    let to_1 = net.peer_id(0, 1);
    let from_0 = net.peer_id(1, 0);

    net.cores[0].inject_outbound(tagged_local(1), net.now);
    assert_eq!(transmitted(&mut net, 0), [(4, tag(1), true)]);

    net.cores[0].inject_outbound_on(to_1, path(1), tagged_local(2), net.now);
    assert_eq!(transmitted(&mut net, 0), [(4, tag(2), true)]);

    let packet = tagged_local(3);
    net.cores[1].inject_inbound(from_0, packet);
    net.drain();
    let (from, delivered) = net.delivered[1].pop().unwrap();
    assert_eq!(from, from_0);
    assert_eq!((delivered.tag(), delivered.is_tracked()), (tag(3), true));

    net.cores[1].receive_plaintext(from_0, path(0), tagged_local(4));
    net.drain();
    let (_, delivered) = net.delivered[1].pop().unwrap();
    assert_eq!((delivered.tag(), delivered.is_tracked()), (tag(4), true));
    // The plaintext packet ran through the inbound filter with its tag.
    assert_eq!(*filter.inbound.lock().unwrap(), [tag(4)]);
}

#[test]
fn an_inbound_filter_tag_reaches_the_delivery() {
    for crypto_jobs in [false, true] {
        let filter = Arc::new(Recording {
            set_in: tag(42),
            ..Recording::default()
        });
        let mut net = net(&filter, crypto_jobs);
        net.cores[1].handle_input(
            Input::Local {
                packet: packet_buf(&udp4(ip4(1), ip4(0), b"in")),
            },
            net.now,
        );
        let datagram = net.drain().pop().unwrap();
        // The wire carries no tag.
        assert_eq!(datagram.data.tag(), None);
        let input = Input::Datagram {
            path: datagram.arrival,
            data: datagram.data,
        };
        feed(&mut net, 0, input, crypto_jobs);
        net.drain();
        let (from, delivered) = net.delivered[0].pop().unwrap();
        assert_eq!(from, net.peer_id(0, 1));
        assert_eq!((delivered.tag(), delivered.is_tracked()), (tag(42), false));
        assert_eq!(*filter.inbound.lock().unwrap(), [None]);
    }
}
