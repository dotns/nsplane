//! Send receipts and plaintext egress between two engines over UDP on the loopback.
//!
//! Node `a` builds a tracked sender and a plaintext egress receiver. Tracked packets mixed
//! with untracked ones each get one `Sent` result with the routed peer and the plaintext
//! length, and arrive at `b`; once `a` marks `b` for plaintext egress, tracked packets are
//! `NotSent` with `PLAINTEXT_EGRESS` and reach the egress receiver untracked, untracked ones
//! too, and nothing reaches `b`; unmarked again, they are sealed. With and without crypto
//! workers.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    reason = "test harness"
)]

use std::collections::BTreeMap;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::num::NonZeroU64;

use nsplane::{
    PlaintextEgress, SendOutcome, SendResults, TrackedSender, TransportId, UdpTransport, reasons,
};
use nsplane_e2e::{Node, Options, QUIET, TestResult, WAIT, exchange, introduce, udp4};
use nsplane_packet::PacketBuf;
use tokio::time::timeout;

/// A node on a UDP transport bound to the loopback, with `workers` crypto workers, a tracked
/// sender and a plaintext egress receiver when `tracked`.
/// The tracked sender, its results and the plaintext egress receiver of a node.
type Receipts = (TrackedSender, SendResults, PlaintextEgress);

fn node(
    seed: u8,
    workers: usize,
    tracked: bool,
) -> TestResult<(Node<UdpTransport>, Option<Receipts>)> {
    let id = TransportId::new(u16::from(seed));
    let transport = UdpTransport::bind(id, SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0))?;
    let addr = transport.local_addr();
    let mut parts = None;
    let node = Node::with_builder(seed, id, addr, Options::default(), |builder| {
        let builder = builder.transport(transport).crypto_workers(workers);
        if !tracked {
            return builder;
        }
        let (builder, sender, results) = builder.tracked_sender(128);
        let (builder, egress) = builder.plaintext_egress(256);
        parts = Some((sender, results, egress));
        builder
    })?;
    Ok((node, parts))
}

fn tracked(a: &Node<UdpTransport>, b: &Node<UdpTransport>, token: u64) -> PacketBuf {
    let mut packet = PacketBuf::from_packet(&udp4(a.ip4, b.ip4, &token.to_be_bytes()));
    packet.set_tag(NonZeroU64::new(token));
    packet
}

#[tokio::test]
async fn tracked_packets_and_plaintext_egress_between_two_engines() -> TestResult {
    for workers in [0, 2] {
        let (mut a, parts) = node(1, workers, true)?;
        let (mut b, _) = node(2, 0, false)?;
        let (sender, mut results, mut egress) = parts.expect("built with a tracked sender");
        introduce(&a, &b, None).await?;
        exchange(&mut a, &mut b).await?;
        let peer = a.handle.peer_id(b.public()).await?.expect("peer");
        let before = a.handle.peer_stats(peer).await?.expect("stats").data_tx;

        // Tracked packets among untracked ones: one result each, all sent and delivered.
        let mut lens = BTreeMap::new();
        for token in 1..=100u64 {
            let packet = tracked(&a, &b, token);
            lens.insert(token, packet.len());
            sender.send(packet).await?;
            a.send(&udp4(a.ip4, b.ip4, b"untracked")).await?;
        }
        let mut sent = 0;
        for _ in 0..100 {
            let result = timeout(WAIT, results.recv()).await?.expect("a result");
            let bytes = lens
                .remove(&result.tag.get())
                .expect("one result per token");
            assert_eq!(result.outcome, SendOutcome::Sent { peer, bytes });
            sent += bytes;
        }
        assert!(timeout(QUIET, results.recv()).await.is_err());
        for _ in 0..200 {
            b.expect_delivery().await?;
        }
        let after = a.handle.peer_stats(peer).await?.expect("stats").data_tx;
        let untracked = udp4(a.ip4, b.ip4, b"untracked").len();
        assert_eq!(after - before, (sent + 100 * untracked) as u64);

        // Marked for plaintext egress: nothing is sealed.
        assert!(a.handle.set_plaintext_egress(peer, true).await?);
        for token in 101..=110u64 {
            sender.send(tracked(&a, &b, token)).await?;
            a.send(&udp4(a.ip4, b.ip4, b"plain")).await?;
        }
        for token in 101..=110u64 {
            let result = timeout(WAIT, results.recv()).await?.expect("a result");
            assert_eq!(result.tag.get(), token);
            let reason = reasons::PLAINTEXT_EGRESS;
            assert_eq!(result.outcome, SendOutcome::NotSent { reason });
        }
        let mut tags = Vec::new();
        for _ in 0..20 {
            let (to, packet) = timeout(WAIT, egress.recv()).await?.expect("egress");
            assert_eq!(to, peer);
            assert!(!packet.is_tracked());
            tags.extend(packet.tag().map(NonZeroU64::get));
        }
        assert_eq!(tags, (101..=110).collect::<Vec<_>>());
        b.expect_no_delivery().await?;

        // Unmarked: sealed again.
        assert!(a.handle.set_plaintext_egress(peer, false).await?);
        sender.send(tracked(&a, &b, 111)).await?;
        let result = timeout(WAIT, results.recv()).await?.expect("a result");
        assert!(matches!(result.outcome, SendOutcome::Sent { .. }));
        b.expect_delivery().await?;

        a.handle.shutdown().await?;
        assert_eq!(timeout(WAIT, results.recv()).await?, None);
    }
    Ok(())
}
