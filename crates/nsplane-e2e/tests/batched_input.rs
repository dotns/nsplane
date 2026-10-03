//! Batched input: bursts of several batches, queued before the engines read them, cross a
//! channel link in both directions at once, with the crypto worker pool off and on. Every
//! packet arrives, in order, nothing is dropped and no queue's high-water mark passes its
//! capacity.

use nsplane::{ChannelTransport, QueueStats};
use nsplane_e2e::{
    Family, Node, Options, TestResult, WAIT, channel_pair_with, exchange, introduce,
};
use tokio::time::timeout;

/// Packets each node sends; several batches, within the harness's queues.
const BURST: u32 = 500;

/// Hands `BURST` numbered packets from `from` to `to` to `from`'s engine.
async fn send_burst(from: &Node<ChannelTransport>, to: &Node<ChannelTransport>) -> TestResult {
    for seq in 0..BURST {
        from.send(&from.packet_to(to, Family::V4, &seq.to_be_bytes()))
            .await?;
    }
    Ok(())
}

/// Receives `BURST` packets at `node` and checks that they are numbered in order.
async fn receive_burst(node: &mut Node<ChannelTransport>) -> TestResult {
    for expected in 0..BURST {
        let (_, packet) = timeout(WAIT, node.delivered.recv())
            .await?
            .ok_or("sink closed")?;
        let packet = packet.as_packet();
        let seq = packet
            .last_chunk::<4>()
            .map(|bytes| u32::from_be_bytes(*bytes))
            .ok_or("short packet")?;
        if seq != expected {
            return Err(format!("packet {seq} arrived in place of {expected}").into());
        }
    }
    Ok(())
}

/// Checks that no high-water mark of `stats` passed its capacity.
fn assert_within_capacity(stats: &QueueStats) {
    for (name, depth) in [
        ("command", stats.command),
        ("local", stats.local),
        ("datagrams", stats.datagrams),
        ("deliver", stats.deliver),
        ("recycle", stats.recycle),
        ("transmit", stats.transmit),
        ("backlog", stats.backlog),
        ("events", stats.events),
        ("crypto", stats.crypto),
        ("crypto_done", stats.crypto_done),
    ] {
        assert!(
            depth.high_water <= depth.capacity,
            "{name}: {} above its capacity {}",
            depth.high_water,
            depth.capacity
        );
    }
}

async fn bursts(workers: usize) -> TestResult {
    let (mut a, mut b) = channel_pair_with(Options::default(), |_, builder| {
        builder.crypto_workers(workers)
    })?;
    introduce(&a, &b, None).await?;
    exchange(&mut a, &mut b).await?;

    // Both bursts are queued before either is received, so the engines find full batches.
    send_burst(&a, &b).await?;
    send_burst(&b, &a).await?;
    receive_burst(&mut b).await?;
    receive_burst(&mut a).await?;

    for node in [&a, &b] {
        let drops = node.handle.drop_counters().await?;
        assert!(
            drops.values().all(|&count| count == 0),
            "drops with {workers} workers: {drops:?}"
        );
        let stats = node.handle.queue_stats().await?;
        assert_within_capacity(&stats);
        // Packets waited in the local queue, so the owner took several at once.
        assert!(
            stats.local.high_water > 1,
            "local queue peaked at {}",
            stats.local.high_water
        );
    }
    Ok(())
}

#[tokio::test]
async fn bursts_without_workers() -> TestResult {
    bursts(0).await
}

#[tokio::test]
async fn bursts_with_workers() -> TestResult {
    bursts(2).await
}
