//! Queue high-water marks: under load the marks of the engine's bounded queues rise but
//! never pass their capacities, they restart at 0 after `take_queue_stats`, and a sink that
//! stops draining fills the deliver queue to its capacity while the overflow is counted
//! under `DROP_SINK_FULL`.

use std::net::SocketAddr;
use std::time::Duration;

use nsplane::{
    ChannelTransport, DROP_SINK_FULL, EngineHandle, PacketBuf, QueueDepth, QueueStats, TransportId,
};
use nsplane_e2e::{
    Family, Node, Options, TestResult, WAIT, channel_pair, exchange, introduce, payload,
    serve_tcp_echo, stack_pair,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::time::{Instant, sleep, timeout};

/// The engine's default queue capacity and the capacity of its command queue.
const QUEUE: usize = 1024;
const COMMAND: usize = 64;
/// Packets of a bulk transfer.
const BULK: usize = 4096;
/// Capacity of the harness's sink channel.
const SINK: usize = 1024;

/// Every queue of `stats` in a fixed order, named.
const fn depths(stats: &QueueStats) -> [(&'static str, QueueDepth); 8] {
    [
        ("command", stats.command),
        ("local", stats.local),
        ("datagrams", stats.datagrams),
        ("deliver", stats.deliver),
        ("recycle", stats.recycle),
        ("transmit", stats.transmit),
        ("backlog", stats.backlog),
        ("events", stats.events),
    ]
}

/// Checks that no high-water mark of `stats` passed its capacity.
fn assert_within_capacity(stats: &QueueStats) {
    for (name, depth) in depths(stats) {
        assert!(
            depth.high_water <= depth.capacity,
            "{name}: {} above its capacity {}",
            depth.high_water,
            depth.capacity
        );
    }
}

/// Restarts the marks of `handle` and checks that an idle engine then reports 0 for every
/// queue.
async fn assert_restart(handle: &EngineHandle) -> TestResult {
    handle.take_queue_stats().await?;
    let stats = handle.queue_stats().await?;
    for (name, depth) in depths(&stats) {
        assert_eq!(depth.high_water, 0, "{name} after a restart");
    }
    Ok(())
}

#[tokio::test]
async fn bulk_udp_raises_marks_within_capacity() -> TestResult {
    let (mut a, mut b) = channel_pair(Options::default());
    introduce(&a, &b, None).await?;
    exchange(&mut a, &mut b).await?;
    let stats = a.handle.queue_stats().await?;
    assert_eq!(stats.local.capacity, QUEUE);
    assert_eq!(stats.command.capacity, COMMAND);
    a.handle.take_queue_stats().await?;
    b.handle.take_queue_stats().await?;

    let packet = a.packet_to(&b, Family::V4, &payload(1300));
    let local = a.local.clone();
    let sender = tokio::spawn(async move {
        for _ in 0..BULK {
            local.send(PacketBuf::from_packet(&packet)).await?;
        }
        TestResult::Ok(())
    });
    for _ in 0..BULK {
        b.expect_delivery().await?;
    }
    timeout(WAIT, sender).await???;

    let sent = a.handle.queue_stats().await?;
    let received = b.handle.queue_stats().await?;
    assert_within_capacity(&sent);
    assert_within_capacity(&received);
    assert!(sent.local.high_water > 0, "{sent:?}");
    assert!(sent.transmit.high_water > 0, "{sent:?}");
    assert!(received.datagrams.high_water > 0, "{received:?}");
    assert!(received.deliver.high_water > 0, "{received:?}");

    assert_restart(&a.handle).await?;
    assert_restart(&b.handle).await
}

#[tokio::test]
async fn netstack_tcp_raises_marks_within_capacity() -> TestResult {
    let (a, b) = stack_pair(nsplane_e2e::MTU).await?;
    serve_tcp_echo(&a.stack);
    let conn = timeout(WAIT, b.stack.connect_tcp(a.socket_addr(Family::V4, 7))).await??;
    let len = 1 << 20;
    let (mut reader, mut writer) = tokio::io::split(conn);
    let write = async {
        writer.write_all(&payload(len)).await?;
        writer.shutdown().await
    };
    let read = async {
        let mut echoed = Vec::with_capacity(len);
        reader.read_to_end(&mut echoed).await?;
        Ok(echoed.len())
    };
    let ((), echoed) = timeout(WAIT, async { tokio::try_join!(write, read) }).await??;
    assert_eq!(echoed, len);

    for node in [&a.handle, &b.handle] {
        let stats = node.queue_stats().await?;
        assert_within_capacity(&stats);
        assert!(stats.local.high_water > 0, "{stats:?}");
        assert!(stats.datagrams.high_water > 0, "{stats:?}");
        assert!(stats.deliver.high_water > 0, "{stats:?}");
        assert!(stats.transmit.high_water > 0, "{stats:?}");
        assert_restart(node).await?;
    }
    Ok(())
}

#[tokio::test]
async fn full_sink_fills_the_deliver_queue() -> TestResult {
    // `b` delivers into the harness's sink channel, which the test stops draining.
    const DELIVER: usize = 8;
    let a_at = (
        TransportId::new(1),
        SocketAddr::from(([192, 0, 2, 1], 1000)),
    );
    let b_at = (
        TransportId::new(2),
        SocketAddr::from(([192, 0, 2, 2], 2000)),
    );
    let (link_a, link_b) = ChannelTransport::pair(QUEUE, a_at, b_at);
    let mut a = Node::new(1, a_at.0, a_at.1, link_a, Options::default());
    let mut b = Node::with_builder(2, b_at.0, b_at.1, Options::default(), |builder| {
        builder.queue_capacity(DELIVER).transport(link_b)
    })?;
    introduce(&a, &b, None).await?;
    exchange(&mut a, &mut b).await?;
    b.handle.take_queue_stats().await?;

    // The sink channel, the packet the sink task holds while waiting for room in it and the
    // deliver queue take this many; the rest is dropped.
    let held = SINK + 1 + DELIVER;
    let sent = held + 64;
    let packet = a.packet_to(&b, Family::V4, &payload(64));
    for _ in 0..sent {
        a.send(&packet).await?;
    }
    let expected = (sent - held) as u64;
    let deadline = Instant::now() + WAIT;
    while b.drops(DROP_SINK_FULL).await? < expected {
        if Instant::now() > deadline {
            return Err(format!("fewer than {expected} sink-full drops within {WAIT:?}").into());
        }
        sleep(Duration::from_millis(10)).await;
    }
    assert_eq!(b.drops(DROP_SINK_FULL).await?, expected);

    let stats = b.handle.queue_stats().await?;
    assert_eq!(
        stats.deliver,
        QueueDepth {
            capacity: DELIVER,
            high_water: DELIVER
        }
    );
    assert_within_capacity(&stats);
    Ok(())
}
