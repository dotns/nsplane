//! Admission events of a transparent stack.

use super::ownership::{tcp_packet, udp_packet};
use super::*;
use crate::{FlowEvent, FlowEventReason, FlowEventsConfig, PendingFlow, TransparentConfig};

const LOCAL: Ipv4Addr = Ipv4Addr::new(10, 8, 0, 1);
const SYN: u8 = 0x02;

/// A stack at [`LOCAL`] with `transparent`, its source (kept so the driver runs) and
/// its sink.
fn start(transparent: TransparentConfig) -> (NetStackHandle, NetStackSource, NetStackSink) {
    let (stack, handle) = NetStack::new(NetStackConfig {
        transparent: Some(transparent),
        ..config(LOCAL)
    });
    let (source, sink) = stack.split();
    (handle, source, sink)
}

/// Transparent mode for `192.0.2.0/24` with `events`.
fn with_events(events: Option<FlowEventsConfig>) -> TransparentConfig {
    TransparentConfig {
        prefixes: vec![(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 0)), 24)],
        events,
        ..Default::default()
    }
}

/// [`with_events`] deciding with `timeout` and `max_pending`.
#[allow(deprecated, reason = "the deprecated field is still honoured")]
fn deciding(timeout: Duration, max_pending: usize) -> TransparentConfig {
    TransparentConfig {
        admission: Admission::Decide {
            timeout,
            max_pending,
        },
        ..with_events(Some(FlowEventsConfig::default()))
    }
}

fn addr(text: &str) -> Result<SocketAddr, Box<dyn Error>> {
    Ok(text.parse()?)
}

async fn send(sink: &NetStackSink, packet: &[u8]) -> TestResult {
    sink.send(PacketBuf::from_packet(packet), PeerId::new(0))
        .await?;
    Ok(())
}

async fn send_syn(sink: &NetStackSink, src: &str, dst: &str) -> TestResult {
    let packet = tcp_packet(addr(src)?, addr(dst)?, SYN);
    send(sink, &packet).await
}

async fn send_udp(sink: &NetStackSink, src: &str, dst: &str) -> TestResult {
    let packet = udp_packet(addr(src)?, addr(dst)?);
    send(sink, &packet).await
}

async fn next_event(
    events: &mut (impl Stream<Item = FlowEvent> + Unpin),
) -> Result<FlowEvent, Box<dyn Error>> {
    Ok(timeout(WAIT, next(events)).await?.ok_or("events ended")?)
}

async fn next_item(
    pending: &mut (impl Stream<Item = PendingFlow> + Unpin),
) -> Result<PendingFlow, Box<dyn Error>> {
    Ok(timeout(WAIT, next(pending)).await?.ok_or("no item")?)
}

/// Checks the 5-tuple, decision and reason of `event`.
fn assert_event(
    event: &FlowEvent,
    protocol: u8,
    src: &str,
    dst: &str,
    reason: FlowEventReason,
) -> TestResult {
    assert_eq!(
        (event.protocol, event.src, event.dst, event.reason),
        (protocol, addr(src)?, addr(dst)?, reason)
    );
    assert_eq!(event.allow, reason == FlowEventReason::Admitted);
    Ok(())
}

/// Waits until `ready` holds for the stack's counters.
async fn until_stats(
    handle: &NetStackHandle,
    ready: impl Fn(&NetStackStats) -> bool + Sync,
) -> TestResult {
    timeout(WAIT, async {
        while !ready(&handle.stats()) {
            sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .map_err(|_| format!("counters should converge: {:?}", handle.stats()))?;
    Ok(())
}

#[tokio::test]
async fn without_events_nothing_is_emitted() -> TestResult {
    let (handle, _source, sink) = start(with_events(None));
    send_syn(&sink, "10.8.0.2:40000", "192.0.2.10:443").await?;
    send_udp(&sink, "10.8.0.2:40000", "192.0.2.10:53").await?;
    send_syn(&sink, "10.8.0.2:40000", "198.51.100.7:443").await?;
    until_stats(&handle, |stats| {
        stats.accepted == 2 && stats.rejected_prefix == 1
    })
    .await?;
    let stats = handle.stats();
    assert_eq!((stats.events_emitted, stats.events_dropped), (0, 0));
    assert!(next(&mut handle.flow_events()).await.is_none());

    let (stack, plain) = NetStack::new(config(LOCAL));
    let _halves = stack.split();
    assert!(next(&mut plain.flow_events()).await.is_none());
    Ok(())
}

#[tokio::test]
async fn immediate_admissions_and_prefix_rejections_are_emitted() -> TestResult {
    let (handle, _source, sink) = start(with_events(Some(FlowEventsConfig::default())));
    let mut events = handle.flow_events();
    assert!(
        next(&mut handle.flow_events()).await.is_none(),
        "taken once"
    );

    send_syn(&sink, "10.8.0.2:40000", "192.0.2.10:443").await?;
    let event = next_event(&mut events).await?;
    assert_event(
        &event,
        protocol::TCP,
        "10.8.0.2:40000",
        "192.0.2.10:443",
        FlowEventReason::Admitted,
    )?;
    send_udp(&sink, "10.8.0.2:40001", "192.0.2.11:53").await?;
    let event = next_event(&mut events).await?;
    assert_event(
        &event,
        protocol::UDP,
        "10.8.0.2:40001",
        "192.0.2.11:53",
        FlowEventReason::Admitted,
    )?;
    send_syn(&sink, "10.8.0.2:40002", "198.51.100.7:443").await?;
    let event = next_event(&mut events).await?;
    assert_event(
        &event,
        protocol::TCP,
        "10.8.0.2:40002",
        "198.51.100.7:443",
        FlowEventReason::Prefix,
    )?;
    let stats = handle.stats();
    assert_eq!((stats.events_emitted, stats.events_dropped), (3, 0));
    Ok(())
}

#[tokio::test]
async fn a_connection_limit_rejection_is_emitted() -> TestResult {
    let (handle, _source, sink) = start(TransparentConfig {
        max_connections: Some(0),
        ..with_events(Some(FlowEventsConfig::default()))
    });
    let mut events = handle.flow_events();
    send_syn(&sink, "10.8.0.2:40000", "192.0.2.10:443").await?;
    let event = next_event(&mut events).await?;
    assert_event(
        &event,
        protocol::TCP,
        "10.8.0.2:40000",
        "192.0.2.10:443",
        FlowEventReason::ConnectionLimit,
    )?;
    assert_eq!(handle.stats().rejected_connection_limit, 1);
    Ok(())
}

#[tokio::test]
async fn decisions_on_held_connections_and_flows_are_emitted() -> TestResult {
    let (handle, _source, sink) = start(deciding(WAIT * 5, 1));
    let mut events = handle.flow_events();
    let mut pending = handle.incoming_pending();

    send_syn(&sink, "10.8.0.2:40000", "192.0.2.10:443").await?;
    next_item(&mut pending).await?.accept();
    let event = next_event(&mut events).await?;
    assert_event(
        &event,
        protocol::TCP,
        "10.8.0.2:40000",
        "192.0.2.10:443",
        FlowEventReason::Admitted,
    )?;

    send_syn(&sink, "10.8.0.2:40001", "192.0.2.10:443").await?;
    next_item(&mut pending).await?.reject();
    let event = next_event(&mut events).await?;
    assert_event(
        &event,
        protocol::TCP,
        "10.8.0.2:40001",
        "192.0.2.10:443",
        FlowEventReason::Hook,
    )?;

    send_udp(&sink, "10.8.0.2:40002", "192.0.2.12:53").await?;
    next_item(&mut pending).await?.accept();
    let event = next_event(&mut events).await?;
    assert_event(
        &event,
        protocol::UDP,
        "10.8.0.2:40002",
        "192.0.2.12:53",
        FlowEventReason::Admitted,
    )?;

    // One held: the next is rejected at once; dropping the held item rejects it.
    send_syn(&sink, "10.8.0.2:40003", "192.0.2.10:443").await?;
    let held = next_item(&mut pending).await?;
    send_udp(&sink, "10.8.0.2:40004", "192.0.2.12:53").await?;
    let event = next_event(&mut events).await?;
    assert_event(
        &event,
        protocol::UDP,
        "10.8.0.2:40004",
        "192.0.2.12:53",
        FlowEventReason::TableFull,
    )?;
    drop(held);
    let event = next_event(&mut events).await?;
    assert_event(
        &event,
        protocol::TCP,
        "10.8.0.2:40003",
        "192.0.2.10:443",
        FlowEventReason::Hook,
    )?;
    let stats = handle.stats();
    assert_eq!((stats.events_emitted, stats.events_dropped), (5, 0));
    Ok(())
}

#[tokio::test]
async fn a_timeout_is_emitted() -> TestResult {
    let (handle, _source, sink) = start(deciding(Duration::from_millis(50), 8));
    let mut events = handle.flow_events();
    let mut pending = handle.incoming_pending();
    send_syn(&sink, "10.8.0.2:40000", "192.0.2.10:443").await?;
    let _held = next_item(&mut pending).await?;
    let event = next_event(&mut events).await?;
    assert_event(
        &event,
        protocol::TCP,
        "10.8.0.2:40000",
        "192.0.2.10:443",
        FlowEventReason::Timeout,
    )?;
    assert_eq!(handle.stats().rejected_timeout, 1);
    Ok(())
}

#[tokio::test]
async fn the_rate_limit_drops_beyond_the_burst_until_it_refills() -> TestResult {
    // Two tokens per second: no refill within the burst below, one after 600 ms.
    let (handle, _source, sink) = start(with_events(Some(FlowEventsConfig {
        rate: 2,
        burst: 3,
        ..Default::default()
    })));
    let mut events = handle.flow_events();
    for port in 40_000..40_005 {
        send_syn(&sink, &format!("10.8.0.2:{port}"), "198.51.100.7:443").await?;
    }
    until_stats(&handle, |stats| stats.rejected_prefix == 5).await?;
    let stats = handle.stats();
    assert_eq!((stats.events_emitted, stats.events_dropped), (3, 2));
    for port in 40_000..40_003 {
        let event = next_event(&mut events).await?;
        assert_eq!(event.src, addr(&format!("10.8.0.2:{port}"))?);
    }
    assert!(try_next(&mut events).is_none());

    sleep(Duration::from_millis(600)).await;
    send_syn(&sink, "10.8.0.2:40005", "198.51.100.7:443").await?;
    let event = next_event(&mut events).await?;
    assert_eq!(event.src, addr("10.8.0.2:40005")?);
    let stats = handle.stats();
    assert_eq!((stats.events_emitted, stats.events_dropped), (4, 2));
    Ok(())
}

#[tokio::test]
async fn a_full_channel_or_a_dropped_receiver_drops_events() -> TestResult {
    let (handle, _source, sink) = start(with_events(Some(FlowEventsConfig {
        capacity: 1,
        ..Default::default()
    })));
    let mut events = handle.flow_events();
    for port in 40_000..40_003 {
        send_syn(&sink, &format!("10.8.0.2:{port}"), "198.51.100.7:443").await?;
    }
    until_stats(&handle, |stats| stats.rejected_prefix == 3).await?;
    let stats = handle.stats();
    assert_eq!((stats.events_emitted, stats.events_dropped), (1, 2));
    let event = next_event(&mut events).await?;
    assert_eq!(event.src, addr("10.8.0.2:40000")?);

    drop(events);
    send_syn(&sink, "10.8.0.2:40003", "198.51.100.7:443").await?;
    until_stats(&handle, |stats| stats.rejected_prefix == 4).await?;
    let stats = handle.stats();
    assert_eq!((stats.events_emitted, stats.events_dropped), (1, 3));
    Ok(())
}
