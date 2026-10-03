//! Latency of one packet: two engines over UDP loopback with the builder defaults (no
//! filters, no fragmenter, no crypto workers). After the handshake, a lone packet on an idle
//! engine is delivered and answered at once: the engines never wait for a batch to fill.
//!
//! The ignored measurement prints p50 / p99 / max of one-packet round trips, idle and under
//! a background bulk flow between the same engines, without and with crypto workers:
//!
//! ```text
//! cargo test --release -p nsplane-e2e --test latency -- --ignored --nocapture
//! ```

use std::io::{self, Write};
use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::Duration;

use nsplane::{PacketBuf, PeerId, TransportId, UdpTransport};
use nsplane_e2e::{Node, Options, TestResult, WAIT, exchange, introduce, udp4};
use tokio::sync::mpsc;
use tokio::task::JoinHandle;
use tokio::time::{Instant, timeout_at};

/// The bound a lone round trip must stay within; generous, for loaded CI machines.
const IDLE_BOUND: Duration = Duration::from_millis(50);
/// Round trips per measurement.
const ROUND_TRIPS: usize = 2000;
/// How long a measured ping waits for its pong before it counts as lost (the socket may drop
/// it under load).
const LOST: Duration = Duration::from_secs(1);
/// Payload of a bulk packet.
const BULK_LEN: usize = 1200;
/// UDP destination port that marks a ping (and its pong) apart from bulk packets.
const PING_PORT: u16 = 7;

type Delivered = mpsc::Receiver<(PeerId, PacketBuf)>;

/// Two peered nodes on UDP loopback, each with `workers` crypto workers, after a handshake.
async fn pair(
    workers: usize,
    capacity: Option<usize>,
) -> TestResult<(Node<UdpTransport>, Node<UdpTransport>)> {
    let node = |seed: u8| -> TestResult<Node<UdpTransport>> {
        let id = TransportId::new(u16::from(seed));
        let transport = UdpTransport::bind(id, (IpAddr::V4(Ipv4Addr::LOCALHOST), 0).into())?;
        let addr = transport.local_addr();
        Node::with_builder(seed, id, addr, Options::default(), |builder| {
            let builder = builder.transport(transport).crypto_workers(workers);
            match capacity {
                Some(capacity) => builder.queue_capacity(capacity),
                None => builder,
            }
        })
    };
    let (mut a, mut b) = (node(1)?, node(2)?);
    introduce(&a, &b, None).await?;
    exchange(&mut a, &mut b).await?;
    Ok((a, b))
}

/// A ping from `from` to `to` (or a pong back): a small UDP packet to [`PING_PORT`].
fn ping(from: Ipv4Addr, to: Ipv4Addr, seq: u32) -> Vec<u8> {
    let mut packet = udp4(from, to, &seq.to_be_bytes());
    // Destination port: bytes 22..24 of an IPv4 UDP packet without options. The checksum is
    // not verified by the engines.
    packet[22..24].copy_from_slice(&PING_PORT.to_be_bytes());
    packet
}

/// Whether `packet` is a ping or a pong.
fn is_ping(packet: &[u8]) -> bool {
    packet.get(22..24) == Some(&PING_PORT.to_be_bytes()[..])
}

/// Answers every ping delivered at `delivered` with a pong through `local`, and drops bulk
/// packets, counting them in `bulk`.
fn ponger(
    mut delivered: Delivered,
    local: mpsc::Sender<PacketBuf>,
    own: Ipv4Addr,
    peer: Ipv4Addr,
    bulk: Arc<AtomicU64>,
) -> JoinHandle<Delivered> {
    tokio::spawn(async move {
        while let Some((_, packet)) = delivered.recv().await {
            let packet = packet.as_packet();
            if !is_ping(packet) {
                bulk.fetch_add(1, Ordering::Relaxed);
                continue;
            }
            let Some(seq) = packet.last_chunk::<4>().map(|b| u32::from_be_bytes(*b)) else {
                continue;
            };
            if local
                .send(PacketBuf::from_packet(&ping(own, peer, seq)))
                .await
                .is_err()
            {
                break;
            }
        }
        delivered
    })
}

/// One-packet round trips from a node, numbered across calls so a late pong never answers a
/// later ping.
struct Pinger {
    node: Node<UdpTransport>,
    peer: Ipv4Addr,
    seq: u32,
}

impl Pinger {
    /// Sends `count` pings to the peer, one at a time, and returns the round trip of each
    /// answered within `wait` and the number of the others.
    async fn round_trips(
        &mut self,
        count: usize,
        wait: Duration,
    ) -> TestResult<(Vec<Duration>, usize)> {
        let mut times = Vec::with_capacity(count);
        let mut lost = 0;
        for _ in 0..count {
            self.seq += 1;
            let seq = self.seq.to_be_bytes();
            let start = Instant::now();
            self.node
                .send(&ping(self.node.ip4, self.peer, self.seq))
                .await?;
            let deadline = start + wait;
            loop {
                match timeout_at(deadline, self.node.delivered.recv()).await {
                    Ok(Some((_, packet))) => {
                        let packet = packet.as_packet();
                        if is_ping(packet) && packet.last_chunk::<4>() == Some(&seq) {
                            times.push(start.elapsed());
                            break;
                        }
                    }
                    Ok(None) => return Err("sink closed".into()),
                    Err(_) => {
                        lost += 1;
                        break;
                    }
                }
            }
        }
        Ok((times, lost))
    }
}

/// Keeps sending bulk packets from `from` to `to` until `stop` is set.
fn bulk(
    local: mpsc::Sender<PacketBuf>,
    from: Ipv4Addr,
    to: Ipv4Addr,
    stop: Arc<AtomicBool>,
) -> JoinHandle<()> {
    tokio::spawn(async move {
        let packet = udp4(from, to, &vec![0x5a; BULK_LEN]);
        while !stop.load(Ordering::Relaxed) {
            if local.send(PacketBuf::from_packet(&packet)).await.is_err() {
                break;
            }
        }
    })
}

/// Prints p50 / p99 / max of `times` and the `lost` pings under `label`.
fn report(label: &str, (mut times, lost): (Vec<Duration>, usize)) -> TestResult {
    times.sort_unstable();
    // Nearest rank of percentile `p`.
    let at = |p: usize| {
        let rank = (times.len() * p).div_ceil(100).clamp(1, times.len());
        times.get(rank - 1).copied().unwrap_or_default()
    };
    writeln!(
        io::stderr(),
        "{label}: n={} lost={lost} p50={:?} p99={:?} max={:?}",
        times.len(),
        at(50),
        at(99),
        times.last().copied().unwrap_or_default()
    )?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn idle_round_trip_is_immediate() -> TestResult {
    let (a, b) = pair(0, None).await?;
    let bulk_delivered = Arc::new(AtomicU64::new(0));
    let pong = ponger(
        b.delivered,
        b.local.clone(),
        b.ip4,
        a.ip4,
        Arc::clone(&bulk_delivered),
    );
    let mut pinger = Pinger {
        peer: b.ip4,
        node: a,
        seq: 0,
    };
    // The first round trip warms up the path; the following ones must each be quick.
    pinger.round_trips(1, WAIT).await?;
    let (times, lost) = pinger.round_trips(10, WAIT).await?;
    assert_eq!(lost, 0, "pings lost on an idle link");
    let worst = times.iter().max().copied().unwrap_or_default();
    assert!(worst < IDLE_BOUND, "a round trip took {worst:?}");
    pong.abort();
    Ok(())
}

/// Measures idle and loaded round trips between engines with `workers` crypto workers and
/// queues of `capacity` (the builder's default if `None`).
async fn measure(workers: usize, capacity: Option<usize>) -> TestResult {
    let label = capacity.map_or_else(
        || format!("workers={workers}"),
        |capacity| format!("workers={workers} queue={capacity}"),
    );
    let (a, b) = pair(workers, capacity).await?;
    let bulk_delivered = Arc::new(AtomicU64::new(0));
    let pong = ponger(
        b.delivered,
        b.local.clone(),
        b.ip4,
        a.ip4,
        Arc::clone(&bulk_delivered),
    );
    let (local, from) = (a.local.clone(), a.ip4);
    let mut pinger = Pinger {
        peer: b.ip4,
        node: a,
        seq: 0,
    };
    pinger.round_trips(100, LOST).await?;
    report(
        &format!("{label} idle"),
        pinger.round_trips(ROUND_TRIPS, LOST).await?,
    )?;

    // Bulk from a to b; b's ponger drops it after delivery, so it competes with the pings
    // on a's local queue, the link and b's receive path.
    let stop = Arc::new(AtomicBool::new(false));
    let flow = bulk(local, from, pinger.peer, Arc::clone(&stop));
    pinger.round_trips(100, LOST).await?;
    pinger.node.handle.take_queue_stats().await?;
    b.handle.take_queue_stats().await?;
    let (started, bulk_before) = (Instant::now(), bulk_delivered.load(Ordering::Relaxed));
    let loaded = pinger.round_trips(ROUND_TRIPS, LOST).await;
    let bulk_rate = u128::from(bulk_delivered.load(Ordering::Relaxed) - bulk_before)
        / started.elapsed().as_millis().max(1);
    stop.store(true, Ordering::Relaxed);
    flow.await?;
    report(&format!("{label} loaded"), loaded?)?;
    // Where the lost pings went: what the engines dropped, and the rate of the bulk flow.
    writeln!(
        io::stderr(),
        "{label} loaded bulk delivered: {bulk_rate} packets/ms\n\
         {label} loaded drops: a {:?}\n{label} loaded drops: b {:?}",
        pinger.node.handle.drop_counters().await?,
        b.handle.drop_counters().await?
    )?;
    // Where the pings queued behind the bulk flow.
    writeln!(
        io::stderr(),
        "{label} loaded queues: a {:?}\n{label} loaded queues: b {:?}",
        pinger.node.handle.queue_stats().await?,
        b.handle.queue_stats().await?
    )?;
    pong.abort();
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "measurement; run with --release --ignored --nocapture"]
async fn round_trip_latency() -> TestResult {
    measure(0, None).await?;
    measure(2, None).await
}

/// The same with shallower queues, for comparison.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "measurement; run with --release --ignored --nocapture"]
async fn round_trip_latency_queue_256() -> TestResult {
    measure(0, Some(256)).await
}
