//! Underlay probe: what a UDP path between two hosts loses and reorders, without a tunnel.
//!
//! `send` writes sequence-numbered datagrams, paced at a bit rate or as fast as the socket
//! takes them, and then an end marker with the count. `listen` prints one JSON line per
//! run: datagrams sent and received, the lost fraction, datagrams that arrived after a
//! later one, the number of loss runs and the longest. A tunnel measurement over a path is
//! read against these numbers: loss the path has on its own is not the tunnel's.
//!
//! No nsplane API is used; the binary is here so that every bench host has the probe once
//! the examples are built.
//!
//! Usage:
//!
//! ```text
//! net_probe listen --bind 0.0.0.0:5300
//! net_probe send --to 192.0.2.7:5300 --count 3227 --size 1300 --rate 50000000
//! ```

use std::net::{SocketAddr, UdpSocket};
use std::time::{Duration, Instant};

use anyhow::Context as _;
use clap::{Parser, Subcommand};
use nsplane_examples::out;
use serde_json::json;
use socket2::SockRef;

/// Bytes of a datagram's header: run id and sequence number.
const HEADER: usize = 8;
/// Sequence number of the end marker; its count follows the header.
const END: u32 = u32::MAX;
/// End markers sent per run, so that one survives a lossy path.
const END_MARKERS: usize = 10;
/// Pause before and between the end markers.
const END_GAP: Duration = Duration::from_millis(50);
/// Socket buffers requested on both ends: a 4 MiB burst has to fit.
const BUFFER: usize = 8 << 20;
/// Largest count a listener accepts from an end marker or a sequence number.
const MAX_COUNT: u32 = 16 << 20;

/// Loss and reordering of a UDP path.
#[derive(Debug, Parser)]
#[command(name = "net_probe", version)]
struct Args {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Receives runs and prints one JSON line for each
    Listen {
        /// Address to receive on
        #[arg(long, value_name = "IP:PORT")]
        bind: SocketAddr,

        /// Milliseconds without a datagram after which a run without an end marker ends
        #[arg(long, value_name = "MS", default_value_t = 2000)]
        idle: u64,

        /// Runs to report before exiting; 0 serves until killed
        #[arg(long, value_name = "N", default_value_t = 0)]
        runs: u64,
    },
    /// Sends one run and prints one JSON line
    Send {
        /// The listener
        #[arg(long, value_name = "IP:PORT")]
        to: SocketAddr,

        /// Datagrams to send
        #[arg(long, value_name = "N", default_value_t = 3227)]
        count: u32,

        /// UDP payload bytes per datagram
        #[arg(long, value_name = "BYTES", default_value_t = 1300)]
        size: usize,

        /// Pace at this bit rate of UDP payload; 0 sends as fast as the socket takes them
        #[arg(long, value_name = "BITS_PER_SEC", default_value_t = 0)]
        rate: u64,
    },
}

/// What a listener saw of one run.
#[derive(Debug, Default)]
struct Run {
    /// The run's id; a datagram with another id starts a new run.
    id: u32,
    /// Which sequence numbers arrived.
    seen: Vec<bool>,
    received: u64,
    duplicates: u64,
    /// Datagrams that arrived after one with a higher sequence number.
    reordered: u64,
    highest: Option<u32>,
    first: Option<Instant>,
    last: Option<Instant>,
}

impl Run {
    fn record(&mut self, seq: u32, now: Instant) {
        let index = seq as usize;
        if self.seen.len() <= index {
            self.seen.resize(index + 1, false);
        }
        if std::mem::replace(&mut self.seen[index], true) {
            self.duplicates += 1;
            return;
        }
        self.received += 1;
        if self.highest.is_some_and(|highest| seq < highest) {
            self.reordered += 1;
        }
        self.highest = self.highest.max(Some(seq));
        self.first.get_or_insert(now);
        self.last = Some(now);
    }

    /// The report line; `sent` is the count of the end marker, if one arrived.
    fn report(&self, sent: Option<u32>, recv_buffer: usize) -> serde_json::Value {
        // Without an end marker the run reaches as far as the highest number seen.
        let total = sent.map_or(self.seen.len(), |sent| sent as usize);
        let (mut runs, mut longest, mut current) = (0_u64, 0_u64, 0_u64);
        for index in 0..total {
            if self.seen.get(index).copied().unwrap_or(false) {
                current = 0;
            } else {
                if current == 0 {
                    runs += 1;
                }
                current += 1;
                longest = longest.max(current);
            }
        }
        let lost = (total as u64).saturating_sub(self.received);
        let span = match (self.first, self.last) {
            (Some(first), Some(last)) => last.duration_since(first).as_secs_f64(),
            _ => 0.0,
        };
        json!({
            "sent": sent,
            "received": self.received,
            "lost": lost,
            "loss": if total == 0 { 0.0 } else { float(lost) / float(total as u64) },
            "reordered": self.reordered,
            "duplicates": self.duplicates,
            "loss_runs": runs,
            "longest_loss_run": longest,
            "span_s": span,
            "recv_buffer": recv_buffer,
        })
    }
}

/// `n` as a float; exact below 2^53, far above any count here.
#[expect(
    clippy::cast_precision_loss,
    reason = "datagram and bit counts stay far below 2^53"
)]
const fn float(n: u64) -> f64 {
    n as f64
}

/// The run id and sequence number of `datagram`, if it has a header.
fn header(datagram: &[u8]) -> Option<(u32, u32)> {
    let id = u32::from_be_bytes(datagram.get(..4)?.try_into().ok()?);
    let seq = u32::from_be_bytes(datagram.get(4..HEADER)?.try_into().ok()?);
    Some((id, seq))
}

fn listen(bind: SocketAddr, idle: Duration, runs: u64) -> anyhow::Result<()> {
    let socket = UdpSocket::bind(bind).with_context(|| format!("bind {bind}"))?;
    // A smaller grant shows in the report.
    let _ = SockRef::from(&socket).set_recv_buffer_size(BUFFER);
    let recv_buffer = SockRef::from(&socket).recv_buffer_size()?;
    let mut buf = vec![0_u8; 65_536];
    let mut run: Option<Run> = None;
    // The id of the run reported last: its remaining end markers are not a new run.
    let mut finished = None;
    let mut reported = 0;
    while runs == 0 || reported < runs {
        socket.set_read_timeout(run.is_some().then_some(idle))?;
        let len = match socket.recv(&mut buf) {
            Ok(len) => len,
            Err(e)
                if matches!(
                    e.kind(),
                    std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                ) =>
            {
                if let Some(run) = run.take() {
                    out::line(format_args!("{}", run.report(None, recv_buffer)));
                    finished = Some(run.id);
                    reported += 1;
                }
                continue;
            }
            Err(e) => return Err(e).context("receive"),
        };
        let now = Instant::now();
        let Some((id, seq)) = header(&buf[..len]) else {
            continue;
        };
        if finished == Some(id) {
            continue;
        }
        if run.as_ref().is_some_and(|run| run.id != id)
            && let Some(run) = run.take()
        {
            out::line(format_args!("{}", run.report(None, recv_buffer)));
            reported += 1;
        }
        let current = run.get_or_insert_with(|| Run {
            id,
            ..Run::default()
        });
        if seq == END {
            let sent = buf
                .get(HEADER..HEADER + 4)
                .and_then(|count| count.try_into().ok())
                .map(u32::from_be_bytes)
                .filter(|sent| *sent <= MAX_COUNT);
            out::line(format_args!("{}", current.report(sent, recv_buffer)));
            finished = Some(id);
            run = None;
            reported += 1;
        } else if seq < MAX_COUNT {
            current.record(seq, now);
        }
    }
    Ok(())
}

fn send(to: SocketAddr, count: u32, size: usize, rate: u64) -> anyhow::Result<()> {
    anyhow::ensure!(
        (HEADER + 4..=65_507).contains(&size),
        "--size must be {} to 65507",
        HEADER + 4
    );
    anyhow::ensure!(count <= MAX_COUNT, "--count must be at most {MAX_COUNT}");
    let bind: SocketAddr = if to.is_ipv4() {
        ([0, 0, 0, 0], 0).into()
    } else {
        ([0_u16; 8], 0).into()
    };
    let socket = UdpSocket::bind(bind).context("bind")?;
    let _ = SockRef::from(&socket).set_send_buffer_size(BUFFER);
    socket
        .connect(to)
        .with_context(|| format!("connect {to}"))?;
    // The nanoseconds of the start time tell this run from the one before.
    let id = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |since| since.subsec_nanos());
    let mut datagram = vec![0_u8; size];
    datagram[..4].copy_from_slice(&id.to_be_bytes());
    let gap = (rate > 0).then(|| Duration::from_secs_f64(float(size as u64 * 8) / float(rate)));
    let (mut sent, mut errors) = (0_u64, 0_u64);
    let start = Instant::now();
    for seq in 0..count {
        if let Some(gap) = gap {
            let due = start + gap * seq;
            // Sleep to within a millisecond, then spin: a sleep alone is too coarse.
            if let Some(wait) = due
                .checked_duration_since(Instant::now())
                .and_then(|wait| wait.checked_sub(Duration::from_millis(1)))
            {
                std::thread::sleep(wait);
            }
            while Instant::now() < due {
                std::hint::spin_loop();
            }
        }
        datagram[4..HEADER].copy_from_slice(&seq.to_be_bytes());
        match socket.send(&datagram) {
            Ok(_) => sent += 1,
            Err(_) => errors += 1,
        }
    }
    let seconds = start.elapsed().as_secs_f64();
    datagram.truncate(HEADER + 4);
    datagram[4..HEADER].copy_from_slice(&END.to_be_bytes());
    datagram[HEADER..].copy_from_slice(&count.to_be_bytes());
    for _ in 0..END_MARKERS {
        std::thread::sleep(END_GAP);
        // A lost marker leaves the listener its idle timeout.
        let _ = socket.send(&datagram);
    }
    out::line(format_args!(
        "{}",
        json!({
            "count": count,
            "sent": sent,
            "send_errors": errors,
            "size": size,
            "rate": rate,
            "seconds": seconds,
            "bits_per_second": if seconds > 0.0 { float(sent * size as u64 * 8) / seconds } else { 0.0 },
        })
    ));
    Ok(())
}

fn main() -> anyhow::Result<()> {
    match Args::parse().command {
        Command::Listen { bind, idle, runs } => listen(bind, Duration::from_millis(idle), runs),
        Command::Send {
            to,
            count,
            size,
            rate,
        } => send(to, count, size, rate),
    }
}
