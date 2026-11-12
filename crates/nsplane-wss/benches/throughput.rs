#![allow(
    clippy::unwrap_used,
    clippy::print_stdout,
    reason = "benchmark harness"
)]

//! A `WssDialer` link against a `WssServerTransport` over loopback `ws://` (no TLS):
//! datagrams of 1200 bytes, first from the link to the server, then back, at most 128 in
//! flight. Prints the datagrams per second and the CPU time of the whole process per
//! datagram (user and system, from `/proc/self/stat`; zero where that file is missing).
//!
//! ```sh
//! cargo bench -p nsplane-wss --bench throughput
//! ```

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use nsplane::{Ecn, LinkConfig, PacketBuf, Path, Transport, TransportId};
use nsplane_wss::{WssAcceptor, WssConfig, WssDialer, WssServerConfig, WssServerTransport, WssTls};
use rustls::RootCertStore;
use tokio::net::TcpListener;
use tokio::sync::Semaphore;

/// Bytes per datagram.
const SIZE: usize = 1200;
/// Datagrams per direction.
const COUNT: u32 = 1_000_000;
/// Datagrams in flight at most: below the send queues, so that no send fails.
const WINDOW: usize = 128;

/// The CPU time the process used so far, at the usual 100 clock ticks per second.
fn cpu() -> Duration {
    let stat = std::fs::read_to_string("/proc/self/stat").unwrap_or_default();
    // The fields after the command name, which may contain spaces: utime and stime are
    // the 12th and 13th of them.
    let ticks: u64 = stat
        .rsplit(')')
        .next()
        .unwrap_or_default()
        .split_whitespace()
        .skip(11)
        .take(2)
        .filter_map(|field| field.parse::<u64>().ok())
        .sum();
    Duration::from_millis(ticks * 10)
}

/// Carries [`COUNT`] datagrams from `from` to `to` and prints the rate.
async fn run<A: Transport, B: Transport>(name: &str, from: &A, to: &B, path: Path) {
    let window = Arc::new(Semaphore::new(WINDOW));
    let (started, cpu_started) = (Instant::now(), cpu());
    let send = async {
        let datagram = [0x5a_u8; SIZE];
        for _ in 0..COUNT {
            window.acquire().await.unwrap().forget();
            from.send(&datagram, &path).await.unwrap();
        }
    };
    let recv = async {
        let mut buf = PacketBuf::with_capacity(2048);
        for _ in 0..COUNT {
            let (len, _) = to.recv(&mut buf).await.unwrap();
            assert_eq!(len, SIZE);
            window.add_permits(1);
        }
    };
    tokio::join!(send, recv);
    let (elapsed, used) = (started.elapsed(), cpu().saturating_sub(cpu_started));
    println!(
        "{name}: {COUNT} datagrams of {SIZE} bytes in {:.2} s: {:.0} datagrams/s, {:.2} us CPU per datagram",
        elapsed.as_secs_f64(),
        f64::from(COUNT) / elapsed.as_secs_f64(),
        used.as_secs_f64() * 1e6 / f64::from(COUNT),
    );
}

#[tokio::main(flavor = "multi_thread", worker_threads = 4)]
async fn main() {
    let (server, acceptor) =
        WssServerTransport::new(TransportId::new(1), WssServerConfig::default());
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let accepting = tokio::spawn(async move {
        let (tcp, _) = listener.accept().await.unwrap();
        tcp.set_nodelay(true).unwrap();
        let ws = tokio_tungstenite::accept_async_with_config(tcp, Some(WssAcceptor::ws_config()))
            .await
            .unwrap();
        acceptor.accept(ws).unwrap()
    });
    let config = WssConfig::new(
        format!("ws://{addr}/"),
        WssTls::Roots(RootCertStore::empty()),
    )
    .allow_plaintext(true);
    let peer: SocketAddr = "192.0.2.1:443".parse().unwrap();
    let link = WssDialer::new(config).unwrap().into_transport(
        TransportId::new(2),
        peer,
        LinkConfig::default(),
    );
    let session = accepting.await.unwrap();
    let path = |transport: u16, addr| Path {
        transport: TransportId::new(transport),
        addr,
        ecn: Ecn::NotEct,
    };
    run("link to server", &link, &server, path(2, peer)).await;
    run("server to link", &server, &link, path(1, session.addr())).await;
}
