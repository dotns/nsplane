//! Server loop over loopback UDP and TCP sockets.

#![allow(clippy::unwrap_used, clippy::panic, reason = "test harness")]

use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, Instant};

use nsplane_dns::{
    Answer, Query, Record, Resolver, Server, ServerConfig, ServerStats, StaticRecords, Transport,
};
use simple_dns::rdata::{OPT, RData};
use simple_dns::{CLASS, Name, Packet, PacketFlag, Question, RCODE, TYPE};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::sync::Notify;

const SHORT: Duration = Duration::from_millis(300);
const LONG: Duration = Duration::from_secs(5);

fn query_message(id: u16, name: &str, qtype: TYPE, edns: Option<u16>) -> Vec<u8> {
    let mut packet = Packet::new_query(id);
    packet.questions.push(Question::new(
        Name::new_unchecked(name),
        qtype.into(),
        CLASS::IN.into(),
        false,
    ));
    if let Some(size) = edns {
        *packet.opt_mut() = Some(OPT {
            opt_codes: Vec::new(),
            udp_packet_size: size,
            version: 0,
        });
    }
    packet.build_bytes_vec().unwrap()
}

/// TXT records of about 63 bytes each on the wire.
fn txt_records(name: &str, count: usize) -> Vec<Record> {
    (0..count)
        .map(|i| Record::txt(name, 60, vec![format!("{i:02}{}", "x".repeat(48))]))
        .collect()
}

fn records() -> StaticRecords {
    let mut table: StaticRecords = [
        Record::a("host.test", 300, Ipv4Addr::new(10, 0, 0, 7)),
        Record::aaaa("host.test", 300, Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 7)),
    ]
    .into_iter()
    .collect();
    // About 760 bytes: above 512, below 1232.
    for record in txt_records("medium.test", 12) {
        table.insert(record);
    }
    // About 2500 bytes: above 1232.
    for record in txt_records("big.test", 40) {
        table.insert(record);
    }
    table
}

async fn udp_server<R: Resolver + 'static>(server: &Server<R>) -> SocketAddr {
    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let addr = socket.local_addr().unwrap();
    let server = server.clone();
    tokio::spawn(async move { server.serve_udp(socket).await });
    addr
}

async fn tcp_server<R: Resolver + 'static>(server: &Server<R>) -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let server = server.clone();
    tokio::spawn(async move { server.serve_tcp(listener).await });
    addr
}

async fn client(server: SocketAddr) -> UdpSocket {
    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    socket.connect(server).await.unwrap();
    socket
}

/// The next datagram on `socket`, `None` when none arrives within `wait`.
async fn recv(socket: &UdpSocket, wait: Duration) -> Option<Vec<u8>> {
    let mut buf = vec![0; 65535];
    let len = tokio::time::timeout(wait, socket.recv(&mut buf))
        .await
        .ok()?
        .unwrap();
    buf.truncate(len);
    Some(buf)
}

async fn udp_exchange(server: SocketAddr, message: &[u8]) -> Vec<u8> {
    let socket = client(server).await;
    socket.send(message).await.unwrap();
    recv(&socket, LONG).await.unwrap()
}

async fn tcp_send(stream: &mut TcpStream, message: &[u8]) {
    let len = u16::try_from(message.len()).unwrap();
    stream.write_all(&len.to_be_bytes()).await.unwrap();
    stream.write_all(message).await.unwrap();
}

async fn tcp_recv(stream: &mut TcpStream) -> Vec<u8> {
    let mut prefix = [0; 2];
    tokio::time::timeout(LONG, stream.read_exact(&mut prefix))
        .await
        .unwrap()
        .unwrap();
    let mut message = vec![0; usize::from(u16::from_be_bytes(prefix))];
    stream.read_exact(&mut message).await.unwrap();
    message
}

async fn wait_for_stats<R: Resolver>(server: &Server<R>, done: impl Fn(&ServerStats) -> bool) {
    let deadline = Instant::now() + LONG;
    while !done(&server.stats()) {
        assert!(Instant::now() < deadline, "stats: {:?}", server.stats());
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
}

#[tokio::test]
async fn udp_answers_static_records() {
    let server = Server::new(records(), ServerConfig::default());
    let addr = udp_server(&server).await;

    let response = udp_exchange(addr, &query_message(1, "HOST.test", TYPE::A, None)).await;
    let packet = Packet::parse(&response).unwrap();
    assert_eq!(packet.id(), 1);
    assert_eq!(packet.rcode(), RCODE::NoError);
    let [answer] = packet.answers.as_slice() else {
        panic!("answers: {:?}", packet.answers);
    };
    assert!(
        matches!(&answer.rdata, RData::A(a) if Ipv4Addr::from(a.address) == Ipv4Addr::new(10, 0, 0, 7))
    );

    let response = udp_exchange(addr, &query_message(2, "host.test", TYPE::AAAA, None)).await;
    let packet = Packet::parse(&response).unwrap();
    let [answer] = packet.answers.as_slice() else {
        panic!("answers: {:?}", packet.answers);
    };
    assert!(matches!(
        &answer.rdata,
        RData::AAAA(a) if Ipv6Addr::from(a.address) == Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 7)
    ));

    let response = udp_exchange(addr, &query_message(3, "missing.test", TYPE::A, None)).await;
    let packet = Packet::parse(&response).unwrap();
    assert_eq!(packet.rcode(), RCODE::NameError);
    assert_eq!(packet.answers.len(), 0);

    let stats = server.stats();
    assert_eq!((stats.queries, stats.responses, stats.truncated), (3, 3, 0));
}

#[tokio::test]
async fn udp_answers_malformed_with_formerr_and_drops_garbage() {
    let server = Server::new(records(), ServerConfig::default());
    let addr = udp_server(&server).await;

    // A header announcing one question that is missing.
    let malformed = [0xab, 0xcd, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0];
    let response = udp_exchange(addr, &malformed).await;
    let packet = Packet::parse(&response).unwrap();
    assert_eq!(packet.id(), 0xabcd);
    assert_eq!(packet.rcode(), RCODE::FormatError);

    let socket = client(addr).await;
    socket.send(&[1, 2, 3, 4, 5]).await.unwrap();
    assert_eq!(recv(&socket, SHORT).await, None);
    wait_for_stats(&server, |s| s.decode_errors == 2).await;
    assert_eq!(server.stats().responses, 1);
}

#[tokio::test]
async fn udp_truncates_above_512_without_edns_and_tcp_returns_everything() {
    let server = Server::new(records(), ServerConfig::default());
    let udp = udp_server(&server).await;
    let tcp = tcp_server(&server).await;
    let message = query_message(7, "big.test", TYPE::TXT, None);

    let packet_bytes = udp_exchange(udp, &message).await;
    let packet = Packet::parse(&packet_bytes).unwrap();
    assert!(packet.has_flags(PacketFlag::TRUNCATION));
    assert_eq!(packet.answers.len(), 0);
    assert!(packet.opt().is_none());

    let mut stream = TcpStream::connect(tcp).await.unwrap();
    tcp_send(&mut stream, &message).await;
    let response = tcp_recv(&mut stream).await;
    assert!(response.len() > 1232);
    let packet = Packet::parse(&response).unwrap();
    assert!(!packet.has_flags(PacketFlag::TRUNCATION));
    assert_eq!(packet.answers.len(), 40);

    // Medium does not fit 512 bytes either.
    let response = udp_exchange(udp, &query_message(8, "medium.test", TYPE::TXT, None)).await;
    assert!(
        Packet::parse(&response)
            .unwrap()
            .has_flags(PacketFlag::TRUNCATION)
    );
    assert_eq!(server.stats().truncated, 2);
}

#[tokio::test]
async fn udp_with_edns_is_limited_by_the_server_payload_size() {
    let server = Server::new(records(), ServerConfig::default());
    let udp = udp_server(&server).await;

    // Fits 1232: the full answer.
    let response = udp_exchange(udp, &query_message(9, "medium.test", TYPE::TXT, Some(4096))).await;
    assert!(response.len() > 512 && response.len() <= 1232);
    let packet = Packet::parse(&response).unwrap();
    assert!(!packet.has_flags(PacketFlag::TRUNCATION));
    assert_eq!(packet.answers.len(), 12);
    assert_eq!(packet.opt().unwrap().udp_packet_size, 1232);

    // Above 1232 although the client advertised 4096: truncated.
    let response = udp_exchange(udp, &query_message(10, "big.test", TYPE::TXT, Some(4096))).await;
    let packet = Packet::parse(&response).unwrap();
    assert!(packet.has_flags(PacketFlag::TRUNCATION));
    assert_eq!(packet.answers.len(), 0);
    assert_eq!(packet.opt().unwrap().udp_packet_size, 1232);
}

#[tokio::test]
async fn tcp_answers_several_queries_on_one_connection() {
    let server = Server::new(records(), ServerConfig::default());
    let tcp = tcp_server(&server).await;
    let mut stream = TcpStream::connect(tcp).await.unwrap();

    tcp_send(&mut stream, &query_message(21, "host.test", TYPE::A, None)).await;
    let first = Packet::parse(&tcp_recv(&mut stream).await).unwrap().id();

    // Pipelined: both sent before reading.
    tcp_send(
        &mut stream,
        &query_message(22, "host.test", TYPE::AAAA, None),
    )
    .await;
    tcp_send(
        &mut stream,
        &query_message(23, "missing.test", TYPE::A, None),
    )
    .await;
    let second = tcp_recv(&mut stream).await;
    let third = tcp_recv(&mut stream).await;
    let (second, third) = (
        Packet::parse(&second).unwrap(),
        Packet::parse(&third).unwrap(),
    );
    assert_eq!((first, second.id(), third.id()), (21, 22, 23));
    assert_eq!(second.answers.len(), 1);
    assert_eq!(third.rcode(), RCODE::NameError);
}

#[tokio::test]
async fn tcp_closes_idle_and_zero_length_connections() {
    let config = ServerConfig::default().with_tcp_idle_timeout(Duration::from_millis(200));
    let server = Server::new(records(), config);
    let tcp = tcp_server(&server).await;

    let mut stream = TcpStream::connect(tcp).await.unwrap();
    let start = Instant::now();
    let mut buf = [0; 1];
    let read = tokio::time::timeout(LONG, stream.read(&mut buf))
        .await
        .unwrap();
    assert_eq!(read.unwrap(), 0);
    assert!(start.elapsed() >= Duration::from_millis(150));

    let mut stream = TcpStream::connect(tcp).await.unwrap();
    stream.write_all(&[0, 0]).await.unwrap();
    let read = tokio::time::timeout(Duration::from_millis(150), stream.read(&mut buf))
        .await
        .unwrap();
    assert_eq!(read.unwrap(), 0);
}

/// Answers `block.test` only after `release`, everything else at once; never answers
/// `hang.test`.
#[derive(Default)]
struct Blocking {
    entered: Notify,
    release: Notify,
}

impl Resolver for Blocking {
    async fn resolve(&self, query: &Query, _client: SocketAddr) -> Answer {
        match query.name() {
            "block.test" => {
                self.entered.notify_one();
                self.release.notified().await;
            }
            "hang.test" => std::future::pending::<()>().await,
            _ => {}
        }
        Answer::Records(vec![Record::a(query.name(), 60, Ipv4Addr::LOCALHOST)])
    }
}

#[tokio::test]
async fn udp_drops_queries_above_the_in_flight_bound() {
    let resolver = Arc::new(Blocking::default());
    let config = ServerConfig::default().with_max_in_flight(1);
    let server = Server::new(Arc::clone(&resolver), config);
    let udp = udp_server(&server).await;

    let blocked = client(udp).await;
    blocked
        .send(&query_message(31, "block.test", TYPE::A, None))
        .await
        .unwrap();
    tokio::time::timeout(LONG, resolver.entered.notified())
        .await
        .unwrap();

    let dropped = client(udp).await;
    dropped
        .send(&query_message(32, "free.test", TYPE::A, None))
        .await
        .unwrap();
    wait_for_stats(&server, |s| s.dropped_overload == 1).await;
    assert_eq!(recv(&dropped, SHORT).await, None);

    resolver.release.notify_one();
    let response = recv(&blocked, LONG).await.unwrap();
    assert_eq!(Packet::parse(&response).unwrap().id(), 31);

    let response = udp_exchange(udp, &query_message(33, "free.test", TYPE::A, None)).await;
    let packet = Packet::parse(&response).unwrap();
    assert_eq!(packet.id(), 33);
    assert_eq!(packet.answers.len(), 1);
    assert_eq!(server.stats().dropped_overload, 1);
}

#[tokio::test]
async fn resolver_timeout_answers_servfail() {
    let config = ServerConfig::default().with_resolve_timeout(Duration::from_millis(100));
    let server = Server::new(Blocking::default(), config);

    let client = SocketAddr::from(([127, 0, 0, 1], 5353));
    let message = query_message(41, "hang.test", TYPE::A, None);
    let response = server
        .handle(&message, client, Transport::Tcp)
        .await
        .unwrap();
    let packet = Packet::parse(&response).unwrap();
    assert_eq!(packet.id(), 41);
    assert_eq!(packet.rcode(), RCODE::ServerFailure);

    let udp = udp_server(&server).await;
    let response = udp_exchange(udp, &message).await;
    assert_eq!(
        Packet::parse(&response).unwrap().rcode(),
        RCODE::ServerFailure
    );
    assert_eq!(server.stats().timeouts, 2);
}
