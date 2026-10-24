//! `Forwarder` against stub upstreams on the loopback.

#![allow(clippy::unwrap_used, clippy::panic, reason = "test harness")]

use std::net::{Ipv4Addr, SocketAddr};
use std::time::Duration;

use nsplane_dns::{
    Answer, Forwarder, ForwarderConfig, ForwarderError, Query, Resolver, ResponseCode,
};
use simple_dns::rdata::{A, RData};
use simple_dns::{CLASS, Name, Packet, PacketFlag, Question, ResourceRecord, TYPE};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, UdpSocket};

fn query(name: &str) -> Query {
    let mut packet = Packet::new_query(0x1234);
    packet.questions.push(Question::new(
        Name::new_unchecked(name),
        TYPE::A.into(),
        CLASS::IN.into(),
        false,
    ));
    packet.set_flags(PacketFlag::RECURSION_DESIRED);
    Query::decode(&packet.build_bytes_vec().unwrap()).unwrap()
}

fn client() -> SocketAddr {
    SocketAddr::from(([127, 0, 0, 1], 40000))
}

/// A response to `request` (with its ID unless `id` is given) carrying `addrs` as A records
/// for `name`.
fn response(request: &[u8], id: Option<u16>, name: &str, addrs: &[Ipv4Addr], tc: bool) -> Vec<u8> {
    let request = Packet::parse(request).unwrap();
    let mut packet = Packet::new_reply(id.unwrap_or_else(|| request.id()));
    packet.questions.push(Question::new(
        Name::new_unchecked(name),
        TYPE::A.into(),
        CLASS::IN.into(),
        false,
    ));
    if tc {
        packet.set_flags(PacketFlag::TRUNCATION);
    }
    for addr in addrs {
        packet.answers.push(ResourceRecord::new(
            Name::new_unchecked(name),
            CLASS::IN,
            60,
            RData::A(A::from(*addr)),
        ));
    }
    packet.build_bytes_vec().unwrap()
}

fn answer_addrs(answer: &Answer) -> Vec<Ipv4Addr> {
    let Answer::Raw(raw) = answer else {
        panic!("expected a raw answer, got {answer:?}");
    };
    Packet::parse(raw)
        .unwrap()
        .answers
        .iter()
        .map(|rr| match &rr.rdata {
            RData::A(a) => Ipv4Addr::from(a.address),
            other => panic!("unexpected rdata {other:?}"),
        })
        .collect()
}

const fn config(upstreams: Vec<SocketAddr>) -> ForwarderConfig {
    let mut config = ForwarderConfig::new(upstreams);
    config.timeout = Duration::from_millis(200);
    config
}

async fn udp_stub() -> (UdpSocket, SocketAddr) {
    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let addr = socket.local_addr().unwrap();
    (socket, addr)
}

#[tokio::test]
async fn forwards_and_returns_the_upstream_response() {
    let (stub, addr) = udp_stub().await;
    let upstream = tokio::spawn(async move {
        let mut buf = [0; 512];
        let (len, peer) = stub.recv_from(&mut buf).await.unwrap();
        let reply = response(
            &buf[..len],
            None,
            "Host.Example",
            &[Ipv4Addr::new(192, 0, 2, 1)],
            false,
        );
        stub.send_to(&reply, peer).await.unwrap();
        Query::decode(&buf[..len]).unwrap()
    });

    let forwarder = Forwarder::new(config(vec![addr])).unwrap();
    let query = query("host.example");
    let answer = forwarder.resolve(&query, client()).await;
    assert_eq!(answer_addrs(&answer), vec![Ipv4Addr::new(192, 0, 2, 1)]);

    let seen = upstream.await.unwrap();
    assert_eq!(seen.name(), query.name());
    assert_eq!(seen.record_type(), query.record_type());
    assert_eq!(seen.class(), query.class());
    assert!(seen.recursion_desired());

    let stats = forwarder.stats();
    assert_eq!(
        (
            stats.forwarded,
            stats.timeouts,
            stats.tcp_retries,
            stats.failures
        ),
        (1, 0, 0, 0)
    );
}

#[tokio::test]
async fn ignores_responses_with_another_id_or_question() {
    let (stub, addr) = udp_stub().await;
    tokio::spawn(async move {
        let mut buf = [0; 512];
        let (len, peer) = stub.recv_from(&mut buf).await.unwrap();
        let request = &buf[..len];
        let id = Packet::parse(request).unwrap().id();
        let wrong_id = response(
            request,
            Some(id ^ 0x5555),
            "host.example",
            &[Ipv4Addr::new(192, 0, 2, 66)],
            false,
        );
        let wrong_question = response(
            request,
            None,
            "other.example",
            &[Ipv4Addr::new(192, 0, 2, 77)],
            false,
        );
        let right = response(
            request,
            None,
            "host.example",
            &[Ipv4Addr::new(192, 0, 2, 1)],
            false,
        );
        for reply in [wrong_id, wrong_question, right] {
            stub.send_to(&reply, peer).await.unwrap();
        }
    });

    let forwarder = Forwarder::new(config(vec![addr])).unwrap();
    let answer = forwarder.resolve(&query("host.example"), client()).await;
    assert_eq!(answer_addrs(&answer), vec![Ipv4Addr::new(192, 0, 2, 1)]);
}

#[tokio::test]
async fn retries_truncated_responses_over_tcp() {
    let (stub, addr) = udp_stub().await;
    let listener = TcpListener::bind(addr).await.unwrap();
    tokio::spawn(async move {
        let mut buf = [0; 512];
        let (len, peer) = stub.recv_from(&mut buf).await.unwrap();
        let reply = response(&buf[..len], None, "host.example", &[], true);
        stub.send_to(&reply, peer).await.unwrap();
    });
    tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let len = stream.read_u16().await.unwrap();
        let mut request = vec![0; usize::from(len)];
        stream.read_exact(&mut request).await.unwrap();
        let addrs: Vec<_> = (1..=3).map(|i| Ipv4Addr::new(192, 0, 2, i)).collect();
        let reply = response(&request, None, "host.example", &addrs, false);
        stream
            .write_all(&u16::try_from(reply.len()).unwrap().to_be_bytes())
            .await
            .unwrap();
        stream.write_all(&reply).await.unwrap();
    });

    let forwarder = Forwarder::new(config(vec![addr])).unwrap();
    let answer = forwarder.resolve(&query("host.example"), client()).await;
    assert_eq!(answer_addrs(&answer).len(), 3);
    let stats = forwarder.stats();
    assert_eq!((stats.forwarded, stats.tcp_retries), (1, 1));
}

#[tokio::test]
async fn rotates_to_the_next_upstream_after_a_timeout() {
    let (_silent, silent_addr) = udp_stub().await;
    let (stub, addr) = udp_stub().await;
    tokio::spawn(async move {
        let mut buf = [0; 512];
        let (len, peer) = stub.recv_from(&mut buf).await.unwrap();
        let reply = response(
            &buf[..len],
            None,
            "host.example",
            &[Ipv4Addr::new(192, 0, 2, 2)],
            false,
        );
        stub.send_to(&reply, peer).await.unwrap();
    });

    let forwarder = Forwarder::new(config(vec![silent_addr, addr])).unwrap();
    let answer = forwarder.resolve(&query("host.example"), client()).await;
    assert_eq!(answer_addrs(&answer), vec![Ipv4Addr::new(192, 0, 2, 2)]);
    let stats = forwarder.stats();
    assert_eq!((stats.forwarded, stats.timeouts, stats.failures), (1, 1, 0));
}

#[tokio::test]
async fn answers_servfail_when_every_attempt_fails() {
    let (_silent, silent_addr) = udp_stub().await;
    // A closed port: the attempt fails with a refusal or a timeout.
    let closed_addr = udp_stub().await.1;

    let mut config = config(vec![silent_addr, closed_addr]);
    config.timeout = Duration::from_millis(100);
    config.attempts = 3;
    let forwarder = Forwarder::new(config).unwrap();
    let answer = forwarder.resolve(&query("host.example"), client()).await;
    assert_eq!(answer, Answer::Code(ResponseCode::ServFail));
    let stats = forwarder.stats();
    assert_eq!((stats.forwarded, stats.failures), (0, 1));
    assert!(stats.timeouts >= 2);
}

#[test]
fn rejects_invalid_configs() {
    assert_eq!(
        Forwarder::new(ForwarderConfig::new(Vec::new())).unwrap_err(),
        ForwarderError::NoUpstreams
    );
    let mut config = ForwarderConfig::new(vec![client()]);
    config.attempts = 0;
    assert_eq!(
        Forwarder::new(config).unwrap_err(),
        ForwarderError::NoAttempts
    );
    assert_eq!(
        ForwarderConfig::new(vec![client()]).timeout,
        Duration::from_secs(2)
    );
    assert_eq!(ForwarderConfig::new(vec![client()]).attempts, 2);
}
