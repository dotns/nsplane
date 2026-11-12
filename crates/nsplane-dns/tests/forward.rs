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
use tokio::sync::mpsc;

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
async fn raw_forward_ignores_responses_with_another_question() {
    let (stub, addr) = udp_stub().await;
    tokio::spawn(async move {
        let mut buf = [0; 512];
        let (len, peer) = stub.recv_from(&mut buf).await.unwrap();
        let request = &buf[..len];
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
            "Host.Example",
            &[Ipv4Addr::new(192, 0, 2, 1)],
            false,
        );
        for reply in [wrong_question, right] {
            stub.send_to(&reply, peer).await.unwrap();
        }
    });

    let forwarder = Forwarder::new(config(vec![addr])).unwrap();
    let message = query("host.example");
    let raw = forwarder.forward(message.raw()).await.unwrap();
    assert_eq!(
        answer_addrs(&Answer::Raw(raw)),
        vec![Ipv4Addr::new(192, 0, 2, 1)]
    );
}

#[tokio::test]
async fn transaction_ids_do_not_follow_the_count_and_source_port() {
    const QUERIES: u16 = 16;
    let (stub, addr) = udp_stub().await;
    let upstream = tokio::spawn(async move {
        let mut seen = Vec::new();
        let mut buf = [0; 512];
        for _ in 0..QUERIES {
            let (len, peer) = stub.recv_from(&mut buf).await.unwrap();
            let request = &buf[..len];
            seen.push((peer.port(), Packet::parse(request).unwrap().id()));
            let reply = response(request, None, "host.example", &[], false);
            stub.send_to(&reply, peer).await.unwrap();
        }
        seen
    });

    let forwarder = Forwarder::new(config(vec![addr])).unwrap();
    for _ in 0..QUERIES {
        let answer = forwarder.resolve(&query("host.example"), client()).await;
        assert!(matches!(answer, Answer::Raw(_)), "answer: {answer:?}");
    }

    // An ID computed from the query count and the source port is known to anyone who
    // sees or guesses the port.
    let seen = upstream.await.unwrap();
    let predictable = (0..QUERIES)
        .zip(&seen)
        .filter(|(count, (port, id))| *id == count.wrapping_mul(0x9e37) ^ port.rotate_left(7))
        .count();
    assert!(predictable < seen.len() / 2, "seen: {seen:?}");
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

/// An upstream that answers every query for `host.example` with `addr`.
async fn answering_stub(addr: Ipv4Addr) -> SocketAddr {
    let (stub, stub_addr) = udp_stub().await;
    tokio::spawn(async move {
        let mut buf = [0; 512];
        loop {
            let (len, peer) = stub.recv_from(&mut buf).await.unwrap();
            let reply = response(&buf[..len], None, "host.example", &[addr], false);
            stub.send_to(&reply, peer).await.unwrap();
        }
    });
    stub_addr
}

#[tokio::test]
async fn starts_with_the_upstream_that_answered_last() {
    let (_silent, silent_addr) = udp_stub().await;
    let live = Ipv4Addr::new(192, 0, 2, 2);
    let live_addr = answering_stub(live).await;

    let forwarder = Forwarder::new(config(vec![silent_addr, live_addr])).unwrap();
    let query = query("host.example");
    let answer = forwarder.resolve(&query, client()).await;
    assert_eq!(answer_addrs(&answer), vec![live]);
    assert_eq!(forwarder.stats().timeouts, 1);

    // The silent upstream is not asked again: no further attempt times out.
    for _ in 0..3 {
        let answer = forwarder.resolve(&query, client()).await;
        assert_eq!(answer_addrs(&answer), vec![live]);
    }
    let raw = forwarder.forward(query.raw()).await.unwrap();
    assert_eq!(answer_addrs(&Answer::Raw(raw)), vec![live]);
    let stats = forwarder.stats();
    assert_eq!((stats.forwarded, stats.timeouts, stats.failures), (5, 1, 0));
}

#[tokio::test]
async fn returns_to_an_earlier_upstream_when_the_last_one_stops_answering() {
    let (first, second) = (Ipv4Addr::new(192, 0, 2, 1), Ipv4Addr::new(192, 0, 2, 2));
    // The first upstream misses one query and answers from then on; the second answers
    // one query and then no more.
    let (late, late_addr) = udp_stub().await;
    tokio::spawn(async move {
        let mut buf = [0; 512];
        late.recv_from(&mut buf).await.unwrap();
        loop {
            let (len, peer) = late.recv_from(&mut buf).await.unwrap();
            let reply = response(&buf[..len], None, "host.example", &[first], false);
            late.send_to(&reply, peer).await.unwrap();
        }
    });
    let (once, once_addr) = udp_stub().await;
    tokio::spawn(async move {
        let mut buf = [0; 512];
        let (len, peer) = once.recv_from(&mut buf).await.unwrap();
        let reply = response(&buf[..len], None, "host.example", &[second], false);
        once.send_to(&reply, peer).await.unwrap();
        std::future::pending::<()>().await;
    });

    let forwarder = Forwarder::new(config(vec![late_addr, once_addr])).unwrap();
    let query = query("host.example");
    let mut answers = Vec::new();
    for _ in 0..3 {
        answers.push(answer_addrs(&forwarder.resolve(&query, client()).await));
    }
    assert_eq!(answers, [vec![second], vec![first], vec![first]]);
    let stats = forwarder.stats();
    assert_eq!((stats.forwarded, stats.timeouts, stats.failures), (3, 2, 0));
}

#[tokio::test]
async fn fewer_attempts_than_upstreams_reach_the_later_ones() {
    let (_silent_a, silent_a) = udp_stub().await;
    let (_silent_b, silent_b) = udp_stub().await;
    let live = Ipv4Addr::new(192, 0, 2, 3);
    let live_addr = answering_stub(live).await;

    let mut config = config(vec![silent_a, silent_b, live_addr]);
    config.timeout = Duration::from_millis(100);
    let forwarder = Forwarder::new(config).unwrap();
    let query = query("host.example");
    // Two attempts: the two silent upstreams.
    assert_eq!(
        forwarder.resolve(&query, client()).await,
        Answer::Code(ResponseCode::ServFail)
    );
    // The next query goes on where the failed one stopped.
    assert_eq!(
        answer_addrs(&forwarder.resolve(&query, client()).await),
        vec![live]
    );
    assert_eq!(
        answer_addrs(&forwarder.resolve(&query, client()).await),
        vec![live]
    );
    let stats = forwarder.stats();
    assert_eq!((stats.forwarded, stats.timeouts, stats.failures), (2, 2, 1));
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

/// An upstream that answers every request with `192.0.2.1` and the reserved header bit
/// set, and reports the second flags byte of each request it saw.
async fn reserved_bit_stub() -> (SocketAddr, mpsc::UnboundedReceiver<u8>) {
    let (stub, addr) = udp_stub().await;
    let (seen, requests) = mpsc::unbounded_channel();
    tokio::spawn(async move {
        let mut buf = [0; 512];
        loop {
            let (len, peer) = stub.recv_from(&mut buf).await.unwrap();
            let _ = seen.send(buf[3]);
            let mut clean = buf[..len].to_vec();
            clean[3] &= !0x40;
            let addrs = [Ipv4Addr::new(192, 0, 2, 1)];
            let mut reply = response(&clean, None, "host.example", &addrs, false);
            reply[3] |= 0x40;
            stub.send_to(&reply, peer).await.unwrap();
        }
    });
    (addr, requests)
}

#[tokio::test]
async fn an_upstream_response_with_the_reserved_bit_is_accepted() {
    let (addr, _requests) = reserved_bit_stub().await;
    let forwarder = Forwarder::new(config(vec![addr])).unwrap();
    let query = query("host.example");
    let answer = forwarder.resolve(&query, client()).await;
    assert_eq!(answer_addrs(&answer), vec![Ipv4Addr::new(192, 0, 2, 1)]);
    assert_eq!(forwarder.stats().timeouts, 0);

    // A message passed as it is comes back without the bit.
    let raw = forwarder.forward(query.raw()).await.unwrap();
    assert_eq!(raw[3] & 0x40, 0);
    assert_eq!(
        answer_addrs(&Answer::Raw(raw)),
        vec![Ipv4Addr::new(192, 0, 2, 1)]
    );
}

#[tokio::test]
async fn the_reserved_bit_of_a_client_is_not_sent_upstream() {
    let (addr, mut requests) = reserved_bit_stub().await;
    let forwarder = Forwarder::new(config(vec![addr])).unwrap();
    let mut message = query("host.example").raw().to_vec();
    message[3] |= 0x40;

    assert!(forwarder.forward(&message).await.is_some());
    assert_eq!(requests.recv().await.unwrap() & 0x40, 0);

    let query = Query::decode(&message).unwrap();
    let answer = forwarder.resolve(&query, client()).await;
    assert_eq!(answer_addrs(&answer), vec![Ipv4Addr::new(192, 0, 2, 1)]);
    assert_eq!(requests.recv().await.unwrap() & 0x40, 0);
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
