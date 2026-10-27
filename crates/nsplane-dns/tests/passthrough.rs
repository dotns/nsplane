//! `Server` passthrough of messages that do not decode as a query, to a stub upstream.

#![allow(clippy::unwrap_used, clippy::panic, reason = "test harness")]

use std::net::{Ipv4Addr, SocketAddr};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use nsplane_dns::{
    Forwarder, ForwarderConfig, PassthroughDecision, PassthroughRequest, Record, Server,
    ServerConfig, StaticRecords, Transport,
};
use simple_dns::rdata::{A, OPT, RData};
use simple_dns::{
    CLASS, Name, OPCODE, Packet, PacketFlag, Question, RCODE, ResourceRecord, TYPE, header_buffer,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::sync::mpsc;

const LONG: Duration = Duration::from_secs(5);

fn client() -> SocketAddr {
    SocketAddr::from(([127, 0, 0, 1], 40000))
}

fn question(name: &str, qtype: TYPE) -> Question<'_> {
    Question::new(
        Name::new_unchecked(name),
        qtype.into(),
        CLASS::IN.into(),
        false,
    )
}

fn query_message(id: u16, name: &str, edns: Option<u16>) -> Vec<u8> {
    let mut packet = Packet::new_query(id);
    packet.questions.push(question(name, TYPE::A));
    if let Some(size) = edns {
        *packet.opt_mut() = Some(OPT {
            opt_codes: Vec::new(),
            udp_packet_size: size,
            version: 0,
        });
    }
    packet.build_bytes_vec().unwrap()
}

/// A NOTIFY for `zone.test` SOA.
fn notify(id: u16, edns: Option<u16>) -> Vec<u8> {
    let mut packet = Packet::new_query(id);
    *packet.opcode_mut() = OPCODE::Notify;
    packet.set_flags(PacketFlag::AUTHORITATIVE_ANSWER);
    packet.questions.push(question("zone.test", TYPE::SOA));
    if let Some(size) = edns {
        *packet.opt_mut() = Some(OPT {
            opt_codes: Vec::new(),
            udp_packet_size: size,
            version: 0,
        });
    }
    packet.build_bytes_vec().unwrap()
}

/// An UPDATE of `zone.test` deleting the A records of `host.zone.test`.
fn update(id: u16) -> Vec<u8> {
    let mut packet = Packet::new_query(id);
    *packet.opcode_mut() = OPCODE::Update;
    packet.questions.push(question("zone.test", TYPE::SOA));
    packet.name_servers.push(ResourceRecord::new(
        Name::new_unchecked("host.zone.test"),
        CLASS::NONE,
        0,
        RData::Empty(TYPE::A),
    ));
    packet.build_bytes_vec().unwrap()
}

/// An inverse query: no question, one answer record.
fn iquery(id: u16) -> Vec<u8> {
    let mut packet = Packet::new_query(id);
    *packet.opcode_mut() = OPCODE::InverseQuery;
    packet.answers.push(ResourceRecord::new(
        Name::new_unchecked(""),
        CLASS::IN,
        0,
        RData::A(A::from(Ipv4Addr::new(192, 0, 2, 1))),
    ));
    packet.build_bytes_vec().unwrap()
}

fn two_questions(id: u16) -> Vec<u8> {
    let mut packet = Packet::new_query(id);
    packet.questions.push(question("a.test", TYPE::A));
    packet.questions.push(question("b.test", TYPE::A));
    packet.build_bytes_vec().unwrap()
}

/// Adds two additional records to a one-question query without EDNS: a record of an unknown
/// type and class, and an OPT record with an unknown option code.
fn with_unknown_records(mut message: Vec<u8>) -> Vec<u8> {
    message[11] = 2;
    message.extend_from_slice(b"\xc0\x0c\xff\x00\x00\x4d\x00\x00\x00\x3c\x00\x03abc");
    message
        .extend_from_slice(b"\x00\x00\x29\x10\x00\x00\x00\x00\x00\x00\x06\xfd\xe9\x00\x02\xaa\xbb");
    message
}

/// The stub's response to `request`: its header with `QR` set and no sections, plus, when
/// `pad` is not zero, one answer record of an unknown type with `pad` bytes of RDATA.
fn stub_response(request: &[u8], pad: usize) -> Vec<u8> {
    let mut response = request[..12].to_vec();
    response[2] |= 0x80;
    response[4..].fill(0);
    if pad > 0 {
        response[7] = 1;
        response.extend_from_slice(b"\x00\xff\x00\x00\x01\x00\x00\x00\x00");
        response.extend_from_slice(&u16::try_from(pad).unwrap().to_be_bytes());
        response.resize(response.len() + pad, 0x55);
    }
    response
}

/// A stub upstream on UDP and TCP of one port; every message it receives is reported on the
/// channel and answered with [`stub_response`].
async fn stub_upstream(pad: usize) -> (SocketAddr, mpsc::UnboundedReceiver<Vec<u8>>) {
    // TCP and UDP allocate ports independently. Keep the listener while trying UDP,
    // and retry only allocation conflicts before starting either serving task.
    let (tcp, udp, addr) = loop {
        let tcp = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = tcp.local_addr().unwrap();
        match UdpSocket::bind(addr).await {
            Ok(udp) => break (tcp, udp, addr),
            Err(error) if error.kind() == std::io::ErrorKind::AddrInUse => {}
            Err(error) => panic!("bind stub UDP socket: {error}"),
        }
    };
    let (seen, received) = mpsc::unbounded_channel();
    let udp_seen = seen.clone();
    tokio::spawn(async move {
        let mut buf = vec![0; 65535];
        loop {
            let (len, peer) = udp.recv_from(&mut buf).await.unwrap();
            udp_seen.send(buf[..len].to_vec()).unwrap();
            udp.send_to(&stub_response(&buf[..len], pad), peer)
                .await
                .unwrap();
        }
    });
    tokio::spawn(async move {
        loop {
            let (mut stream, _) = tcp.accept().await.unwrap();
            let len = stream.read_u16().await.unwrap();
            let mut request = vec![0; usize::from(len)];
            stream.read_exact(&mut request).await.unwrap();
            seen.send(request.clone()).unwrap();
            let response = stub_response(&request, pad);
            let len = u16::try_from(response.len()).unwrap();
            stream.write_all(&len.to_be_bytes()).await.unwrap();
            stream.write_all(&response).await.unwrap();
        }
    });
    (addr, received)
}

fn forwarder(upstream: SocketAddr) -> Arc<Forwarder> {
    let mut config = ForwarderConfig::new(vec![upstream]);
    config.timeout = Duration::from_millis(200);
    Arc::new(Forwarder::new(config).unwrap())
}

fn records() -> StaticRecords {
    let mut table = StaticRecords::new();
    table.insert(Record::a("host.test", 300, Ipv4Addr::new(10, 0, 0, 7)));
    table
}

fn server() -> Server<StaticRecords> {
    Server::new(records(), ServerConfig::default())
}

async fn handle(server: &Server<StaticRecords>, message: &[u8], transport: Transport) -> Vec<u8> {
    server
        .handle(message, client(), transport)
        .await
        .unwrap()
        .to_vec()
}

/// Asserts that the upstream received `message` byte for byte apart from the ID.
fn assert_passed_verbatim(seen: &[u8], message: &[u8]) {
    assert_eq!(seen.len(), message.len());
    assert_eq!(seen[2..], message[2..]);
}

#[tokio::test]
async fn notify_update_and_iquery_are_passed_through() {
    let (upstream, mut seen) = stub_upstream(0).await;
    let forwarder = forwarder(upstream);
    let server = server().with_passthrough(Arc::clone(&forwarder));

    for (message, opcode) in [
        (notify(0x1001, None), OPCODE::Notify),
        (update(0x1002), OPCODE::Update),
        (iquery(0x1003), OPCODE::InverseQuery),
    ] {
        let response = handle(&server, &message, Transport::Udp).await;
        assert_eq!(
            header_buffer::id(&response).unwrap(),
            header_buffer::id(&message).unwrap()
        );
        assert!(header_buffer::has_flags(&response, PacketFlag::RESPONSE).unwrap());
        assert_eq!(header_buffer::opcode(&response).unwrap(), opcode);
        assert_eq!(header_buffer::rcode(&response).unwrap(), RCODE::NoError);
        assert_passed_verbatim(&seen.recv().await.unwrap(), &message);
    }

    let stats = server.stats();
    assert_eq!(
        (
            stats.queries,
            stats.responses,
            stats.decode_errors,
            stats.passed
        ),
        (3, 3, 3, 3)
    );
    assert_eq!((stats.pass_refused, stats.pass_failed), (0, 0));
    assert_eq!(forwarder.stats().forwarded, 3);
}

#[tokio::test]
async fn policy_keeps_messages_local() {
    let (upstream, mut seen) = stub_upstream(0).await;
    let requests = Arc::new(Mutex::new(Vec::new()));
    let log = Arc::clone(&requests);
    let server = server()
        .with_passthrough_policy(move |request: &PassthroughRequest| {
            log.lock().unwrap().push(*request);
            if request.opcode == 4 {
                PassthroughDecision::Pass
            } else {
                PassthroughDecision::Local
            }
        })
        .with_passthrough(forwarder(upstream));

    let response = handle(&server, &update(0x2001), Transport::Udp).await;
    let packet = Packet::parse(&response).unwrap();
    assert_eq!(packet.id(), 0x2001);
    assert_eq!(packet.rcode(), RCODE::NotImplemented);

    let response = handle(&server, &iquery(0x2002), Transport::Udp).await;
    assert_eq!(
        Packet::parse(&response).unwrap().rcode(),
        RCODE::NotImplemented
    );

    let response = handle(&server, &two_questions(0x2003), Transport::Udp).await;
    assert_eq!(
        Packet::parse(&response).unwrap().rcode(),
        RCODE::FormatError
    );

    let message = notify(0x2004, None);
    let response = handle(&server, &message, Transport::Udp).await;
    assert_eq!(header_buffer::id(&response).unwrap(), 0x2004);
    assert!(header_buffer::has_flags(&response, PacketFlag::RESPONSE).unwrap());
    assert_passed_verbatim(&seen.recv().await.unwrap(), &message);
    assert!(seen.try_recv().is_err());

    let requests = requests.lock().unwrap();
    let seen: Vec<_> = requests
        .iter()
        .map(|r| (r.client, r.opcode, r.question_count))
        .collect();
    assert_eq!(
        seen,
        vec![
            (client(), 5, 1),
            (client(), 1, 0),
            (client(), 0, 2),
            (client(), 4, 1)
        ]
    );
    let stats = server.stats();
    assert_eq!(
        (stats.passed, stats.pass_refused, stats.pass_failed),
        (1, 3, 0)
    );
}

#[tokio::test]
async fn two_question_message_is_passed_through() {
    let (upstream, mut seen) = stub_upstream(0).await;
    let server = server().with_passthrough(forwarder(upstream));

    let message = two_questions(0x3001);
    let response = handle(&server, &message, Transport::Udp).await;
    assert_eq!(header_buffer::id(&response).unwrap(), 0x3001);
    assert_eq!(header_buffer::rcode(&response).unwrap(), RCODE::NoError);
    assert_passed_verbatim(&seen.recv().await.unwrap(), &message);
}

#[tokio::test]
async fn malformed_question_is_passed_through() {
    let (upstream, mut seen) = stub_upstream(0).await;
    let server = server().with_passthrough(forwarder(upstream));

    let mut message = query_message(0x3101, "host.test", None);
    message.truncate(message.len() - 3);
    let response = handle(&server, &message, Transport::Udp).await;
    assert_eq!(header_buffer::id(&response).unwrap(), 0x3101);
    assert!(header_buffer::has_flags(&response, PacketFlag::RESPONSE).unwrap());
    assert_passed_verbatim(&seen.recv().await.unwrap(), &message);
}

#[tokio::test]
async fn query_with_unknown_records_is_answered_locally() {
    let (upstream, mut seen) = stub_upstream(0).await;
    let forwarder = forwarder(upstream);
    let message = with_unknown_records(query_message(0x4001, "host.test", None));

    for server in [server(), server().with_passthrough(Arc::clone(&forwarder))] {
        let response = handle(&server, &message, Transport::Udp).await;
        let packet = Packet::parse(&response).unwrap();
        assert_eq!(packet.id(), 0x4001);
        assert_eq!(packet.rcode(), RCODE::NoError);
        let [answer] = packet.answers.as_slice() else {
            panic!("answers: {:?}", packet.answers);
        };
        assert!(
            matches!(&answer.rdata, RData::A(a) if Ipv4Addr::from(a.address) == Ipv4Addr::new(10, 0, 0, 7))
        );
        assert_eq!(packet.opt().unwrap().udp_packet_size, 1232);
        let stats = server.stats();
        assert_eq!((stats.decode_errors, stats.passed), (0, 0));
    }
    assert!(seen.try_recv().is_err());
    assert_eq!(forwarder.stats().forwarded, 0);
}

#[tokio::test]
async fn without_passthrough_errors_are_unchanged() {
    let server = server();

    let response = handle(&server, &notify(0x5001, None), Transport::Udp).await;
    let packet = Packet::parse(&response).unwrap();
    assert_eq!(
        (packet.id(), packet.rcode()),
        (0x5001, RCODE::NotImplemented)
    );
    assert!(packet.questions.is_empty());

    for message in [update(0x5002), iquery(0x5003)] {
        let response = handle(&server, &message, Transport::Udp).await;
        assert_eq!(
            Packet::parse(&response).unwrap().rcode(),
            RCODE::NotImplemented
        );
    }

    let response = handle(&server, &two_questions(0x5004), Transport::Udp).await;
    assert_eq!(
        Packet::parse(&response).unwrap().rcode(),
        RCODE::FormatError
    );

    let mut truncated = query_message(0x5005, "host.test", None);
    truncated.truncate(truncated.len() - 3);
    let response = handle(&server, &truncated, Transport::Tcp).await;
    assert_eq!(
        Packet::parse(&response).unwrap().rcode(),
        RCODE::FormatError
    );

    assert_eq!(
        server.handle(&[1, 2, 3], client(), Transport::Udp).await,
        None
    );
    let stats = server.stats();
    assert_eq!(
        (stats.decode_errors, stats.passed, stats.pass_refused),
        (6, 0, 0)
    );
}

#[tokio::test]
async fn responses_and_short_messages_are_not_passed() {
    let (upstream, mut seen) = stub_upstream(0).await;
    let server = server().with_passthrough(forwarder(upstream));

    let mut response = notify(0x5101, None);
    response[2] |= 0x80;
    assert_eq!(
        server.handle(&response, client(), Transport::Udp).await,
        None
    );
    assert_eq!(
        server.handle(&[0; 11], client(), Transport::Udp).await,
        None
    );
    assert!(seen.try_recv().is_err());
    assert_eq!(server.stats().passed, 0);
}

#[tokio::test]
async fn passed_responses_are_truncated_for_udp() {
    // About 700 bytes: above 512, below 1232.
    let (upstream, _seen) = stub_upstream(700).await;
    let server = server().with_passthrough(forwarder(upstream));

    let response = handle(&server, &notify(0x6001, None), Transport::Udp).await;
    assert_eq!(response.len(), 12);
    assert_eq!(header_buffer::id(&response).unwrap(), 0x6001);
    assert!(
        header_buffer::has_flags(&response, PacketFlag::TRUNCATION | PacketFlag::RESPONSE).unwrap()
    );
    assert_eq!(header_buffer::opcode(&response).unwrap(), OPCODE::Notify);
    assert_eq!(header_buffer::answers(&response).unwrap(), 0);

    let response = handle(&server, &notify(0x6002, Some(4096)), Transport::Udp).await;
    assert!(response.len() > 700);
    assert!(!header_buffer::has_flags(&response, PacketFlag::TRUNCATION).unwrap());
    assert_eq!(header_buffer::answers(&response).unwrap(), 1);

    let response = handle(&server, &notify(0x6003, None), Transport::Tcp).await;
    assert!(response.len() > 700);
    assert_eq!(header_buffer::id(&response).unwrap(), 0x6003);
    assert!(!header_buffer::has_flags(&response, PacketFlag::TRUNCATION).unwrap());

    let stats = server.stats();
    assert_eq!((stats.passed, stats.truncated), (3, 1));
}

#[tokio::test]
async fn passed_over_tcp_sockets() {
    let (upstream, mut seen) = stub_upstream(3000).await;
    let server = server().with_passthrough(forwarder(upstream));
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let serving = server.clone();
    tokio::spawn(async move { serving.serve_tcp(listener).await });

    let mut stream = TcpStream::connect(addr).await.unwrap();
    for message in [update(0x7001), query_message(0x7002, "host.test", None)] {
        let len = u16::try_from(message.len()).unwrap();
        stream.write_all(&len.to_be_bytes()).await.unwrap();
        stream.write_all(&message).await.unwrap();
    }
    let mut responses = Vec::new();
    for _ in 0..2 {
        let len = tokio::time::timeout(LONG, stream.read_u16())
            .await
            .unwrap()
            .unwrap();
        let mut response = vec![0; usize::from(len)];
        stream.read_exact(&mut response).await.unwrap();
        responses.push(response);
    }
    assert!(responses[0].len() > 3000);
    assert_eq!(header_buffer::id(&responses[0]).unwrap(), 0x7001);
    assert_eq!(
        header_buffer::opcode(&responses[0]).unwrap(),
        OPCODE::Update
    );
    let local = Packet::parse(&responses[1]).unwrap();
    assert_eq!((local.id(), local.answers.len()), (0x7002, 1));
    assert_passed_verbatim(&seen.recv().await.unwrap(), &update(0x7001));
}

#[tokio::test]
async fn failed_passthrough_answers_servfail() {
    let silent = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let server = server().with_passthrough(forwarder(silent.local_addr().unwrap()));

    let response = handle(&server, &notify(0x8001, None), Transport::Udp).await;
    let packet = Packet::parse(&response).unwrap();
    assert_eq!(
        (packet.id(), packet.rcode()),
        (0x8001, RCODE::ServerFailure)
    );
    let stats = server.stats();
    assert_eq!((stats.passed, stats.pass_failed), (0, 1));
}
