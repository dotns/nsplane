//! `PolicyResolver` behind a `Server` over loopback UDP and TCP, with local records, a fake
//! pool and two forwarders to stub upstreams.

#![allow(clippy::unwrap_used, clippy::panic, reason = "test harness")]

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use nsplane_dns::{
    Action, FakePool, FakePoolConfig, Forwarder, ForwarderConfig, NameMatch, PolicyResolver,
    PolicyTable, Record, RecordData, ResolverSet, ResponseCode, Rule, Server, ServerConfig,
    StaticRecords,
};
use simple_dns::rdata::{A, RData};
use simple_dns::{CLASS, Name, Packet, PacketFlag, Question, RCODE, ResourceRecord, TYPE};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};

const LONG: Duration = Duration::from_secs(5);
const CORP: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 1);
const PUBLIC: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 2);
const PRINTER: Ipv4Addr = Ipv4Addr::new(10, 0, 0, 7);

/// An upstream answering every query with one A record `addr` for the question name.
async fn stub_upstream(addr: Ipv4Addr) -> SocketAddr {
    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let local = socket.local_addr().unwrap();
    tokio::spawn(async move {
        let mut buf = [0; 512];
        loop {
            let (len, peer) = socket.recv_from(&mut buf).await.unwrap();
            let request = Packet::parse(&buf[..len]).unwrap();
            let mut reply = Packet::new_reply(request.id());
            reply.set_flags(PacketFlag::RECURSION_AVAILABLE);
            let question = request.questions[0].clone();
            reply.answers.push(ResourceRecord::new(
                question.qname.clone(),
                CLASS::IN,
                30,
                RData::A(A::from(addr)),
            ));
            reply.questions.push(question);
            socket
                .send_to(&reply.build_bytes_vec().unwrap(), peer)
                .await
                .unwrap();
        }
    });
    local
}

struct Setup {
    server: Server<PolicyResolver>,
    corp: Arc<Forwarder>,
    public: Arc<Forwarder>,
}

async fn setup() -> Setup {
    let corp =
        Arc::new(Forwarder::new(ForwarderConfig::new(vec![stub_upstream(CORP).await])).unwrap());
    let public =
        Arc::new(Forwarder::new(ForwarderConfig::new(vec![stub_upstream(PUBLIC).await])).unwrap());
    let local: StaticRecords = std::iter::once(Record::a("printer.lan", 300, PRINTER)).collect();
    let fake = FakePool::new(FakePoolConfig {
        ipv4: Some((Ipv4Addr::new(198, 18, 0, 0), 15)),
        ..FakePoolConfig::default()
    })
    .unwrap();
    let resolvers = ResolverSet::new()
        .with("local", local)
        .with("fake", fake)
        .with("corp", Arc::clone(&corp))
        .with("public", Arc::clone(&public));
    let big = (0..40)
        .map(|i| RecordData::Txt(vec![format!("{i:02}{}", "x".repeat(48))]))
        .collect();
    let rule = |name, action| Rule::new(name, action);
    let table = PolicyTable::new([
        rule(
            NameMatch::Exact("printer.lan".into()),
            Action::Resolve("local".into()),
        ),
        rule(
            NameMatch::Suffix("corp.example".into()),
            Action::Resolve("corp".into()),
        ),
        rule(
            NameMatch::Wildcard("*.fake.test".into()),
            Action::Resolve("fake".into()),
        ),
        rule(NameMatch::Suffix("ads.test".into()), Action::Sinkhole),
        rule(
            NameMatch::Exact("blocked.test".into()),
            Action::Block(ResponseCode::NxDomain),
        ),
        rule(
            NameMatch::Exact("www.example".into()),
            Action::Cname("edge.corp.example".into()),
        ),
        rule(
            NameMatch::Exact("alias.test".into()),
            Action::Cname("printer.lan".into()),
        ),
        rule(NameMatch::Exact("big.test".into()), Action::Records(big)),
        rule(NameMatch::Default, Action::Resolve("public".into())),
    ])
    .unwrap();
    let policy = PolicyResolver::new(resolvers, table).unwrap();
    Setup {
        server: Server::new(policy, ServerConfig::default()),
        corp,
        public,
    }
}

fn query_message(id: u16, name: &str, qtype: TYPE) -> Vec<u8> {
    let mut packet = Packet::new_query(id);
    packet.questions.push(Question::new(
        Name::new_unchecked(name),
        qtype.into(),
        CLASS::IN.into(),
        false,
    ));
    packet.set_flags(PacketFlag::RECURSION_DESIRED);
    packet.build_bytes_vec().unwrap()
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Via {
    Udp,
    Tcp,
}

struct Endpoints {
    udp: SocketAddr,
    tcp: SocketAddr,
}

async fn serve(server: &Server<PolicyResolver>) -> Endpoints {
    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let udp = socket.local_addr().unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let tcp = listener.local_addr().unwrap();
    let udp_server = server.clone();
    tokio::spawn(async move { udp_server.serve_udp(socket).await });
    let tcp_server = server.clone();
    tokio::spawn(async move { tcp_server.serve_tcp(listener).await });
    Endpoints { udp, tcp }
}

async fn exchange(endpoints: &Endpoints, via: Via, message: &[u8]) -> Vec<u8> {
    match via {
        Via::Udp => {
            let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
            socket.connect(endpoints.udp).await.unwrap();
            socket.send(message).await.unwrap();
            let mut buf = vec![0; 65535];
            let len = tokio::time::timeout(LONG, socket.recv(&mut buf))
                .await
                .unwrap()
                .unwrap();
            buf.truncate(len);
            buf
        }
        Via::Tcp => {
            let mut stream = TcpStream::connect(endpoints.tcp).await.unwrap();
            let len = u16::try_from(message.len()).unwrap();
            stream.write_all(&len.to_be_bytes()).await.unwrap();
            stream.write_all(message).await.unwrap();
            let mut prefix = [0; 2];
            tokio::time::timeout(LONG, stream.read_exact(&mut prefix))
                .await
                .unwrap()
                .unwrap();
            let mut response = vec![0; usize::from(u16::from_be_bytes(prefix))];
            stream.read_exact(&mut response).await.unwrap();
            response
        }
    }
}

/// What the checks look at in a response.
#[derive(Debug, PartialEq, Eq)]
enum Data {
    Addr(IpAddr),
    Cname(String),
    Txt,
}

#[derive(Debug)]
struct Response {
    id: u16,
    rcode: RCODE,
    truncated: bool,
    question: String,
    answers: Vec<(String, Data)>,
}

fn parse(bytes: &[u8]) -> Response {
    let packet = Packet::parse(bytes).unwrap();
    let answers = packet
        .answers
        .iter()
        .map(|rr| {
            let data = match &rr.rdata {
                RData::A(a) => Data::Addr(IpAddr::V4(Ipv4Addr::from(a.address))),
                RData::AAAA(a) => Data::Addr(IpAddr::V6(Ipv6Addr::from(a.address))),
                RData::CNAME(c) => Data::Cname(c.0.to_string()),
                RData::TXT(_) => Data::Txt,
                other => panic!("unexpected rdata {other:?}"),
            };
            (rr.name.to_string(), data)
        })
        .collect();
    Response {
        id: packet.id(),
        rcode: packet.rcode(),
        truncated: packet.has_flags(PacketFlag::TRUNCATION),
        question: packet.questions[0].qname.to_string(),
        answers,
    }
}

async fn ask(endpoints: &Endpoints, via: Via, id: u16, name: &str, qtype: TYPE) -> Response {
    let response = parse(&exchange(endpoints, via, &query_message(id, name, qtype)).await);
    assert_eq!(response.id, id);
    response
}

fn addr(name: &str, addr: impl Into<IpAddr>) -> (String, Data) {
    (name.to_owned(), Data::Addr(addr.into()))
}

#[tokio::test]
async fn routes_each_name_to_its_resolver_over_udp_and_tcp() {
    let setup = setup().await;
    let endpoints = serve(&setup.server).await;
    for (round, via) in [Via::Udp, Via::Tcp].into_iter().enumerate() {
        let id = u16::try_from(round * 100).unwrap();
        let r = ask(&endpoints, via, id + 1, "Printer.LAN", TYPE::A).await;
        assert_eq!(r.question, "Printer.LAN");
        assert_eq!(r.answers, [addr("printer.lan", PRINTER)], "{via:?}");

        let r = ask(&endpoints, via, id + 2, "host.corp.example", TYPE::A).await;
        assert_eq!(r.answers, [addr("host.corp.example", CORP)], "{via:?}");

        let r = ask(&endpoints, via, id + 3, "other.example", TYPE::A).await;
        assert_eq!(r.answers, [addr("other.example", PUBLIC)], "{via:?}");

        let r = ask(&endpoints, via, id + 4, "app.fake.test", TYPE::A).await;
        let [(name, Data::Addr(IpAddr::V4(fake)))] = r.answers.as_slice() else {
            panic!("{via:?}: {:?}", r.answers);
        };
        assert_eq!(name, "app.fake.test");
        assert_eq!(fake.octets()[..2], [198, 18]);
        // The wildcard does not cover its apex: the default upstream answers.
        let r = ask(&endpoints, via, id + 5, "fake.test", TYPE::A).await;
        assert_eq!(r.answers, [addr("fake.test", PUBLIC)], "{via:?}");
    }
    assert_eq!(setup.corp.stats().forwarded, 2);
    assert_eq!(setup.public.stats().forwarded, 4);
    let stats = setup.server.resolver().stats();
    assert_eq!(stats.rule_hits[..3], [2, 2, 2]);
    assert_eq!(stats.rule_hits[8], 4);
}

#[tokio::test]
async fn sinkhole_and_block_responses() {
    let setup = setup().await;
    let endpoints = serve(&setup.server).await;
    for via in [Via::Udp, Via::Tcp] {
        let r = ask(&endpoints, via, 1, "tracker.ads.test", TYPE::A).await;
        assert_eq!(r.rcode, RCODE::NoError);
        assert_eq!(r.answers, [addr("tracker.ads.test", Ipv4Addr::UNSPECIFIED)]);
        let r = ask(&endpoints, via, 2, "ads.test", TYPE::AAAA).await;
        assert_eq!(r.answers, [addr("ads.test", Ipv6Addr::UNSPECIFIED)]);
        let r = ask(&endpoints, via, 3, "ads.test", TYPE::MX).await;
        assert_eq!((r.rcode, r.answers.len()), (RCODE::NoError, 0));

        let r = ask(&endpoints, via, 4, "blocked.test", TYPE::A).await;
        assert_eq!((r.rcode, r.answers.len()), (RCODE::NameError, 0));
        assert_eq!(r.question, "blocked.test");
    }
    assert_eq!(
        setup.public.stats().forwarded + setup.corp.stats().forwarded,
        0
    );
}

#[tokio::test]
async fn cname_answers_carry_the_chain() {
    let setup = setup().await;
    let endpoints = serve(&setup.server).await;
    for via in [Via::Udp, Via::Tcp] {
        // Target answered by an upstream: the CNAME is spliced in front of its answer.
        let r = ask(&endpoints, via, 1, "WWW.example", TYPE::A).await;
        assert_eq!(r.rcode, RCODE::NoError);
        assert_eq!(r.question, "WWW.example");
        assert_eq!(
            r.answers,
            [
                (
                    "www.example".to_owned(),
                    Data::Cname("edge.corp.example".into())
                ),
                addr("edge.corp.example", CORP),
            ],
            "{via:?}"
        );
        // Target answered locally.
        let r = ask(&endpoints, via, 2, "alias.test", TYPE::A).await;
        assert_eq!(
            r.answers,
            [
                ("alias.test".to_owned(), Data::Cname("printer.lan".into())),
                addr("printer.lan", PRINTER),
            ],
            "{via:?}"
        );
    }
    assert_eq!(setup.corp.stats().forwarded, 2);
}

#[tokio::test]
async fn truncation_still_applies() {
    let setup = setup().await;
    let endpoints = serve(&setup.server).await;
    let r = ask(&endpoints, Via::Udp, 1, "big.test", TYPE::TXT).await;
    assert!(r.truncated);
    assert_eq!(r.answers, Vec::new());
    let r = ask(&endpoints, Via::Tcp, 2, "big.test", TYPE::TXT).await;
    assert!(!r.truncated);
    assert_eq!(r.answers.len(), 40);
    assert!(
        r.answers
            .iter()
            .all(|(name, data)| name == "big.test" && *data == Data::Txt)
    );
    assert_eq!(setup.server.stats().truncated, 1);
}
