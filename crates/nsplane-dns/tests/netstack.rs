//! Server on the flows of a user-space stack: a client stack and a server stack wired back to
//! back in process.

#![cfg(feature = "netstack")]
#![allow(clippy::unwrap_used, clippy::panic, reason = "test harness")]

use std::future::poll_fn;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::pin::Pin;
use std::time::Duration;

use futures_core::Stream;
use nsplane::{PacketSink, PacketSource, PeerId};
use nsplane_dns::{Record, Server, ServerConfig, StaticRecords};
use nsplane_netstack::{NetStack, NetStackConfig, NetStackHandle, NetStackSink, NetStackSource};
use simple_dns::rdata::RData;
use simple_dns::{CLASS, Name, Packet, PacketFlag, Question, TYPE};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::time::timeout;

const WAIT: Duration = Duration::from_secs(5);
const DNS: SocketAddr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)), 53);

/// Forwards every packet from `from` to `to`.
async fn wire(mut from: NetStackSource, to: NetStackSink) {
    while let Ok(packet) = from.recv().await {
        if to.send(packet, PeerId::new(1)).await.is_err() {
            break;
        }
    }
}

/// A client stack (`10.0.0.1`) and a server stack (`10.0.0.2`) wired back to back.
fn pair() -> (NetStackHandle, NetStackHandle) {
    let (client_stack, client) = NetStack::new(NetStackConfig::new(
        vec![(IpAddr::from([10, 0, 0, 1]), 24)],
        1420,
    ));
    let (server_stack, server) = NetStack::new(NetStackConfig::new(
        vec![(IpAddr::from([10, 0, 0, 2]), 24)],
        1420,
    ));
    let (client_source, client_sink) = client_stack.split();
    let (server_source, server_sink) = server_stack.split();
    tokio::spawn(wire(client_source, server_sink));
    tokio::spawn(wire(server_source, client_sink));
    (client, server)
}

async fn next<S: Stream + Unpin>(stream: &mut S) -> Option<S::Item> {
    poll_fn(|cx| Pin::new(&mut *stream).poll_next(cx)).await
}

/// Routes the server stack's flows and connections to port 53 to `server`, dropping others.
fn route(handle: &NetStackHandle, server: &Server<StaticRecords>) {
    let mut flows = handle.incoming_udp();
    let udp_server = server.clone();
    tokio::spawn(async move {
        while let Some(flow) = next(&mut flows).await {
            if flow.local_addr().port() == 53 {
                let server = udp_server.clone();
                tokio::spawn(async move { server.serve_udp_flow(flow).await });
            }
        }
    });
    let mut connections = handle.incoming_tcp();
    let tcp_server = server.clone();
    tokio::spawn(async move {
        while let Some(conn) = next(&mut connections).await {
            if conn.local_addr().port() == 53 {
                let server = tcp_server.clone();
                tokio::spawn(async move { server.serve_tcp_connection(conn).await });
            }
        }
    });
}

fn records() -> StaticRecords {
    let mut table = StaticRecords::new();
    table.insert(Record::a("host.test", 300, Ipv4Addr::new(10, 0, 0, 7)));
    // About 2500 bytes on the wire.
    for i in 0..40 {
        table.insert(Record::txt(
            "big.test",
            60,
            vec![format!("{i:02}{}", "x".repeat(48))],
        ));
    }
    table
}

fn query_message(id: u16, name: &str, qtype: TYPE) -> Vec<u8> {
    let mut packet = Packet::new_query(id);
    packet.questions.push(Question::new(
        Name::new_unchecked(name),
        qtype.into(),
        CLASS::IN.into(),
        false,
    ));
    packet.build_bytes_vec().unwrap()
}

async fn udp_exchange(client: &NetStackHandle, message: &[u8]) -> Vec<u8> {
    let mut socket = client.connect_udp(DNS).await.unwrap();
    socket.send(message).await.unwrap();
    let (response, from) = timeout(WAIT, socket.recv_from()).await.unwrap().unwrap();
    assert_eq!(from, DNS);
    response.to_vec()
}

async fn tcp_exchange(client: &NetStackHandle, message: &[u8]) -> Vec<u8> {
    let mut conn = client.connect_tcp(DNS).await.unwrap();
    let len = u16::try_from(message.len()).unwrap();
    conn.write_all(&len.to_be_bytes()).await.unwrap();
    conn.write_all(message).await.unwrap();
    let mut prefix = [0; 2];
    timeout(WAIT, conn.read_exact(&mut prefix))
        .await
        .unwrap()
        .unwrap();
    let mut response = vec![0; usize::from(u16::from_be_bytes(prefix))];
    timeout(WAIT, conn.read_exact(&mut response))
        .await
        .unwrap()
        .unwrap();
    response
}

#[tokio::test]
async fn udp_flow_answers_from_the_resolver() {
    let (client, server_stack) = pair();
    let server = Server::new(records(), ServerConfig::default());
    route(&server_stack, &server);

    let response = udp_exchange(&client, &query_message(1, "host.test", TYPE::A)).await;
    let packet = Packet::parse(&response).unwrap();
    assert_eq!(packet.id(), 1);
    assert!(!packet.has_flags(PacketFlag::TRUNCATION));
    assert_eq!(packet.answers.len(), 1);
    match &packet.answers[0].rdata {
        RData::A(a) => assert_eq!(Ipv4Addr::from(a.address), Ipv4Addr::new(10, 0, 0, 7)),
        other => panic!("unexpected answer {other:?}"),
    }
    let stats = server.stats();
    assert_eq!((stats.queries, stats.responses), (1, 1));
}

#[tokio::test]
async fn large_answer_truncates_over_udp_and_completes_over_tcp() {
    let (client, server_stack) = pair();
    let server = Server::new(records(), ServerConfig::default());
    route(&server_stack, &server);
    let message = query_message(2, "big.test", TYPE::TXT);

    let response = udp_exchange(&client, &message).await;
    assert!(response.len() <= 512);
    let packet = Packet::parse(&response).unwrap();
    assert_eq!(packet.id(), 2);
    assert!(packet.has_flags(PacketFlag::TRUNCATION));

    let response = tcp_exchange(&client, &message).await;
    assert!(response.len() > 2000);
    let packet = Packet::parse(&response).unwrap();
    assert_eq!(packet.id(), 2);
    assert!(!packet.has_flags(PacketFlag::TRUNCATION));
    assert_eq!(packet.answers.len(), 40);
    assert_eq!(server.stats().truncated, 1);
}
