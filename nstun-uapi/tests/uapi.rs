//! UAPI tests against a real in-process engine.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    reason = "test harness"
)]

use nstun::x25519::{PublicKey, StaticSecret};
use nstun::{
    AllowedIp, ChannelSink, ChannelSource, Engine, EngineBuilder, EngineHandle, PacketBuf, PeerId,
    PeerStats, UdpTransport,
};
use nstun_uapi::Uapi;
use tokio::io::BufReader;
use tokio::sync::{mpsc, watch};

/// One engine with its UAPI and the test ends of its source and sink.
struct Node {
    _engine: Engine,
    handle: EngineHandle<UdpTransport>,
    uapi: Uapi,
    _local: mpsc::Sender<PacketBuf>,
    _mtu: watch::Sender<u16>,
    _delivered: mpsc::Receiver<(PeerId, PacketBuf)>,
}

impl Node {
    async fn new() -> Self {
        let (source, local, mtu) = ChannelSource::new(16, 1420);
        let (sink, delivered) = ChannelSink::new(16);
        let engine = EngineBuilder::new(source, sink).build();
        let handle = engine.handle();
        let uapi = Uapi::new(handle.clone());
        uapi.bind_transport(0).await.unwrap();
        Self {
            _engine: engine,
            handle,
            uapi,
            _local: local,
            _mtu: mtu,
            _delivered: delivered,
        }
    }

    async fn request(&self, body: &str) -> String {
        let mut reader = BufReader::new(body.as_bytes());
        let mut out = Vec::new();
        self.uapi
            .handle_request(&mut reader, &mut out)
            .await
            .unwrap();
        String::from_utf8(out).unwrap()
    }

    async fn peer(&self, key: &PublicKey) -> Option<PeerStats> {
        let peers = self.handle.peers().await.unwrap();
        peers.into_iter().find(|p| p.public_key == *key)
    }
}

fn key(seed: u8) -> (String, PublicKey) {
    let secret = StaticSecret::from([seed; 32]);
    (hex::encode(secret.to_bytes()), PublicKey::from(&secret))
}

fn hex_pub(key: &PublicKey) -> String {
    hex::encode(key.as_bytes())
}

fn ip(s: &str) -> AllowedIp {
    s.parse().unwrap()
}

/// A free UDP port: bound once and released.
fn free_port() -> u16 {
    udp_socket().local_addr().unwrap().port()
}

/// A UDP socket on an ephemeral port, dual-stack where IPv6 is available.
fn udp_socket() -> std::net::UdpSocket {
    std::net::UdpSocket::bind("[::]:0")
        .or_else(|_| std::net::UdpSocket::bind("0.0.0.0:0"))
        .unwrap()
}

#[tokio::test]
async fn set_then_get_round_trips() {
    let node = Node::new().await;
    let (private, _) = key(1);
    let (_, peer) = key(2);
    let peer_hex = hex_pub(&peer);
    let psk = hex::encode([7u8; 32]);
    let port = free_port();
    let reply = node
        .request(&format!(
            "set=1\nprivate_key={private}\nlisten_port={port}\npublic_key={peer_hex}\n\
             preshared_key={psk}\nendpoint=192.0.2.1:51820\nallowed_ip=10.0.0.0/24\n\
             allowed_ip=fd00::/64\npersistent_keepalive_interval=25\nprotocol_version=1\n\n"
        ))
        .await;
    assert_eq!(reply, "errno=0\n\n");

    let reply = node.request("get=1\n\n").await;
    assert!(reply.starts_with(&format!("private_key={private}\nlisten_port={port}\n")));
    assert!(!reply.contains("fwmark="));
    let expected = format!(
        "public_key={peer_hex}\npreshared_key={psk}\nprotocol_version=1\n\
         endpoint=192.0.2.1:51820\nlast_handshake_time_sec=0\nlast_handshake_time_nsec=0\n\
         rx_bytes=0\ntx_bytes=0\npersistent_keepalive_interval=25\n\
         allowed_ip=10.0.0.0/24\nallowed_ip=fd00::/64\nerrno=0\n\n"
    );
    assert!(reply.ends_with(&expected), "{reply}");

    let stats = node.peer(&peer).await.unwrap();
    assert_eq!(stats.preshared_key, Some([7; 32]));
    assert_eq!(stats.persistent_keepalive, Some(25));
    let path = stats.path.unwrap();
    assert_eq!(path.transport, nstun_uapi::TRANSPORT_ID);
    assert_eq!(path.addr, "192.0.2.1:51820".parse().unwrap());
}

#[tokio::test]
async fn listen_port_rebinds_the_transport() {
    let node = Node::new().await;
    let initial = node.request("get=1\n\n").await;
    // The initial transport has an ephemeral port.
    assert!(!initial.contains("listen_port=0\n"));
    assert!(initial.contains("listen_port="));

    let port = free_port();
    let set = format!("set=1\nlisten_port={port}\n\n");
    assert_eq!(node.request(&set).await, "errno=0\n\n");
    // Repeating the current port keeps the transport.
    assert_eq!(node.request(&set).await, "errno=0\n\n");
    assert!(
        node.request("get=1\n\n")
            .await
            .contains(&format!("listen_port={port}\n"))
    );
    // The engine holds the port.
    assert!(std::net::UdpSocket::bind(("0.0.0.0", port)).is_err());

    // fwmark=0 removes a mark that is not set: nothing to do.
    assert_eq!(node.request("set=1\nfwmark=0\n\n").await, "errno=0\n\n");
    // A port in use elsewhere is reported.
    let taken = udp_socket();
    let taken_port = taken.local_addr().unwrap().port();
    assert_eq!(
        node.request(&format!("set=1\nlisten_port={taken_port}\n\n"))
            .await,
        "errno=98\n\n"
    );
}

#[tokio::test]
async fn settings_do_not_leak_into_the_next_peer_section() {
    let node = Node::new().await;
    let (private, _) = key(1);
    let (_, a) = key(2);
    let (_, b) = key(3);
    let (a_hex, b_hex) = (hex_pub(&a), hex_pub(&b));
    node.request(&format!(
        "set=1\nprivate_key={private}\npublic_key={a_hex}\npublic_key={b_hex}\n\n"
    ))
    .await;
    // `remove=true` belongs to a only; b must survive and get no keepalive.
    let reply = node
        .request(&format!(
            "set=1\npublic_key={a_hex}\npersistent_keepalive_interval=25\nremove=true\n\
             public_key={b_hex}\nallowed_ip=10.0.1.0/24\n\n"
        ))
        .await;
    assert_eq!(reply, "errno=0\n\n");
    let b_peer = node.peer(&b).await.expect("b survives");
    assert_eq!(b_peer.persistent_keepalive, None);
    assert_eq!(b_peer.allowed_ips, vec![ip("10.0.1.0/24")]);
    assert!(node.peer(&a).await.is_none());
}

#[tokio::test]
async fn malformed_requests_are_rejected() {
    let node = Node::new().await;
    let (_, peer) = key(2);
    let peer_hex = hex_pub(&peer);
    assert_eq!(node.request("set=1\nbogus\n\n").await, "errno=71\n\n");
    assert_eq!(
        node.request("set=1\nprivate_key=xyz\n\n").await,
        "errno=22\n\n"
    );
    assert_eq!(
        node.request("set=1\nlisten_port=x\n\n").await,
        "errno=22\n\n"
    );
    assert_eq!(node.request("set=1\nfrob=1\n\n").await, "errno=22\n\n");
    assert_eq!(node.request("frob=1\n\n").await, "errno=5\n\n");
    // Peers need a private key first.
    assert_eq!(
        node.request(&format!("set=1\npublic_key={peer_hex}\n\n"))
            .await,
        "errno=28\n\n"
    );
    let (private, _) = key(1);
    for bad in [
        "endpoint=nowhere",
        "allowed_ip=10.0.0.0/33",
        "protocol_version=2",
        "persistent_keepalive_interval=-1",
        "remove=yes",
        "preshared_key=00",
        // Interface settings are not allowed in a peer section.
        "listen_port=1",
    ] {
        assert_eq!(
            node.request(&format!(
                "set=1\nprivate_key={private}\npublic_key={peer_hex}\n{bad}\n\n"
            ))
            .await,
            "errno=22\n\n",
            "{bad}"
        );
    }
}

#[tokio::test]
async fn remove_peer_and_update_only() {
    let node = Node::new().await;
    let (private, _) = key(1);
    let (_, a) = key(2);
    let (_, b) = key(3);
    let (a_hex, b_hex) = (hex_pub(&a), hex_pub(&b));
    node.request(&format!(
        "set=1\nprivate_key={private}\npublic_key={a_hex}\n\n"
    ))
    .await;
    // update_only does not add an unknown peer, but updates a known one.
    let reply = node
        .request(&format!(
            "set=1\npublic_key={b_hex}\nupdate_only=true\npublic_key={a_hex}\n\
             update_only=true\npersistent_keepalive_interval=5\n\n"
        ))
        .await;
    assert_eq!(reply, "errno=0\n\n");
    assert!(node.peer(&b).await.is_none());
    assert_eq!(node.peer(&a).await.unwrap().persistent_keepalive, Some(5));

    let reply = node
        .request(&format!("set=1\npublic_key={a_hex}\nremove=true\n\n"))
        .await;
    assert_eq!(reply, "errno=0\n\n");
    assert!(node.handle.peers().await.unwrap().is_empty());
}

#[tokio::test]
async fn replace_peers() {
    let node = Node::new().await;
    let (private, _) = key(1);
    let (_, a) = key(2);
    let (_, b) = key(3);
    let (a_hex, b_hex) = (hex_pub(&a), hex_pub(&b));
    node.request(&format!(
        "set=1\nprivate_key={private}\npublic_key={a_hex}\n\n"
    ))
    .await;
    let reply = node
        .request(&format!(
            "set=1\nreplace_peers=true\npublic_key={b_hex}\n\n"
        ))
        .await;
    assert_eq!(reply, "errno=0\n\n");
    let peers = node.handle.peers().await.unwrap();
    assert_eq!(peers.len(), 1);
    assert_eq!(peers[0].public_key, b);
}

#[tokio::test]
async fn replace_allowed_ips() {
    let node = Node::new().await;
    let (private, _) = key(1);
    let (_, a) = key(2);
    let a_hex = hex_pub(&a);
    node.request(&format!(
        "set=1\nprivate_key={private}\npublic_key={a_hex}\nallowed_ip=10.0.0.0/24\n\n"
    ))
    .await;
    // Without replace_allowed_ips the IPs add up.
    node.request(&format!(
        "set=1\npublic_key={a_hex}\nallowed_ip=10.0.1.0/24\n\n"
    ))
    .await;
    assert_eq!(
        node.peer(&a).await.unwrap().allowed_ips,
        vec![ip("10.0.0.0/24"), ip("10.0.1.0/24")]
    );
    let reply = node
        .request(&format!(
            "set=1\npublic_key={a_hex}\nreplace_allowed_ips=true\nallowed_ip=10.0.2.0/24\n\n"
        ))
        .await;
    assert_eq!(reply, "errno=0\n\n");
    assert_eq!(
        node.peer(&a).await.unwrap().allowed_ips,
        vec![ip("10.0.2.0/24")]
    );
    // An all-zero preshared key removes it.
    let zero = hex::encode([0u8; 32]);
    node.request(&format!(
        "set=1\npublic_key={a_hex}\npreshared_key={}\n\n",
        hex::encode([9u8; 32])
    ))
    .await;
    assert_eq!(node.peer(&a).await.unwrap().preshared_key, Some([9; 32]));
    node.request(&format!(
        "set=1\npublic_key={a_hex}\npreshared_key={zero}\n\n"
    ))
    .await;
    assert_eq!(node.peer(&a).await.unwrap().preshared_key, None);
}

#[tokio::test]
async fn a_stopped_engine_reports_eio() {
    let node = Node::new().await;
    node.handle.shutdown().await.unwrap();
    assert_eq!(node.request("get=1\n\n").await, "errno=5\n\n");
    let (private, _) = key(1);
    assert_eq!(
        node.request(&format!("set=1\nprivate_key={private}\n\n"))
            .await,
        "errno=5\n\n"
    );
}

#[cfg(unix)]
#[tokio::test]
async fn serves_requests_over_a_unix_socket() {
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::time::Duration;

    use nstun_uapi::UapiListener;
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt};
    use tokio::net::UnixStream;

    /// Reads one response, up to and including the empty line after `errno`.
    async fn response(reader: &mut BufReader<tokio::net::unix::OwnedReadHalf>) -> String {
        let mut out = String::new();
        loop {
            let mut line = String::new();
            assert_ne!(reader.read_line(&mut line).await.unwrap(), 0);
            let done = line == "\n" && out.contains("errno=");
            out.push_str(&line);
            if done {
                return out;
            }
        }
    }

    static COUNTER: AtomicUsize = AtomicUsize::new(0);
    let dir = std::env::temp_dir().join(format!(
        "nstun-uapi-{}-{}",
        std::process::id(),
        COUNTER.fetch_add(1, Ordering::Relaxed)
    ));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("wg-test.sock");
    // A stale socket file is replaced.
    std::fs::write(&path, b"").unwrap();

    let node = Node::new().await;
    let listener = UapiListener::bind_path(&path).unwrap();
    assert_eq!(listener.path(), path);
    let uapi = node.uapi.clone();
    let server = tokio::spawn(async move { uapi.serve(listener).await });

    let (private, _) = key(1);
    let (_, peer) = key(2);
    let peer_hex = hex_pub(&peer);
    let stream = UnixStream::connect(&path).await.unwrap();
    let (reader, mut writer) = stream.into_split();
    let mut reader = BufReader::new(reader);
    writer
        .write_all(
            format!(
                "set=1\nprivate_key={private}\npublic_key={peer_hex}\n\
                 endpoint=[2001:db8::1]:51820\nallowed_ip=10.0.0.0/24\n\n"
            )
            .as_bytes(),
        )
        .await
        .unwrap();
    assert_eq!(response(&mut reader).await, "errno=0\n\n");
    // A second request on the same connection.
    writer.write_all(b"get=1\n\n").await.unwrap();
    let reply = response(&mut reader).await;
    assert!(reply.contains(&format!("public_key={peer_hex}\n")));
    assert!(reply.contains("endpoint=[2001:db8::1]:51820\n"));
    assert!(reply.ends_with("errno=0\n\n"));

    // The server stops with the engine and removes its socket.
    node.handle.shutdown().await.unwrap();
    tokio::time::timeout(Duration::from_secs(5), server)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    assert!(!path.exists());
    std::fs::remove_dir(&dir).unwrap();
}

#[cfg(unix)]
#[test]
fn socket_path_is_the_standard_one() {
    assert_eq!(
        nstun_uapi::socket_path("wg0"),
        std::path::Path::new("/var/run/wireguard/wg0.sock")
    );
}
