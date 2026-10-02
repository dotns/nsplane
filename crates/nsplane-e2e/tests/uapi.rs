//! The `wg` UAPI end to end: two engines configured only through `set=1` requests exchange
//! traffic over UDP on the loopback interface, and `get=1` reports what their handles see.

use std::fmt::Write as _;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use std::time::SystemTime;

use nsplane::x25519::{PublicKey, StaticSecret};
use nsplane::{
    AllowedIp, ChannelSink, ChannelSource, Engine, EngineBuilder, EngineHandle, PeerStats,
    UdpTransport,
};
use nsplane_e2e::{Family, MTU, QUIET, TestResult, WAIT, payload, udp4, udp6};
use nsplane_packet::{PacketBuf, PeerId};
use nsplane_uapi::{TRANSPORT_ID, Uapi};
use tokio::io::BufReader;
use tokio::sync::{mpsc, watch};
use tokio::time::timeout;

const PSK: [u8; 32] = [7; 32];
const KEEPALIVE: u16 = 25;

fn hex(bytes: &[u8]) -> String {
    bytes.iter().fold(String::new(), |mut out, b| {
        // Writing to a `String` cannot fail.
        let _ = write!(out, "{b:02x}");
        out
    })
}

/// One peer of a parsed `get=1` response.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
struct PeerConfig {
    public_key: String,
    preshared_key: Option<String>,
    endpoint: Option<SocketAddr>,
    last_handshake_sec: u64,
    last_handshake_nsec: u32,
    rx: u64,
    tx: u64,
    keepalive: u16,
    allowed_ips: Vec<AllowedIp>,
}

/// A parsed `get=1` response.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
struct Config {
    private_key: Option<String>,
    listen_port: Option<u16>,
    peers: Vec<PeerConfig>,
    errno: i32,
}

impl Config {
    /// The configuration without the counters and handshake times traffic changes.
    fn settings(mut self) -> Self {
        for peer in &mut self.peers {
            peer.last_handshake_sec = 0;
            peer.last_handshake_nsec = 0;
            peer.rx = 0;
            peer.tx = 0;
        }
        self
    }
}

/// Parses a UAPI response: `key=value` lines, `errno=N` last, then an empty line.
fn parse(reply: &str) -> TestResult<Config> {
    let body = reply
        .strip_suffix("\n\n")
        .ok_or_else(|| format!("unterminated response {reply:?}"))?;
    let mut config = Config::default();
    let mut errno = None;
    for line in body.lines() {
        let (key, val) = line
            .split_once('=')
            .ok_or_else(|| format!("malformed line {line:?}"))?;
        if errno.is_some() {
            return Err(format!("line {line:?} after errno").into());
        }
        match (config.peers.last_mut(), key) {
            (_, "errno") => errno = Some(val.parse()?),
            (_, "public_key") => config.peers.push(PeerConfig {
                public_key: val.to_owned(),
                ..PeerConfig::default()
            }),
            (None, "private_key") => config.private_key = Some(val.to_owned()),
            (None, "listen_port") => config.listen_port = Some(val.parse()?),
            (Some(peer), "preshared_key") => peer.preshared_key = Some(val.to_owned()),
            (Some(_), "protocol_version") if val == "1" => {}
            (Some(peer), "endpoint") => peer.endpoint = Some(val.parse()?),
            (Some(peer), "last_handshake_time_sec") => peer.last_handshake_sec = val.parse()?,
            (Some(peer), "last_handshake_time_nsec") => peer.last_handshake_nsec = val.parse()?,
            (Some(peer), "rx_bytes") => peer.rx = val.parse()?,
            (Some(peer), "tx_bytes") => peer.tx = val.parse()?,
            (Some(peer), "persistent_keepalive_interval") => peer.keepalive = val.parse()?,
            (Some(peer), "allowed_ip") => peer.allowed_ips.push(val.parse()?),
            _ => return Err(format!("unexpected line {line:?}").into()),
        }
    }
    config.errno = errno.ok_or("no errno")?;
    Ok(config)
}

/// One engine configured through its UAPI, with the test ends of its source and sink.
struct Node {
    _engine: Engine,
    handle: EngineHandle<UdpTransport>,
    uapi: Uapi,
    local: mpsc::Sender<PacketBuf>,
    delivered: mpsc::Receiver<(PeerId, PacketBuf)>,
    _mtu: watch::Sender<u16>,
    secret: StaticSecret,
    ip4: Ipv4Addr,
    ip6: Ipv6Addr,
    /// The listen port, read back with `get=1` after `listen_port=0`.
    port: u16,
}

impl Node {
    /// An engine with neither a private key nor a transport; the seed picks the key the UAPI
    /// sets and the tunnel addresses `10.0.0.<seed>` and `fd00::<seed>`.
    fn new(seed: u8) -> Self {
        let (source, local, mtu) = ChannelSource::new(1024, MTU);
        let (sink, delivered) = ChannelSink::new(1024);
        let engine = EngineBuilder::new(source, sink).build();
        let handle = engine.handle();
        Self {
            uapi: Uapi::new(handle.clone()),
            handle,
            _engine: engine,
            local,
            delivered,
            _mtu: mtu,
            secret: StaticSecret::from([seed; 32]),
            ip4: Ipv4Addr::new(10, 0, 0, seed),
            ip6: Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, u16::from(seed)),
            port: 0,
        }
    }

    fn public(&self) -> PublicKey {
        PublicKey::from(&self.secret)
    }

    /// The raw response to `body`.
    async fn request(&self, body: &str) -> TestResult<String> {
        let mut reader = BufReader::new(body.as_bytes());
        let mut out = Vec::new();
        timeout(WAIT, self.uapi.handle_request(&mut reader, &mut out)).await??;
        Ok(String::from_utf8(out)?)
    }

    /// The parsed `get=1` response, which must succeed.
    async fn get(&self) -> TestResult<Config> {
        let config = parse(&self.request("get=1\n\n").await?)?;
        if config.errno != 0 {
            return Err(format!("get failed with errno {}", config.errno).into());
        }
        Ok(config)
    }

    /// Sends a `set=1` request, which must succeed.
    async fn set(&self, body: &str) -> TestResult {
        let reply = self.request(&format!("set=1\n{body}\n")).await?;
        if reply != "errno=0\n\n" {
            return Err(format!("set {body:?} failed: {reply:?}").into());
        }
        Ok(())
    }

    /// Sets the private key and binds an ephemeral listen port, read back with `get=1`.
    async fn configure(&mut self) -> TestResult {
        self.set(&format!(
            "private_key={}\nlisten_port=0\n",
            hex(&self.secret.to_bytes())
        ))
        .await?;
        let port = self.get().await?.listen_port.ok_or("no listen port")?;
        if port == 0 {
            return Err("listen_port=0 reported as bound".into());
        }
        self.port = port;
        Ok(())
    }

    /// The `set=1` peer section that makes this node a peer: preshared key, loopback
    /// endpoint, both tunnel addresses and a persistent keepalive.
    fn peer_section(&self) -> String {
        format!(
            "public_key={}\npreshared_key={}\nendpoint=127.0.0.1:{}\nallowed_ip={}/32\n\
             allowed_ip={}/128\npersistent_keepalive_interval={KEEPALIVE}\n",
            hex(self.public().as_bytes()),
            hex(&PSK),
            self.port,
            self.ip4,
            self.ip6,
        )
    }

    /// The handle's view of the peer with key `key`.
    async fn peer(&self, key: PublicKey) -> TestResult<PeerStats> {
        let peers = self.handle.peers().await?;
        Ok(peers
            .into_iter()
            .find(|p| p.public_key == key)
            .ok_or("unknown peer")?)
    }

    fn packet_to(&self, other: &Self, family: Family) -> Vec<u8> {
        match family {
            Family::V4 => udp4(self.ip4, other.ip4, &payload(64)),
            Family::V6 => udp6(self.ip6, other.ip6, &payload(64)),
        }
    }

    async fn send(&self, packet: &[u8]) -> TestResult {
        self.local.send(PacketBuf::from_packet(packet)).await?;
        Ok(())
    }

    /// Succeeds if nothing is delivered within [`QUIET`].
    async fn expect_no_delivery(&mut self) -> TestResult {
        match timeout(QUIET, self.delivered.recv()).await {
            Ok(Some(_)) => Err("unexpected delivery".into()),
            Ok(None) => Err("sink closed".into()),
            Err(_) => Ok(()),
        }
    }
}

/// Sends a `family` packet from `from` to `to` and checks that it arrives intact and
/// attributed to `from`.
async fn transfer(from: &Node, to: &mut Node, family: Family) -> TestResult {
    let packet = from.packet_to(to, family);
    from.send(&packet).await?;
    let (peer, delivered) = match timeout(WAIT, to.delivered.recv()).await {
        Ok(Some(delivery)) => delivery,
        Ok(None) => return Err("sink closed".into()),
        Err(_) => return Err(format!("no {family:?} delivery within {WAIT:?}").into()),
    };
    if Some(peer) != to.handle.peer_id(from.public()).await? {
        return Err(format!("packet attributed to {peer:?}").into());
    }
    if delivered.as_packet() != packet {
        return Err(format!("{family:?} packet changed in transit").into());
    }
    Ok(())
}

/// Two nodes (seeds 1 and 2) configured as peers of each other through `set=1` only.
async fn pair() -> TestResult<(Node, Node)> {
    let (mut a, mut b) = (Node::new(1), Node::new(2));
    a.configure().await?;
    b.configure().await?;
    a.set(&b.peer_section()).await?;
    b.set(&a.peer_section()).await?;
    Ok((a, b))
}

/// Seconds since the Unix epoch.
fn unix_now() -> TestResult<u64> {
    Ok(SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)?
        .as_secs())
}

/// Checks `node`'s `get=1` response against its handle after traffic with `other` that
/// started at Unix time `started`.
async fn assert_get_matches_handle(node: &Node, other: &Node, started: u64) -> TestResult {
    let before = node.peer(other.public()).await?;
    let config = node.get().await?;
    let after = node.peer(other.public()).await?;
    let finished = unix_now()?;

    assert_eq!(config.errno, 0);
    assert_eq!(config.private_key, Some(hex(&node.secret.to_bytes())));
    assert_eq!(
        node.handle.private_key().await?.map(|k| k.to_bytes()),
        Some(node.secret.to_bytes())
    );
    assert_eq!(node.handle.public_key().await?, Some(node.public()));
    assert_eq!(config.listen_port, Some(node.port));

    let [peer] = config.peers.as_slice() else {
        return Err(format!("expected one peer, got {:?}", config.peers).into());
    };
    assert_eq!(node.handle.peers().await?.len(), 1);
    assert_eq!(peer.public_key, hex(other.public().as_bytes()));
    assert_eq!(peer.public_key, hex(after.public_key.as_bytes()));
    assert_eq!(peer.preshared_key, Some(hex(&PSK)));
    assert_eq!(after.preshared_key, Some(PSK));

    let path = after.path.ok_or("no path")?;
    assert_eq!(path.transport, TRANSPORT_ID);
    assert_eq!(peer.endpoint, Some(path.addr));
    assert_eq!(
        peer.endpoint,
        Some(SocketAddr::from((Ipv4Addr::LOCALHOST, other.port)))
    );

    let allowed: Vec<AllowedIp> = vec![
        format!("{}/32", other.ip4).parse()?,
        format!("{}/128", other.ip6).parse()?,
    ];
    assert_eq!(peer.allowed_ips, allowed);
    assert_eq!(after.allowed_ips, allowed);
    assert_eq!(peer.keepalive, KEEPALIVE);
    assert_eq!(after.persistent_keepalive, Some(KEEPALIVE));

    // The counters only grow, so the response lies between the two handle snapshots.
    assert!(peer.rx > 0 && peer.tx > 0, "{peer:?}");
    assert!(
        (before.rx..=after.rx).contains(&peer.rx),
        "{before:?} {peer:?} {after:?}"
    );
    assert!(
        (before.tx..=after.tx).contains(&peer.tx),
        "{before:?} {peer:?} {after:?}"
    );

    // The handshake happened during the traffic; allow a second for rounding.
    assert!(after.last_handshake.is_some());
    assert!(
        peer.last_handshake_sec + 1 >= started && peer.last_handshake_sec <= finished,
        "handshake at {} outside {started}..={finished}",
        peer.last_handshake_sec
    );
    assert!(peer.last_handshake_nsec < 1_000_000_000);
    Ok(())
}

#[tokio::test]
async fn engines_configured_over_uapi_exchange_traffic_and_report_it() -> TestResult {
    let (mut a, mut b) = pair().await?;
    let started = unix_now()?;
    for family in [Family::V4, Family::V6] {
        transfer(&a, &mut b, family).await?;
        transfer(&b, &mut a, family).await?;
    }
    assert_get_matches_handle(&a, &b, started).await?;
    assert_get_matches_handle(&b, &a, started).await
}

#[tokio::test]
async fn set_changes_reach_the_handle_and_handle_changes_reach_get() -> TestResult {
    let (a, mut b) = pair().await?;
    transfer(&a, &mut b, Family::V4).await?;
    transfer(&a, &mut b, Family::V6).await?;
    let a_hex = hex(a.public().as_bytes());
    let a4: AllowedIp = format!("{}/32", a.ip4).parse()?;
    let a6: AllowedIp = format!("{}/128", a.ip6).parse()?;

    // replace_allowed_ips: b only accepts IPv4 from a now.
    b.set(&format!(
        "public_key={a_hex}\nreplace_allowed_ips=true\nallowed_ip={}/32\n",
        a.ip4
    ))
    .await?;
    assert_eq!(b.peer(a.public()).await?.allowed_ips, [a4]);
    assert_eq!(b.get().await?.peers[0].allowed_ips, [a4]);
    transfer(&a, &mut b, Family::V4).await?;
    a.send(&a.packet_to(&b, Family::V6)).await?;
    b.expect_no_delivery().await?;

    // Changes through the handle show up in get=1 and in the traffic.
    b.handle.set_allowed_ips(a.public(), vec![a4, a6]).await?;
    b.handle.set_keepalive(a.public(), Some(7)).await?;
    let config = b.get().await?;
    assert_eq!(config.peers[0].allowed_ips, [a4, a6]);
    assert_eq!(config.peers[0].keepalive, 7);
    transfer(&a, &mut b, Family::V6).await?;

    // remove: b forgets a and drops its traffic.
    b.set(&format!("public_key={a_hex}\nremove=true\n")).await?;
    assert_eq!(b.handle.peers().await?, []);
    assert_eq!(b.handle.peer_id(a.public()).await?, None);
    assert_eq!(b.get().await?.peers, []);
    a.send(&a.packet_to(&b, Family::V4)).await?;
    b.expect_no_delivery().await?;

    // replace_peers: a ends up with c only.
    let c = PublicKey::from(&StaticSecret::from([3; 32]));
    a.set(&format!(
        "replace_peers=true\npublic_key={}\nallowed_ip=10.0.0.3/32\n",
        hex(c.as_bytes())
    ))
    .await?;
    let peers = a.handle.peers().await?;
    assert_eq!(peers.len(), 1);
    assert_eq!(peers[0].public_key, c);
    assert_eq!(a.handle.peer_id(b.public()).await?, None);
    let config = a.get().await?;
    assert_eq!(config.peers.len(), 1);
    assert_eq!(config.peers[0].public_key, hex(c.as_bytes()));
    assert_eq!(config.peers[0].allowed_ips, [peers[0].allowed_ips[0]]);
    Ok(())
}

/// The settings `node` reports through `get=1` and through its handle, without counters.
async fn settings(node: &Node) -> TestResult<(Config, Vec<PeerStats>, Option<PublicKey>)> {
    let peers = node
        .handle
        .peers()
        .await?
        .into_iter()
        .map(|p| PeerStats {
            rx: 0,
            tx: 0,
            data_rx: 0,
            last_handshake: None,
            ..p
        })
        .collect();
    Ok((
        node.get().await?.settings(),
        peers,
        node.handle.public_key().await?,
    ))
}

#[tokio::test]
async fn invalid_requests_fail_and_change_nothing() -> TestResult {
    let (mut a, mut b) = pair().await?;
    let b_hex = hex(b.public().as_bytes());
    let peer = |setting: &str| format!("set=1\npublic_key={b_hex}\n{setting}\n\n");
    let requests = [
        "set=1\nbogus\n\n".to_owned(),
        "set=1\nprivate_key=xyz\n\n".to_owned(),
        "set=1\nlisten_port=70000\n\n".to_owned(),
        // b's engine holds its port.
        format!("set=1\nlisten_port={}\n\n", b.port),
        "set=1\nfrob=1\n\n".to_owned(),
        "set=1\nreplace_peers=maybe\n\n".to_owned(),
        "set=1\npublic_key=zz\n\n".to_owned(),
        "get=2\n\n".to_owned(),
        peer("allowed_ip=10.0.0.0/33"),
        peer("endpoint=nowhere"),
        peer("persistent_keepalive_interval=70000"),
        peer("preshared_key=00"),
        peer("protocol_version=2"),
        peer("remove=yes"),
        peer("replace_allowed_ips=maybe"),
        peer("listen_port=1"),
    ];

    let state = settings(&a).await?;
    for request in &requests {
        let reply = parse(&a.request(request).await?)?;
        assert_ne!(reply.errno, 0, "{request:?}");
        assert_eq!(reply.peers, [], "{request:?}");
        assert_eq!(settings(&a).await?, state, "{request:?}");
    }

    // The configuration still carries traffic both ways.
    transfer(&a, &mut b, Family::V4).await?;
    transfer(&b, &mut a, Family::V6).await
}

#[cfg(unix)]
#[tokio::test]
async fn get_and_set_over_a_unix_socket() -> TestResult {
    use nsplane_uapi::UapiListener;
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt};
    use tokio::net::UnixStream;
    use tokio::net::unix::OwnedReadHalf;

    /// Reads one response, up to and including the empty line after `errno`.
    async fn response(reader: &mut BufReader<OwnedReadHalf>) -> TestResult<Config> {
        let mut out = String::new();
        loop {
            let mut line = String::new();
            if timeout(WAIT, reader.read_line(&mut line)).await?? == 0 {
                return Err("connection closed".into());
            }
            let done = line == "\n" && out.contains("errno=");
            out.push_str(&line);
            if done {
                return parse(&out);
            }
        }
    }

    let (a, mut b) = pair().await?;
    let path = std::env::temp_dir().join(format!("nsplane-e2e-uapi-{}.sock", std::process::id()));
    let listener = UapiListener::bind_path(&path)?;
    let uapi = a.uapi.clone();
    let server = tokio::spawn(async move { uapi.serve(listener).await });

    let stream = timeout(WAIT, UnixStream::connect(&path)).await??;
    let (reader, mut writer) = stream.into_split();
    let mut reader = BufReader::new(reader);
    let b_hex = hex(b.public().as_bytes());
    writer
        .write_all(
            format!("set=1\npublic_key={b_hex}\npersistent_keepalive_interval=9\n\n").as_bytes(),
        )
        .await?;
    assert_eq!(response(&mut reader).await?.errno, 0);
    assert_eq!(a.peer(b.public()).await?.persistent_keepalive, Some(9));

    writer.write_all(b"get=1\n\n").await?;
    let config = response(&mut reader).await?;
    assert_eq!(config.errno, 0);
    assert_eq!(config.private_key, Some(hex(&a.secret.to_bytes())));
    assert_eq!(config.listen_port, Some(a.port));
    let [peer] = config.peers.as_slice() else {
        return Err(format!("expected one peer, got {:?}", config.peers).into());
    };
    assert_eq!(peer.public_key, b_hex);
    assert_eq!(peer.keepalive, 9);
    transfer(&a, &mut b, Family::V4).await?;

    // The server stops with the engine and removes the socket.
    a.handle.shutdown().await?;
    timeout(WAIT, server).await???;
    assert!(!path.exists());
    Ok(())
}
