//! Engines on real TUN devices, and interop with kernel WireGuard.
//!
//! Every test needs root (`CAP_NET_ADMIN`) and `/dev/net/tun`, and the interop test needs a
//! kernel WireGuard peer in another container, so all of them are `#[ignore]`d. They run
//! with `--ignored --test-threads=1` inside the containers `scripts/e2e/lib.sh` (`just
//! e2e-lib`) sets up; the interop tests read their parameters from the `NSPLANE_E2E_LIB_*`
//! variables that script sets, including the `nsplane-cli` binary (`NSPLANE_E2E_LIB_CLI`).
#![cfg(target_os = "linux")]

use std::collections::BTreeSet;
use std::future::{Future, poll_fn};
use std::io::{self, Write as _};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::os::fd::{AsFd as _, AsRawFd as _};
use std::path::PathBuf;
use std::pin::Pin;
use std::process::{Child, Command, ExitStatus, Output};
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use futures_core::Stream;
use nix::fcntl::{FcntlArg, FdFlag, fcntl};
use nix::sys::signal::{Signal, kill};
use nix::unistd::Pid;
use nsplane::x25519::{PublicKey, StaticSecret};
use nsplane::{
    AllowedIp, Engine, EngineBuilder, EngineHandle, Event, PacketSink, PacketSource, Peer,
    PeerStats, UdpTransport,
};
use nsplane_acl::{
    AclAction, AclEngine, AclFilter, AclPolicy, AclRule, Label, LabelSet, PeerLabelMap, reasons,
};
use nsplane_e2e::{Family, Node, Options, TestResult, WAIT, payload, serve_udp_echo, udp};
use nsplane_netstack::{DEFAULT_MTU, NetStack, NetStackConfig, NetStackHandle, TcpConnection};
use nsplane_packet::{Ecn, FiveTuple, IpPacket, Path, PeerId, TransportId, UdpHeader, protocol};
use nsplane_tun::Tun;
use nsplane_uapi::{TRANSPORT_ID, Uapi, UapiListener, udp_transport};
use tokio::io::{
    AsyncBufReadExt as _, AsyncRead, AsyncReadExt as _, AsyncWriteExt as _, BufReader,
};
use tokio::net::{TcpListener, UdpSocket};
use tokio::sync::{broadcast, mpsc};
use tokio::time::{Instant, sleep, timeout, timeout_at};

/// Upper bound for one external command (`ip`, `wg`, `ping`).
const COMMAND_WAIT: Duration = Duration::from_secs(30);
/// Upper bound for the kernel peer's first handshake: it retries every 5 seconds.
const KERNEL_HANDSHAKE_WAIT: Duration = Duration::from_secs(15);
/// How long a handshake that must fail is given to complete anyway.
const MISMATCH_WINDOW: Duration = Duration::from_secs(2);
/// How much our counters' growth may differ from the kernel's over the counter window.
///
/// Each end of the window reads our counters, then the kernel's through
/// [`Interop::kernel_transfer`] (container b answers within about 50 ms), so the two reads
/// are well under a second apart. Between the reads and on the wire at either read can be at
/// most two of our persistent keepalives (every second) and one of the kernel's (every two
/// seconds), 32 bytes each; both ends of the window add their error, and at most one
/// handshake message (initiation, 148 bytes) can be in flight across the window.
const TRANSFER_TOLERANCE: u64 = 2 * 2 * 32 + 148;
/// The interface name of the interop test.
const IFACE: &str = "nsplane0";
/// The interface name of the CLI interop test.
const CLI_IFACE: &str = "nsplane1";
/// The interface name of the ACL test.
const ACL_IFACE: &str = "nsplane2";
/// The port the ACL test's policy allows, and one it does not.
const ALLOWED: u16 = 7000;
const DENIED: u16 = 7001;
/// Upper bound for one connect request to the kernel peer: it gives up after 3 seconds.
const CONNECT_WAIT: Duration = Duration::from_secs(10);
/// How long a connection the ACL drops is given to arrive anyway, after the kernel peer
/// gave up on it.
const DENIED_WINDOW: Duration = Duration::from_millis(500);
/// The UDP payload size of the large packets.
const LARGE: usize = 1300;
/// The interface name of the TUN throughput test.
const BULK_IFACE: &str = "nsplane3";
/// The port the netstack echoes TCP on, and the one the kernel peer's bulk transfers go to.
const ECHO_PORT: u16 = 7;
const BULK_PORT: u16 = 9000;
/// Bytes the kernel peer sends through each TCP echo, and in each UDP echo datagram.
const TCP_ECHO_LEN: usize = 256 * 1024;
const UDP_ECHO_LEN: usize = 1200;
/// Upper bound for one echo request to the kernel peer: it gives up after 10 seconds.
const ECHO_WAIT: Duration = Duration::from_secs(20);
/// Bytes of one bulk transfer from the kernel peer.
const BULK_BYTES: u64 = 64 * 1024 * 1024;
/// Upper bound for one bulk transfer: the kernel peer gives up after 120 seconds.
const BULK_WAIT: Duration = Duration::from_secs(150);

/// Logs a test step; the output shows with `--nocapture`.
fn step(message: &str) -> TestResult {
    writeln!(io::stderr(), "== {message}")?;
    Ok(())
}

/// Runs `program` with `args` on a blocking thread, so the engine and the UAPI keep
/// serving, and returns its output whatever its exit status.
async fn run(program: &str, args: &[&str]) -> TestResult<Output> {
    let mut command = Command::new(program);
    command.args(args);
    let line = format!("{program} {}", args.join(" "));
    match timeout(
        COMMAND_WAIT,
        tokio::task::spawn_blocking(move || command.output()),
    )
    .await
    {
        Ok(output) => Ok(output??),
        Err(_) => Err(format!("`{line}` did not finish within {COMMAND_WAIT:?}").into()),
    }
}

/// Runs `program` with `args`, which must succeed, and returns its standard output.
async fn ok(program: &str, args: &[&str]) -> TestResult<String> {
    let output = run(program, args).await?;
    if !output.status.success() {
        return Err(format!(
            "`{program} {}` failed with {}: {}{}",
            args.join(" "),
            output.status,
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr),
        )
        .into());
    }
    Ok(String::from_utf8(output.stdout)?)
}

/// Runs `ip` with the whitespace-separated `args`, which must succeed.
async fn ip(args: &str) -> TestResult {
    ok("ip", &args.split_whitespace().collect::<Vec<_>>()).await?;
    Ok(())
}

/// Gives `iface` the addresses `v4` and `v6` (with prefix lengths), without duplicate
/// address detection, and brings it up.
async fn configure_iface(iface: &str, v4: &str, v6: &str) -> TestResult {
    ip(&format!("addr add {v4} dev {iface}")).await?;
    ip(&format!("-6 addr add {v6} dev {iface} nodad")).await?;
    ip(&format!("link set dev {iface} mtu 1420 up")).await
}

/// Seconds since the Unix epoch.
fn unix_now() -> TestResult<u64> {
    Ok(SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)?
        .as_secs())
}

/// A UDP datagram sent by the kernel from a socket on a TUN device reaches the peer engine
/// intact, and the peer's reply arrives back on that socket, for IPv4 and IPv6 with a
/// 1300-byte payload.
#[tokio::test]
#[ignore = "needs CAP_NET_ADMIN and /dev/net/tun; run by `just e2e-lib`"]
async fn tun_carries_socket_datagrams_both_ways() -> TestResult {
    let tun = Tun::create("nsplane-e2e%d")?;
    let name = tun.name()?;
    let (source, sink) = tun.split()?;
    let id = TransportId::new(1);
    let transport = UdpTransport::bind(id, SocketAddr::from((Ipv4Addr::LOCALHOST, 0)))?;
    let addr = transport.local_addr();
    let secret = StaticSecret::from([1; 32]);
    let engine = EngineBuilder::new(source, sink)
        .transport(transport)
        .private_key(secret.clone())
        .build()?;
    let handle = engine.handle();

    // The peer engine (seed 2: 10.0.0.2, fd00::2) uses channels as its source and sink.
    let peer_id = TransportId::new(2);
    let peer_transport = UdpTransport::bind(peer_id, SocketAddr::from((Ipv4Addr::LOCALHOST, 0)))?;
    let peer_addr = peer_transport.local_addr();
    let mut peer = Node::new(2, peer_id, peer_addr, peer_transport, Options::default());

    let (tun4, tun6) = (
        Ipv4Addr::new(10, 0, 0, 1),
        Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 1),
    );
    handle.add_or_update_peer(peer.as_peer(id)).await?;
    peer.handle
        .add_or_update_peer(Peer {
            allowed_ips: vec![
                AllowedIp {
                    addr: IpAddr::V4(tun4),
                    cidr: 32,
                },
                AllowedIp {
                    addr: IpAddr::V6(tun6),
                    cidr: 128,
                },
            ],
            path: Some(Path {
                transport: peer_id,
                addr,
                ecn: Ecn::NotEct,
            }),
            ..Peer::new(PublicKey::from(&secret))
        })
        .await?;
    configure_iface(&name, &format!("{tun4}/24"), &format!("{tun6}/64")).await?;
    let from_tun = peer
        .handle
        .peer_id(PublicKey::from(&secret))
        .await?
        .ok_or("the peer engine does not know the TUN engine")?;

    for family in [Family::V4, Family::V6] {
        step(&format!("{family:?} through {name}"))?;
        let (local, remote) = match family {
            Family::V4 => (IpAddr::V4(tun4), IpAddr::V4(peer.ip4)),
            Family::V6 => (IpAddr::V6(tun6), IpAddr::V6(peer.ip6)),
        };
        let socket = UdpSocket::bind(SocketAddr::new(local, 0)).await?;
        let local = socket.local_addr()?;
        let remote = SocketAddr::new(remote, 9);
        let data = payload(LARGE);

        // Kernel -> TUN -> engine -> peer engine -> peer sink.
        socket.send_to(&data, remote).await?;
        let (from, packet) = peer.expect_delivery().await?;
        if from != from_tun {
            return Err(format!("{family:?} packet attributed to {from:?}").into());
        }
        let ip = IpPacket::parse(&packet)?;
        let expected = FiveTuple {
            src: local.ip(),
            dst: remote.ip(),
            protocol: protocol::UDP,
            src_port: local.port(),
            dst_port: remote.port(),
        };
        if ip.five_tuple() != Some(expected) {
            return Err(format!("{family:?} packet is {:?}", ip.five_tuple()).into());
        }
        let (_, delivered) = UdpHeader::parse(ip.payload())?;
        if delivered != data.as_slice() {
            return Err(format!("{family:?} payload changed in transit").into());
        }

        // Peer engine -> engine -> TUN -> kernel -> socket.
        peer.send(&udp(remote, local, &data)).await?;
        let mut buf = vec![0; 2 * LARGE];
        let (len, sender) = timeout(WAIT, socket.recv_from(&mut buf))
            .await
            .map_err(|_| format!("no {family:?} reply on {local} within {WAIT:?}"))??;
        if sender != remote || buf[..len] != data[..] {
            return Err(format!("{family:?} reply of {len} bytes from {sender}").into());
        }
    }
    Ok(())
}

/// Waits for `Event::MtuChanged { mtu }`; the TUN watcher polls the interface MTU every
/// second, so it is due well within [`WAIT`].
async fn expect_mtu_changed(events: &mut broadcast::Receiver<Event>, mtu: u16) -> TestResult {
    let deadline = Instant::now() + WAIT;
    loop {
        match timeout_at(deadline, events.recv()).await {
            Ok(Ok(Event::MtuChanged { mtu: changed })) if changed == mtu => return Ok(()),
            Ok(Ok(Event::MtuChanged { mtu: changed })) => {
                return Err(format!("MTU changed to {changed}, expected {mtu}").into());
            }
            Ok(Ok(_) | Err(broadcast::error::RecvError::Lagged(_))) => {}
            Ok(Err(broadcast::error::RecvError::Closed)) => return Err("engine stopped".into()),
            Err(_) => return Err(format!("no MTU change to {mtu} within {WAIT:?}").into()),
        }
    }
}

/// `ip link set mtu` on the TUN device reaches the engine on it: each change publishes
/// `Event::MtuChanged` and `EngineHandle::mtu` follows.
#[tokio::test]
#[ignore = "needs CAP_NET_ADMIN and /dev/net/tun; run by `just e2e-lib`"]
async fn tun_mtu_changes_reach_the_engine() -> TestResult {
    let tun = Tun::create("nsplane-mtu%d")?;
    let name = tun.name()?;
    let initial = tun.mtu();
    let (source, sink) = tun.split()?;
    let transport = UdpTransport::bind(
        TransportId::new(1),
        SocketAddr::from((Ipv4Addr::LOCALHOST, 0)),
    )?;
    let engine = EngineBuilder::new(source, sink)
        .transport(transport)
        .build()?;
    let handle = engine.handle();
    let mut events = handle.subscribe().await?;
    if handle.mtu().await? != initial {
        return Err(format!("initial MTU {} instead of {initial}", handle.mtu().await?).into());
    }

    for mtu in [1280, 1400] {
        step(&format!("MTU {mtu} on {name}"))?;
        ip(&format!("link set dev {name} mtu {mtu}")).await?;
        expect_mtu_changed(&mut events, mtu).await?;
        let current = handle.mtu().await?;
        if current != mtu {
            return Err(format!("mtu() is {current} after a change to {mtu}").into());
        }
    }
    handle.shutdown().await?;
    Ok(())
}

/// The parameters of the interop test, set by `scripts/e2e/lib.sh`.
#[derive(Debug)]
struct Interop {
    /// File with this side's private key (`wg genkey`).
    private_key: String,
    /// File with the preshared key both sides use.
    psk: String,
    /// The kernel peer's public key (base64).
    peer_pub: String,
    /// The kernel peer's address.
    peer_endpoint: SocketAddr,
    /// The port this side listens on; the kernel peer's endpoint.
    listen_port: u16,
    /// This side's tunnel addresses, with prefix lengths.
    addr_v4: String,
    addr_v6: String,
    /// The kernel peer's tunnel addresses.
    peer_v4: Ipv4Addr,
    peer_v6: Ipv6Addr,
    /// Directory shared with the kernel peer's container: creating `request` there makes it
    /// write `wg show wg0 transfer` to `transfer`.
    kernel_dir: PathBuf,
}

/// The variable `NSPLANE_E2E_LIB_<name>`, which must be set.
fn var(name: &str) -> TestResult<String> {
    let key = format!("NSPLANE_E2E_LIB_{name}");
    std::env::var(&key).map_err(|_| {
        format!("{key} is not set: run this test through scripts/e2e/lib.sh (`just e2e-lib`)")
            .into()
    })
}

impl Interop {
    fn from_env() -> TestResult<Self> {
        Ok(Self {
            private_key: var("PRIVATE_KEY")?,
            psk: var("PSK")?,
            peer_pub: var("PEER_PUB")?,
            peer_endpoint: var("PEER_ENDPOINT")?.parse()?,
            listen_port: var("LISTEN_PORT")?.parse()?,
            addr_v4: var("ADDR_V4")?,
            addr_v6: var("ADDR_V6")?,
            peer_v4: var("PEER_V4")?.parse()?,
            peer_v6: var("PEER_V6")?.parse()?,
            kernel_dir: var("KERNEL_DIR")?.into(),
        })
    }

    /// The kernel peer's addresses as a `wg set ... allowed-ips` argument.
    fn peer_allowed_ips_arg(&self) -> String {
        format!("{}/32,{}/128", self.peer_v4, self.peer_v6)
    }

    /// The kernel peer's addresses as single-host allowed IPs.
    const fn peer_allowed_ips(&self) -> [AllowedIp; 2] {
        [
            AllowedIp {
                addr: IpAddr::V4(self.peer_v4),
                cidr: 32,
            },
            AllowedIp {
                addr: IpAddr::V6(self.peer_v6),
                cidr: 128,
            },
        ]
    }

    /// `wg set <iface> peer <peer> <args>`, which must succeed.
    async fn set_peer(&self, args: &[&str]) -> TestResult {
        let mut all = vec!["set", IFACE, "peer", &self.peer_pub];
        all.extend_from_slice(args);
        ok("wg", &all).await?;
        Ok(())
    }

    /// The single `<peer>\t<value>` line of `wg show <iface> <field>`, as its value.
    async fn show(&self, field: &str) -> TestResult<String> {
        let out = ok("wg", &["show", IFACE, field]).await?;
        let mut lines = out.lines();
        match (lines.next().and_then(|l| l.split_once('\t')), lines.next()) {
            (Some((peer, value)), None) if peer == self.peer_pub => Ok(value.to_owned()),
            _ => Err(format!("`wg show {IFACE} {field}`: {out:?}").into()),
        }
    }

    /// The kernel peer's `(rx, tx)` for this side, from `wg show wg0 transfer` in its
    /// container.
    async fn kernel_transfer(&self) -> TestResult<(u64, u64)> {
        let transfer = self.kernel_dir.join("transfer");
        match std::fs::remove_file(&transfer) {
            Err(e) if e.kind() != io::ErrorKind::NotFound => return Err(e.into()),
            _ => {}
        }
        std::fs::write(self.kernel_dir.join("request"), "")?;
        let deadline = Instant::now() + WAIT;
        let out = loop {
            match std::fs::read_to_string(&transfer) {
                Ok(out) => break out,
                Err(e) if e.kind() == io::ErrorKind::NotFound && Instant::now() < deadline => {
                    sleep(Duration::from_millis(10)).await;
                }
                Err(e) => return Err(format!("no kernel transfer within {WAIT:?}: {e}").into()),
            }
        };
        let fields: Vec<&str> = out.trim().split('\t').collect();
        match fields.as_slice() {
            [_, rx, tx] if !out.trim().contains('\n') => Ok((rx.parse()?, tx.parse()?)),
            _ => Err(format!("`wg show wg0 transfer`: {out:?}").into()),
        }
    }

    /// Creates `request` with `content` in the shared directory (through a rename, so the
    /// kernel peer never reads it half written) and returns the contents of `answer` once the
    /// kernel peer wrote it, for at most `within`.
    async fn kernel_request(
        &self,
        request: &str,
        content: &str,
        answer: &str,
        within: Duration,
    ) -> TestResult<String> {
        let answer = self.kernel_dir.join(answer);
        match std::fs::remove_file(&answer) {
            Err(e) if e.kind() != io::ErrorKind::NotFound => return Err(e.into()),
            _ => {}
        }
        let tmp = self.kernel_dir.join(format!("{request}.req"));
        std::fs::write(&tmp, content)?;
        std::fs::rename(&tmp, self.kernel_dir.join(request))?;
        let deadline = Instant::now() + within;
        loop {
            match std::fs::read_to_string(&answer) {
                Ok(out) => return Ok(out),
                Err(e) if e.kind() == io::ErrorKind::NotFound && Instant::now() < deadline => {
                    sleep(Duration::from_millis(10)).await;
                }
                Err(e) => {
                    return Err(format!("no answer to {request} within {within:?}: {e}").into());
                }
            }
        }
    }

    /// Makes the kernel peer send `hello` to this side's IPv4 address on `port` over `proto`
    /// (`tcp` or `udp`) and returns the exit status of its attempt.
    async fn kernel_connect(&self, proto: &str, port: u16) -> TestResult<i32> {
        let status = self
            .kernel_request(
                "connect",
                &format!("{proto} {port}\n"),
                "connect.result",
                CONNECT_WAIT,
            )
            .await?;
        Ok(status.trim().parse()?)
    }

    /// Drops the kernel peer's session with this side, so that it initiates the next
    /// handshake as at the start.
    async fn reset_kernel_peer(&self) -> TestResult {
        self.kernel_request("reset", "", "reset.done", WAIT).await?;
        Ok(())
    }

    /// Pings the kernel peer's `family` address with `size` bytes of payload.
    async fn ping(&self, family: Family, size: usize) -> TestResult<bool> {
        let dst = match family {
            Family::V4 => IpAddr::V4(self.peer_v4),
            Family::V6 => IpAddr::V6(self.peer_v6),
        };
        let (dst, size) = (dst.to_string(), size.to_string());
        let output = run("ping", &["-c", "3", "-W", "2", "-s", &size, &dst]).await?;
        Ok(output.status.success())
    }

    /// Pings the kernel peer, which must answer.
    async fn expect_ping(&self, family: Family, size: usize) -> TestResult {
        if !self.ping(family, size).await? {
            return Err(format!("{family:?} ping of {size} bytes got no reply").into());
        }
        Ok(())
    }
}

/// The engine's only peer.
async fn the_peer(handle: &EngineHandle) -> TestResult<PeerStats> {
    match <[PeerStats; 1]>::try_from(handle.peers().await?) {
        Ok([peer]) => Ok(peer),
        Err(peers) => Err(format!("expected one peer, got {peers:?}").into()),
    }
}

/// How many handshakes completed within `window`.
async fn handshakes(
    events: &mut broadcast::Receiver<Event>,
    window: Duration,
) -> TestResult<usize> {
    let deadline = Instant::now() + window;
    let mut count = 0;
    loop {
        match timeout_at(deadline, events.recv()).await {
            Ok(Ok(Event::HandshakeCompleted { .. })) => count += 1,
            Ok(Ok(_) | Err(broadcast::error::RecvError::Lagged(_))) => {}
            Ok(Err(broadcast::error::RecvError::Closed)) => return Err("engine stopped".into()),
            Err(_) => return Ok(count),
        }
    }
}

/// How many handshake messages the engine rejected.
async fn rejected_handshakes(handle: &EngineHandle) -> TestResult<u64> {
    let counters = handle.drop_counters().await?;
    Ok(counters.get("handshake rejected").copied().unwrap_or(0))
}

/// Polls the engine's only peer until `done` holds for it, for at most `within`.
async fn wait_for_peer(
    handle: &EngineHandle,
    within: Duration,
    what: &str,
    mut done: impl FnMut(&PeerStats) -> bool,
) -> TestResult<PeerStats> {
    let deadline = Instant::now() + within;
    loop {
        let peer = the_peer(handle).await?;
        if done(&peer) {
            return Ok(peer);
        }
        if Instant::now() >= deadline {
            return Err(format!("{what} within {within:?}: {peer:?}").into());
        }
        sleep(Duration::from_millis(100)).await;
    }
}

/// Configures the engine with one `wg set` over the UAPI socket and checks the handle's view.
async fn configure(env: &Interop, handle: &EngineHandle) -> TestResult<PeerId> {
    let allowed = env.peer_allowed_ips_arg();
    let port = env.listen_port.to_string();
    let endpoint = env.peer_endpoint.to_string();
    ok(
        "wg",
        &[
            "set",
            IFACE,
            "private-key",
            &env.private_key,
            "listen-port",
            &port,
            "peer",
            &env.peer_pub,
            "preshared-key",
            &env.psk,
            "allowed-ips",
            &allowed,
            "endpoint",
            &endpoint,
        ],
    )
    .await?;
    let peer = the_peer(handle).await?;
    assert_eq!(peer.allowed_ips, env.peer_allowed_ips());
    assert_eq!(peer.path.map(|p| p.addr), Some(env.peer_endpoint));
    assert!(peer.preshared_key.is_some());
    assert!(handle.private_key().await?.is_some());
    Ok(peer.peer)
}

/// Waits for the handshake the kernel peer initiates: this side sends nothing yet, so the
/// kernel's persistent keepalive is what starts it.
async fn kernel_initiates(handle: &EngineHandle) -> TestResult {
    wait_for_peer(
        handle,
        KERNEL_HANDSHAKE_WAIT,
        "no handshake from the kernel",
        |p| p.last_handshake.is_some(),
    )
    .await?;
    Ok(())
}

/// A handshake with a mismatched preshared key fails; restoring the key repairs it.
async fn psk_mismatch_and_repair(
    env: &Interop,
    handle: &EngineHandle,
    events: &mut broadcast::Receiver<Event>,
    id: PeerId,
) -> TestResult {
    let wrong = std::env::temp_dir().join("nsplane-e2e-lib-wrong.psk");
    let wrong_key = ok("wg", &["genpsk"]).await?;
    std::fs::write(&wrong, &wrong_key)?;
    let wrong = wrong.to_str().ok_or("temporary path is not UTF-8")?;
    env.set_peer(&["preshared-key", wrong]).await?;
    assert_eq!(env.show("preshared-keys").await?, wrong_key.trim());
    let before = the_peer(handle).await?;
    let rejected = rejected_handshakes(handle).await?;
    handshakes(events, Duration::ZERO).await?;
    handle.force_handshake(id, None).await?;
    let completed = handshakes(events, MISMATCH_WINDOW).await?;
    let after = the_peer(handle).await?;
    // The kernel answered the initiation; its response failed to authenticate here.
    assert!(
        rejected_handshakes(handle).await? > rejected,
        "no handshake response rejected"
    );
    assert_eq!(
        completed, 0,
        "handshake with a wrong preshared key completed"
    );
    assert!(
        after.last_handshake >= before.last_handshake,
        "{before:?} {after:?}"
    );

    step("restoring the preshared key repairs it")?;
    env.set_peer(&["preshared-key", &env.psk]).await?;
    handle.force_handshake(id, None).await?;
    if handshakes(events, WAIT).await? == 0 {
        return Err("no handshake after restoring the preshared key".into());
    }
    env.expect_ping(Family::V4, 56).await
}

/// `wg set ... allowed-ips` replaces the peer's allowed IPs in `wg show`, in the handle and
/// in the routing of traffic.
async fn replace_allowed_ips(env: &Interop, handle: &EngineHandle) -> TestResult {
    let v4_only = format!("{}/32", env.peer_v4);
    env.set_peer(&["allowed-ips", &v4_only]).await?;
    assert_eq!(env.show("allowed-ips").await?, v4_only);
    assert_eq!(
        the_peer(handle).await?.allowed_ips,
        [env.peer_allowed_ips()[0]]
    );
    env.expect_ping(Family::V4, 56).await?;
    assert!(
        !env.ping(Family::V6, 56).await?,
        "IPv6 still routed to the peer"
    );

    let allowed = env.peer_allowed_ips_arg();
    env.set_peer(&["allowed-ips", &allowed]).await?;
    let shown: BTreeSet<String> = env
        .show("allowed-ips")
        .await?
        .split(' ')
        .map(str::to_owned)
        .collect();
    let expected: BTreeSet<String> = allowed.split(',').map(str::to_owned).collect();
    assert_eq!(shown, expected);
    assert_eq!(the_peer(handle).await?.allowed_ips, env.peer_allowed_ips());
    env.expect_ping(Family::V6, 56).await
}

/// A persistent keepalive set with `wg set` reaches `wg show` and the handle.
async fn persistent_keepalive(env: &Interop, handle: &EngineHandle) -> TestResult {
    env.set_peer(&["persistent-keepalive", "1"]).await?;
    assert_eq!(env.show("persistent-keepalive").await?, "1");
    assert_eq!(the_peer(handle).await?.persistent_keepalive, Some(1));
    Ok(())
}

/// Our wire-byte counters grow like the kernel's `wg show wg0 transfer` in the other
/// direction (kernel rx like our tx, kernel tx like our rx) while pings flow, within
/// [`TRANSFER_TOLERANCE`].
///
/// Only the growth over a window is compared: the kernel also counts what never reached this
/// side's counters, its initiations sent before this side listened and its response to the
/// initiation with the wrong preshared key.
async fn counters_match_kernel_transfer(env: &Interop, handle: &EngineHandle) -> TestResult {
    let ours = the_peer(handle).await?;
    let (kernel_rx, kernel_tx) = env.kernel_transfer().await?;
    for family in [Family::V4, Family::V6] {
        env.expect_ping(family, LARGE).await?;
    }
    let ours_after = the_peer(handle).await?;
    let (kernel_rx_after, kernel_tx_after) = env.kernel_transfer().await?;

    let (rx, tx) = (ours_after.rx - ours.rx, ours_after.tx - ours.tx);
    let (k_rx, k_tx) = (kernel_rx_after - kernel_rx, kernel_tx_after - kernel_tx);
    writeln!(
        io::stderr(),
        "ours: rx +{rx} tx +{tx}; kernel: rx +{k_rx} tx +{k_tx}"
    )?;
    // Three pings of 1300 bytes per family, each way.
    let pings = 2 * 3 * u64::try_from(LARGE)?;
    assert!(rx > pings && tx > pings, "ours: rx +{rx} tx +{tx}");
    assert!(
        k_rx.abs_diff(tx) <= TRANSFER_TOLERANCE,
        "kernel rx +{k_rx}, our tx +{tx}"
    );
    assert!(
        k_tx.abs_diff(rx) <= TRANSFER_TOLERANCE,
        "kernel tx +{k_tx}, our rx +{rx}"
    );
    Ok(())
}

/// `wg show` reports the configuration, and the latest handshake as recent wall-clock
/// time (the test started at Unix time `started`).
async fn wg_show(env: &Interop, started: u64) -> TestResult {
    let latest: u64 = env.show("latest-handshakes").await?.parse()?;
    let now = unix_now()?;
    assert!(
        latest + 1 >= started && latest <= now,
        "latest handshake at {latest}, test ran {started}..={now}"
    );
    let show = ok("wg", &["show", IFACE]).await?;
    writeln!(io::stderr(), "{show}")?;
    let public = ok("sh", &["-c", &format!("wg pubkey < {}", env.private_key)]).await?;
    for expected in [
        format!("interface: {IFACE}"),
        format!("public key: {}", public.trim()),
        format!("listening port: {}", env.listen_port),
        format!("peer: {}", env.peer_pub),
        "preshared key: (hidden)".to_owned(),
        format!("endpoint: {}", env.peer_endpoint),
        "latest handshake: ".to_owned(),
        "transfer: ".to_owned(),
        "persistent keepalive: every 1 second".to_owned(),
    ] {
        assert!(show.contains(&expected), "`wg show` lacks {expected:?}");
    }
    Ok(())
}

/// An engine on a TUN device, configured only with `wg`, against kernel WireGuard: the
/// kernel's handshake, pings in every flavour, a preshared key mismatch and
/// its repair, replacing allowed IPs, persistent keepalive, the byte counters against the
/// kernel's, and `wg show`.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "needs a kernel WireGuard peer; run by `just e2e-lib`"]
async fn kernel_wireguard_interop() -> TestResult {
    let env = Interop::from_env()?;
    let started = unix_now()?;

    let tun = Tun::create(IFACE)?;
    let (source, sink) = tun.split()?;
    let transport = udp_transport(0)?;
    let port = transport.local_addr().port();
    let engine = EngineBuilder::new(source, sink)
        .transport(transport)
        .build()?;
    let handle = engine.handle();
    let uapi = Uapi::with_listen_port(handle.clone(), port);
    let listener = UapiListener::bind(IFACE)?;
    let server = tokio::spawn(async move { uapi.serve(listener).await });
    configure_iface(IFACE, &env.addr_v4, &env.addr_v6).await?;
    let mut events = handle.subscribe().await?;

    step("configure over the UAPI socket")?;
    let id = configure(&env, &handle).await?;
    step("the kernel peer initiates a handshake")?;
    kernel_initiates(&handle).await?;
    step("ping the kernel peer: IPv4, IPv6, 1300 bytes")?;
    for family in [Family::V4, Family::V6] {
        for size in [56, LARGE] {
            env.expect_ping(family, size).await?;
        }
    }
    step("a mismatched preshared key fails the handshake")?;
    psk_mismatch_and_repair(&env, &handle, &mut events, id).await?;
    step("replace allowed IPs")?;
    replace_allowed_ips(&env, &handle).await?;
    step("persistent keepalive")?;
    persistent_keepalive(&env, &handle).await?;
    step("counters match the kernel's transfer")?;
    counters_match_kernel_transfer(&env, &handle).await?;
    step("wg show")?;
    wg_show(&env, started).await?;

    server.abort();
    drop(engine);
    Ok(())
}

/// The 32-byte key in base64 `key` (a key file's contents or `wg` output) in the UAPI's
/// hex form.
async fn key_hex(key: &str) -> TestResult<String> {
    let script = format!(
        "printf %s '{}' | base64 -d | od -An -v -tx1 | tr -d ' \\n'",
        key.trim()
    );
    let hex = ok("sh", &["-c", &script]).await?;
    if hex.len() != 64 {
        return Err(format!("{key:?} is not a base64 32-byte key").into());
    }
    Ok(hex)
}

/// Sends `request` on the UAPI stream and reads the response, up to and including the
/// empty line after `errno`.
async fn uapi_request(
    stream: &mut BufReader<tokio::net::UnixStream>,
    request: &str,
) -> TestResult<String> {
    stream.get_mut().write_all(request.as_bytes()).await?;
    let mut out = String::new();
    loop {
        let mut line = String::new();
        let len = timeout(WAIT, stream.read_line(&mut line))
            .await
            .map_err(|_| format!("no UAPI response within {WAIT:?}: {out:?}"))??;
        if len == 0 {
            return Err(format!("UAPI stream closed: {out:?}").into());
        }
        let done = line == "\n" && out.contains("errno=");
        out.push_str(&line);
        if done {
            return Ok(out);
        }
    }
}

/// The numeric `field` of a UAPI `get=1` response.
fn uapi_field(response: &str, field: &str) -> TestResult<u64> {
    let value = response
        .lines()
        .find_map(|line| line.strip_prefix(field)?.strip_prefix('='))
        .ok_or_else(|| format!("no {field} in {response:?}"))?;
    Ok(value.parse()?)
}

/// A running `nsplane-cli`, killed when dropped before it exited.
struct Daemon(Child);

impl Daemon {
    /// Sends SIGTERM and waits for the exit, for at most [`COMMAND_WAIT`].
    async fn terminate(&mut self) -> TestResult<ExitStatus> {
        kill(Pid::from_raw(i32::try_from(self.0.id())?), Signal::SIGTERM)?;
        let deadline = Instant::now() + COMMAND_WAIT;
        loop {
            if let Some(status) = self.0.try_wait()? {
                return Ok(status);
            }
            if Instant::now() >= deadline {
                return Err(
                    format!("nsplane-cli still runs {COMMAND_WAIT:?} after SIGTERM").into(),
                );
            }
            sleep(Duration::from_millis(100)).await;
        }
    }
}

impl Drop for Daemon {
    fn drop(&mut self) {
        if matches!(self.0.try_wait(), Ok(None)) {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }
}

/// `nsplane-cli` on a TUN device and a UAPI stream that the test opens and hands over by
/// number (`--tun-fd`, `--uapi-fd`), against kernel WireGuard: configured only over that
/// stream, it pings the kernel peer, reports the handshake and the traffic over the same
/// stream, and exits cleanly on SIGTERM.
///
/// Its name sorts after `kernel_wireguard_interop`, so with `--test-threads=1` it runs
/// second: that test needs the kernel peer to initiate, which it does not while a session
/// made here is still fresh. This test initiates itself and needs no particular state.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "needs a kernel WireGuard peer and nsplane-cli; run by `just e2e-lib`"]
async fn kernel_wireguard_interop_through_the_cli() -> TestResult {
    let env = Interop::from_env()?;
    let cli = std::env::var("NSPLANE_E2E_LIB_CLI").map_err(|_| {
        "NSPLANE_E2E_LIB_CLI is not set: run this test through scripts/e2e/lib.sh (`just e2e-lib`)"
    })?;
    let private = key_hex(&std::fs::read_to_string(&env.private_key)?).await?;
    let psk = key_hex(&std::fs::read_to_string(&env.psk)?).await?;
    let peer = key_hex(&env.peer_pub).await?;

    let tun = Tun::create(CLI_IFACE)?;
    configure_iface(CLI_IFACE, &env.addr_v4, &env.addr_v6).await?;
    let (parent, child) = std::os::unix::net::UnixStream::pair()?;
    // The child inherits both fds by number.
    fcntl(tun.as_fd(), FcntlArg::F_SETFD(FdFlag::empty()))?;
    fcntl(child.as_fd(), FcntlArg::F_SETFD(FdFlag::empty()))?;
    let tun_fd = tun.as_fd().as_raw_fd().to_string();
    let uapi_fd = child.as_raw_fd().to_string();
    step("start nsplane-cli with --tun-fd and --uapi-fd")?;
    let mut daemon = Daemon(
        Command::new(&cli)
            .args(["--disable-drop-privileges", "--tun-fd", &tun_fd])
            .args(["--uapi-fd", &uapi_fd, "-v", "debug", CLI_IFACE])
            .spawn()?,
    );
    // The child owns its copies now.
    drop((tun, child));
    parent.set_nonblocking(true)?;
    let mut uapi = BufReader::new(tokio::net::UnixStream::from_std(parent)?);

    step("configure over --uapi-fd")?;
    let request = format!(
        "set=1\nprivate_key={private}\nlisten_port={}\npublic_key={peer}\npreshared_key={psk}\n\
         endpoint={}\nallowed_ip={}/32\nallowed_ip={}/128\npersistent_keepalive_interval=25\n\n",
        env.listen_port, env.peer_endpoint, env.peer_v4, env.peer_v6
    );
    let reply = uapi_request(&mut uapi, &request).await?;
    if reply != "errno=0\n\n" {
        return Err(format!("set=1 over --uapi-fd: {reply:?}").into());
    }
    step("ping the kernel peer through nsplane-cli: IPv4, IPv6, 1300 bytes")?;
    for family in [Family::V4, Family::V6] {
        for size in [56, LARGE] {
            env.expect_ping(family, size).await?;
        }
    }
    step("get=1 over --uapi-fd reports the handshake and the traffic")?;
    let reply = uapi_request(&mut uapi, "get=1\n\n").await?;
    if !reply.ends_with("errno=0\n\n") {
        return Err(format!("get=1 over --uapi-fd: {reply:?}").into());
    }
    for field in ["last_handshake_time_sec", "rx_bytes", "tx_bytes"] {
        if uapi_field(&reply, field)? == 0 {
            return Err(format!("{field} is 0: {reply:?}").into());
        }
    }

    step("SIGTERM stops nsplane-cli")?;
    let status = daemon.terminate().await?;
    if !status.success() {
        return Err(format!("nsplane-cli exited with {status}").into());
    }
    Ok(())
}

/// Waits for `Event::Dropped` with `reason`.
async fn expect_dropped(events: &mut broadcast::Receiver<Event>, reason: &str) -> TestResult {
    let deadline = Instant::now() + WAIT;
    loop {
        match timeout_at(deadline, events.recv()).await {
            Ok(Ok(Event::Dropped { reason: r, .. })) if r == reason => return Ok(()),
            Ok(Ok(_) | Err(broadcast::error::RecvError::Lagged(_))) => {}
            Ok(Err(broadcast::error::RecvError::Closed)) => return Err("engine stopped".into()),
            Err(_) => return Err(format!("no drop for {reason:?} within {WAIT:?}").into()),
        }
    }
}

/// An accept rule from `src` to `dst` for TCP and UDP.
fn accept(src: &str, dst: String) -> AclRule {
    AclRule {
        action: AclAction::Accept,
        src: vec![src.to_owned()],
        dst: vec![dst],
        proto: None,
    }
}

/// The kernel peer's TCP connection to [`ALLOWED`] on `local4` carries its data; the one to
/// [`DENIED`] never connects and counts as a denial.
async fn acl_tcp(
    env: &Interop,
    local4: Ipv4Addr,
    filter: &AclFilter,
    events: &mut broadcast::Receiver<Event>,
) -> TestResult {
    step("TCP to the allowed port connects and carries data")?;
    let tcp_allowed = TcpListener::bind((local4, ALLOWED)).await?;
    let tcp_denied = TcpListener::bind((local4, DENIED)).await?;
    let status = env.kernel_connect("tcp", ALLOWED).await?;
    if status != 0 {
        return Err(format!("TCP to {ALLOWED} failed with exit status {status}").into());
    }
    let (mut stream, from) = timeout(WAIT, tcp_allowed.accept())
        .await
        .map_err(|_| format!("no TCP connection on {ALLOWED} within {WAIT:?}"))??;
    let mut data = Vec::new();
    timeout(WAIT, stream.read_to_end(&mut data))
        .await
        .map_err(|_| format!("TCP stream from {from} did not end within {WAIT:?}"))??;
    if from.ip() != IpAddr::V4(env.peer_v4) || data != b"hello" {
        return Err(format!("TCP from {from}: {data:?}").into());
    }

    step("TCP to the denied port never connects")?;
    let denied_before = filter.stats().denied;
    let status = env.kernel_connect("tcp", DENIED).await?;
    if status == 0 {
        return Err(format!("TCP to {DENIED} connected").into());
    }
    if let Ok(accepted) = timeout(DENIED_WINDOW, tcp_denied.accept()).await {
        return Err(format!("TCP connection on {DENIED}: {accepted:?}").into());
    }
    expect_dropped(events, reasons::DENIED).await?;
    assert!(
        filter.stats().denied > denied_before,
        "no TCP denial counted"
    );
    Ok(())
}

/// The kernel peer's UDP datagram to [`ALLOWED`] on `local4` arrives; the one to
/// [`DENIED`] does not and counts as a denial.
async fn acl_udp(
    env: &Interop,
    local4: Ipv4Addr,
    filter: &AclFilter,
    events: &mut broadcast::Receiver<Event>,
) -> TestResult {
    step("UDP to the allowed port arrives, to the denied port it does not")?;
    let udp_allowed = UdpSocket::bind((local4, ALLOWED)).await?;
    let udp_denied = UdpSocket::bind((local4, DENIED)).await?;
    let mut buf = [0; 64];
    let status = env.kernel_connect("udp", ALLOWED).await?;
    let (len, from) = timeout(WAIT, udp_allowed.recv_from(&mut buf))
        .await
        .map_err(|_| format!("no UDP datagram on {ALLOWED} within {WAIT:?}"))??;
    if status != 0 || from.ip() != IpAddr::V4(env.peer_v4) || buf[..len] != *b"hello" {
        return Err(format!("UDP from {from} (status {status}): {:?}", &buf[..len]).into());
    }
    // Later drops are the UDP one: the TCP attempt is over.
    while events.try_recv().is_ok() {}
    let denied_before = filter.stats().denied;
    env.kernel_connect("udp", DENIED).await?;
    if let Ok(received) = timeout(DENIED_WINDOW, udp_denied.recv_from(&mut buf)).await {
        return Err(format!("UDP datagram on {DENIED}: {received:?}").into());
    }
    expect_dropped(events, reasons::DENIED).await?;
    let stats = filter.stats();
    writeln!(io::stderr(), "{stats:?}")?;
    assert!(
        stats.denied > denied_before,
        "no UDP denial counted: {stats:?}"
    );
    assert!(stats.accepted >= 2, "{stats:?}");
    Ok(())
}

/// An engine on a TUN device with an `AclFilter` that lets the kernel peer's key reach
/// [`ALLOWED`] on this side and nothing else: the kernel peer's TCP connection and UDP
/// datagram to [`ALLOWED`] arrive at sockets here, those to [`DENIED`] are dropped with
/// `reasons::DENIED` before they reach the kernel.
///
/// This side initiates the handshake, so the test needs no particular state of the kernel
/// peer; at the end it resets the kernel peer's session so that the kernel initiates again
/// for the tests after it.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "needs a kernel WireGuard peer; run by `just e2e-lib`"]
async fn kernel_peer_through_acl_filter() -> TestResult {
    let env = Interop::from_env()?;
    let acl = Arc::new(AclEngine::new());
    let identities = Arc::new(PeerLabelMap::new());
    let filter = AclFilter::new(Arc::clone(&acl), Arc::clone(&identities));

    let tun = Tun::create(ACL_IFACE)?;
    let (source, sink) = tun.split()?;
    let engine = EngineBuilder::new(source, sink)
        .transport(udp_transport(env.listen_port)?)
        .filter(Box::new(filter.clone()))
        .build()?;
    let handle = engine.handle();
    let uapi = Uapi::with_listen_port(handle.clone(), env.listen_port);
    let listener = UapiListener::bind(ACL_IFACE)?;
    let server = tokio::spawn(async move { uapi.serve(listener).await });
    configure_iface(ACL_IFACE, &env.addr_v4, &env.addr_v6).await?;
    let mut events = handle.subscribe().await?;

    step("configure over the UAPI socket, with a policy for the kernel peer's key")?;
    let allowed = env.peer_allowed_ips_arg();
    let endpoint = env.peer_endpoint.to_string();
    ok(
        "wg",
        &[
            "set",
            ACL_IFACE,
            "private-key",
            &env.private_key,
            "peer",
            &env.peer_pub,
            "preshared-key",
            &env.psk,
            "allowed-ips",
            &allowed,
            "endpoint",
            &endpoint,
        ],
    )
    .await?;
    let peer = the_peer(&handle).await?;
    // The label the policy's `key:<hex>` source compiles to.
    let src = peer
        .public_key
        .to_bytes()
        .iter()
        .fold(String::from("key:"), |mut text, b| {
            use std::fmt::Write as _;
            let _ = write!(text, "{b:02x}");
            text
        });
    identities.insert(peer.peer, LabelSet::new([Label::from(src.as_str())]));
    let local4: Ipv4Addr = env.addr_v4.split('/').next().unwrap_or_default().parse()?;
    let local6: Ipv6Addr = env.addr_v6.split('/').next().unwrap_or_default().parse()?;
    acl.load(AclPolicy {
        acls: vec![
            accept(&src, format!("{local4}:{ALLOWED}")),
            accept(&src, format!("{local6}:{ALLOWED}")),
        ],
        ..AclPolicy::default()
    })?;

    step("this side initiates the handshake")?;
    handle.force_handshake(peer.peer, None).await?;
    wait_for_peer(&handle, WAIT, "no handshake with the kernel", |p| {
        p.last_handshake.is_some()
    })
    .await?;

    acl_tcp(&env, local4, &filter, &mut events).await?;
    acl_udp(&env, local4, &filter, &mut events).await?;

    server.abort();
    handle.shutdown().await?;
    drop(engine);
    step("reset the kernel peer's session for the tests after this one")?;
    env.reset_kernel_peer().await
}

/// The 32-byte key in base64 `key` (a key file's contents or `wg` output).
async fn key_bytes(key: &str) -> TestResult<[u8; 32]> {
    let hex = key_hex(key).await?;
    let mut bytes = [0; 32];
    for (byte, pair) in bytes.iter_mut().zip(hex.as_bytes().chunks(2)) {
        *byte = u8::from_str_radix(std::str::from_utf8(pair)?, 16)?;
    }
    Ok(bytes)
}

/// An engine on `source` and `sink` that listens on this side's port and knows the kernel
/// peer (key, preshared key, allowed IPs, endpoint) through its handle, with a handshake
/// this side initiated, so the test needs no particular state of the kernel peer.
async fn kernel_peer_engine<Src: PacketSource, Snk: PacketSink>(
    env: &Interop,
    source: Src,
    sink: Snk,
) -> TestResult<(Engine, EngineHandle)> {
    let private = key_bytes(&std::fs::read_to_string(&env.private_key)?).await?;
    let engine = EngineBuilder::new(source, sink)
        .transport(udp_transport(env.listen_port)?)
        .private_key(StaticSecret::from(private))
        .build()?;
    let handle = engine.handle();
    let key = PublicKey::from(key_bytes(&env.peer_pub).await?);
    handle
        .add_or_update_peer(Peer {
            allowed_ips: env.peer_allowed_ips().to_vec(),
            preshared_key: Some(key_bytes(&std::fs::read_to_string(&env.psk)?).await?),
            path: Some(Path {
                transport: TRANSPORT_ID,
                addr: env.peer_endpoint,
                ecn: Ecn::NotEct,
            }),
            ..Peer::new(key)
        })
        .await?;
    let id = handle
        .peer_id(key)
        .await?
        .ok_or("the engine does not know the kernel peer")?;
    handle.force_handshake(id, None).await?;
    wait_for_peer(&handle, WAIT, "no handshake with the kernel", |p| {
        p.last_handshake.is_some()
    })
    .await?;
    Ok((engine, handle))
}

/// Shuts `engine` down, which frees its port (and removes its TUN device), and resets the
/// kernel peer's session so that it initiates the next handshake for the tests after this
/// one.
async fn stop_engine(env: &Interop, engine: Engine, handle: &EngineHandle) -> TestResult {
    handle.shutdown().await?;
    drop(engine);
    env.reset_kernel_peer().await
}

/// Echoes every byte of `conn` until EOF, then shuts its write half down.
async fn echo_tcp(conn: TcpConnection) -> io::Result<()> {
    let (mut reader, mut writer) = tokio::io::split(conn);
    tokio::io::copy(&mut reader, &mut writer).await?;
    writer.shutdown().await
}

/// Accepts every inbound TCP connection of `stack`: those to [`BULK_PORT`] go to the
/// returned receiver, all others are echoed, each on its own task, until the stack stops.
fn serve_tcp(stack: &NetStackHandle) -> mpsc::UnboundedReceiver<TcpConnection> {
    let mut incoming = stack.incoming_tcp();
    let (bulk, accepted) = mpsc::unbounded_channel();
    tokio::spawn(async move {
        while let Some(conn) = poll_fn(|cx| Pin::new(&mut incoming).poll_next(cx)).await {
            if conn.local_addr().port() == BULK_PORT {
                // The test may have stopped listening.
                let _ = bulk.send(conn);
            } else {
                tokio::spawn(echo_tcp(conn));
            }
        }
    });
    accepted
}

/// Makes the kernel peer send `len` bytes to `target` over `proto` (`tcp` or `udp`, one
/// datagram) and checks that exactly those bytes came back.
async fn kernel_echo(env: &Interop, proto: &str, target: SocketAddr, len: usize) -> TestResult {
    let sent = payload(len);
    let echoed = env.kernel_dir.join("netstack-echo.data");
    match std::fs::remove_file(&echoed) {
        Err(e) if e.kind() != io::ErrorKind::NotFound => return Err(e.into()),
        _ => {}
    }
    std::fs::write(env.kernel_dir.join("netstack-echo.payload"), &sent)?;
    let request = format!("{proto} {} {} {len}\n", target.ip(), target.port());
    let status = env
        .kernel_request("netstack-echo", &request, "netstack-echo.result", ECHO_WAIT)
        .await?;
    let echoed = std::fs::read(&echoed)?;
    if status.trim() != "0" || echoed != sent {
        return Err(format!(
            "{proto} echo from {target}: {} of {len} bytes, exit status {}",
            echoed.len(),
            status.trim()
        )
        .into());
    }
    Ok(())
}

/// Reads `reader` until [`BULK_BYTES`] arrived or it ends, and returns the byte count.
async fn count_bytes(mut reader: impl AsyncRead + Unpin) -> TestResult<u64> {
    let mut buf = vec![0; 64 * 1024];
    let mut total = 0;
    while total < BULK_BYTES {
        let len = reader.read(&mut buf).await?;
        if len == 0 {
            break;
        }
        total += u64::try_from(len)?;
    }
    Ok(total)
}

/// Makes the kernel peer send [`BULK_BYTES`] over TCP to `target`, where `received` reads
/// them and closes the connection, and logs the throughput the kernel peer measured.
async fn kernel_bulk(
    env: &Interop,
    target: SocketAddr,
    what: &str,
    received: impl Future<Output = TestResult<u64>>,
) -> TestResult {
    let request = format!("{} {} {BULK_BYTES}\n", target.ip(), target.port());
    let (answer, received) = tokio::join!(
        env.kernel_request("netstack-bulk", &request, "netstack-bulk.result", BULK_WAIT),
        timeout(BULK_WAIT, received),
    );
    let received = received.map_err(|_| format!("{what}: no transfer within {BULK_WAIT:?}"))??;
    let answer = answer?;
    let (status, nanos) = match answer.split_whitespace().collect::<Vec<_>>().as_slice() {
        [status, nanos] => (status.parse::<i32>()?, nanos.parse::<u128>()?),
        _ => return Err(format!("netstack-bulk.result: {answer:?}").into()),
    };
    if status != 0 || received != BULK_BYTES {
        return Err(
            format!("{what}: {received} of {BULK_BYTES} bytes, exit status {status}").into(),
        );
    }
    // Tenths of MiB/s, in integers.
    let tenths = u128::from(BULK_BYTES) * 10_000_000_000 / (nanos.max(1) << 20);
    step(&format!(
        "throughput {what}: {} MiB in {}.{:03} s, {}.{} MiB/s",
        BULK_BYTES >> 20,
        nanos / 1_000_000_000,
        nanos % 1_000_000_000 / 1_000_000,
        tenths / 10,
        tenths % 10
    ))
}

/// A node whose local side is a netstack (no TUN device), with the kernel peer configured
/// through the engine handle: the kernel peer's TCP and UDP echoes through the stack come
/// back byte-exact over IPv4 and IPv6, and a bulk TCP transfer from the kernel peer arrives
/// complete (its throughput is logged).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "needs a kernel WireGuard peer; run by `just e2e-lib`"]
async fn netstack_only_node_against_kernel_wireguard() -> TestResult {
    let env = Interop::from_env()?;
    let mut addresses = Vec::new();
    for addr in [&env.addr_v4, &env.addr_v6] {
        let (ip, prefix) = addr.split_once('/').ok_or("address without prefix")?;
        addresses.push((ip.parse::<IpAddr>()?, prefix.parse::<u8>()?));
    }
    let local: Vec<IpAddr> = addresses.iter().map(|&(ip, _)| ip).collect();
    let (stack, stack_handle) = NetStack::new(NetStackConfig::new(addresses, DEFAULT_MTU));
    let mut bulk = serve_tcp(&stack_handle);
    let mut flows = serve_udp_echo(&stack_handle);
    let (source, sink) = stack.split();

    step("netstack node: this side initiates the handshake")?;
    let (engine, handle) = kernel_peer_engine(&env, source, sink).await?;
    for (family, ip, peer) in [
        (Family::V4, local[0], IpAddr::V4(env.peer_v4)),
        (Family::V6, local[1], IpAddr::V6(env.peer_v6)),
    ] {
        step(&format!(
            "the kernel peer's {family:?} TCP and UDP echo through the stack"
        ))?;
        let target = SocketAddr::new(ip, ECHO_PORT);
        kernel_echo(&env, "tcp", target, TCP_ECHO_LEN).await?;
        kernel_echo(&env, "udp", target, UDP_ECHO_LEN).await?;
        let (remote, flow_local) = timeout(WAIT, flows.recv())
            .await?
            .ok_or("UDP echo server stopped")?;
        if remote.ip() != peer || flow_local != target {
            return Err(format!("{family:?} UDP flow {remote} -> {flow_local}").into());
        }
    }

    step("bulk TCP from the kernel peer into the netstack")?;
    let received = async {
        let conn = bulk.recv().await.ok_or("TCP server stopped")?;
        count_bytes(conn).await
    };
    let target = SocketAddr::new(local[0], BULK_PORT);
    kernel_bulk(&env, target, "kernel -> netstack", received).await?;
    let stats = stack_handle.stats();
    writeln!(io::stderr(), "{stats:?}")?;

    stop_engine(&env, engine, &handle).await
}

/// A node on a TUN device, with the kernel peer configured through the engine handle: a
/// bulk TCP transfer from the kernel peer to a socket on the TUN address arrives complete
/// (its throughput is logged, for comparison with the netstack node's).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "needs a kernel WireGuard peer; run by `just e2e-lib`"]
async fn tun_node_bulk_tcp_from_kernel_wireguard() -> TestResult {
    let env = Interop::from_env()?;
    let tun = Tun::create(BULK_IFACE)?;
    let (source, sink) = tun.split()?;
    configure_iface(BULK_IFACE, &env.addr_v4, &env.addr_v6).await?;
    let local4: Ipv4Addr = env.addr_v4.split('/').next().unwrap_or_default().parse()?;
    let listener = TcpListener::bind((local4, BULK_PORT)).await?;

    step("TUN node: this side initiates the handshake")?;
    let (engine, handle) = kernel_peer_engine(&env, source, sink).await?;
    step("bulk TCP from the kernel peer into the TUN node")?;
    let received = async {
        let (stream, _) = listener.accept().await?;
        count_bytes(stream).await
    };
    let target = SocketAddr::from((local4, BULK_PORT));
    kernel_bulk(&env, target, "kernel -> TUN", received).await?;

    drop(listener);
    stop_engine(&env, engine, &handle).await
}
