//! Path MTU discovery from real ICMP errors (`UdpTransport::set_path_mtu_discovery`): node
//! 1 runs in the test process on a dual-stack `UdpTransport` bound with offload (so its
//! datagrams carry DF) and a fragmenter; its peer is `nsplane-cli` in network namespace B,
//! reached through a forwarding router in namespace R (the test's own namespace - R - B,
//! linked with veth pairs). For an IPv4 and an IPv6 outer path in turn:
//!
//! - R's route to B carries at most 1400 bytes (`mtu lock 1400`): the first large (1408-byte)
//!   datagram makes R answer with Fragmentation Needed or Packet Too Big, which the transport
//!   reads off its error queue and reports, so node 1's inner MTU for B drops to 1340 (IPv4
//!   outer) or 1320 (IPv6 outer);
//! - then larger inner packets are answered with Packet Too Big or Fragmentation Needed, or,
//!   IPv4 without DF, fragmented and answered by B's kernel, and packets at the inner MTU
//!   reach B: R counts no further datagram above its MTU, so the largest outer datagram
//!   after adapting fits it;
//! - once R's route is restored and the learned MTU expired, large packets reach B
//!   again.
//!
//! Needs root in a throwaway network namespace (it adds veth links and routes to the one it
//! runs in) and a release `nsplane-cli` named by `NSPLANE_E2E_PMTU_CLI`, for example:
//!
//! ```text
//! cargo build -p nsplane-cli --release --locked
//! cargo test -p nsplane-e2e --test path_mtu_root --no-run --locked
//! docker run --rm --label ai-agent=true --cap-add NET_ADMIN --cap-add SYS_ADMIN \
//!   --security-opt apparmor=unconfined --security-opt systempaths=unconfined \
//!   --device /dev/net/tun --sysctl net.ipv6.conf.all.disable_ipv6=0 \
//!   -v "$PWD:$PWD" -w "$PWD" -e NSPLANE_E2E_PMTU_CLI=$PWD/target/release/nsplane-cli \
//!   ai-agent/nstun-dev target/debug/deps/path_mtu_root-<hash> --ignored --nocapture
//! ```

#![cfg(target_os = "linux")]

use std::fmt::Write as _;
use std::io::{self, Write as _};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::process::{Child, Command, Stdio};
use std::time::Duration;

use nsplane::x25519::{PublicKey, StaticSecret};
use nsplane::{AllowedIp, FragmentConfig, Peer, PeerId, TransportId, UdpTransport};
use nsplane_e2e::{Family, MTU, Node, Options, TestResult, WAIT, icmp, payload};
use nsplane_packet::checksum::ipv4_header_checksum;
use nsplane_packet::{Ecn, Ipv4Header, Ipv6Header, Path, protocol};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::UnixStream;
use tokio::time::{Instant, sleep, timeout};

/// The outer MTU of R's route to B.
const LIMIT: u16 = 1400;
/// The size of large packets: a multiple of 16 below the source MTU.
const FULL: usize = 1408;
/// How long node 1 keeps a learned path MTU.
const EXPIRY: Duration = Duration::from_secs(8);
/// B's WireGuard port.
const PORT: u16 = 51820;
/// The key seed and tunnel addresses of B (node 1 is seed 1: 10.0.0.1, `fd00::1`).
const B_SEED: u8 = 2;
const B_IP4: Ipv4Addr = Ipv4Addr::new(10, 0, 0, 2);
const B_IP6: Ipv6Addr = Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 2);

/// Runs `ip` with `args`.
fn ip(args: &[&str]) -> TestResult {
    let status = Command::new("ip").args(args).status()?;
    if !status.success() {
        return Err(format!("ip {}: {status}", args.join(" ")).into());
    }
    Ok(())
}

/// Runs `command` in namespace `ns` and returns its output.
fn in_ns(ns: &str, command: &[&str]) -> TestResult<String> {
    let output = Command::new("ip")
        .args(["netns", "exec", ns])
        .args(command)
        .output()?;
    if !output.status.success() {
        return Err(format!("{ns}: {}: {:?}", command.join(" "), output).into());
    }
    Ok(String::from_utf8(output.stdout)?)
}

/// Namespaces R and B and the links between them and the test's namespace; removed when
/// dropped.
struct Topology {
    r: String,
    b: String,
}

impl Topology {
    /// The test's namespace on 10.77.1.1 / `fd77:1::1`, R on .2 / `::2` of both nets, B on
    /// 10.77.2.1 / `fd77:2::1`.
    fn new() -> TestResult<Self> {
        let id = std::process::id() % 100_000;
        let topology = Self {
            r: format!("pmtu-r-{id}"),
            b: format!("pmtu-b-{id}"),
        };
        let (r, b) = (topology.r.as_str(), topology.b.as_str());
        let a_link = format!("pmtu{id}");
        ip(&["netns", "add", r])?;
        ip(&["netns", "add", b])?;
        ip(&[
            "link", "add", &a_link, "type", "veth", "peer", "name", "ra", "netns", r,
        ])?;
        ip(&[
            "-n", r, "link", "add", "rb", "type", "veth", "peer", "name", "vb", "netns", b,
        ])?;
        for (ns, link, v4, v6) in [
            (None, a_link.as_str(), "10.77.1.1/24", "fd77:1::1/64"),
            (Some(r), "ra", "10.77.1.2/24", "fd77:1::2/64"),
            (Some(r), "rb", "10.77.2.2/24", "fd77:2::2/64"),
            (Some(b), "vb", "10.77.2.1/24", "fd77:2::1/64"),
        ] {
            let mut args = ns.map_or_else(Vec::new, |ns| vec!["-n", ns]);
            let n = args.len();
            args.extend(["addr", "add", v4, "dev", link]);
            ip(&args)?;
            args.truncate(n);
            args.extend(["addr", "add", v6, "dev", link, "nodad"]);
            ip(&args)?;
            args.truncate(n);
            args.extend(["link", "set", link, "up"]);
            ip(&args)?;
        }
        ip(&["-n", r, "link", "set", "lo", "up"])?;
        ip(&["-n", b, "link", "set", "lo", "up"])?;
        ip(&["route", "add", "10.77.2.0/24", "via", "10.77.1.2"])?;
        ip(&["-6", "route", "add", "fd77:2::/64", "via", "fd77:1::2"])?;
        ip(&["-n", b, "route", "add", "10.77.1.0/24", "via", "10.77.2.2"])?;
        ip(&[
            "-n",
            b,
            "-6",
            "route",
            "add",
            "fd77:1::/64",
            "via",
            "fd77:2::2",
        ])?;
        in_ns(
            r,
            &[
                "sysctl",
                "-qw",
                "net.ipv4.ip_forward=1",
                "net.ipv6.conf.all.forwarding=1",
            ],
        )?;
        // Until IPv6 has settled (link-local addresses leave the tentative state), the
        // first packets may get lost; wait until both families pass both ways.
        let reachable = |ns: Option<&str>, to: &str| {
            let mut command = Command::new(if ns.is_some() { "ip" } else { "ping" });
            if let Some(ns) = ns {
                command.args(["netns", "exec", ns, "ping"]);
            }
            command
                .args(["-c1", "-W1", to])
                .stdout(Stdio::null())
                .status()
                .is_ok_and(|status| status.success())
        };
        for (ns, to) in [
            (None, "10.77.2.1"),
            (None, "fd77:2::1"),
            (Some(b), "10.77.1.1"),
            (Some(b), "fd77:1::1"),
        ] {
            if !(0..10).any(|_| reachable(ns, to)) {
                return Err(format!("{to} unreachable from {ns:?}").into());
            }
        }
        Ok(topology)
    }

    /// Limits R's routes to B to `mtu`, or restores them.
    fn limit(&self, mtu: Option<u16>) -> TestResult {
        let mtu = mtu.map(|mtu| mtu.to_string());
        for (family, net, metric) in [("-4", "10.77.2.0/24", "0"), ("-6", "fd77:2::/64", "256")] {
            let mut args = vec![
                "-n",
                self.r.as_str(),
                family,
                "route",
                "replace",
                net,
                "dev",
                "rb",
            ];
            args.extend(["metric", metric]);
            if let Some(mtu) = &mtu {
                args.extend(["mtu", "lock", mtu]);
            }
            ip(&args)?;
        }
        Ok(())
    }

    /// The datagrams R dropped as too big for the next hop: IPv4 `FragFails` and IPv6
    /// `Ip6InTooBigErrors`.
    fn too_big(&self, family: Family) -> TestResult<u64> {
        match family {
            Family::V4 => {
                let snmp = in_ns(&self.r, &["cat", "/proc/net/snmp"])?;
                let mut ip_lines = snmp.lines().filter(|line| line.starts_with("Ip: "));
                let (names, values) = (ip_lines.next(), ip_lines.next());
                let (names, values) = names.zip(values).ok_or("no Ip: lines")?;
                let column = names
                    .split_whitespace()
                    .position(|name| name == "FragFails")
                    .ok_or("no FragFails")?;
                let value = values.split_whitespace().nth(column).ok_or("no value")?;
                Ok(value.parse()?)
            }
            Family::V6 => {
                let snmp = in_ns(&self.r, &["cat", "/proc/net/snmp6"])?;
                let value = snmp
                    .lines()
                    .find_map(|line| line.strip_prefix("Ip6InTooBigErrors"))
                    .ok_or("no Ip6InTooBigErrors")?;
                Ok(value.trim().parse()?)
            }
        }
    }
}

impl Drop for Topology {
    fn drop(&mut self) {
        // Removing the namespaces removes the veth pairs and the routes over them.
        let _ = ip(&["netns", "del", &self.r]);
        let _ = ip(&["netns", "del", &self.b]);
    }
}

/// `nsplane-cli` in B, killed when dropped.
struct Cli(Child);

impl Drop for Cli {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn hex(key: &[u8; 32]) -> String {
    key.iter().fold(String::new(), |mut hex, byte| {
        let _ = write!(hex, "{byte:02x}");
        hex
    })
}

/// Starts `nsplane-cli` as B on interface `name` in namespace `ns`, configured with node 1
/// (`a`) as its peer, its tunnel addresses up.
async fn start_cli(cli: &str, ns: &str, name: &str, a: &PublicKey) -> TestResult<Cli> {
    let child = Command::new("ip")
        .args(["netns", "exec", ns, cli, "--disable-drop-privileges", name])
        .stdin(Stdio::null())
        .spawn()?;
    let cli = Cli(child);
    let socket = nsplane_uapi::socket_path(name);
    let deadline = Instant::now() + WAIT;
    let stream = loop {
        match UnixStream::connect(&socket).await {
            Ok(stream) => break stream,
            Err(e) if Instant::now() >= deadline => return Err(format!("UAPI: {e}").into()),
            Err(_) => sleep(Duration::from_millis(50)).await,
        }
    };
    let private = StaticSecret::from([B_SEED; 32]).to_bytes();
    let request = format!(
        "set=1\nprivate_key={}\nlisten_port={PORT}\npublic_key={}\nallowed_ip=10.0.0.1/32\n\
         allowed_ip=fd00::1/128\n\n",
        hex(&private),
        hex(a.as_bytes())
    );
    let mut stream = BufReader::new(stream);
    stream.get_mut().write_all(request.as_bytes()).await?;
    let mut reply = String::new();
    while !reply.ends_with("\n\n") {
        if timeout(WAIT, stream.read_line(&mut reply)).await?? == 0 {
            break;
        }
    }
    if reply != "errno=0\n\n" {
        return Err(format!("set=1: {reply:?}").into());
    }
    let mtu = MTU.to_string();
    ip(&["-n", ns, "link", "set", name, "mtu", &mtu, "up"])?;
    ip(&["-n", ns, "addr", "add", "10.0.0.2/24", "dev", name])?;
    ip(&["-n", ns, "addr", "add", "fd00::2/64", "dev", name, "nodad"])?;
    Ok(cli)
}

/// The identifier and sequence number `seq` of the echo requests.
const fn echo_rest(seq: u16) -> [u8; 4] {
    let [high, low] = seq.to_be_bytes();
    [0x50, 0x4d, high, low]
}

/// An echo request of `len` bytes from node 1 to B with sequence number `seq`; IPv4 with DF
/// unless `fragmentable`.
fn echo(family: Family, len: usize, seq: u16, fragmentable: bool) -> Vec<u8> {
    let rest = echo_rest(seq);
    match family {
        Family::V4 => {
            let mut packet = icmp(
                IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
                IpAddr::V4(B_IP4),
                (8, 0),
                rest,
                &payload(len - 28),
            );
            if fragmentable {
                packet[6] &= !0x40;
                packet[10..12].fill(0);
                let sum = ipv4_header_checksum(&packet[..20]);
                packet[10..12].copy_from_slice(&sum.to_be_bytes());
            }
            packet
        }
        Family::V6 => icmp(
            IpAddr::V6(Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 1)),
            IpAddr::V6(B_IP6),
            (128, 0),
            rest,
            &payload(len - 48),
        ),
    }
}

/// The ICMP message of `packet` (type, code, rest of header) when it is one.
fn icmp_of(packet: &[u8]) -> Option<(u8, u8, [u8; 4], usize)> {
    let message = match packet.first()? >> 4 {
        4 => {
            let (header, message) = Ipv4Header::parse(packet).ok()?;
            (header.protocol() == protocol::ICMP).then_some(message)?
        }
        6 => {
            let (header, message) = Ipv6Header::parse(packet).ok()?;
            (header.next_header() == protocol::ICMPV6).then_some(message)?
        }
        _ => return None,
    };
    let rest = message.get(4..8)?.try_into().ok()?;
    Some((message[0], message[1], rest, packet.len()))
}

/// Waits for the ICMP message `(kind, code)` at node 1 and returns its rest of header and
/// the packet's length; other packets are skipped.
async fn expect_icmp(
    a: &mut Node<UdpTransport>,
    (kind, code): (u8, u8),
    rest: Option<[u8; 4]>,
) -> TestResult<([u8; 4], usize)> {
    let deadline = Instant::now() + WAIT;
    while Instant::now() < deadline {
        let Ok(Some((_, packet))) = timeout(WAIT, a.delivered.recv()).await else {
            break;
        };
        if let Some((k, c, r, len)) = icmp_of(packet.as_packet())
            && (k, c) == (kind, code)
            && rest.is_none_or(|rest| rest == r)
        {
            return Ok((r, len));
        }
    }
    Err(format!("no ICMP {kind}/{code} within {WAIT:?}").into())
}

/// Sends an echo request and expects B's reply, of the same length.
async fn ping(
    a: &mut Node<UdpTransport>,
    family: Family,
    len: usize,
    seq: u16,
    df: bool,
) -> TestResult {
    a.send(&echo(family, len, seq, !df)).await?;
    let reply = match family {
        Family::V4 => (0, 0),
        Family::V6 => (129, 0),
    };
    let rest = echo_rest(seq);
    let (_, got) = expect_icmp(a, reply, Some(rest)).await?;
    if got != len {
        return Err(format!("{family:?} reply of {got} bytes to {len}").into());
    }
    Ok(())
}

/// Node 1 on a dual-stack `UdpTransport` with path MTU discovery and a fragmenter, with B
/// at `b_outer` as its peer; returns the node and B's id.
async fn node_with_b(b_outer: IpAddr) -> TestResult<(Node<UdpTransport>, PeerId)> {
    let id = TransportId::new(1);
    let transport = UdpTransport::bind(id, "[::]:0".parse()?)?;
    transport.set_path_mtu_discovery(true)?;
    let local = transport.local_addr();
    let a = Node::with_builder(1, id, local, Options::default(), |builder| {
        builder
            .transport(transport)
            .fragmenter(FragmentConfig::default())
            .path_mtu_expiry(EXPIRY)
    })?;
    let b_public = PublicKey::from(&StaticSecret::from([B_SEED; 32]));
    a.handle
        .add_or_update_peer(Peer {
            allowed_ips: vec![
                AllowedIp {
                    addr: IpAddr::V4(B_IP4),
                    cidr: 32,
                },
                AllowedIp {
                    addr: IpAddr::V6(B_IP6),
                    cidr: 128,
                },
            ],
            path: Some(Path {
                transport: id,
                addr: SocketAddr::new(b_outer, PORT),
                ecn: Ecn::NotEct,
            }),
            ..Peer::new(b_public)
        })
        .await?;
    let b_id = a.handle.peer_id(b_public).await?.ok_or("no peer B")?;
    Ok((a, b_id))
}

/// One run over an outer path to B at `b_outer`; inner packets of both families.
async fn run(topology: &Topology, cli: &str, b_outer: IpAddr, inner: u16) -> TestResult {
    let outer_family = if b_outer.is_ipv4() {
        Family::V4
    } else {
        Family::V6
    };
    let (mut a, b_id) = node_with_b(b_outer).await?;
    let name = format!(
        "pmtu{}{}",
        std::process::id() % 100_000,
        u8::from(b_outer.is_ipv6())
    );
    let _cli = start_cli(cli, &topology.b, &name, &a.public()).await?;
    let mut mtus = a.handle.peer_mtus().await?;
    // Large packets: B (nsplane-cli, without path MTU state) pads its data to a multiple
    // of 16 bytes, so its reply to a 1420-byte packet would make a 1504-byte IPv6 packet.
    let full = FULL;

    // Full-size packets reach B before the limit.
    ping(&mut a, Family::V4, 100, 1, true).await?;
    for (seq, family) in [(2, Family::V4), (3, Family::V6)] {
        ping(&mut a, family, full, seq, true).await?;
    }
    assert!(mtus.borrow_and_update().peers.is_empty());

    // R's route shrinks: the next full-size datagram makes R report the limit.
    topology.limit(Some(LIMIT))?;
    let dropped = topology.too_big(outer_family)?;
    a.send(&echo(Family::V6, full, 4, false)).await?;
    let published = timeout(WAIT, mtus.wait_for(|m| m.peers.contains_key(&b_id)))
        .await??
        .clone();
    assert_eq!(published.peers.get(&b_id), Some(&inner), "{b_outer}");
    assert_eq!(a.handle.peer_mtu(b_id).await?, Some(inner));
    let stats = a.handle.path_mtu_stats().await?;
    assert!(stats.applied >= 1 && stats.paths == 1, "{stats:?}");
    let dropped = topology.too_big(outer_family)? - dropped;
    assert!(dropped >= 1, "R dropped nothing");
    let after = topology.too_big(outer_family)?;
    writeln!(
        io::stderr(),
        "{b_outer}: inner MTU {inner}, R dropped {dropped}, {stats:?}"
    )?;

    // Larger inner packets: Packet Too Big, Fragmentation Needed, or fragments that B
    // reassembles and answers.
    a.send(&echo(Family::V6, full, 5, false)).await?;
    let (rest, _) = expect_icmp(&mut a, (2, 0), None).await?;
    assert_eq!(rest, u32::from(inner).to_be_bytes());
    a.send(&echo(Family::V4, full, 6, false)).await?;
    let (rest, _) = expect_icmp(&mut a, (3, 4), None).await?;
    assert_eq!(rest[2..], inner.to_be_bytes());
    ping(&mut a, Family::V4, full, 7, false).await?;
    // Packets at the inner MTU fit the path, padding included.
    let at = usize::from(inner);
    ping(&mut a, Family::V4, at, 9, true).await?;
    ping(&mut a, Family::V6, at, 10, true).await?;
    ping(&mut a, Family::V6, at - 1, 11, true).await?;
    assert_eq!(
        topology.too_big(outer_family)?,
        after,
        "{b_outer}: an outer datagram above {LIMIT} after adapting"
    );
    let send_errors = a.drops(nsplane::DROP_TRANSPORT_SEND_ERROR).await?;
    writeln!(io::stderr(), "{b_outer}: send errors {send_errors}")?;

    // R's route recovers; once the learned MTU expires, full-size packets go through.
    topology.limit(None)?;
    sleep(EXPIRY).await;
    let published = timeout(WAIT, mtus.wait_for(|m| m.peers.is_empty()))
        .await??
        .clone();
    assert_eq!(published.min, MTU);
    for (seq, family) in [(12, Family::V4), (13, Family::V6)] {
        if let Err(e) = ping(&mut a, family, full, seq, true).await {
            writeln!(
                io::stderr(),
                "DEBUG {e} stats {:?} r {} drops {:?} mtus {:?}",
                a.handle.path_mtu_stats().await?,
                topology.too_big(outer_family)?,
                a.handle.drop_counters().await?,
                a.handle.peer_mtus().await?.borrow().clone()
            )?;
            ping(&mut a, family, 100, 99, true).await?;
            writeln!(io::stderr(), "DEBUG small ok")?;
            ping(&mut a, family, full, 98, true).await?;
            writeln!(io::stderr(), "DEBUG full ok")?;
        }
    }
    assert_eq!(a.handle.path_mtu_stats().await?.expired, 1);
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "needs CAP_NET_ADMIN"]
async fn path_mtu_follows_real_icmp_errors() -> TestResult {
    let cli = std::env::var("NSPLANE_E2E_PMTU_CLI")
        .map_err(|_| "NSPLANE_E2E_PMTU_CLI does not name a release nsplane-cli")?;
    let topology = Topology::new()?;
    // Outer path MTU 1400 less the IP and UDP headers and the data message's 32 bytes.
    run(
        &topology,
        &cli,
        IpAddr::V4(Ipv4Addr::new(10, 77, 2, 1)),
        1340,
    )
    .await?;
    run(
        &topology,
        &cli,
        IpAddr::V6(Ipv6Addr::new(0xfd77, 2, 0, 0, 0, 0, 0, 1)),
        1320,
    )
    .await
}
