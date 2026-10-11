//! Kernel WireGuard peers of two local identities: node 1 runs in the test process on one
//! `UdpTransport` with a second local identity; kernel WireGuard interfaces in network
//! namespaces A and B (linked to the test's namespace with veth pairs), each with its own
//! key, are peers of the default identity and of the second one. Each kernel interface
//! pings node 1 through its tunnel, so the kernel initiates the handshake and node 1 picks
//! the identity by mac1; node 1 answers the echo requests itself. Both pings succeed, both
//! kernel peers report a handshake, and node 1 attributes each tunnel to the right identity.
//!
//! Needs root in a throwaway network namespace (it adds veth links to the one it runs in),
//! `ip`, `ping` and `wg`, and the `wireguard` module on the host, for example:
//!
//! ```text
//! cargo test -p nsplane-e2e --test local_identities_root --no-run --locked
//! docker run --rm --label ai-agent=true --cap-add NET_ADMIN --cap-add SYS_ADMIN \
//!   --security-opt apparmor=unconfined --security-opt systempaths=unconfined \
//!   --device /dev/net/tun -v "$PWD:$PWD" -w "$PWD" \
//!   ai-agent/nstun-dev target/debug/deps/local_identities_root-<hash> --ignored --nocapture
//! ```

#![cfg(target_os = "linux")]

use std::io::Write as _;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::process::{Command, Stdio};
use std::time::Duration;

use nsplane::x25519::{PublicKey, StaticSecret};
use nsplane::{AllowedIp, Ecn, LocalIdentityId, Path, Peer, PeerId, TransportId, UdpTransport};
use nsplane_e2e::{Node, Options, TestResult, WAIT, icmp};
use tokio::time::{Instant, sleep};

/// The id of node 1's transport.
const UDP: TransportId = TransportId::new(1);
/// The kernel interfaces' WireGuard port.
const PORT: u16 = 51820;
/// Node 1's tunnel address (key seed 1).
const NODE_IP: Ipv4Addr = Ipv4Addr::new(10, 0, 0, 1);

/// Runs `ip` with `args`.
fn ip(args: &[&str]) -> TestResult {
    let status = Command::new("ip").args(args).status()?;
    if !status.success() {
        return Err(format!("ip {}: {status}", args.join(" ")).into());
    }
    Ok(())
}

/// Runs `command` in namespace `ns` with `input` on its standard input and returns its
/// output.
fn in_ns(ns: &str, command: &[&str], input: &str) -> TestResult<String> {
    let mut child = Command::new("ip")
        .args(["netns", "exec", ns])
        .args(command)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()?;
    child
        .stdin
        .take()
        .ok_or("no stdin")?
        .write_all(input.as_bytes())?;
    let output = child.wait_with_output()?;
    if !output.status.success() {
        return Err(format!("{ns}: {}: {:?}", command.join(" "), output).into());
    }
    Ok(String::from_utf8(output.stdout)?)
}

/// Standard base64 of a 32-byte key, as `wg` reads and prints keys.
fn base64(key: &[u8; 32]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(44);
    for chunk in key.chunks(3) {
        let byte = |i: usize| usize::from(chunk.get(i).copied().unwrap_or(0));
        let n = (byte(0) << 16) | (byte(1) << 8) | byte(2);
        for i in 0..4 {
            if i <= chunk.len() {
                out.push(char::from(ALPHABET[(n >> (18 - 6 * i)) & 63]));
            } else {
                out.push('=');
            }
        }
    }
    out
}

/// One kernel WireGuard side: a namespace with a veth link to the test's namespace and a
/// WireGuard interface `wg0`.
struct Kernel {
    ns: String,
    /// The tunnel address of `wg0`.
    tunnel: Ipv4Addr,
    /// The namespace's address on the veth link, where `wg0` listens.
    outer: Ipv4Addr,
    /// The private key of `wg0`.
    key: [u8; 32],
}

impl Kernel {
    /// Namespace `li-<name>-<pid>` on veth net `10.79.<net>.0/24` (the test's namespace on
    /// .1, the namespace on .2), with `wg0` on tunnel address `10.0.0.<net + 1>`, keyed with
    /// seed `seed` and peering `node` (node 1's key for this tunnel) at `endpoint`.
    fn new(
        name: &str,
        net: u8,
        seed: u8,
        node: &PublicKey,
        endpoint: SocketAddr,
    ) -> TestResult<Self> {
        let id = std::process::id() % 100_000;
        let kernel = Self {
            ns: format!("li-{name}-{id}"),
            tunnel: Ipv4Addr::new(10, 0, 0, net + 1),
            outer: Ipv4Addr::new(10, 79, net, 2),
            key: [seed; 32],
        };
        let ns = kernel.ns.as_str();
        let link = format!("li{name}{id}");
        let (here, there) = (format!("10.79.{net}.1/24"), format!("{}/24", kernel.outer));
        ip(&["netns", "add", ns])?;
        ip(&[
            "link", "add", &link, "type", "veth", "peer", "name", "veth0", "netns", ns,
        ])?;
        ip(&["addr", "add", &here, "dev", &link])?;
        ip(&["link", "set", &link, "up"])?;
        ip(&["-n", ns, "addr", "add", &there, "dev", "veth0"])?;
        ip(&["-n", ns, "link", "set", "veth0", "up"])?;
        ip(&["-n", ns, "link", "set", "lo", "up"])?;

        ip(&["-n", ns, "link", "add", "wg0", "type", "wireguard"])?;
        let (port, node, endpoint) = (
            PORT.to_string(),
            base64(node.as_bytes()),
            endpoint.to_string(),
        );
        in_ns(
            ns,
            &[
                "wg",
                "set",
                "wg0",
                "private-key",
                "/dev/stdin",
                "listen-port",
                &port,
                "peer",
                &node,
                "allowed-ips",
                "10.0.0.1/32",
                "endpoint",
                &endpoint,
            ],
            &base64(&kernel.key),
        )?;
        let tunnel = format!("{}/24", kernel.tunnel);
        ip(&["-n", ns, "addr", "add", &tunnel, "dev", "wg0"])?;
        ip(&["-n", ns, "link", "set", "wg0", "up"])?;
        Ok(kernel)
    }

    /// The public key of `wg0`.
    fn public(&self) -> PublicKey {
        PublicKey::from(&StaticSecret::from(self.key))
    }

    /// `wg0` as a peer of node 1: its tunnel address as /32, its listening address as the
    /// path.
    fn as_peer(&self) -> Peer {
        Peer {
            allowed_ips: vec![AllowedIp {
                addr: IpAddr::V4(self.tunnel),
                cidr: 32,
            }],
            path: Some(Path {
                transport: UDP,
                addr: SocketAddr::from((self.outer, PORT)),
                ecn: Ecn::NotEct,
            }),
            ..Peer::new(self.public())
        }
    }

    /// The time of `wg0`'s latest handshake with its peer, 0 if none.
    fn latest_handshake(&self) -> TestResult<u64> {
        let output = in_ns(&self.ns, &["wg", "show", "wg0", "latest-handshakes"], "")?;
        let line = output.lines().next().ok_or("no peer in wg show")?;
        let time = line.split_whitespace().nth(1).ok_or("no handshake time")?;
        Ok(time.parse()?)
    }
}

impl Drop for Kernel {
    fn drop(&mut self) {
        // Removing the namespace removes `wg0` and the veth pair.
        let _ = ip(&["netns", "del", &self.ns]);
    }
}

/// Pings node 1 once from `kernel` through its tunnel and answers the echo request in
/// node 1; checks that the request came from `peer` and that the ping succeeded.
async fn ping(node: &mut Node<UdpTransport>, kernel: &Kernel, peer: PeerId) -> TestResult {
    let mut child = Command::new("ip")
        .args(["netns", "exec", &kernel.ns, "ping", "-c1", "-W5"])
        .arg(NODE_IP.to_string())
        .stdout(Stdio::null())
        .spawn()?;
    let (from, request) = node.expect_delivery().await?;
    if from != peer {
        return Err(format!("echo request attributed to {from:?}, not {peer:?}").into());
    }
    // An IPv4 header without options, then an echo request.
    let source = Ipv4Addr::new(request[12], request[13], request[14], request[15]);
    if (request[0], request[9], request[20], source) != (0x45, 1, 8, kernel.tunnel) {
        return Err(format!("not an echo request from {}: {request:?}", kernel.tunnel).into());
    }
    let rest = [request[24], request[25], request[26], request[27]];
    let reply = icmp(
        IpAddr::V4(NODE_IP),
        IpAddr::V4(kernel.tunnel),
        (0, 0),
        rest,
        &request[28..],
    );
    node.send(&reply).await?;

    let deadline = Instant::now() + WAIT;
    loop {
        if let Some(status) = child.try_wait()? {
            if !status.success() {
                return Err(format!("ping from {}: {status}", kernel.ns).into());
            }
            return Ok(());
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            return Err(format!("ping from {} did not finish", kernel.ns).into());
        }
        sleep(Duration::from_millis(20)).await;
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "needs CAP_NET_ADMIN and the wireguard module"]
async fn kernel_peers_reach_their_own_local_identities() -> TestResult {
    let transport = UdpTransport::bind(UDP, SocketAddr::from((Ipv4Addr::UNSPECIFIED, 0)))?;
    let port = transport.local_addr().port();
    let mut node = Node::new(
        1,
        UDP,
        transport.local_addr(),
        transport,
        Options::default(),
    );
    let second = StaticSecret::from([11; 32]);
    let second_public = PublicKey::from(&second);
    let i1 = node
        .handle
        .add_local_identity(second)
        .await?
        .ok_or("second identity refused")?;

    // A peers the default identity, B the second one.
    let a = Kernel::new(
        "a",
        1,
        21,
        &node.public(),
        SocketAddr::from(([10, 79, 1, 1], port)),
    )?;
    let b = Kernel::new(
        "b",
        2,
        22,
        &second_public,
        SocketAddr::from(([10, 79, 2, 1], port)),
    )?;
    node.handle.add_or_update_peer(a.as_peer()).await?;
    node.handle
        .add_or_update_peer(Peer {
            local_identity: Some(i1),
            ..b.as_peer()
        })
        .await?;
    let to_a = node
        .handle
        .peer_id_in(LocalIdentityId::DEFAULT, a.public())
        .await?
        .ok_or("no peer for A")?;
    let to_b = node
        .handle
        .peer_id_in(i1, b.public())
        .await?
        .ok_or("no peer for B")?;

    ping(&mut node, &a, to_a).await?;
    ping(&mut node, &b, to_b).await?;

    for (kernel, peer, identity) in [(&a, to_a, LocalIdentityId::DEFAULT), (&b, to_b, i1)] {
        assert_ne!(
            kernel.latest_handshake()?,
            0,
            "{} saw no handshake",
            kernel.ns
        );
        let stats = node.handle.peer_stats(peer).await?.ok_or("unknown peer")?;
        assert_eq!(stats.local_identity, identity);
        assert_eq!(stats.public_key, kernel.public());
        assert!(stats.last_handshake.is_some());
        assert!(stats.data_rx >= 1 && stats.data_tx >= 1);
    }
    let status = node.handle.status().await?;
    let peers: Vec<_> = status
        .local_identities
        .iter()
        .map(|i| (i.id, i.peers))
        .collect();
    assert_eq!(peers, [(LocalIdentityId::DEFAULT, 1), (i1, 1)]);
    writeln!(
        std::io::stderr(),
        "kernel peers handshaked with identities {:?} and {i1:?}",
        LocalIdentityId::DEFAULT
    )?;
    Ok(())
}
