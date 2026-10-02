//! The command line and engine assembly every node example shares.
//!
//! [`NodeArgs`] is flattened into each node example's arguments. [`build_engine`] turns it
//! into a running [`Engine`] on any packet source and sink (private key, transports, path
//! policy), [`configure_peers`] adds the `--peer`s, and [`run`] waits for Ctrl-C, the end
//! of the checks or the engine, and shuts the engine down.

use std::fmt;
use std::fs;
use std::net::{IpAddr, SocketAddr, ToSocketAddrs as _};
use std::path::{Path as FsPath, PathBuf};
use std::process::{Command, ExitCode};
use std::str::FromStr;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use anyhow::{Context as _, anyhow, bail};
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use clap::{Args, ValueEnum};
use nsplane::x25519::{PublicKey, StaticSecret};
use nsplane::{
    AllowedIp, Ecn, Engine, EngineBuilder, EngineHandle, PacketSink, PacketSource, Path, Peer,
    StandardRoaming, TransportId, UdpTransport,
};
use tracing_subscriber::filter::Targets;
use tracing_subscriber::layer::SubscriberExt as _;
use tracing_subscriber::util::SubscriberInitExt as _;

use crate::echo::{Backend, EchoArgs};
use crate::relay::client::{ClientConfig, ProbeTimers, RelayClient};
use crate::relay::envelope::MachineKey;
use crate::relay::ladder::{LadderTimers, Pin};
use crate::relay::server::lock;
use crate::relay::wss::client::{WssConfig, WssStats, WssTransport, rediscover_on_connect};
use crate::relay::wss::{WssUrl, client_tls_file};
use crate::status::Status;

/// The id of the UDP transport `--transport udp` installs.
///
/// It is the UAPI's transport id, so `wg set <iface> listen-port N` on a node that serves
/// the UAPI rebinds this transport.
pub const UDP_TRANSPORT: TransportId = TransportId::new(0);

/// Options shared by every node example.
#[derive(Debug, Clone, Args)]
pub struct NodeArgs {
    /// Own private key, base64 (`wg genkey` output)
    #[arg(
        long,
        value_name = "BASE64",
        conflicts_with = "private_key_file",
        required_unless_present = "private_key_file"
    )]
    pub private_key: Option<String>,

    /// File holding the own private key, base64 (`wg genkey > key`)
    #[arg(long, value_name = "PATH")]
    pub private_key_file: Option<PathBuf>,

    /// Local UDP address of the transport
    #[arg(long, value_name = "SOCKETADDR", default_value = "0.0.0.0:51820")]
    pub listen: SocketAddr,

    /// A peer, repeatable: `<base64 pubkey>[,endpoint=<host:port>][,allowed-ips=<cidr>[+<cidr>...]][,keepalive=<secs>][,psk-file=<path>]`
    #[arg(long, value_name = "SPEC")]
    pub peer: Vec<PeerSpec>,

    /// Write a JSON status snapshot to this file every second
    #[arg(long, value_name = "PATH")]
    pub status_file: Option<PathBuf>,

    /// Log filter for stderr (`info`, `debug`, `nsplane=trace,info`, ...)
    #[arg(long, value_name = "FILTER", default_value = "info")]
    pub log: String,

    /// Turn segmentation offload off: a plain TUN device (one packet per read and write)
    /// and UDP without GSO/GRO
    #[arg(long)]
    pub no_offload: bool,

    /// Transport selection
    #[command(flatten)]
    pub transport: TransportArgs,
}

impl NodeArgs {
    /// The own private key from `--private-key` or `--private-key-file`.
    pub fn private_key(&self) -> anyhow::Result<StaticSecret> {
        let encoded = match (&self.private_key, &self.private_key_file) {
            (Some(key), _) => key.clone(),
            (None, Some(path)) => fs::read_to_string(path)
                .with_context(|| format!("cannot read {}", path.display()))?,
            (None, None) => bail!("--private-key or --private-key-file is required"),
        };
        Ok(StaticSecret::from(decode_key(&encoded)?))
    }
}

/// The transport kinds a node can run.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum TransportKind {
    /// Plain UDP on `--listen`.
    Udp,
    /// UDP on `--listen` with the single-port relay extensions: capability discovery of
    /// the `--relay` endpoints, registration, reflexive address, and the direct/relay
    /// path ladder.
    Relay,
    /// `relay` with the relay reached over WebSocket over TLS (`--relay-url`); UDP on
    /// `--listen` carries the direct paths and the other `--relay` endpoints.
    Wss,
}

/// Transport options, flattened into [`NodeArgs`].
#[derive(Debug, Clone, Args)]
pub struct TransportArgs {
    /// Transport to run
    #[arg(long, value_enum, default_value_t = TransportKind::Udp)]
    pub transport: TransportKind,

    /// Relay endpoint to discover (`--transport relay`), repeatable
    #[arg(long = "relay", value_name = "IP:PORT")]
    pub relays: Vec<SocketAddr>,

    /// Ed25519 machine key file (`--transport relay|wss`; `relay_server gen-machine-key`)
    #[arg(
        long,
        value_name = "PATH",
        required_if_eq_any([("transport", "relay"), ("transport", "wss")])
    )]
    pub machine_key_file: Option<PathBuf>,

    /// The relay's WebSocket URL (`--transport wss`): `wss://<host>[:<port>]/`; the host is
    /// the TLS server name
    #[arg(long, value_name = "URL", required_if_eq("transport", "wss"))]
    pub relay_url: Option<String>,

    /// PEM certificate of the relay, the only one trusted (`--transport wss`;
    /// `relay_server --wss-cert-out`)
    #[arg(long, value_name = "PEM", required_if_eq("transport", "wss"))]
    pub relay_ca: Option<PathBuf>,

    /// Address to connect to instead of resolving the `--relay-url` host (`--transport wss`)
    #[arg(long, value_name = "IP:PORT")]
    pub relay_addr: Option<SocketAddr>,

    /// JSON `{"<wg pubkey b64>": ["ip:port", ...]}` of direct candidates, polled every second
    #[arg(long, value_name = "FILE")]
    pub peer_candidates: Option<PathBuf>,

    /// Write this node's reflexive address as JSON to this file
    #[arg(long, value_name = "FILE")]
    pub reflexive_out: Option<PathBuf>,

    /// Path of peers reached through a relay: direct first with relay fallback, or pinned
    #[arg(long, value_enum, default_value_t = Pin::Auto)]
    pub pin: Pin,

    /// Wait after the first unanswered relay probe, doubled per attempt
    #[arg(long, value_name = "MS", default_value_t = 1000)]
    pub probe_backoff_ms: u64,

    /// Relay probes before an endpoint that never answered is stopped
    #[arg(long, value_name = "N", default_value_t = 5)]
    pub probe_attempts: u32,

    /// Source registration interval with a capable relay
    #[arg(long, value_name = "MS", default_value_t = 30_000)]
    pub register_interval_ms: u64,

    /// Reflexive request interval with a capable relay
    #[arg(long, value_name = "MS", default_value_t = 20_000)]
    pub reflexive_interval_ms: u64,

    /// Time a direct path has to authenticate before the relay is used
    #[arg(long, value_name = "MS", default_value_t = 5000)]
    pub direct_timeout_ms: u64,

    /// Interval of direct probes while on the relay
    #[arg(long, value_name = "MS", default_value_t = 30_000)]
    pub direct_probe_interval_ms: u64,
}

/// Relay clients built by [`TransportArgs::transports`], until [`build_engine`] starts
/// them and [`run`] reports them in the status file.
static RELAY_CLIENTS: Mutex<Vec<(SocketAddr, RelayClient)>> = Mutex::new(Vec::new());

/// The WSS carriers built by [`TransportArgs::transports`], by the local address of the
/// node's UDP socket, for the status file.
static WSS_CARRIERS: Mutex<Vec<(SocketAddr, Arc<WssStats>)>> = Mutex::new(Vec::new());

/// The relay client of the transport bound to `listen`.
fn relay_client_at(listen: SocketAddr) -> Option<RelayClient> {
    lock(&RELAY_CLIENTS)
        .iter()
        .find(|(addr, _)| *addr == listen)
        .map(|(_, client)| client.clone())
}

/// The relay client of the engine with WireGuard public key `key`, and the local address
/// of its transport.
fn relay_client_of(key: &PublicKey) -> Option<(SocketAddr, RelayClient)> {
    lock(&RELAY_CLIENTS)
        .iter()
        .find(|(_, client)| client.public_key() == Some(key.to_bytes()))
        .cloned()
}

/// The WSS carrier of the transport bound to `listen`.
fn wss_carrier_at(listen: SocketAddr) -> Option<Arc<WssStats>> {
    lock(&WSS_CARRIERS)
        .iter()
        .find(|(addr, _)| *addr == listen)
        .map(|(_, stats)| Arc::clone(stats))
}

/// What [`TransportArgs::transports`] installed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Transports {
    /// The transport peer endpoints use by default.
    pub default: TransportId,
    /// The local address the node listens on.
    pub listen: SocketAddr,
}

impl TransportArgs {
    /// Installs the chosen transport(s) and the path policy on `builder`.
    ///
    /// UDP: one [`UdpTransport`] with id [`UDP_TRANSPORT`] bound to `listen`, and
    /// [`StandardRoaming`]. Relay: the same socket wrapped in the extension-aware
    /// [`ExtTransport`](crate::relay::client::ExtTransport), and the
    /// [`LadderPolicy`](crate::relay::ladder::LadderPolicy); [`build_engine`] starts its
    /// driver. WSS: like relay, over a [`WssTransport`] to `--relay-url` that keeps the
    /// UDP socket for every other address, with the relay's address added to the
    /// endpoints; discovery restarts on every (re)connect.
    ///
    /// The UDP socket has segmentation offload (GSO/GRO) on if `offload`, else off.
    pub fn transports<Src: PacketSource, Snk: PacketSink>(
        &self,
        builder: EngineBuilder<Src, Snk>,
        listen: SocketAddr,
        offload: bool,
    ) -> anyhow::Result<(EngineBuilder<Src, Snk>, Transports)> {
        match self.transport {
            TransportKind::Udp => {
                let udp = bind_udp(listen, offload)?;
                let transports = Transports {
                    default: UDP_TRANSPORT,
                    listen: udp.local_addr(),
                };
                let builder = builder.transport(udp).policy(Box::new(StandardRoaming));
                Ok((builder, transports))
            }
            TransportKind::Relay => {
                let udp = bind_udp(listen, offload)?;
                let transports = Transports {
                    default: UDP_TRANSPORT,
                    listen: udp.local_addr(),
                };
                let (client, ext, policy) = RelayClient::new(udp, self.client_config()?);
                lock(&RELAY_CLIENTS).push((transports.listen, client));
                let builder = builder.transport(ext).policy(Box::new(policy));
                Ok((builder, transports))
            }
            TransportKind::Wss => {
                let udp = bind_udp(listen, offload)?;
                let transports = Transports {
                    default: UDP_TRANSPORT,
                    listen: udp.local_addr(),
                };
                let wss = WssTransport::connect(UDP_TRANSPORT, self.wss_config()?, Some(udp));
                let (relay, stats) = (wss.relay(), wss.stats());
                let mut config = self.client_config()?;
                if !config.relays.contains(&relay) {
                    config.relays.push(relay);
                }
                let (client, ext, policy) = RelayClient::new(wss, config);
                rediscover_on_connect(client.clone(), &stats, relay);
                lock(&RELAY_CLIENTS).push((transports.listen, client));
                lock(&WSS_CARRIERS).push((transports.listen, stats));
                let builder = builder.transport(ext).policy(Box::new(policy));
                Ok((builder, transports))
            }
        }
    }

    /// The carrier options of `--transport wss`.
    pub fn wss_config(&self) -> anyhow::Result<WssConfig> {
        let (Some(url), Some(ca)) = (&self.relay_url, &self.relay_ca) else {
            bail!("--relay-url and --relay-ca are required with --transport wss");
        };
        let url = WssUrl::parse(url)?;
        let relay = match self.relay_addr {
            Some(addr) => addr,
            None => url.resolve()?,
        };
        Ok(WssConfig::new(
            url.url.clone(),
            url.server_name()?,
            relay,
            client_tls_file(ca)?,
        ))
    }

    /// The relay client options of `--transport relay`.
    pub fn client_config(&self) -> anyhow::Result<ClientConfig> {
        let path = self
            .machine_key_file
            .as_ref()
            .ok_or_else(|| anyhow!("--machine-key-file is required with --transport relay|wss"))?;
        let machine_key = MachineKey::load(path)
            .with_context(|| format!("cannot read the machine key {}", path.display()))?;
        Ok(ClientConfig {
            relays: self.relays.clone(),
            machine_key,
            pin: self.pin,
            probe: ProbeTimers {
                backoff: Duration::from_millis(self.probe_backoff_ms),
                attempts: self.probe_attempts,
                register_interval: Duration::from_millis(self.register_interval_ms),
                reflexive_interval: Duration::from_millis(self.reflexive_interval_ms),
                ..ProbeTimers::default()
            },
            ladder: LadderTimers {
                direct_timeout: Duration::from_millis(self.direct_timeout_ms),
                probe_interval: Duration::from_millis(self.direct_probe_interval_ms),
            },
            peer_candidates: self.peer_candidates.clone(),
            reflexive_out: self.reflexive_out.clone(),
        })
    }
}

/// Binds the [`UDP_TRANSPORT`] to `listen`, with segmentation offload on if `offload`.
fn bind_udp(listen: SocketAddr, offload: bool) -> anyhow::Result<UdpTransport> {
    let udp = UdpTransport::bind(UDP_TRANSPORT, listen)
        .with_context(|| format!("cannot bind UDP {listen}"))?;
    udp.set_offload(offload)
        .context("cannot set the UDP segmentation offload")?;
    let mode = if udp.offload() { "gso,gro" } else { "off" };
    tracing::info!(listen = %udp.local_addr(), udp_offload = %mode, "UDP transport bound");
    Ok(udp)
}

/// A built engine and what its transports listen on.
#[derive(Debug)]
pub struct Node {
    /// The running engine.
    pub engine: Engine,
    /// What the transports installed.
    pub transports: Transports,
}

/// Builds the engine of a node example: the private key, the transports and path policy of
/// `args`, on `source` and `sink`. Peers are added afterwards with [`configure_peers`].
///
/// With `--transport relay|wss` it also starts the relay client's driver for the `--peer`s.
pub fn build_engine<Src: PacketSource, Snk: PacketSink>(
    source: Src,
    sink: Snk,
    args: &NodeArgs,
) -> anyhow::Result<Node> {
    build_engine_with(source, sink, args, |builder| builder)
}

/// Like [`build_engine`], with `configure` applied to the builder first (packet filters,
/// stats interval, queue sizes, ...).
pub fn build_engine_with<Src: PacketSource, Snk: PacketSink>(
    source: Src,
    sink: Snk,
    args: &NodeArgs,
    configure: impl FnOnce(EngineBuilder<Src, Snk>) -> EngineBuilder<Src, Snk>,
) -> anyhow::Result<Node> {
    let private_key = args.private_key()?;
    let public_key = PublicKey::from(&private_key);
    let builder = configure(EngineBuilder::new(source, sink)).private_key(private_key);
    let (builder, transports) =
        args.transport
            .transports(builder, args.listen, !args.no_offload)?;
    let engine = builder.build().context("cannot build the engine")?;
    if matches!(
        args.transport.transport,
        TransportKind::Relay | TransportKind::Wss
    ) && let Some(client) = relay_client_at(transports.listen)
    {
        let peers = args
            .peer
            .iter()
            .map(|peer| (peer.public_key.to_bytes(), peer.endpoint))
            .collect();
        client.start(engine.handle(), public_key.to_bytes(), peers);
    }
    Ok(Node { engine, transports })
}

/// One `--peer`: `<base64 pubkey>[,endpoint=<host:port>][,allowed-ips=<cidr>[+<cidr>...]][,keepalive=<secs>][,psk-file=<path>]`.
///
/// The endpoint is resolved and the preshared key file read when the spec is parsed.
#[derive(Clone)]
pub struct PeerSpec {
    /// The peer's public key.
    pub public_key: PublicKey,
    /// Where to reach the peer; `None` waits for the peer to connect.
    pub endpoint: Option<SocketAddr>,
    /// The transport the endpoint is reached on; [`UDP_TRANSPORT`] by default.
    pub transport: TransportId,
    /// Networks routed to the peer.
    pub allowed_ips: Vec<AllowedIp>,
    /// Persistent keepalive interval in seconds.
    pub keepalive: Option<u16>,
    /// The preshared key.
    pub preshared_key: Option<[u8; 32]>,
}

impl fmt::Debug for PeerSpec {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PeerSpec")
            .field("public_key", &encode_public_key(&self.public_key))
            .field("endpoint", &self.endpoint)
            .field("transport", &self.transport)
            .field("allowed_ips", &self.allowed_ips)
            .field("keepalive", &self.keepalive)
            .field("preshared_key", &self.preshared_key.map(|_| "<redacted>"))
            .finish()
    }
}

impl PeerSpec {
    /// A peer with `public_key` and no settings.
    pub const fn new(public_key: PublicKey) -> Self {
        Self {
            public_key,
            endpoint: None,
            transport: UDP_TRANSPORT,
            allowed_ips: Vec::new(),
            keepalive: None,
            preshared_key: None,
        }
    }

    /// The engine's description of this peer.
    pub fn to_peer(&self) -> Peer {
        let mut peer = Peer::new(self.public_key);
        peer.allowed_ips.clone_from(&self.allowed_ips);
        peer.replace_allowed_ips = true;
        peer.preshared_key = self.preshared_key;
        peer.persistent_keepalive = self.keepalive;
        peer.path = self.endpoint.map(|addr| Path {
            transport: self.transport,
            addr,
            ecn: Ecn::NotEct,
        });
        peer
    }
}

impl FromStr for PeerSpec {
    type Err = anyhow::Error;

    fn from_str(spec: &str) -> anyhow::Result<Self> {
        let mut parts = spec.split(',');
        let key = parts.next().unwrap_or_default();
        let mut peer = Self::new(PublicKey::from(decode_key(key)?));
        for part in parts {
            let (name, value) = part
                .split_once('=')
                .ok_or_else(|| anyhow!("`{part}` is not `name=value`"))?;
            match name {
                "endpoint" => peer.endpoint = Some(resolve(value)?),
                "allowed-ips" => {
                    for cidr in value.split('+') {
                        peer.allowed_ips.push(parse_cidr(cidr)?);
                    }
                }
                "keepalive" => {
                    peer.keepalive = Some(
                        value
                            .parse()
                            .with_context(|| format!("invalid keepalive `{value}`"))?,
                    );
                }
                "psk-file" => peer.preshared_key = Some(read_key_file(FsPath::new(value))?),
                _ => bail!("unknown peer option `{name}`"),
            }
        }
        Ok(peer)
    }
}

/// Adds or updates every peer in `peers` on the engine behind `handle`.
pub async fn configure_peers(handle: &EngineHandle, peers: &[PeerSpec]) -> anyhow::Result<()> {
    for peer in peers {
        handle
            .add_or_update_peer(peer.to_peer())
            .await
            .context("cannot add a peer")?;
        tracing::info!(peer = ?peer, "peer configured");
    }
    Ok(())
}

/// Installs a stderr logger with `filter` (`tracing_subscriber` targets syntax, e.g.
/// `info` or `nsplane=debug,info`).
pub fn init_logging(filter: &str) -> anyhow::Result<()> {
    let targets: Targets = filter
        .parse()
        .with_context(|| format!("invalid log filter `{filter}`"))?;
    tracing_subscriber::registry()
        .with(tracing_subscriber::fmt::layer().with_writer(std::io::stderr))
        .with(targets)
        .try_init()
        .context("cannot install the logger")
}

/// Generates a fresh private key.
pub fn generate_key() -> StaticSecret {
    StaticSecret::random_from_rng(rand_core::OsRng)
}

/// A 32-byte key in base64, as `wg` prints it.
pub fn encode_key(key: &[u8; 32]) -> String {
    STANDARD.encode(key)
}

/// A public key in base64, as `wg` prints it.
pub fn encode_public_key(key: &PublicKey) -> String {
    encode_key(key.as_bytes())
}

/// Decodes a base64 32-byte key; surrounding whitespace is ignored.
pub fn decode_key(encoded: &str) -> anyhow::Result<[u8; 32]> {
    let bytes = STANDARD
        .decode(encoded.trim())
        .context("a key is not valid base64")?;
    <[u8; 32]>::try_from(bytes).map_err(|_| anyhow!("a key is not 32 bytes long"))
}

/// Reads a base64 32-byte key from `path`.
pub fn read_key_file(path: &FsPath) -> anyhow::Result<[u8; 32]> {
    let encoded =
        fs::read_to_string(path).with_context(|| format!("cannot read {}", path.display()))?;
    decode_key(&encoded).with_context(|| format!("invalid key in {}", path.display()))
}

/// Parses `addr/len` into an [`AllowedIp`].
pub fn parse_cidr(cidr: &str) -> anyhow::Result<AllowedIp> {
    cidr.parse()
        .map_err(|e| anyhow!("invalid CIDR `{cidr}`: {e}"))
}

/// Resolves `host:port` to its first address.
fn resolve(endpoint: &str) -> anyhow::Result<SocketAddr> {
    endpoint
        .to_socket_addrs()
        .with_context(|| format!("cannot resolve `{endpoint}`"))?
        .next()
        .ok_or_else(|| anyhow!("`{endpoint}` resolves to no address"))
}

/// Serves echo, runs the checks and waits; then shuts the engine down.
///
/// Waits for Ctrl-C, for the engine to stop, or, with `--exit-after-checks`, for the
/// checks to finish. Writes a last status snapshot before returning when `status` is set.
/// The exit code is a failure iff a check failed.
///
/// With `--transport relay|wss` the status gets `extra.relay` (endpoints, reflexive
/// address) and `extra.paths` (the ladder) of the relay client; with `--transport wss`
/// also `extra.wss` (the carrier, see [`WssStats::status_json`]).
pub async fn run(
    engine: Engine,
    echo: &EchoArgs,
    backend: Backend,
    status: Option<Status>,
) -> anyhow::Result<ExitCode> {
    let handle = engine.handle();
    let client = handle
        .public_key()
        .await?
        .and_then(|key| relay_client_of(&key));
    let status = match (status, client) {
        (Some(status), Some((listen, client))) => {
            let wss = wss_carrier_at(listen);
            Some(status.extra(move |extra| {
                extra.insert("relay".to_owned(), client.relay_json());
                extra.insert("paths".to_owned(), client.paths_json());
                if let Some(wss) = &wss {
                    extra.insert("wss".to_owned(), wss.status_json());
                }
            }))
        }
        (status, _) => status,
    };
    let writer = status.as_ref().map(Status::spawn);
    echo.serve(&backend).await?;
    let checks = echo.clone();
    let mut checks = tokio::spawn(async move { checks.run_checks(&backend).await });
    let mut checks_done = false;
    let mut passed = true;
    let wait = engine.wait();
    tokio::pin!(wait);
    loop {
        tokio::select! {
            signal = tokio::signal::ctrl_c() => {
                signal.context("cannot watch Ctrl-C")?;
                tracing::info!("Ctrl-C received, shutting down");
                break;
            }
            result = &mut checks, if !checks_done => {
                checks_done = true;
                passed = result.context("the checks failed")?.unwrap_or(true);
                if echo.exit_after_checks {
                    break;
                }
            }
            stopped = &mut wait => {
                stopped.context("the engine failed")?;
                bail!("the engine stopped");
            }
        }
    }
    // Stop the periodic writer first, so the final snapshot is the last one written.
    if let Some(writer) = writer {
        writer.abort();
        let _ = writer.await;
    }
    if let Some(status) = &status {
        status.write().await?;
    }
    checks.abort();
    let _ = handle.shutdown().await;
    wait.await.context("the engine failed")?;
    Ok(if passed {
        ExitCode::SUCCESS
    } else {
        ExitCode::FAILURE
    })
}

/// The default TUN interface name: Linux names it freely, macOS needs `utun[N]`.
pub const DEFAULT_TUN_NAME: &str = if cfg!(target_os = "macos") {
    "utun"
} else {
    "nsp0"
};

/// The TUN options of a TUN node, flattened into its arguments.
#[derive(Debug, Clone, Args)]
pub struct TunArgs {
    /// Name of the TUN interface (macOS: `utun` or `utunN`)
    #[arg(long, value_name = "NAME", default_value = DEFAULT_TUN_NAME)]
    pub tun_name: String,

    /// Address of the interface with its prefix, repeatable
    #[arg(long, value_name = "CIDR", value_parser = parse_cidr)]
    pub address: Vec<AllowedIp>,

    /// MTU of the interface
    #[arg(long, value_name = "N", default_value_t = 1420)]
    pub mtu: u16,
}

/// `addr/cidr`.
pub fn cidr(ip: &AllowedIp) -> String {
    format!("{}/{}", ip.addr, ip.cidr)
}

/// The first `bits` bits of `addr`, as a number of its family's width.
fn masked(addr: IpAddr, bits: u8) -> u128 {
    let (value, width) = match addr {
        IpAddr::V4(v4) => (u128::from(v4.to_bits()), 32),
        IpAddr::V6(v6) => (v6.to_bits(), 128),
    };
    let bits = u32::from(bits.min(width));
    if bits == 0 {
        0
    } else {
        value >> (u32::from(width) - bits)
    }
}

/// Whether the network `net` contains all of `ip`.
pub fn covers(net: &AllowedIp, ip: &AllowedIp) -> bool {
    net.addr.is_ipv4() == ip.addr.is_ipv4()
        && net.cidr <= ip.cidr
        && masked(net.addr, net.cidr) == masked(ip.addr, net.cidr)
}

/// Whether the network `net` contains the address `addr`.
pub fn contains(net: &AllowedIp, addr: IpAddr) -> bool {
    let cidr = if addr.is_ipv4() { 32 } else { 128 };
    covers(net, &AllowedIp { addr, cidr })
}

/// The peers' allowed IPs that no interface address's connected prefix covers: the routes
/// a TUN interface with `addresses` needs.
pub fn tun_routes(addresses: &[AllowedIp], peers: &[PeerSpec]) -> Vec<AllowedIp> {
    let mut routes: Vec<AllowedIp> = Vec::new();
    for ip in peers.iter().flat_map(|peer| &peer.allowed_ips) {
        if !addresses.iter().any(|net| covers(net, ip)) && !routes.contains(ip) {
            routes.push(*ip);
        }
    }
    routes
}

/// Configures the TUN interface `name` like `tun_node`: its `addresses`, `mtu`, link state
/// and the routes to `peers` (see [`tun_routes`]).
///
/// Linux runs `ip`; a "File exists" error (already configured) is fine. Other systems
/// print the `ifconfig` / `route` commands to run instead.
pub fn configure_tun(
    name: &str,
    addresses: &[AllowedIp],
    mtu: u16,
    peers: &[PeerSpec],
) -> anyhow::Result<()> {
    let routes = tun_routes(addresses, peers);
    if cfg!(target_os = "linux") {
        for address in addresses {
            ip(&["address", "add", &cidr(address), "dev", name])?;
        }
        ip(&["link", "set", "dev", name, "mtu", &mtu.to_string(), "up"])?;
        for route in &routes {
            ip(&["route", "add", &cidr(route), "dev", name])?;
        }
        return Ok(());
    }
    let mut commands = Vec::new();
    for address in addresses {
        if address.addr.is_ipv4() {
            commands.push(format!(
                "ifconfig {name} inet {} {} alias",
                cidr(address),
                address.addr
            ));
        } else {
            commands.push(format!("ifconfig {name} inet6 {} alias", cidr(address)));
        }
    }
    commands.push(format!("ifconfig {name} mtu {mtu} up"));
    for net in addresses.iter().chain(&routes) {
        let family = if net.addr.is_ipv4() {
            "-inet"
        } else {
            "-inet6"
        };
        commands.push(format!(
            "route -q -n add {family} {} -interface {name}",
            cidr(net)
        ));
    }
    crate::out::line(format_args!("Configure the interface with:"));
    for command in commands {
        crate::out::line(format_args!("  sudo {command}"));
    }
    Ok(())
}

/// Runs `ip <args>`; a "File exists" error (already configured) is fine.
fn ip(args: &[&str]) -> anyhow::Result<()> {
    let output = Command::new("ip")
        .args(args)
        .output()
        .context("cannot run `ip`")?;
    let stderr = String::from_utf8_lossy(&output.stderr);
    if output.status.success() || stderr.contains("File exists") {
        tracing::info!(command = format!("ip {}", args.join(" ")), "configured");
        Ok(())
    } else {
        bail!("`ip {}` failed: {}", args.join(" "), stderr.trim())
    }
}

/// Creates the TUN device `name`, with segmentation offloads unless `--no-offload`, and
/// logs the offloads it uses ([`offload_mode`]).
#[cfg(unix)]
pub fn create_tun(name: &str, args: &NodeArgs) -> anyhow::Result<nsplane_tun::Tun> {
    let options = nsplane_tun::TunOptions::new().offload(!args.no_offload);
    let tun = nsplane_tun::Tun::create_with(name, options)
        .with_context(|| format!("cannot create TUN {name}"))?;
    tracing::info!(offload = %offload_mode(tun.offload()), "TUN device opened");
    Ok(tun)
}

/// The segmentation offloads of a TUN device for logs: `tso,uso`, `tso`, `vnet_hdr` (the
/// header without offloads, an adopted fd) or `off`.
#[cfg(unix)]
pub fn offload_mode(offload: nsplane_tun::Offload) -> String {
    let mut modes: Vec<&str> = [("tso", offload.tso), ("uso", offload.uso)]
        .into_iter()
        .filter_map(|(mode, on)| on.then_some(mode))
        .collect();
    if modes.is_empty() {
        modes.push(if offload.vnet_hdr { "vnet_hdr" } else { "off" });
    }
    modes.join(",")
}

/// Serves the UAPI of `handle`'s engine on the standard socket of interface `name`.
///
/// `wg show <name>` and `wg set <name> ...` then work; `listen_port` is the port of the
/// [`UDP_TRANSPORT`]. Returns the socket path.
#[cfg(unix)]
pub fn serve_uapi(handle: EngineHandle, name: &str, listen_port: u16) -> anyhow::Result<String> {
    use nsplane_uapi::{TRANSPORT_ID, Uapi, UapiListener};

    // `wg set listen-port` rebinds the UAPI's transport, so the node's UDP transport is it.
    const _: () = assert!(UDP_TRANSPORT.get() == TRANSPORT_ID.get());

    let uapi = Uapi::with_listen_port(handle, listen_port);
    let listener = UapiListener::bind(name).context("cannot bind the UAPI socket")?;
    let socket = listener.path().display().to_string();
    tokio::spawn(async move {
        if let Err(e) = uapi.serve(listener).await {
            tracing::warn!(error = %e, "UAPI server failed");
        }
    });
    Ok(socket)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn prefix_cover() {
        let net = parse_cidr("10.0.0.1/24").unwrap();
        assert!(covers(&net, &parse_cidr("10.0.0.2/32").unwrap()));
        assert!(!covers(&net, &parse_cidr("10.0.1.2/32").unwrap()));
        assert!(!covers(&net, &parse_cidr("10.0.0.0/16").unwrap()));
        assert!(!covers(&net, &parse_cidr("fd00::1/128").unwrap()));
        assert!(contains(&net, "10.0.0.200".parse().unwrap()));
        assert!(!contains(&net, "fd00::1".parse().unwrap()));
        let v6 = parse_cidr("fd00::1/64").unwrap();
        assert!(contains(&v6, "fd00::2".parse().unwrap()));
        assert!(covers(&parse_cidr("0.0.0.0/0").unwrap(), &net));
    }
}
