//! The command line and engine assembly every node example shares.
//!
//! [`NodeArgs`] is flattened into each node example's arguments. [`build_engine`] turns it
//! into a running [`Engine`] on any packet source and sink (private key, transports, path
//! policy), [`configure_peers`] adds the `--peer`s, and [`run`] waits for Ctrl-C, the end
//! of the checks or the engine, and shuts the engine down.

use std::fmt;
use std::fs;
use std::net::{SocketAddr, ToSocketAddrs as _};
use std::path::{Path as FsPath, PathBuf};
use std::process::ExitCode;
use std::str::FromStr;
use std::sync::Mutex;
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

    /// Ed25519 machine key file (`--transport relay`; `relay_server gen-machine-key`)
    #[arg(long, value_name = "PATH", required_if_eq("transport", "relay"))]
    pub machine_key_file: Option<PathBuf>,

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

/// The relay client of the transport bound to `listen`.
fn relay_client_at(listen: SocketAddr) -> Option<RelayClient> {
    lock(&RELAY_CLIENTS)
        .iter()
        .find(|(addr, _)| *addr == listen)
        .map(|(_, client)| client.clone())
}

/// The relay client of the engine with WireGuard public key `key`.
fn relay_client_of(key: &PublicKey) -> Option<RelayClient> {
    lock(&RELAY_CLIENTS)
        .iter()
        .find(|(_, client)| client.public_key() == Some(key.to_bytes()))
        .map(|(_, client)| client.clone())
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
    /// driver.
    pub fn transports<Src: PacketSource, Snk: PacketSink>(
        &self,
        builder: EngineBuilder<Src, Snk>,
        listen: SocketAddr,
    ) -> anyhow::Result<(EngineBuilder<Src, Snk>, Transports)> {
        match self.transport {
            TransportKind::Udp => {
                let udp = UdpTransport::bind(UDP_TRANSPORT, listen)
                    .with_context(|| format!("cannot bind UDP {listen}"))?;
                let transports = Transports {
                    default: UDP_TRANSPORT,
                    listen: udp.local_addr(),
                };
                let builder = builder.transport(udp).policy(Box::new(StandardRoaming));
                Ok((builder, transports))
            }
            TransportKind::Relay => {
                let udp = UdpTransport::bind(UDP_TRANSPORT, listen)
                    .with_context(|| format!("cannot bind UDP {listen}"))?;
                let transports = Transports {
                    default: UDP_TRANSPORT,
                    listen: udp.local_addr(),
                };
                let (client, ext, policy) = RelayClient::new(udp, self.client_config()?);
                lock(&RELAY_CLIENTS).push((transports.listen, client));
                let builder = builder.transport(ext).policy(Box::new(policy));
                Ok((builder, transports))
            }
        }
    }

    /// The relay client options of `--transport relay`.
    pub fn client_config(&self) -> anyhow::Result<ClientConfig> {
        let path = self
            .machine_key_file
            .as_ref()
            .ok_or_else(|| anyhow!("--machine-key-file is required with --transport relay"))?;
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
/// With `--transport relay` it also starts the relay client's driver for the `--peer`s.
pub fn build_engine<Src: PacketSource, Snk: PacketSink>(
    source: Src,
    sink: Snk,
    args: &NodeArgs,
) -> anyhow::Result<Node> {
    let private_key = args.private_key()?;
    let public_key = PublicKey::from(&private_key);
    let builder = EngineBuilder::new(source, sink).private_key(private_key);
    let (builder, transports) = args.transport.transports(builder, args.listen)?;
    let engine = builder.build().context("cannot build the engine")?;
    if args.transport.transport == TransportKind::Relay
        && let Some(client) = relay_client_at(transports.listen)
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
/// With `--transport relay` the status gets `extra.relay` (endpoints, reflexive address)
/// and `extra.paths` (the ladder) of the relay client.
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
        (Some(status), Some(client)) => Some(status.extra(move |extra| {
            extra.insert("relay".to_owned(), client.relay_json());
            extra.insert("paths".to_owned(), client.paths_json());
        })),
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
    if let Some(status) = &status {
        status.write().await?;
    }
    if let Some(writer) = writer {
        writer.abort();
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
