//! A single-port relay that is also a WireGuard node.
//!
//! One UDP socket carries native WireGuard to the relay's own engine, WireGuard between
//! other peers relayed blindly (by mac1 and receiver index, never decrypted), and the
//! relay's control messages (`register_source`, reflexive address). The socket is wrapped
//! in [`RelayServerTransport`], whose receive loop runs the [`Router`] on every datagram:
//! own-engine WireGuard goes to the engine, relayed datagrams and control replies leave
//! on the same socket, everything else is dropped and counted. The own engine has a
//! userspace stack with `--address` and serves TCP/UDP echo (`--echo-port`) so peers can
//! check it through the tunnel.
//!
//! Targets (the WireGuard keys the relay forwards to) come from `--target` /
//! `--static-target` and from `--config <relay.json>`, which is re-read when it changes:
//! `{"machine_keys": [{"machine_key": b64, "wg_public_key": b64}], "static_targets":
//! [{"wg_public_key": b64, "endpoint": "ip:port"}]}`. A pinned target's source is learned
//! from its signed `register_source`; a static target is at a fixed endpoint.
//! `gen-machine-key <path>` writes a machine key file for a node and prints its public key.
//! The status file's `extra.relay` holds the counters, routes and targets.
//!
//! APIs shown: a wrapping [`Transport`] over [`UdpTransport`], [`EngineBuilder::transport`]
//! with a custom transport, and the relay modules (`relay::router`, `relay::server`).
//!
//! Usage: `cargo run -p nsplane-examples --bin relay_server -- --private-key <KEY>
//! --listen 0.0.0.0:51820 --address 10.0.0.1/24 --config relay.json
//! --peer <PUBKEY>,allowed-ips=10.0.0.2/32 --echo-port 7`
//!
//! [`Transport`]: nsplane::Transport

use std::fs::OpenOptions;
use std::io::Write as _;
use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Instant;

use anyhow::{Context as _, bail};
use clap::{Parser, Subcommand};
use nsplane::x25519::PublicKey;
use nsplane::{AllowedIp, EngineBuilder, StandardRoaming, UdpTransport};
use nsplane_examples::echo::{Backend, EchoArgs};
use nsplane_examples::node::{
    self, NodeArgs, TransportKind, UDP_TRANSPORT, configure_peers, decode_key, init_logging,
    parse_cidr,
};
use nsplane_examples::out;
use nsplane_examples::relay::envelope::MachineKey;
use nsplane_examples::relay::router::{MachinePin, Router, Source, TargetConfig, machine_id};
use nsplane_examples::relay::server::{
    RelayConfig, RelayServerTransport, split_pair, status_json, watch_config,
};
use nsplane_examples::status::Status;
use nsplane_netstack::{DEFAULT_MTU, NetStack, NetStackConfig};

/// A single-port relay with its own WireGuard engine.
#[derive(Debug, Parser)]
#[command(
    name = "relay_server",
    version,
    args_conflicts_with_subcommands = true,
    subcommand_negates_reqs = true
)]
struct Args {
    #[command(subcommand)]
    command: Option<Command>,

    #[command(flatten)]
    node: NodeArgs,

    #[command(flatten)]
    echo: EchoArgs,

    /// Address of the own engine's stack with its prefix, repeatable
    #[arg(long, value_name = "CIDR", value_parser = parse_cidr, required = true)]
    address: Vec<AllowedIp>,

    /// MTU of the stack
    #[arg(long, value_name = "N", default_value_t = DEFAULT_MTU)]
    mtu: u16,

    /// Relay configuration file (JSON), re-read when it changes
    #[arg(long, value_name = "PATH")]
    config: Option<PathBuf>,

    /// A pinned target, repeatable: `<machine key b64>=<wg pubkey b64>`
    #[arg(long = "target", value_name = "MACHINE=WGKEY")]
    targets: Vec<String>,

    /// A target at a fixed endpoint, repeatable: `<wg pubkey b64>=<ip:port>`
    #[arg(long = "static-target", value_name = "WGKEY=IP:PORT")]
    static_targets: Vec<String>,

    /// Identifier carried in reflexive responses
    #[arg(long, value_name = "ID", default_value = "relay")]
    gateway_id: String,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Write a new machine key file (base64 Ed25519 seed, mode 0600) and print its public key
    GenMachineKey {
        /// The file to create; an existing file is not overwritten
        path: PathBuf,
    },
}

/// Creates the machine key file at `path` and prints the public key.
fn gen_machine_key(path: &PathBuf) -> anyhow::Result<ExitCode> {
    let key = MachineKey::generate();
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    std::os::unix::fs::OpenOptionsExt::mode(&mut options, 0o600);
    let mut file = options
        .open(path)
        .with_context(|| format!("cannot create {}", path.display()))?;
    writeln!(file, "{}", key.to_base64())
        .with_context(|| format!("cannot write {}", path.display()))?;
    out::line(format_args!("{}", key.public_b64()));
    Ok(ExitCode::SUCCESS)
}

/// The targets of `--target` and `--static-target`.
fn flag_targets(args: &Args) -> anyhow::Result<Vec<TargetConfig>> {
    let mut targets = Vec::new();
    for spec in &args.targets {
        let (machine, wg) = split_pair(spec)?;
        let machine_key = decode_key(machine)?;
        targets.push(TargetConfig {
            wg_public_key: decode_key(wg)?,
            pin: Some(MachinePin {
                machine_id: machine_id(&machine_key),
                machine_key,
            }),
            static_source: None,
        });
    }
    for spec in &args.static_targets {
        let (wg, endpoint) = split_pair(spec)?;
        let endpoint = endpoint
            .parse()
            .with_context(|| format!("invalid endpoint `{endpoint}`"))?;
        targets.push(TargetConfig {
            wg_public_key: decode_key(wg)?,
            pin: None,
            static_source: Some(Source::Udp(endpoint)),
        });
    }
    Ok(targets)
}

#[tokio::main]
async fn main() -> anyhow::Result<ExitCode> {
    let args = Args::parse();
    if let Some(Command::GenMachineKey { path }) = &args.command {
        return gen_machine_key(path);
    }
    init_logging(&args.node.log)?;
    if args.node.transport.transport != TransportKind::Udp {
        bail!("relay_server always runs its own relay transport; --transport relay is for nodes");
    }

    let private_key = args.node.private_key()?;
    let public_key = PublicKey::from(&private_key);
    let udp = UdpTransport::bind(UDP_TRANSPORT, args.node.listen)
        .with_context(|| format!("cannot bind UDP {}", args.node.listen))?;
    let listen = udp.local_addr();

    let base = flag_targets(&args)?;
    let mut targets = base.clone();
    let mut config_text = String::new();
    if let Some(path) = &args.config {
        config_text = std::fs::read_to_string(path)
            .with_context(|| format!("cannot read {}", path.display()))?;
        targets.extend(RelayConfig::parse(&config_text)?.targets()?);
    }
    let mut router = Router::new(public_key.to_bytes(), args.gateway_id.clone(), listen);
    router.set_targets(targets);
    let router = Arc::new(Mutex::new(router));
    if let Some(path) = &args.config {
        watch_config(path.clone(), base, Arc::clone(&router), config_text);
    }

    let addresses = args.address.iter().map(|ip| (ip.addr, ip.cidr)).collect();
    let (stack, stack_handle) = NetStack::new(NetStackConfig::new(addresses, args.mtu));
    let (source, sink) = stack.split();
    let engine = EngineBuilder::new(source, sink)
        .private_key(private_key)
        .transport(RelayServerTransport::new(udp, Arc::clone(&router)))
        .policy(Box::new(StandardRoaming))
        .build()
        .context("cannot build the engine")?;
    configure_peers(&engine.handle(), &args.node.peer).await?;
    tracing::info!(%listen, "relay server started");

    let status = args.node.status_file.clone().map(|path| {
        Status::new(path, engine.handle(), listen).extra(move |extra| {
            let router = router.lock().unwrap_or_else(PoisonError::into_inner);
            extra.insert("relay".to_owned(), status_json(&router, Instant::now()));
        })
    });
    node::run(engine, &args.echo, Backend::NetStack(stack_handle), status).await
}
