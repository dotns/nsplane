//! A node without TUN and without root: the engine's local side is an `nsplane-netstack`.
//!
//! The userspace stack owns the `--address`es; TCP and UDP echo (`--echo-port`) and the
//! `--check`s run on its [`NetStackHandle`], so the host's kernel never sees the tunnel
//! traffic. The status file's `extra.netstack` holds the stack's drop counters.
//!
//! APIs shown: [`NetStack::new`] and [`NetStack::split`] as the engine's packet source and
//! sink, [`NetStackHandle`] (`connect_tcp`, `bind_udp`, `incoming_tcp`, `incoming_udp`,
//! `stats`), and the shared node assembly (`build_engine`, `configure_peers`).
//!
//! Usage: `cargo run -p nsplane-examples --bin netstack_node -- --private-key <KEY>
//! --listen 127.0.0.1:51820 --address 10.0.0.1/24 --peer <PUBKEY>,allowed-ips=10.0.0.2/32
//! --echo-port 7`

use std::process::ExitCode;

use clap::Parser;
use nsplane::AllowedIp;
use nsplane_examples::echo::{Backend, EchoArgs};
use nsplane_examples::node::{
    self, NodeArgs, build_engine, configure_peers, init_logging, parse_cidr,
};
use nsplane_examples::status::Status;
use nsplane_netstack::{DEFAULT_MTU, NetStack, NetStackConfig, NetStackHandle};
use serde_json::json;

/// An nsplane node whose local side is a userspace TCP/IP stack (no TUN, no root).
#[derive(Debug, Parser)]
#[command(name = "netstack_node", version)]
struct Args {
    #[command(flatten)]
    node: NodeArgs,

    #[command(flatten)]
    echo: EchoArgs,

    /// Address of the stack with its prefix, repeatable (one IPv4 and one IPv6 are used)
    #[arg(long, value_name = "CIDR", value_parser = parse_cidr, required = true)]
    address: Vec<AllowedIp>,

    /// MTU of the stack
    #[arg(long, value_name = "N", default_value_t = DEFAULT_MTU)]
    mtu: u16,
}

/// The status file's `extra.netstack` object.
fn netstack_json(stack: &NetStackHandle) -> serde_json::Value {
    let stats = stack.stats();
    json!({
        "malformed": stats.malformed,
        "no_address": stats.no_address,
        "unsupported": stats.unsupported,
        "syn_refused": stats.syn_refused,
        "tcp_not_accepted": stats.tcp_not_accepted,
        "udp_queue_full": stats.udp_queue_full,
        "udp_flow_limit": stats.udp_flow_limit,
        "udp_not_accepted": stats.udp_not_accepted,
        "egress_full": stats.egress_full,
    })
}

#[tokio::main]
async fn main() -> anyhow::Result<ExitCode> {
    let args = Args::parse();
    init_logging(&args.node.log)?;
    let addresses = args.address.iter().map(|ip| (ip.addr, ip.cidr)).collect();
    let (stack, handle) = NetStack::new(NetStackConfig::new(addresses, args.mtu));
    let (source, sink) = stack.split();
    let node = build_engine(source, sink, &args.node)?;
    configure_peers(&node.engine.handle(), &args.node.peer).await?;
    tracing::info!(listen = %node.transports.listen, "netstack node started");

    let status = args.node.status_file.clone().map(|path| {
        let stack = handle.clone();
        Status::new(path, node.engine.handle(), node.transports.listen).extra(move |extra| {
            extra.insert("netstack".to_owned(), netstack_json(&stack));
        })
    });
    node::run(node.engine, &args.echo, Backend::NetStack(handle), status).await
}
