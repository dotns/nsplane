//! A TUN device and a userspace netstack side by side behind one engine.
//!
//! Packets the engine delivers are routed by their destination address: inside a
//! `--tun-address` prefix to the TUN device (the host's kernel, local services), anything
//! else to the netstack, which owns the `--stack-address`es. Packets from both sides are
//! merged into the engine's one packet source. The TUN is configured like `tun_node` (Linux:
//! through `ip`; macOS: prints the commands) and the UAPI is served on the standard socket.
//! Echo (`--echo-port`) and `--check`s run on the NETSTACK side. The status file's
//! `extra.splitter.misrouted` counts delivered packets that were not IP (no route), and
//! `extra.netstack` holds the stack's drop counters. Needs root (or `CAP_NET_ADMIN`).
//!
//! APIs shown: [`Splitter`] (a closure picks the sink per packet; shared through an `Arc`
//! to read [`Splitter::misrouted`]), [`MergeSource`] (the minimum MTU of its sources),
//! `nsplane_packet::IpPacket` header views, `nsplane_tun::Tun`, [`NetStack`], and the
//! shared node assembly (`build_engine`, `configure_peers`, `configure_tun`, `serve_uapi`).
//!
//! Usage: `sudo cargo run -p nsplane-examples --bin hybrid -- --private-key <KEY>
//! --tun-address 10.0.0.1/24 --stack-address 10.1.0.1/24
//! --peer <PUBKEY>,endpoint=192.0.2.2:51820,allowed-ips=10.0.0.2/32+10.1.0.2/32
//! --echo-port 7`

#[cfg(unix)]
mod unix {
    use std::io;
    use std::process::ExitCode;
    use std::sync::Arc;

    use anyhow::Context as _;
    use clap::Parser;
    use nsplane::{AllowedIp, MergeSource, PacketBuf, PacketSink, PeerId, Splitter};
    use nsplane_examples::echo::{Backend, EchoArgs};
    use nsplane_examples::node::{
        self, DEFAULT_TUN_NAME, NodeArgs, build_engine, configure_peers, configure_tun, contains,
        init_logging, parse_cidr, serve_uapi,
    };
    use nsplane_examples::status::{Status, netstack_json};
    use nsplane_netstack::{NetStack, NetStackConfig};
    use nsplane_packet::IpPacket;
    use nsplane_tun::Tun;
    use serde_json::json;

    /// Index of the TUN sink in the splitter.
    const TUN: usize = 0;
    /// Index of the netstack sink in the splitter.
    const STACK: usize = 1;
    /// No sink: the splitter counts the packet as misrouted.
    const NO_ROUTE: usize = 2;

    /// A TUN device for local services and a netstack for the rest, behind one engine
    /// (needs root).
    #[derive(Debug, Parser)]
    #[command(name = "hybrid", version)]
    pub(crate) struct Args {
        #[command(flatten)]
        node: NodeArgs,

        #[command(flatten)]
        echo: EchoArgs,

        /// Name of the TUN interface (macOS: `utun` or `utunN`)
        #[arg(long, value_name = "NAME", default_value = DEFAULT_TUN_NAME)]
        tun_name: String,

        /// Address of the TUN interface (kernel side) with its prefix, repeatable; packets
        /// to these prefixes go to the TUN
        #[arg(long, value_name = "CIDR", value_parser = parse_cidr)]
        tun_address: Vec<AllowedIp>,

        /// Address of the netstack with its prefix, repeatable (one IPv4 and one IPv6 are
        /// used); every other packet goes to the netstack
        #[arg(long, value_name = "CIDR", value_parser = parse_cidr, required = true)]
        stack_address: Vec<AllowedIp>,

        /// MTU of the TUN interface and the netstack
        #[arg(long, value_name = "N", default_value_t = 1420)]
        mtu: u16,
    }

    /// The splitter, shared so the status file can read its counter.
    struct SharedSplitter(Arc<Splitter>);

    impl PacketSink for SharedSplitter {
        async fn send(&self, packet: PacketBuf, from: PeerId) -> io::Result<()> {
            self.0.send(packet, from).await
        }
    }

    /// The splitter sink for `packet`: [`TUN`] if its destination is inside a TUN prefix,
    /// [`STACK`] for any other IP packet, [`NO_ROUTE`] for anything else.
    fn route(tun_prefixes: &[AllowedIp], packet: &PacketBuf) -> usize {
        match IpPacket::parse(packet.as_packet()) {
            Ok(ip) if tun_prefixes.iter().any(|net| contains(net, ip.dst())) => TUN,
            Ok(_) => STACK,
            Err(_) => NO_ROUTE,
        }
    }

    pub(crate) async fn main(args: Args) -> anyhow::Result<ExitCode> {
        init_logging(&args.node.log)?;
        let tun = Tun::create(&args.tun_name)
            .with_context(|| format!("cannot create TUN {}", args.tun_name))?;
        let name = tun.name().unwrap_or_else(|_| args.tun_name.clone());
        configure_tun(&name, &args.tun_address, args.mtu, &args.node.peer)?;
        let (tun_source, tun_sink) = tun.split().context("cannot open the TUN device")?;

        let addresses = args
            .stack_address
            .iter()
            .map(|ip| (ip.addr, ip.cidr))
            .collect();
        let (stack, stack_handle) = NetStack::new(NetStackConfig::new(addresses, args.mtu));
        let (stack_source, stack_sink) = stack.split();

        let tun_prefixes = args.tun_address.clone();
        let splitter = Arc::new(
            Splitter::new(move |_peer, packet| route(&tun_prefixes, packet))
                .sink(tun_sink)
                .sink(stack_sink),
        );
        let merge = MergeSource::new().source(tun_source).source(stack_source);
        let node = build_engine(merge, SharedSplitter(Arc::clone(&splitter)), &args.node)?;
        let handle = node.engine.handle();
        configure_peers(&handle, &args.node.peer).await?;
        let socket = serve_uapi(handle.clone(), &name, node.transports.listen.port())?;
        tracing::info!(interface = %name, listen = %node.transports.listen, uapi = %socket, "hybrid node started");

        let status = args.node.status_file.clone().map(|path| {
            let stack = stack_handle.clone();
            Status::new(path, handle, node.transports.listen).extra(move |extra| {
                extra.insert(
                    "splitter".to_owned(),
                    json!({ "misrouted": splitter.misrouted() }),
                );
                extra.insert("netstack".to_owned(), netstack_json(&stack));
            })
        });
        node::run(
            node.engine,
            &args.echo,
            Backend::NetStack(stack_handle),
            status,
        )
        .await
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn routes_by_destination() {
            let prefixes = [parse_cidr("10.0.0.1/24").unwrap()];
            let v4 = |dst: [u8; 4]| {
                let mut packet = vec![0x45, 0, 0, 20, 0, 0, 0x40, 0, 64, 17, 0, 0, 10, 9, 9, 9];
                packet.extend_from_slice(&dst);
                PacketBuf::from_packet(&packet)
            };
            assert_eq!(route(&prefixes, &v4([10, 0, 0, 7])), TUN);
            assert_eq!(route(&prefixes, &v4([10, 1, 0, 1])), STACK);
            assert_eq!(route(&prefixes, &PacketBuf::from_packet(&[0x10])), NO_ROUTE);
        }
    }
}

#[cfg(unix)]
#[tokio::main]
async fn main() -> anyhow::Result<std::process::ExitCode> {
    use clap::Parser as _;
    unix::main(unix::Args::parse()).await
}

#[cfg(not(unix))]
fn main() -> anyhow::Result<std::process::ExitCode> {
    anyhow::bail!("hybrid runs on Linux and macOS only")
}
