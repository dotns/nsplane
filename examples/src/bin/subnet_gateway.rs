//! A TUN node that lets IPv6 peers reach an IPv4 LAN behind it through stateful NAT64.
//!
//! Runs like `tun_node` (TUN device, `ip` configuration on Linux, UAPI on the standard
//! socket, echo and checks on the kernel stack) with its local side wrapped in a
//! [`Nat64Lan`]. Each `--route <MAPPED>/96=<REAL>/<len>,snat=<SNAT4>` maps an IPv6 /96 to an
//! IPv4 LAN prefix: a peer's packet to `MAPPED::<IPv4>` leaves on the TUN device as IPv4 to
//! that LAN host, from `SNAT4` with a SNAT port reserved for the flow, and the host's reply
//! to `SNAT4` comes back to the peer as IPv6 from the mapped address. TCP, UDP and ICMP echo
//! are translated; unsafe targets (broadcast, loopback, ...) are dropped. Needs root (or
//! `CAP_NET_ADMIN`), and IP forwarding between the TUN device and the LAN.
//!
//! `SNAT4` must not be an address of this host (the kernel would take the replies itself):
//! the node routes `SNAT4/32` into the TUN device, and the LAN routes it to this host. The
//! peers route the mapped /96 to this node (it is in their allowed IPs for it); this node's
//! allowed IPs for a peer are the peer's own IPv6 sources, as usual. `--max-tcp-mss` lowers
//! the MSS of TCP SYNs both ways. The translator's counters are in the status file's
//! `extra.nat64_lan`.
//!
//! APIs shown: [`LanRoute::new`], [`Nat64Lan::new`] with a [`Nat64LanConfig`],
//! [`Nat64LanSink`] and [`Nat64LanSource`] around the TUN device's sink and source,
//! [`Nat64Lan::stats`], and the shared TUN node assembly.
//!
//! Usage: `sudo cargo run -p nsplane-examples --bin subnet_gateway -- --private-key <KEY>
//! --address fd00:c::1/64 --peer <PUBKEY>,endpoint=192.0.2.2:51820,allowed-ips=fd00:c::2/128
//! --route fd00:64::/96=192.168.50.0/24,snat=10.201.0.1`
//!
//! [`LanRoute::new`]: nsplane_nat::LanRoute::new
//! [`Nat64Lan`]: nsplane_nat::Nat64Lan
//! [`Nat64Lan::new`]: nsplane_nat::Nat64Lan::new
//! [`Nat64Lan::stats`]: nsplane_nat::Nat64Lan::stats
//! [`Nat64LanConfig`]: nsplane_nat::Nat64LanConfig
//! [`Nat64LanSink`]: nsplane_nat::Nat64LanSink
//! [`Nat64LanSource`]: nsplane_nat::Nat64LanSource

#[cfg(unix)]
mod unix {
    use std::net::{IpAddr, Ipv4Addr};
    use std::process::{Command, ExitCode};
    use std::str::FromStr;
    use std::sync::Arc;

    use anyhow::{Context as _, anyhow, bail};
    use arc_swap::ArcSwap;
    use clap::Parser;
    use nsplane::AllowedIp;
    use nsplane_examples::echo::{Backend, EchoArgs};
    use nsplane_examples::node::{
        self, NodeArgs, TunArgs, build_engine, configure_peers, configure_tun, init_logging,
        parse_cidr, serve_uapi,
    };
    use nsplane_examples::out;
    use nsplane_examples::status::Status;
    use nsplane_nat::{LanRoute, Nat64Lan, Nat64LanConfig, Nat64LanSink, Nat64LanSource};
    use serde_json::{Value, json};

    /// A TUN node translating its peers' IPv6 to an IPv4 LAN (needs root).
    #[derive(Debug, Parser)]
    #[command(name = "subnet_gateway", version)]
    pub(crate) struct Args {
        #[command(flatten)]
        node: NodeArgs,

        #[command(flatten)]
        echo: EchoArgs,

        #[command(flatten)]
        tun: TunArgs,

        /// A LAN reachable through a mapped IPv6 /96, repeatable:
        /// `<IPv6>/96=<IPv4>/<len>,snat=<IPv4>`
        #[arg(long, value_name = "MAPPED=REAL,snat=SNAT4")]
        route: Vec<RouteSpec>,

        /// Lower the MSS option of TCP SYNs to this value in both directions
        #[arg(long, value_name = "BYTES")]
        max_tcp_mss: Option<u16>,
    }

    /// One `--route`.
    #[derive(Debug, Clone, Copy)]
    pub(crate) struct RouteSpec(LanRoute);

    impl FromStr for RouteSpec {
        type Err = anyhow::Error;

        fn from_str(s: &str) -> anyhow::Result<Self> {
            let (pair, snat) = s
                .split_once(",snat=")
                .ok_or_else(|| anyhow!("`{s}` is not `<mapped>=<real>,snat=<IPv4>`"))?;
            let (mapped, real) = pair
                .split_once('=')
                .ok_or_else(|| anyhow!("`{pair}` is not `<mapped>=<real>`"))?;
            let mapped = match parse_cidr(mapped)? {
                AllowedIp {
                    addr: IpAddr::V6(addr),
                    cidr,
                } => (addr, cidr),
                AllowedIp { .. } => bail!("`{mapped}` is not an IPv6 prefix"),
            };
            let real = match parse_cidr(real)? {
                AllowedIp {
                    addr: IpAddr::V4(addr),
                    cidr,
                } => (addr, cidr),
                AllowedIp { .. } => bail!("`{real}` is not an IPv4 prefix"),
            };
            let snat: Ipv4Addr = snat
                .parse()
                .with_context(|| format!("invalid IPv4 address `{snat}`"))?;
            let route = LanRoute::new(mapped, real, snat)
                .with_context(|| format!("invalid route `{s}`"))?;
            Ok(Self(route))
        }
    }

    /// Routes every route's SNAT address into the TUN device `name`, so the LAN's replies
    /// reach the translator.
    fn route_snat(name: &str, routes: &[LanRoute]) -> anyhow::Result<()> {
        for route in routes {
            let snat = format!("{}/32", route.snat_source);
            if !cfg!(target_os = "linux") {
                out::line(format_args!(
                    "  sudo route -q -n add -inet {snat} -interface {name}"
                ));
                continue;
            }
            let output = Command::new("ip")
                .args(["route", "add", &snat, "dev", name])
                .output()
                .context("cannot run `ip`")?;
            let stderr = String::from_utf8_lossy(&output.stderr);
            if !output.status.success() && !stderr.contains("File exists") {
                bail!("`ip route add {snat} dev {name}` failed: {}", stderr.trim());
            }
            tracing::info!(route = %snat, interface = name, "SNAT route configured");
        }
        Ok(())
    }

    /// The status file's `extra.nat64_lan` object.
    fn nat64_lan_json(nat: &Nat64Lan) -> Value {
        let stats = nat.stats();
        json!({
            "forwarded": stats.forwarded,
            "reversed": stats.reversed,
            "packet_too_big": stats.packet_too_big,
            "unsafe_target": stats.unsafe_target,
            "port_exhausted": stats.port_exhausted,
            "other_drops": stats.other_drops,
            "not_ours": stats.not_ours,
            "flows": stats.conntrack.entries,
            "flows_inserted": stats.conntrack.inserted,
        })
    }

    pub(crate) async fn main(args: Args) -> anyhow::Result<ExitCode> {
        init_logging(&args.node.log)?;
        let routes: Vec<LanRoute> = args.route.iter().map(|route| route.0).collect();
        let tun = node::create_tun(&args.tun.tun_name, &args.node)?;
        let name = tun.name().unwrap_or_else(|_| args.tun.tun_name.clone());
        configure_tun(&name, &args.tun.address, args.tun.mtu, &args.node.peer)?;
        route_snat(&name, &routes)?;
        let (source, sink) = tun.split().context("cannot open the TUN device")?;

        let mut config = Nat64LanConfig::default();
        config.max_tcp_mss = args.max_tcp_mss;
        let nat = Arc::new(Nat64Lan::new(
            Arc::new(ArcSwap::from_pointee(routes)),
            config,
        ));
        let node = build_engine(
            Nat64LanSource::new(source, Arc::clone(&nat)),
            Nat64LanSink::new(sink, Arc::clone(&nat)),
            &args.node,
        )?;
        let handle = node.engine.handle();
        configure_peers(&handle, &args.node.peer).await?;
        for route in &args.route {
            tracing::info!(mapped = %route.0.mapped.0, real = %route.0.real.0, real_len = route.0.real.1, snat = %route.0.snat_source, "LAN routed");
        }

        let socket = serve_uapi(handle.clone(), &name, node.transports.listen.port())?;
        tracing::info!(interface = %name, listen = %node.transports.listen, uapi = %socket, "subnet gateway started");

        let status = args.node.status_file.clone().map(|path| {
            Status::new(path, handle, node.transports.listen).extra(move |extra| {
                extra.insert("nat64_lan".to_owned(), nat64_lan_json(&nat));
            })
        });
        node::run(node.engine, &args.echo, Backend::Kernel, status).await
    }

    #[cfg(test)]
    mod tests {
        use std::net::Ipv6Addr;

        use super::*;

        #[test]
        fn route_spec() {
            let RouteSpec(route) = "fd00:64::/96=192.168.50.0/24,snat=10.201.0.1"
                .parse()
                .unwrap();
            assert_eq!(route.mapped, ("fd00:64::".parse::<Ipv6Addr>().unwrap(), 96));
            assert_eq!(route.real, (Ipv4Addr::new(192, 168, 50, 0), 24));
            assert_eq!(route.snat_source, Ipv4Addr::new(10, 201, 0, 1));
            for bad in [
                "fd00:64::/96=192.168.50.0/24",
                "fd00:64::/64=192.168.50.0/24,snat=10.201.0.1",
                "fd00:64::/96=192.168.50.1/24,snat=10.201.0.1",
                "192.168.50.0/24=fd00:64::/96,snat=10.201.0.1",
                "fd00:64::/96=192.168.50.0/24,snat=fd00::1",
            ] {
                assert!(bad.parse::<RouteSpec>().is_err(), "{bad}");
            }
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
    anyhow::bail!("subnet_gateway runs on Linux and macOS only")
}
