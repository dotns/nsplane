//! A TUN node that publishes local services to its peers through a port map (DNAT/SNAT).
//!
//! Runs like `tun_node` (TUN device, `ip` configuration on Linux, UAPI on the standard
//! socket, echo and checks on the kernel stack) with a [`PortMap`] in the engine. Each
//! `--publish <tcp|udp>:<listen>=<target>[@<PUBKEY>]` maps a tunnel-facing address and port
//! to a local service: a peer's packet to `listen` is rewritten to `target` (DNAT) and its
//! flow recorded, and the service's replies are rewritten back to come from `listen`
//! (SNAT). With `@<PUBKEY>` only that `--peer` may use the rule; packets of other peers to
//! `listen` are dropped. Everything else passes unchanged. Needs root (or `CAP_NET_ADMIN`).
//!
//! `listen` and `target` are of the same address family, as the tunnel side sees them:
//! `listen` is typically an interface `--address` (or this node's own IPv6 address with
//! `translate_node`'s address model) and `target` a service on the same address, e.g. the
//! `--echo-port`. Only unfragmented TCP and UDP packets are mapped.
//!
//! Flows are kept in a bounded [`Conntrack`] whose idle timeouts are set by
//! `--tcp-established-timeout`, `--tcp-transitory-timeout`, `--udp-timeout` and
//! `--icmp-timeout` (seconds), its size by `--max-flows`. An idle flow expires: its next
//! packet is judged by the rules again and starts a new flow. The rules and the conntrack
//! counters are in the status file's `extra.port_map`.
//!
//! APIs shown: [`PortMap::with_conntrack`] as an engine filter, [`Conntrack::new`] with a
//! [`ConntrackConfig`], [`PortMap::set_rules`] once the engine assigned the peer ids,
//! [`Conntrack::stats`], and the shared TUN node assembly.
//!
//! Usage: `sudo cargo run -p nsplane-examples --bin port_map -- --private-key <KEY>
//! --address fd00:b::1/64 --peer <PUBKEY>,endpoint=192.0.2.2:51820,allowed-ips=fd00:b::2/128
//! --echo-port 7 --publish 'tcp:[fd00:b::1]:8007=[fd00:b::1]:7@<PUBKEY>' --udp-timeout 5`
//!
//! [`Conntrack`]: nsplane_nat::Conntrack
//! [`Conntrack::new`]: nsplane_nat::Conntrack::new
//! [`Conntrack::stats`]: nsplane_nat::Conntrack::stats
//! [`ConntrackConfig`]: nsplane_nat::ConntrackConfig
//! [`PortMap`]: nsplane_nat::PortMap
//! [`PortMap::set_rules`]: nsplane_nat::PortMap::set_rules
//! [`PortMap::with_conntrack`]: nsplane_nat::PortMap::with_conntrack

#[cfg(unix)]
mod unix {
    use std::net::SocketAddr;
    use std::process::ExitCode;
    use std::str::FromStr;
    use std::sync::Arc;
    use std::time::Duration;

    use anyhow::{Context as _, anyhow, bail};
    use clap::Parser;
    use nsplane::x25519::PublicKey;
    use nsplane_core::{PacketFilter, Verdict};
    use nsplane_examples::echo::{Backend, EchoArgs};
    use nsplane_examples::node::{
        self, NodeArgs, TunArgs, build_engine_with, configure_peers, configure_tun, decode_key,
        encode_public_key, init_logging, serve_uapi,
    };
    use nsplane_examples::status::Status;
    use nsplane_nat::{Conntrack, ConntrackConfig, PortMap, PortMapProtocol, PortMapRule};
    use nsplane_packet::{PacketBuf, PeerId};
    use nsplane_tun::Tun;
    use serde_json::{Value, json};

    /// A TUN node publishing local services to its peers (needs root).
    #[derive(Debug, Parser)]
    #[command(name = "port_map", version)]
    pub(crate) struct Args {
        #[command(flatten)]
        node: NodeArgs,

        #[command(flatten)]
        echo: EchoArgs,

        #[command(flatten)]
        tun: TunArgs,

        /// A published service, repeatable: `<tcp|udp>:<listen ip:port>=<target ip:port>`,
        /// with `@<base64 pubkey>` for one `--peer` only (IPv6 in brackets)
        #[arg(long, value_name = "PROTO:LISTEN=TARGET[@PUBKEY]")]
        publish: Vec<Publish>,

        /// Idle timeout of an established TCP flow
        #[arg(long, value_name = "SECS", default_value_t = 300)]
        tcp_established_timeout: u64,

        /// Idle timeout of a TCP flow in handshake, closing or reset
        #[arg(long, value_name = "SECS", default_value_t = 30)]
        tcp_transitory_timeout: u64,

        /// Idle timeout of a UDP flow
        #[arg(long, value_name = "SECS", default_value_t = 30)]
        udp_timeout: u64,

        /// Idle timeout of an ICMP echo flow
        #[arg(long, value_name = "SECS", default_value_t = 30)]
        icmp_timeout: u64,

        /// Flows tracked at most; the least recently seen one makes room for a new one
        #[arg(long, value_name = "N", default_value_t = 65_536)]
        max_flows: usize,
    }

    impl Args {
        const fn conntrack_config(&self) -> ConntrackConfig {
            ConntrackConfig {
                max_entries: self.max_flows,
                tcp_established_timeout: Duration::from_secs(self.tcp_established_timeout),
                tcp_transitory_timeout: Duration::from_secs(self.tcp_transitory_timeout),
                udp_timeout: Duration::from_secs(self.udp_timeout),
                icmp_timeout: Duration::from_secs(self.icmp_timeout),
            }
        }
    }

    /// One `--publish`.
    #[derive(Debug, Clone)]
    pub(crate) struct Publish {
        protocol: PortMapProtocol,
        listen: SocketAddr,
        target: SocketAddr,
        peer: Option<PublicKey>,
    }

    impl FromStr for Publish {
        type Err = anyhow::Error;

        fn from_str(s: &str) -> anyhow::Result<Self> {
            let (protocol, rest) = s
                .split_once(':')
                .ok_or_else(|| anyhow!("`{s}` is not `<tcp|udp>:<listen>=<target>`"))?;
            let protocol = match protocol {
                "tcp" => PortMapProtocol::Tcp,
                "udp" => PortMapProtocol::Udp,
                _ => bail!("unknown protocol `{protocol}` (tcp or udp)"),
            };
            // The base64 key may contain `=` padding, so the key is split off first.
            let (pair, peer) = match rest.split_once('@') {
                Some((pair, key)) => (pair, Some(PublicKey::from(decode_key(key)?))),
                None => (rest, None),
            };
            let (listen, target) = pair
                .split_once('=')
                .ok_or_else(|| anyhow!("`{s}` is not `<tcp|udp>:<listen>=<target>`"))?;
            Ok(Self {
                protocol,
                listen: listen
                    .parse()
                    .with_context(|| format!("invalid listen address `{listen}`"))?,
                target: target
                    .parse()
                    .with_context(|| format!("invalid target address `{target}`"))?,
                peer,
            })
        }
    }

    /// The engine's share of the port map; the status file reads the same one.
    struct SharedPortMap(Arc<PortMap>);

    impl PacketFilter for SharedPortMap {
        fn inbound(&self, peer: PeerId, packet: &mut PacketBuf) -> Verdict {
            self.0.inbound(peer, packet)
        }

        fn outbound(&self, peer: PeerId, packet: &mut PacketBuf) -> Verdict {
            self.0.outbound(peer, packet)
        }
    }

    /// The status file's `extra.port_map` object.
    fn port_map_json(map: &PortMap) -> Value {
        let stats = map.conntrack().stats();
        json!({
            "rules": map.rules().len(),
            "conntrack": {
                "entries": stats.entries,
                "inserted": stats.inserted,
                "expired": stats.expired,
                "evicted": stats.evicted,
                "removed": stats.removed,
                "hits": stats.hits,
                "misses": stats.misses,
            },
        })
    }

    pub(crate) async fn main(args: Args) -> anyhow::Result<ExitCode> {
        init_logging(&args.node.log)?;
        // The rules name peers by the ids the engine assigns when they are added, so the
        // port map starts without rules (everything passes) and gets them right after.
        let conntrack = Conntrack::new(args.conntrack_config());
        let map = Arc::new(PortMap::with_conntrack(Vec::new(), conntrack)?);

        let tun = Tun::create(&args.tun.tun_name)
            .with_context(|| format!("cannot create TUN {}", args.tun.tun_name))?;
        let name = tun.name().unwrap_or_else(|_| args.tun.tun_name.clone());
        configure_tun(&name, &args.tun.address, args.tun.mtu, &args.node.peer)?;
        let (source, sink) = tun.split().context("cannot open the TUN device")?;
        let engine_map = SharedPortMap(Arc::clone(&map));
        let node = build_engine_with(source, sink, &args.node, |builder| {
            builder.filter(Box::new(engine_map))
        })?;
        let handle = node.engine.handle();
        configure_peers(&handle, &args.node.peer).await?;
        let mut rules = Vec::new();
        for publish in &args.publish {
            let peers = match publish.peer {
                Some(key) => Some(vec![handle.peer_id(key).await?.with_context(|| {
                    format!(
                        "--publish names {}, which is no --peer",
                        encode_public_key(&key)
                    )
                })?]),
                None => None,
            };
            rules.push(PortMapRule {
                protocol: publish.protocol,
                listen: publish.listen,
                target: publish.target,
                peers,
            });
            tracing::info!(protocol = ?publish.protocol, listen = %publish.listen, target = %publish.target, "service published");
        }
        map.set_rules(rules)?;

        let socket = serve_uapi(handle.clone(), &name, node.transports.listen.port())?;
        tracing::info!(interface = %name, listen = %node.transports.listen, uapi = %socket, "port map node started");

        let status = args.node.status_file.clone().map(|path| {
            Status::new(path, handle, node.transports.listen).extra(move |extra| {
                extra.insert("port_map".to_owned(), port_map_json(&map));
            })
        });
        node::run(node.engine, &args.echo, Backend::Kernel, status).await
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn publish_forms() {
            let key = "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=";
            let any: Publish = "udp:[fd00::1]:8007=[fd00::1]:7".parse().unwrap();
            assert_eq!(any.protocol, PortMapProtocol::Udp);
            assert_eq!(any.listen, "[fd00::1]:8007".parse().unwrap());
            assert_eq!(any.target, "[fd00::1]:7".parse().unwrap());
            assert!(any.peer.is_none());
            let one: Publish = format!("tcp:10.0.0.1:80=10.0.0.1:7@{key}").parse().unwrap();
            assert_eq!(one.protocol, PortMapProtocol::Tcp);
            assert_eq!(one.peer.map(|key| key.to_bytes()), Some([1; 32]));
            assert!("icmp:10.0.0.1:80=10.0.0.1:7".parse::<Publish>().is_err());
            assert!("tcp:10.0.0.1:80".parse::<Publish>().is_err());
            assert!("tcp:fd00::1:80=[fd00::1]:7".parse::<Publish>().is_err());
        }

        #[test]
        fn conntrack_timeouts() {
            let key = "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=";
            let args =
                Args::try_parse_from(["port_map", "--private-key", key, "--udp-timeout", "3"])
                    .unwrap();
            let config = args.conntrack_config();
            assert_eq!(config.udp_timeout, Duration::from_secs(3));
            let defaults = ConntrackConfig::default();
            assert_eq!(
                config.tcp_established_timeout,
                defaults.tcp_established_timeout
            );
            assert_eq!(config.max_entries, defaults.max_entries);
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
    anyhow::bail!("port_map runs on Linux and macOS only")
}
