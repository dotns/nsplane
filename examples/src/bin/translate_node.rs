//! A TUN node whose local side speaks IPv4 to peers that are reached over IPv6 only.
//!
//! Runs like `tun_node` (TUN device, `ip` configuration on Linux, UAPI on the standard
//! socket, echo and checks on the kernel stack) with a [`Translator`] in the engine: local
//! IPv4 packets to a peer become IPv6 in the tunnel (RFC 7915) and the peer's IPv6 replies
//! become IPv4 again. Needs root (or `CAP_NET_ADMIN`).
//!
//! The address model ([`TranslationTable`]):
//!
//! - Every peer owns a /127 IPv6 group: `node6`, its native IPv6 address, and `node4`, the
//!   address that stands for its IPv4 side. `--map <PUBKEY>,node6=..,node4=..` names them.
//! - `alias4=<IPv4>` is the local IPv4 address of the peer: IPv4 to `alias4` leaves as IPv6
//!   to `node4`, and IPv6 from `node4` arrives from `alias4`. `alias6=<IPv6>` is a local
//!   IPv6 alias, rewritten to and from `node6`.
//! - `--self <SELF4>=<NODE4>`: this node's own IPv4 address and the `node4` of its own
//!   group; local packets from `self4` leave from `node4` and replies to `node4` arrive at
//!   `self4`. `self4/32` is added to the interface unless an `--address` covers it.
//! - `--lan <LAN4>=<LAN6>[@<PUBKEY>]` pairs an IPv4 prefix with an IPv6 /96: an IPv4
//!   address inside `lan4` is the IPv6 address `lan6` with the IPv4 address in its low 32
//!   bits. Without `@` the LAN is behind this node (hosts that route to the peers' aliases
//!   through it, with IP forwarding on); with `@` it is behind that peer.
//!
//! The core routes a local packet by its destination before the translator runs, and
//! checks a peer's source address before the translator sees it. So each mapped peer's
//! allowed IPs get its `alias4/32`, `alias6/128`, `node4/128` and `node6/128`, and those of
//! a peer with LANs behind it the `lan4` and `lan6` prefixes, on top of its `allowed-ips`;
//! the interface gets the routes to them as `tun_node` does. The translator's counters are
//! in the status file's `extra.translate`.
//!
//! APIs shown: [`Translator::new`] as an engine filter, [`TranslationTable::builder`] with
//! [`PeerMapping`], [`SelfMapping`] and [`LanPrefix`], [`Translator::store`] once the
//! engine assigned the peer ids, [`Translator::stats`], and the shared TUN node assembly.
//!
//! Usage: `sudo cargo run -p nsplane-examples --bin translate_node -- --private-key <KEY>
//! --self 10.200.0.1=fd00:a::1:1 --peer <PUBKEY>,endpoint=192.0.2.2:51820
//! --map <PUBKEY>,node6=fd00:a::2:0,node4=fd00:a::2:1,alias4=10.200.0.2
//! --lan 192.168.50.0/24=fd00:1::/96`
//!
//! [`LanPrefix`]: nsplane_nat::LanPrefix
//! [`PeerMapping`]: nsplane_nat::PeerMapping
//! [`SelfMapping`]: nsplane_nat::SelfMapping
//! [`TranslationTable`]: nsplane_nat::TranslationTable
//! [`TranslationTable::builder`]: nsplane_nat::TranslationTable::builder
//! [`Translator`]: nsplane_nat::Translator
//! [`Translator::new`]: nsplane_nat::Translator::new
//! [`Translator::stats`]: nsplane_nat::Translator::stats
//! [`Translator::store`]: nsplane_nat::Translator::store

#[cfg(unix)]
mod unix {
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
    use std::process::ExitCode;
    use std::str::FromStr;
    use std::sync::Arc;

    use anyhow::{Context as _, anyhow, bail};
    use clap::Parser;
    use nsplane::x25519::PublicKey;
    use nsplane::{AllowedIp, EngineHandle};
    use nsplane_core::{PacketFilter, Verdict};
    use nsplane_examples::echo::{Backend, EchoArgs};
    use nsplane_examples::node::{
        self, NodeArgs, PeerSpec, TunArgs, build_engine_with, configure_peers, configure_tun,
        contains, decode_key, encode_public_key, init_logging, parse_cidr, serve_uapi,
    };
    use nsplane_examples::status::Status;
    use nsplane_nat::{
        LanPrefix, PeerMapping, SelfMapping, TranslationTable, Translator, TranslatorStats,
    };
    use nsplane_packet::{PacketBuf, PeerId};
    use nsplane_tun::Tun;
    use serde_json::{Value, json};

    /// A TUN node translating local IPv4 to IPv6 in the tunnel (needs root).
    #[derive(Debug, Parser)]
    #[command(name = "translate_node", version)]
    pub(crate) struct Args {
        #[command(flatten)]
        node: NodeArgs,

        #[command(flatten)]
        echo: EchoArgs,

        #[command(flatten)]
        tun: TunArgs,

        /// This node's IPv4 address and the `node4` of its own /127 group
        #[arg(long = "self", value_name = "SELF4=NODE4")]
        self_mapping: Option<SelfSpec>,

        /// The addresses of a `--peer`, repeatable:
        /// `<base64 pubkey>,node6=<IPv6>,node4=<IPv6>[,alias4=<IPv4>][,alias6=<IPv6>]`
        #[arg(long, value_name = "SPEC")]
        map: Vec<MapSpec>,

        /// An IPv4 LAN prefix and its IPv6 /96, behind this node or behind a `--peer`,
        /// repeatable: `<IPv4>/<len>=<IPv6>/96[@<base64 pubkey>]`
        #[arg(long, value_name = "LAN4=LAN6[@PUBKEY]")]
        lan: Vec<LanSpec>,
    }

    /// `--self`.
    #[derive(Debug, Clone, Copy)]
    pub(crate) struct SelfSpec(SelfMapping);

    impl FromStr for SelfSpec {
        type Err = anyhow::Error;

        fn from_str(s: &str) -> anyhow::Result<Self> {
            let (self4, node4) = s
                .split_once('=')
                .ok_or_else(|| anyhow!("`{s}` is not `<self4>=<node4>`"))?;
            Ok(Self(SelfMapping {
                self4: self4
                    .parse()
                    .with_context(|| format!("invalid IPv4 address `{self4}`"))?,
                node4: node4
                    .parse()
                    .with_context(|| format!("invalid IPv6 address `{node4}`"))?,
            }))
        }
    }

    /// One `--map`.
    #[derive(Debug, Clone)]
    pub(crate) struct MapSpec {
        public_key: PublicKey,
        mapping: PeerMapping,
    }

    impl FromStr for MapSpec {
        type Err = anyhow::Error;

        fn from_str(spec: &str) -> anyhow::Result<Self> {
            let mut parts = spec.split(',');
            let public_key = PublicKey::from(decode_key(parts.next().unwrap_or_default())?);
            let (mut node6, mut node4, mut alias6, mut alias4) = (None, None, None, None);
            for part in parts {
                let (name, value) = part
                    .split_once('=')
                    .ok_or_else(|| anyhow!("`{part}` is not `name=value`"))?;
                let v6 = || {
                    value
                        .parse::<Ipv6Addr>()
                        .with_context(|| format!("invalid IPv6 address `{value}`"))
                };
                match name {
                    "node6" => node6 = Some(v6()?),
                    "node4" => node4 = Some(v6()?),
                    "alias6" => alias6 = Some(v6()?),
                    "alias4" => {
                        alias4 = Some(
                            value
                                .parse::<Ipv4Addr>()
                                .with_context(|| format!("invalid IPv4 address `{value}`"))?,
                        );
                    }
                    _ => bail!("unknown map option `{name}`"),
                }
            }
            let mapping = PeerMapping {
                node6: node6.ok_or_else(|| anyhow!("`{spec}` has no node6"))?,
                node4: node4.ok_or_else(|| anyhow!("`{spec}` has no node4"))?,
                alias6,
                alias4,
            };
            Ok(Self {
                public_key,
                mapping,
            })
        }
    }

    /// One `--lan`.
    #[derive(Debug, Clone)]
    pub(crate) struct LanSpec {
        lan4: (Ipv4Addr, u8),
        lan6: (Ipv6Addr, u8),
        peer: Option<PublicKey>,
    }

    impl FromStr for LanSpec {
        type Err = anyhow::Error;

        fn from_str(s: &str) -> anyhow::Result<Self> {
            // The base64 key may contain `=` padding, so the key is split off first.
            let (pair, peer) = match s.split_once('@') {
                Some((pair, key)) => (pair, Some(PublicKey::from(decode_key(key)?))),
                None => (s, None),
            };
            let (lan4, lan6) = pair
                .split_once('=')
                .ok_or_else(|| anyhow!("`{s}` is not `<lan4>=<lan6>[@<pubkey>]`"))?;
            let lan4 = match parse_cidr(lan4)? {
                AllowedIp {
                    addr: IpAddr::V4(addr),
                    cidr,
                } => (addr, cidr),
                AllowedIp { .. } => bail!("`{lan4}` is not an IPv4 prefix"),
            };
            let lan6 = match parse_cidr(lan6)? {
                AllowedIp {
                    addr: IpAddr::V6(addr),
                    cidr,
                } => (addr, cidr),
                AllowedIp { .. } => bail!("`{lan6}` is not an IPv6 prefix"),
            };
            Ok(Self { lan4, lan6, peer })
        }
    }

    /// The engine's share of the translator; the status file reads the same one.
    struct SharedTranslator(Arc<Translator>);

    impl PacketFilter for SharedTranslator {
        fn inbound(&self, peer: PeerId, packet: &mut PacketBuf) -> Verdict {
            self.0.inbound(peer, packet)
        }

        fn outbound(&self, peer: PeerId, packet: &mut PacketBuf) -> Verdict {
            self.0.outbound(peer, packet)
        }
    }

    /// Adds `ip` to `allowed` unless it is there already.
    fn allow(allowed: &mut Vec<AllowedIp>, addr: IpAddr, cidr: u8) {
        let ip = AllowedIp { addr, cidr };
        if !allowed.contains(&ip) {
            allowed.push(ip);
        }
    }

    /// The `--peer`s with the mapped addresses and LAN prefixes added to their allowed IPs.
    fn peers_with_mappings(args: &Args) -> anyhow::Result<Vec<PeerSpec>> {
        let mut peers = args.node.peer.clone();
        let peer_of = |key: &PublicKey, option: &str| {
            peers
                .iter()
                .position(|peer| peer.public_key == *key)
                .ok_or_else(|| {
                    anyhow!(
                        "{option} names {}, which is no --peer",
                        encode_public_key(key)
                    )
                })
        };
        let mut added = Vec::new();
        for map in &args.map {
            let index = peer_of(&map.public_key, "--map")?;
            let m = map.mapping;
            let mut ips = vec![(m.node6.into(), 128), (m.node4.into(), 128)];
            ips.extend(m.alias6.map(|a| (a.into(), 128)));
            ips.extend(m.alias4.map(|a| (a.into(), 32)));
            added.push((index, ips));
        }
        for lan in &args.lan {
            if let Some(key) = &lan.peer {
                let index = peer_of(key, "--lan")?;
                added.push((
                    index,
                    vec![
                        (lan.lan4.0.into(), lan.lan4.1),
                        (lan.lan6.0.into(), lan.lan6.1),
                    ],
                ));
            }
        }
        for (index, ips) in added {
            if let Some(peer) = peers.get_mut(index) {
                for (addr, cidr) in ips {
                    allow(&mut peer.allowed_ips, addr, cidr);
                }
            }
        }
        Ok(peers)
    }

    /// The interface addresses: `--address`es, and `self4/32` unless one covers it.
    fn addresses(args: &Args) -> Vec<AllowedIp> {
        let mut addresses = args.tun.address.clone();
        if let Some(SelfSpec(own)) = args.self_mapping
            && !addresses
                .iter()
                .any(|net| contains(net, IpAddr::V4(own.self4)))
        {
            addresses.push(AllowedIp {
                addr: IpAddr::V4(own.self4),
                cidr: 32,
            });
        }
        addresses
    }

    /// The translation table of `args`, with the engine's ids of the peers.
    async fn table(handle: &EngineHandle, args: &Args) -> anyhow::Result<TranslationTable> {
        let peer_id = |key: PublicKey| async move {
            handle
                .peer_id(key)
                .await?
                .with_context(|| format!("{} is not configured", encode_public_key(&key)))
        };
        let mut builder = TranslationTable::builder();
        if let Some(SelfSpec(own)) = args.self_mapping {
            builder = builder.self_mapping(own);
        }
        for map in &args.map {
            builder = builder.peer(peer_id(map.public_key).await?, map.mapping);
        }
        for lan in &args.lan {
            let peer = match lan.peer {
                Some(key) => Some(peer_id(key).await?),
                None => None,
            };
            builder = builder.lan(LanPrefix {
                lan4: lan.lan4,
                lan6: lan.lan6,
                peer,
            });
        }
        builder.build().context("invalid translation table")
    }

    /// The status file's `extra.translate` object.
    fn translate_json(stats: TranslatorStats) -> Value {
        json!({
            "translated_out": stats.translated_out,
            "translated_in": stats.translated_in,
            "rewritten_out": stats.rewritten_out,
            "rewritten_in": stats.rewritten_in,
            "dropped_out": stats.dropped_out,
            "dropped_in": stats.dropped_in,
            "reassembled": stats.reassembled,
        })
    }

    pub(crate) async fn main(args: Args) -> anyhow::Result<ExitCode> {
        init_logging(&args.node.log)?;
        let peers = peers_with_mappings(&args)?;
        let tun = Tun::create(&args.tun.tun_name)
            .with_context(|| format!("cannot create TUN {}", args.tun.tun_name))?;
        let name = tun.name().unwrap_or_else(|_| args.tun.tun_name.clone());
        configure_tun(&name, &addresses(&args), args.tun.mtu, &peers)?;
        let (source, sink) = tun.split().context("cannot open the TUN device")?;
        // The table names peers by the ids the engine assigns when they are added, so the
        // translator starts empty (everything passes) and gets its table right after.
        let translator = Arc::new(Translator::new(TranslationTable::default()));
        let engine_translator = SharedTranslator(Arc::clone(&translator));
        let node = build_engine_with(source, sink, &args.node, |builder| {
            builder.filter(Box::new(engine_translator))
        })?;
        let handle = node.engine.handle();
        configure_peers(&handle, &peers).await?;
        translator.store(table(&handle, &args).await?);
        tracing::info!(
            peers = args.map.len(),
            lans = args.lan.len(),
            self_mapping = args.self_mapping.is_some(),
            "translation table set"
        );

        let socket = serve_uapi(handle.clone(), &name, node.transports.listen.port())?;
        tracing::info!(interface = %name, listen = %node.transports.listen, uapi = %socket, "translate node started");

        let status = args.node.status_file.clone().map(|path| {
            Status::new(path, handle, node.transports.listen).extra(move |extra| {
                extra.insert("translate".to_owned(), translate_json(translator.stats()));
            })
        });
        node::run(node.engine, &args.echo, Backend::Kernel, status).await
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        const KEY: &str = "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=";

        fn v6(s: &str) -> Ipv6Addr {
            s.parse().unwrap()
        }

        #[test]
        fn map_spec() {
            let map: MapSpec = format!("{KEY},node6=fd00::2:0,node4=fd00::2:1,alias4=10.1.0.2")
                .parse()
                .unwrap();
            assert_eq!(map.public_key.to_bytes(), [1; 32]);
            assert_eq!(map.mapping.node6, v6("fd00::2:0"));
            assert_eq!(map.mapping.node4, v6("fd00::2:1"));
            assert_eq!(map.mapping.alias4, Some(Ipv4Addr::new(10, 1, 0, 2)));
            assert_eq!(map.mapping.alias6, None);
            assert!(format!("{KEY},node4=fd00::2:1").parse::<MapSpec>().is_err());
            assert!(
                format!("{KEY},node6=fd00::,node4=fd00::1,alias4=fd00::9")
                    .parse::<MapSpec>()
                    .is_err()
            );
            assert!(
                format!("{KEY},node6=fd00::,node4=fd00::1,mtu=1")
                    .parse::<MapSpec>()
                    .is_err()
            );
        }

        #[test]
        fn lan_spec() {
            let local: LanSpec = "192.168.50.0/24=fd00:1::/96".parse().unwrap();
            assert_eq!(local.lan4, (Ipv4Addr::new(192, 168, 50, 0), 24));
            assert_eq!(local.lan6, (v6("fd00:1::"), 96));
            assert!(local.peer.is_none());
            let remote: LanSpec = format!("10.9.0.0/16=fd00:2::/96@{KEY}").parse().unwrap();
            assert_eq!(remote.peer.map(|key| key.to_bytes()), Some([1; 32]));
            assert!("fd00:1::/96=192.168.50.0/24".parse::<LanSpec>().is_err());
            assert!("192.168.50.0/24".parse::<LanSpec>().is_err());
        }

        #[test]
        fn mapped_addresses_are_allowed_and_self4_is_an_address() {
            let args = Args::try_parse_from([
                "translate_node",
                "--private-key",
                KEY,
                "--self",
                "10.1.0.1=fd00::1:1",
                "--peer",
                &format!("{KEY},allowed-ips=fd00::2:1/128"),
                "--map",
                &format!("{KEY},node6=fd00::2:0,node4=fd00::2:1,alias4=10.1.0.2"),
                "--lan",
                "192.168.50.0/24=fd00:1::/96",
                "--lan",
                &format!("10.9.0.0/16=fd00:2::/96@{KEY}"),
            ])
            .unwrap();
            let peers = peers_with_mappings(&args).unwrap();
            let allowed: Vec<String> = peers[0]
                .allowed_ips
                .iter()
                .map(|ip| format!("{}/{}", ip.addr, ip.cidr))
                .collect();
            assert_eq!(
                allowed,
                [
                    "fd00::2:1/128",
                    "fd00::2:0/128",
                    "10.1.0.2/32",
                    "10.9.0.0/16",
                    "fd00:2::/96"
                ]
            );
            let addresses = addresses(&args);
            assert_eq!(addresses.len(), 1);
            assert_eq!(addresses[0].addr, IpAddr::V4(Ipv4Addr::new(10, 1, 0, 1)));
            assert_eq!(addresses[0].cidr, 32);
        }

        #[test]
        fn map_of_unknown_peer() {
            let other = "AgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgI=";
            let args = Args::try_parse_from([
                "translate_node",
                "--private-key",
                KEY,
                "--peer",
                KEY,
                "--map",
                &format!("{other},node6=fd00::2:0,node4=fd00::2:1"),
            ])
            .unwrap();
            assert!(peers_with_mappings(&args).is_err());
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
    anyhow::bail!("translate_node runs on Linux and macOS only")
}
