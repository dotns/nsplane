//! A virtual machine reaching WireGuard peers through one engine: the wiring of the
//! `vm_wireguard` example.
//!
//! The guest runtime (QEMU `-netdev stream`, passt, libkrun) carries the guest's ethernet
//! frames over a frame transport. [`start`] puts an `nsplane-ether` adapter on it and builds
//! an engine on the adapter's IP side instead of a TUN device:
//!
//! ```text
//! guest (virtio-net) -> frames -> EtherSource / EtherSink -> Engine -> UdpTransport -> peer
//! ```
//!
//! - **Address plan** ([`VmArgs::ether_config`]): the guest leases its tunnel IPv4 address
//!   by DHCP, with the gateway, the DNS servers and the tunnel MTU. The adapter answers ARP
//!   for the gateway only; every IP packet the guest sends, to the gateway or past it,
//!   enters the engine and is routed to the peer whose allowed IPs contain its destination.
//!   The default gateway is the first host of the prefix other than the guest, typically
//!   the peer's own tunnel address. IPv6 is optional: a /64 advertised by router
//!   advertisement, where the guest picks its address itself (SLAAC).
//! - **MTU**: the link MTU is the tunnel MTU, so the guest never sends a packet the
//!   tunnel cannot carry. It is in the DHCP lease (option 26), in the router advertisement
//!   and in the engine, whose fragmentation stage answers a larger IPv4 packet with DF set
//!   with an ICMP Fragmentation Needed, splits one without DF, and answers a larger IPv6
//!   packet with an `ICMPv6` Packet Too Big.
//! - **Masquerade** (optional, IPv6): when the tunnel gives a single IPv6 address instead
//!   of a /64, the guest's flows from the advertised prefix are rewritten to that address
//!   on their way in ([`Masquerade::forward`]) and the replies restored on their way back
//!   ([`Masquerade::reverse`]). IPv4 needs none: the lease is the tunnel address.
//! - **ACL** (optional, [`Acl`]): an [`AclFilter`] on the engine with a reloadable
//!   [`VmPolicy`]: the flows the guest may open to the peers (`from_guest`, by protocol and
//!   port) and the flows the peers may open to the guest (`to_guest`, typed rules with
//!   source and destination prefixes). Replies of an accepted flow pass both ways;
//!   everything else is dropped and counted in [`AclFilterStats`].

use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::path::PathBuf;
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

use anyhow::{Context as _, anyhow, bail, ensure};
use clap::Args;
use nsplane::{
    AllowedIp, Engine, FragmentConfig, MapSink, MapVerdict, PacketBuf, PacketSource, PeerId,
};
use nsplane_acl::{
    AclEngine, AclFilter, AclFilterStats, Label, LabelSet, NamespaceMember, NamespacePolicy,
    OutboundRule, PeerLabelMap, Rule,
};
use nsplane_ether::{
    DhcpConfig, EtherConfig, EtherHandle, EtherSource, FrameRead, FrameWrite, MacAddr, spawn_port,
};
use nsplane_nat::{Masquerade, MasqueradeConfig, MasqueradeDecision, MasqueradeVerdict};
use nsplane_packet::FiveTuple;
use serde::Deserialize;
use serde_json::{Value, json};
use tokio::sync::{oneshot, watch};

use crate::node::{NodeArgs, build_engine_with, configure_peers, contains, parse_cidr};

/// MAC of the gateway the adapter stands in for (locally administered).
pub const GATEWAY_MAC: MacAddr = MacAddr([0x02, 0x00, 0x00, 0x00, 0x00, 0x01]);

/// The default link MTU: the tunnel MTU of a standard WireGuard interface.
pub const DEFAULT_MTU: u16 = 1420;

/// How often [`Acl::watch`] reads the policy file.
const POLL_INTERVAL: Duration = Duration::from_secs(1);

/// The ACL namespace the peers are members of.
const NAMESPACE: &str = "vm";

/// The ACL label of every peer.
const REMOTE: &str = "remote";

/// The guest side of a `vm_wireguard` node, flattened into its arguments next to
/// [`NodeArgs`].
#[derive(Debug, Clone, Args)]
pub struct VmArgs {
    /// The guest's tunnel IPv4 address with its prefix, handed out by DHCP
    #[arg(long, value_name = "CIDR", value_parser = parse_cidr)]
    pub address: AllowedIp,

    /// Gateway of the lease; default: the first host of the prefix other than the guest
    #[arg(long, value_name = "IPV4")]
    pub gateway: Option<Ipv4Addr>,

    /// DNS server for the guest, repeatable: IPv4 in the lease, IPv6 in the router
    /// advertisement
    #[arg(long, value_name = "IP")]
    pub dns: Vec<IpAddr>,

    /// Link MTU: the tunnel MTU, in the lease, the router advertisement and the engine
    #[arg(long, value_name = "N", default_value_t = DEFAULT_MTU)]
    pub mtu: u16,

    /// IPv6 /64 advertised to the guest by router advertisement; the gateway is its `::1`
    #[arg(long, value_name = "CIDR", value_parser = parse_cidr)]
    pub ipv6_prefix: Option<AllowedIp>,

    /// Masquerade the guest's IPv6 flows from `--ipv6-prefix` to this tunnel address
    #[arg(long, value_name = "IPV6", requires = "ipv6_prefix")]
    pub masquerade: Option<Ipv6Addr>,

    /// ACL policy file (JSON `{"from_guest": [...], "to_guest": [...]}`), re-read every
    /// second; without it the engine filters nothing
    #[arg(long, value_name = "PATH")]
    pub policy: Option<PathBuf>,
}

impl VmArgs {
    /// The guest's tunnel IPv4 address.
    pub fn guest_ipv4(&self) -> anyhow::Result<Ipv4Addr> {
        match self.address.addr {
            IpAddr::V4(addr) if self.address.cidr <= 32 => Ok(addr),
            _ => bail!("--address must be an IPv4 CIDR"),
        }
    }

    /// The gateway of the lease: `--gateway`, or the first host of the guest's prefix other
    /// than the guest.
    pub fn gateway_ipv4(&self) -> anyhow::Result<Ipv4Addr> {
        let guest = self.guest_ipv4()?;
        let gateway = if let Some(gateway) = self.gateway {
            gateway
        } else {
            ensure!(
                self.address.cidr <= 30,
                "--address /{} has no room for a gateway; give --gateway",
                self.address.cidr
            );
            let host_bits = 32 - u32::from(self.address.cidr);
            let network = guest.to_bits() & u32::MAX.checked_shl(host_bits).unwrap_or(0);
            let first = Ipv4Addr::from_bits(network + 1);
            if first == guest {
                Ipv4Addr::from_bits(network + 2)
            } else {
                first
            }
        };
        ensure!(gateway != guest, "--gateway is the guest's own address");
        Ok(gateway)
    }

    /// The advertised /64.
    fn ipv6_prefix(&self) -> anyhow::Result<Option<Ipv6Addr>> {
        self.ipv6_prefix
            .map(|prefix| match prefix.addr {
                IpAddr::V6(addr) if prefix.cidr == 64 => Ok(addr),
                _ => Err(anyhow!("--ipv6-prefix must be an IPv6 /64")),
            })
            .transpose()
    }

    /// The adapter configuration: the DHCP lease of the tunnel address with gateway, DNS
    /// and MTU, ARP for the gateway, and the router advertisement of `--ipv6-prefix` with
    /// its `::1` as the global gateway address.
    pub fn ether_config(&self) -> anyhow::Result<EtherConfig> {
        let guest = self.guest_ipv4()?;
        let gateway = self.gateway_ipv4()?;
        let prefix = self.ipv6_prefix()?;
        let dns4 = self.dns.iter().filter_map(|ip| match ip {
            IpAddr::V4(v4) => Some(*v4),
            IpAddr::V6(_) => None,
        });
        let dns6 = self.dns.iter().filter_map(|ip| match ip {
            IpAddr::V6(v6) => Some(*v6),
            IpAddr::V4(_) => None,
        });
        Ok(EtherConfig {
            gateway_ipv4: Some(gateway),
            gateway_ipv6: prefix.map(|p| Ipv6Addr::from_bits(p.to_bits() | 1)),
            ipv6_prefix: prefix,
            ipv6_dns: dns6.collect(),
            dhcp: Some(DhcpConfig {
                router: Some(gateway),
                dns: dns4.collect(),
                mtu: Some(self.mtu),
                ..DhcpConfig::new(gateway, guest, self.address.cidr)
            }),
            mtu: self.mtu,
            ..EtherConfig::new(GATEWAY_MAC)
        })
    }

    /// The masquerade of `--masquerade`: flows from the advertised /64 take the tunnel
    /// address as their source.
    fn masquerade(&self) -> anyhow::Result<Option<Masquerade>> {
        let (Some(source), Some(prefix)) = (self.masquerade, self.ipv6_prefix()?) else {
            return Ok(None);
        };
        let prefix = AllowedIp {
            addr: IpAddr::V6(prefix),
            cidr: 64,
        };
        let decide = move |tuple: &FiveTuple| {
            (contains(&prefix, tuple.src) && tuple.src != IpAddr::V6(source))
                .then_some(MasqueradeDecision { source, route: 0 })
        };
        Ok(Some(Masquerade::new(decide, MasqueradeConfig::default())))
    }
}

/// The ACL policy of a `vm_wireguard` node.
///
/// Rules only accept: a flow no rule accepts is dropped, and the replies of an accepted
/// flow pass both ways.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VmPolicy {
    /// The flows the guest may open to the peers, by protocol and destination port (or
    /// ICMP type).
    #[serde(default)]
    pub from_guest: Vec<OutboundRule>,
    /// The flows the peers may open to the guest, by source and destination prefix,
    /// protocol and destination port (or ICMP type).
    #[serde(default)]
    pub to_guest: Vec<Rule>,
}

impl VmPolicy {
    /// The namespace that enforces the policy: every peer is a member, its `to_guest`
    /// rules accept inbound flows and its `from_guest` rules restrict outbound ones.
    fn namespace(self) -> NamespacePolicy {
        NamespacePolicy {
            members: vec![NamespaceMember {
                label: Label::from(REMOTE),
                addresses: Vec::new(),
            }],
            rules: self.to_guest,
            outbound: Some(self.from_guest),
            ..NamespacePolicy::default()
        }
    }
}

/// Reload state of an [`Acl`].
#[derive(Debug, Default)]
struct PolicyState {
    /// The file content of the last poll.
    seen: Option<Vec<u8>>,
    reloads: u64,
    errors: u64,
}

/// The engine's ACL and its policy file. Clones share the filter, the policy and the state.
#[derive(Debug, Clone)]
pub struct Acl {
    path: PathBuf,
    engine: Arc<AclEngine>,
    filter: AclFilter,
    state: Arc<Mutex<PolicyState>>,
}

impl Acl {
    /// An ACL whose policy is the file at `path`, read once now; the filter labels every
    /// peer in `identities` as a member of the policy's namespace.
    fn load(path: PathBuf, identities: Arc<PeerLabelMap>) -> anyhow::Result<Self> {
        let engine = Arc::new(AclEngine::new());
        let filter = AclFilter::new(Arc::clone(&engine), identities);
        let content = std::fs::read(&path)
            .with_context(|| format!("cannot read the policy {}", path.display()))?;
        let acl = Self {
            path,
            engine,
            filter,
            state: Arc::default(),
        };
        acl.install(&content)
            .with_context(|| format!("invalid policy {}", acl.path.display()))?;
        acl.lock().seen = Some(content);
        Ok(acl)
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, PolicyState> {
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Parses `content` and installs it atomically; on error the previous policy stays.
    fn install(&self, content: &[u8]) -> anyhow::Result<()> {
        let policy: VmPolicy = serde_json::from_slice(content)?;
        self.engine.store_namespace(NAMESPACE, policy.namespace())?;
        Ok(())
    }

    /// Reads the policy file and installs it if its content changed since the last read.
    /// Returns whether a new policy was installed; a file that cannot be read or parsed
    /// keeps the previous policy and is reported once.
    pub async fn reload(&self) -> bool {
        let content = match tokio::fs::read(&self.path).await {
            Ok(content) => content,
            Err(error) => {
                tracing::warn!(path = %self.path.display(), %error, "cannot read the policy, keeping the previous policy");
                return false;
            }
        };
        if self.lock().seen.as_ref() == Some(&content) {
            return false;
        }
        let installed = self.install(&content);
        let mut state = self.lock();
        state.seen = Some(content);
        match installed {
            Ok(()) => {
                state.reloads += 1;
                tracing::info!(path = %self.path.display(), "policy reloaded");
                true
            }
            Err(error) => {
                state.errors += 1;
                tracing::warn!(path = %self.path.display(), error = format!("{error:#}"), "policy rejected, keeping the previous policy");
                false
            }
        }
    }

    /// Reloads the policy file every second, forever.
    pub async fn watch(self) {
        let mut ticks = tokio::time::interval(POLL_INTERVAL);
        loop {
            ticks.tick().await;
            self.reload().await;
        }
    }

    /// The filter's counters.
    pub fn stats(&self) -> AclFilterStats {
        self.filter.stats()
    }

    /// The status file's `extra.acl` object.
    pub fn status_json(&self) -> Value {
        let stats = self.stats();
        let state = self.lock();
        json!({
            "reloads": state.reloads,
            "reload_errors": state.errors,
            "accepted": stats.accepted,
            "replies": stats.replies,
            "denied": stats.denied,
            "protocol": stats.protocol,
            "outbound_denied": stats.outbound_denied,
            "outbound_replies": stats.outbound_replies,
            "unknown_peer": stats.unknown_peer,
            "fragment": stats.fragment,
            "malformed": stats.malformed,
        })
    }
}

/// The guest's IP packets for the engine: the masquerade's forward step, and a signal once
/// the guest is gone.
#[derive(Debug)]
struct GuestSource {
    inner: EtherSource,
    masquerade: Option<Arc<Masquerade>>,
    gone: Option<oneshot::Sender<()>>,
}

impl PacketSource for GuestSource {
    async fn recv(&mut self) -> io::Result<PacketBuf> {
        loop {
            let mut packet = match self.inner.recv().await {
                Ok(packet) => packet,
                Err(error) => {
                    if let Some(gone) = self.gone.take() {
                        let _ = gone.send(());
                    }
                    return Err(error);
                }
            };
            match self.masquerade.as_ref().map(|m| m.forward(&mut packet)) {
                Some(MasqueradeVerdict::Drop(reason)) => {
                    tracing::debug!(reason, "guest packet dropped by the masquerade");
                }
                _ => return Ok(packet),
            }
        }
    }

    fn recycle(&mut self, bufs: &mut Vec<PacketBuf>) {
        self.inner.recycle(bufs);
    }

    fn mtu(&self) -> watch::Receiver<u16> {
        self.inner.mtu()
    }
}

/// A running `vm_wireguard` node. See [`start`].
#[derive(Debug)]
pub struct Vm {
    /// The engine.
    pub engine: Engine,
    /// The local address of the engine's transport.
    pub listen: SocketAddr,
    /// The adapter's counters and learned guest MAC.
    pub ether: EtherHandle,
    /// The ACL of `--policy`.
    pub acl: Option<Acl>,
    /// The masquerade of `--masquerade`.
    pub masquerade: Option<Arc<Masquerade>>,
    /// Resolves once the guest disconnected.
    pub guest_gone: oneshot::Receiver<()>,
}

/// Starts the adapter on the guest's frame transport and the engine on its IP side.
///
/// The adapter runs on `reader` and `writer`; the engine gets the transports and `--peer`s
/// of `node` and the address plan, masquerade and ACL of `vm`. The policy file is read once before the engine starts; a
/// missing or invalid one is an error.
pub async fn start<R: FrameRead, W: FrameWrite>(
    reader: R,
    writer: W,
    node: &NodeArgs,
    vm: &VmArgs,
) -> anyhow::Result<Vm> {
    let config = vm.ether_config()?;
    let masquerade = vm.masquerade()?.map(Arc::new);
    let identities = Arc::new(PeerLabelMap::new());
    let acl = vm
        .policy
        .clone()
        .map(|path| Acl::load(path, Arc::clone(&identities)))
        .transpose()?;

    let (source, sink, ether) = spawn_port(reader, writer, config);
    let (gone, guest_gone) = oneshot::channel();
    let source = GuestSource {
        inner: source,
        masquerade: masquerade.clone(),
        gone: Some(gone),
    };
    let reverse = masquerade.clone();
    let sink = MapSink::new(sink, move |packet: &mut PacketBuf, _: PeerId| match reverse
        .as_ref()
        .map(|m| m.reverse(packet))
    {
        Some(MasqueradeVerdict::Drop(_)) => MapVerdict::Drop,
        _ => MapVerdict::Keep,
    });
    let filter = acl.as_ref().map(|acl| acl.filter.clone());
    let built = build_engine_with(source, sink, node, |builder| {
        let builder = builder.fragmenter(FragmentConfig::default());
        match filter {
            Some(filter) => builder.filter(Box::new(filter)),
            None => builder,
        }
    })?;
    let handle = built.engine.handle();
    configure_peers(&handle, &node.peer).await?;
    for peer in &node.peer {
        if let Some(id) = handle.peer_id(peer.public_key).await? {
            identities.insert(id, LabelSet::new([Label::from(REMOTE)]));
        }
    }
    Ok(Vm {
        engine: built.engine,
        listen: built.transports.listen,
        ether,
        acl,
        masquerade,
        guest_gone,
    })
}

/// The status file's `extra.ether` object.
pub fn ether_json(ether: &EtherHandle) -> Value {
    let stats = ether.stats();
    json!({
        "guest_mac": ether.guest_mac().map(|mac| mac.to_string()),
        "frames_in": stats.frames_in,
        "frames_out": stats.frames_out,
        "ip_in": stats.ip_in,
        "ip_out": stats.ip_out,
        "arp_replies": stats.arp_replies,
        "nd_replies": stats.nd_replies,
        "dhcp_replies": stats.dhcp_replies,
        "drop_malformed": stats.drop_malformed,
        "drop_no_guest_mac": stats.drop_no_guest_mac,
        "drop_backlog": stats.drop_backlog,
    })
}

/// The status file's `extra.masquerade` object.
pub fn masquerade_json(masquerade: &Masquerade) -> Value {
    let stats = masquerade.stats();
    json!({
        "flows": stats.flows,
        "forwarded": stats.forwarded,
        "reversed": stats.reversed,
        "passed": stats.passed,
        "dropped": stats.tcp_not_syn + stats.capacity + stats.route_changed
            + stats.tokens_exhausted + stats.bad_checksum,
    })
}
