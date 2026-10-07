//! A TUN node that filters what its peers send with an `nsplane-acl` policy.
//!
//! Runs like `tun_node` (TUN device, `ip` configuration on Linux, UAPI on the standard
//! socket, echo and checks on the kernel stack) with two packet filters in the engine: an
//! [`AclFilter`] that accepts inbound packets only as the `--policy` allows, then a
//! [`FlowTracker`] that counts the accepted traffic per flow. Needs root (or
//! `CAP_NET_ADMIN`).
//!
//! - Identities: each `--identity <WG_PUBKEY>=<LABEL>[,<LABEL>]` gives the ACL labels of a
//!   `--peer` ([`PeerLabelMap`], a [`LabelSet`]). Labels are opaque: a policy rule with the
//!   source `key:<hex>` matches the label `key:<lowercase hex>`, and CIDR and host-alias
//!   sources match the packet's source address whatever the labels. Packets from a peer
//!   without identity are dropped.
//! - Live reload: the policy file (JSON [`AclPolicy`]) is read every second; when its
//!   content changed it is parsed and swapped into the [`AclEngine`] atomically, logging
//!   `policy reloaded (N rules)`, or the error while the previous policy stays in effect.
//!   Until the first valid policy, every inbound packet is dropped (fail closed).
//! - Stateful replies: connections the gateway side opens get their replies even when
//!   the policy does not allow that inbound flow ([`AclFilterConfig::stateful_replies`]).
//! - Status: `extra.acl` holds the [`AclFilter::stats`] counters and the policy state,
//!   `extra.flows` the tracker's counters and flows.
//!
//! The sample policy `examples/policies/acl_gateway.json` is written for a gateway at
//! `10.0.0.1` and its peer at `10.0.0.2`: it allows TCP and UDP port 7 (echo) from the peer
//! address `10.0.0.2` to the gateway and denies everything else (e.g. TCP port 8). Its
//! built-in tests must pass for it to load.
//!
//! APIs shown: [`AclEngine::load`], [`AclFilter::with_config`], [`PeerLabelMap`],
//! [`LabelSet`], [`FlowTracker`], `EngineBuilder::filter` (through `build_engine_with`), and
//! the shared TUN node assembly.
//!
//! Usage: `sudo cargo run -p nsplane-examples --bin acl_gateway -- --private-key <KEY>
//! --address 10.0.0.1/24 --peer <PUBKEY>,endpoint=192.0.2.2:51820,allowed-ips=10.0.0.2/32
//! --identity <PUBKEY>=peer-a --policy examples/policies/acl_gateway.json --echo-port 7`
//!
//! [`AclEngine`]: nsplane_acl::AclEngine
//! [`AclEngine::load`]: nsplane_acl::AclEngine::load
//! [`AclFilter`]: nsplane_acl::AclFilter
//! [`AclFilter::stats`]: nsplane_acl::AclFilter::stats
//! [`AclFilter::with_config`]: nsplane_acl::AclFilter::with_config
//! [`AclFilterConfig::stateful_replies`]: nsplane_acl::AclFilterConfig::stateful_replies
//! [`AclPolicy`]: nsplane_acl::AclPolicy
//! [`FlowTracker`]: nsplane_acl::FlowTracker
//! [`LabelSet`]: nsplane_acl::LabelSet
//! [`PeerLabelMap`]: nsplane_acl::PeerLabelMap

#[cfg(unix)]
mod unix {
    use std::net::SocketAddr;
    use std::path::PathBuf;
    use std::process::ExitCode;
    use std::str::FromStr;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
    use std::time::Duration;

    use anyhow::{Context as _, anyhow, ensure};
    use clap::Parser;
    use nsplane::x25519::PublicKey;
    use nsplane_acl::{
        AclEngine, AclFilter, AclFilterConfig, AclPolicy, FlowTracker, Label, LabelSet,
        PeerLabelMap,
    };
    use nsplane_examples::echo::{Backend, EchoArgs};
    use nsplane_examples::node::{
        self, NodeArgs, TunArgs, build_engine_with, configure_peers, configure_tun, decode_key,
        encode_public_key, init_logging, serve_uapi,
    };
    use nsplane_examples::status::Status;
    use serde_json::{Value, json};

    /// How often the policy file is read.
    const POLL_INTERVAL: Duration = Duration::from_secs(1);
    /// Flows the tracker holds at most.
    const FLOW_CAPACITY: usize = 1024;

    /// A TUN node whose inbound traffic is filtered by a reloadable ACL policy (needs
    /// root).
    #[derive(Debug, Parser)]
    #[command(name = "acl_gateway", version)]
    pub(crate) struct Args {
        #[command(flatten)]
        node: NodeArgs,

        #[command(flatten)]
        echo: EchoArgs,

        #[command(flatten)]
        tun: TunArgs,

        /// ACL policy file (JSON), re-read every second
        #[arg(long, value_name = "PATH")]
        policy: PathBuf,

        /// The ACL labels of a peer, repeatable: `<base64 pubkey>=<label>[,<label>]` (labels
        /// contain neither `=` nor `,`)
        #[arg(long, value_name = "WG_PUBKEY=LABELS")]
        identity: Vec<Identity>,
    }

    /// One `--identity`.
    #[derive(Debug, Clone)]
    pub(crate) struct Identity {
        public_key: PublicKey,
        labels: LabelSet,
    }

    impl FromStr for Identity {
        type Err = anyhow::Error;

        fn from_str(s: &str) -> anyhow::Result<Self> {
            // The base64 key may end in `=` padding; the labels never contain `=`.
            let (key, labels) = s
                .rsplit_once('=')
                .ok_or_else(|| anyhow!("`{s}` is not `<pubkey>=<label>[,<label>]`"))?;
            let public_key = PublicKey::from(decode_key(key)?);
            let labels: Vec<Label> = labels.split(',').map(Label::from).collect();
            ensure!(
                labels.iter().all(|label| !label.as_str().is_empty()),
                "`{s}` has an empty label"
            );
            Ok(Self {
                public_key,
                labels: LabelSet::new(labels),
            })
        }
    }

    /// The policy state the status file reports.
    #[derive(Debug, Default)]
    struct PolicyState {
        rules: AtomicUsize,
        reloads: AtomicU64,
        errors: AtomicU64,
    }

    /// What the policy file held at the last poll.
    #[derive(Debug, PartialEq, Eq)]
    enum Seen {
        Content(Vec<u8>),
        Unreadable(String),
    }

    /// Reads the policy file into the ACL engine whenever its content changes.
    struct PolicyFile {
        path: PathBuf,
        engine: Arc<AclEngine>,
        state: Arc<PolicyState>,
        seen: Option<Seen>,
    }

    impl PolicyFile {
        /// Reads the file once; loads it if it changed since the last poll.
        async fn poll(&mut self) {
            let seen = match tokio::fs::read(&self.path).await {
                Ok(content) => Seen::Content(content),
                Err(e) => Seen::Unreadable(e.to_string()),
            };
            if self.seen.as_ref() == Some(&seen) {
                return;
            }
            match &seen {
                Seen::Content(content) => self.load(content),
                Seen::Unreadable(error) => {
                    self.state.errors.fetch_add(1, Ordering::Relaxed);
                    tracing::warn!(path = %self.path.display(), %error, "cannot read the policy, keeping the previous policy");
                }
            }
            self.seen = Some(seen);
        }

        fn load(&self, content: &[u8]) {
            let loaded = serde_json::from_slice::<AclPolicy>(content)
                .map_err(anyhow::Error::from)
                .and_then(|policy| {
                    let rules = policy.acls.len();
                    self.engine.load(policy)?;
                    Ok(rules)
                });
            match loaded {
                Ok(rules) => {
                    self.state.rules.store(rules, Ordering::Relaxed);
                    self.state.reloads.fetch_add(1, Ordering::Relaxed);
                    tracing::info!(path = %self.path.display(), "policy reloaded ({rules} rules)");
                }
                Err(e) => {
                    self.state.errors.fetch_add(1, Ordering::Relaxed);
                    tracing::warn!(path = %self.path.display(), error = format!("{e:#}"), "policy rejected, keeping the previous policy");
                }
            }
        }

        /// Polls every [`POLL_INTERVAL`] forever.
        async fn watch(mut self) {
            let mut ticks = tokio::time::interval(POLL_INTERVAL);
            loop {
                ticks.tick().await;
                self.poll().await;
            }
        }
    }

    /// The status file's `extra.acl` object.
    fn acl_json(filter: &AclFilter, engine: &AclEngine, state: &PolicyState) -> Value {
        let stats = filter.stats();
        json!({
            "policy_loaded": engine.is_loaded(),
            "rules": state.rules.load(Ordering::Relaxed),
            "reloads": state.reloads.load(Ordering::Relaxed),
            "reload_errors": state.errors.load(Ordering::Relaxed),
            "accepted": stats.accepted,
            "replies": stats.replies,
            "denied": stats.denied,
            "no_policy": stats.no_policy,
            "unknown_peer": stats.unknown_peer,
            "protocol": stats.protocol,
            "fragment": stats.fragment,
            "malformed": stats.malformed,
            "fragment_evictions": stats.fragment_evictions,
            "reply_evictions": stats.reply_evictions,
            "reply_expired": stats.reply_expired,
        })
    }

    /// The status file's `extra.flows` object; flows are oriented peer -> gateway.
    fn flows_json(tracker: &FlowTracker) -> Value {
        let flows: Vec<Value> = tracker
            .flows()
            .iter()
            .map(|(key, stats)| {
                let proto = match key.tuple.protocol {
                    6 => "tcp".to_owned(),
                    17 => "udp".to_owned(),
                    other => other.to_string(),
                };
                json!({
                    "peer": key.peer.get(),
                    "proto": proto,
                    "remote": SocketAddr::new(key.tuple.src, key.tuple.src_port).to_string(),
                    "local": SocketAddr::new(key.tuple.dst, key.tuple.dst_port).to_string(),
                    "rx_packets": stats.rx_packets,
                    "rx_bytes": stats.rx_bytes,
                    "tx_packets": stats.tx_packets,
                    "tx_bytes": stats.tx_bytes,
                })
            })
            .collect();
        json!({
            "tracked": flows.len(),
            "evictions": tracker.evictions(),
            "untracked": tracker.untracked(),
            "flows": flows,
        })
    }

    pub(crate) async fn main(args: Args) -> anyhow::Result<ExitCode> {
        init_logging(&args.node.log)?;
        let acl = Arc::new(AclEngine::new());
        let identities = Arc::new(PeerLabelMap::new());
        let config = AclFilterConfig {
            stateful_replies: true,
            ..AclFilterConfig::default()
        };
        let filter = AclFilter::with_config(Arc::clone(&acl), Arc::clone(&identities), config);
        let tracker = FlowTracker::new(FLOW_CAPACITY);
        let state = Arc::new(PolicyState::default());
        let mut policy = PolicyFile {
            path: args.policy.clone(),
            engine: Arc::clone(&acl),
            state: Arc::clone(&state),
            seen: None,
        };
        policy.poll().await;

        let tun = node::create_tun(&args.tun.tun_name, &args.node)?;
        let name = tun.name().unwrap_or_else(|_| args.tun.tun_name.clone());
        configure_tun(&name, &args.tun.address, args.tun.mtu, &args.node.peer)?;
        let (source, sink) = tun.split().context("cannot open the TUN device")?;
        let (engine_filter, engine_tracker) = (filter.clone(), tracker.clone());
        let node = build_engine_with(source, sink, &args.node, |builder| {
            builder
                .filter(Box::new(engine_filter))
                .filter(Box::new(engine_tracker))
        })?;
        let handle = node.engine.handle();
        configure_peers(&handle, &args.node.peer).await?;
        for identity in &args.identity {
            let peer = handle
                .peer_id(identity.public_key)
                .await?
                .with_context(|| {
                    format!(
                        "--identity names {}, which is no --peer",
                        encode_public_key(&identity.public_key)
                    )
                })?;
            identities.insert(peer, identity.labels.clone());
            tracing::info!(peer = %encode_public_key(&identity.public_key), labels = ?identity.labels, "identity set");
        }
        tokio::spawn(policy.watch());

        let socket = serve_uapi(handle.clone(), &name, node.transports.listen.port())?;
        tracing::info!(interface = %name, listen = %node.transports.listen, uapi = %socket, "ACL gateway started");

        let status = args.node.status_file.clone().map(|path| {
            Status::new(path, handle, node.transports.listen).extra(move |extra| {
                extra.insert("acl".to_owned(), acl_json(&filter, &acl, &state));
                extra.insert("flows".to_owned(), flows_json(&tracker));
            })
        });
        node::run(node.engine, &args.echo, Backend::Kernel, status).await
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn sample_policy_loads() {
            let content = include_bytes!("../../policies/acl_gateway.json");
            let policy: AclPolicy = serde_json::from_slice(content).unwrap();
            assert_eq!(policy.acls.len(), 2);
            AclEngine::new().load(policy).unwrap();
        }

        #[test]
        fn identity_forms() {
            let key = "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=";
            let one: Identity = format!("{key}=10.0.0.2").parse().unwrap();
            assert_eq!(one.public_key.to_bytes(), [1; 32]);
            assert_eq!(one.labels, LabelSet::new([Label::from("10.0.0.2")]));
            let two: Identity = format!("{key}=team-a,host:web").parse().unwrap();
            assert_eq!(
                two.labels,
                LabelSet::new([Label::from("host:web"), Label::from("team-a")])
            );
            assert!(format!("{key}=").parse::<Identity>().is_err());
            assert!(format!("{key}=a,,b").parse::<Identity>().is_err());
            assert!("nokey".parse::<Identity>().is_err());
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
    anyhow::bail!("acl_gateway runs on Linux and macOS only")
}
