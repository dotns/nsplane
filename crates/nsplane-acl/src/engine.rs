//! Access requests, compiled policies and the shared [`AclEngine`].

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Arc;

use arc_swap::ArcSwapOption;
use tracing::{debug, warn};

use crate::{
    Error,
    matcher::{
        DstMatcher, HostMatcher, PortMatcher, SrcMatcher, parse_dst, parse_protocol, parse_src,
    },
    net::{IpNet, Protocol},
    policy::{AclPolicy, AclTest},
};

// ── Public types ──────────────────────────────────────────────────────────────

/// How the source identity of an access request was established.
///
/// The ACL judge keys on a **principal**, not a bare IP. For the relay/direct
/// link modes the caller resolves the end-to-end client's WireGuard key and
/// builds [`SourceAssertion::WgPeerKey`]; for the terminate mode the gateway
/// asserted a binding. [`AccessRequest`] still carries `src_ip` for legacy CIDR rules and
/// logging, but the assertion is what carries the key principal + the
/// `source_class`/`source_anchor` used in decision logs.
#[derive(Debug, Clone)]
pub enum SourceAssertion {
    /// An end-to-end client WireGuard public key (wg-relay / wss-relay / direct).
    WgPeerKey {
        /// The client's 32-byte WireGuard public key.
        pubkey: [u8; 32],
    },
    /// The gateway terminated the client tunnel and asserted this binding.
    Terminate {
        /// The asserted binding (an optional tunnel IP + a stable anchor).
        binding: TerminateBinding,
    },
    /// An external identity-provider assertion.
    External {
        /// The identity-provider identifier.
        idp: String,
    },
}

/// A gateway-asserted terminate binding.
#[derive(Debug, Clone)]
pub struct TerminateBinding {
    /// The tunnel IP the gateway assigned, when present (kept for CIDR rules).
    pub ip: Option<IpAddr>,
    /// A stable identity string for rules/logs.
    pub anchor: String,
}

impl SourceAssertion {
    /// The decision-log source class string.
    #[must_use]
    pub const fn source_class(&self) -> &'static str {
        match self {
            Self::WgPeerKey { .. } => "client-wg-key",
            Self::Terminate { .. } => "terminate-binding",
            Self::External { .. } => "external-idp",
        }
    }

    /// A stable identity string for rules/logs.
    #[must_use]
    pub fn source_anchor(&self) -> String {
        match self {
            Self::WgPeerKey { pubkey } => wg_peer_anchor(pubkey),
            Self::Terminate { binding } => binding.anchor.clone(),
            Self::External { idp } => format!("idp:{idp}"),
        }
    }

    /// The IP-bearing source, when any (terminate bindings). `None` for
    /// key/IdP assertions — those match by anchor, not CIDR.
    #[must_use]
    pub const fn ip(&self) -> Option<IpAddr> {
        match self {
            Self::Terminate { binding } => binding.ip,
            Self::WgPeerKey { .. } | Self::External { .. } => None,
        }
    }
}

/// Canonical anchor encoding for a WireGuard peer key: `key:<hex>` (64 lowercase
/// hex chars). This is the `src` form key principals use in rules, so an
/// inbound client key can be matched against a rule.
#[must_use]
pub fn wg_peer_anchor(pubkey: &[u8; 32]) -> String {
    let mut s = String::with_capacity(4 + 64);
    s.push_str("key:");
    for b in pubkey {
        use std::fmt::Write as _;
        let _ = write!(s, "{b:02x}");
    }
    s
}

/// A connection access request to evaluate against the policy.
#[derive(Debug, Clone)]
pub struct AccessRequest {
    /// Legacy source IP (tunnel/inner src) — still used by CIDR rules + logs.
    pub src_ip: IpAddr,
    /// Typed source assertion: the principal + how it was established.
    pub source: SourceAssertion,
    /// Destination IP address.
    pub dst_ip: IpAddr,
    /// Destination port.
    pub dst_port: u16,
    /// Transport protocol.
    pub protocol: Protocol,
}

impl AccessRequest {
    /// Build a request from a bare source IP (the legacy/terminate path): the
    /// assertion is a [`SourceAssertion::Terminate`] binding carrying that IP.
    /// Behaviour-preserving for IP/CIDR rules.
    #[must_use]
    pub fn from_ip(src_ip: IpAddr, dst_ip: IpAddr, dst_port: u16, protocol: Protocol) -> Self {
        Self {
            src_ip,
            source: SourceAssertion::Terminate {
                binding: TerminateBinding {
                    ip: Some(src_ip),
                    anchor: src_ip.to_string(),
                },
            },
            dst_ip,
            dst_port,
            protocol,
        }
    }

    /// Build a request whose source is an end-to-end client WireGuard key
    /// (wg-relay / wss-relay / direct). `src_ip` is retained for legacy CIDR
    /// rules + logs; the key is what the subject principals match against.
    #[must_use]
    pub const fn with_wg_peer_key(
        pubkey: [u8; 32],
        src_ip: IpAddr,
        dst_ip: IpAddr,
        dst_port: u16,
        protocol: Protocol,
    ) -> Self {
        Self {
            src_ip,
            source: SourceAssertion::WgPeerKey { pubkey },
            dst_ip,
            dst_port,
            protocol,
        }
    }
}

/// Result of an ACL evaluation.
#[derive(Debug, Clone)]
pub struct AclDecision {
    /// `true` if an accept rule matched; `false` means default deny.
    pub allowed: bool,
    /// Index of the matched rule within the compiled rule list (if any).
    pub matched_rule_index: Option<usize>,
    /// Human-readable explanation.
    pub reason: String,
}

/// A failed built-in policy test.
#[derive(Debug, Clone)]
pub struct AclTestFailure {
    /// The test that failed.
    pub test: AclTest,
    /// Why it failed.
    pub reason: String,
}

// ── Internal compiled rule ────────────────────────────────────────────────────

#[derive(Debug)]
struct CompiledRule {
    src: Vec<SrcMatcher>,
    dst: Vec<DstMatcher>,
    /// `None` means match both TCP and UDP.
    proto: Option<Protocol>,
}

impl CompiledRule {
    fn matches(&self, req: &AccessRequest) -> bool {
        if !self.src.iter().any(|m| m.matches(&req.source)) {
            return false;
        }
        if !self.dst.iter().any(|m| m.matches(req.dst_ip, req.dst_port)) {
            return false;
        }
        self.proto.is_none_or(|proto| proto == req.protocol)
    }
}

// ── CompiledPolicy ────────────────────────────────────────────────────────────

/// A validated, compiled policy: evaluate connection requests against it.
///
/// Default policy is **deny** — traffic is blocked unless an explicit `accept`
/// rule matches. Immutable once compiled; share it through an [`AclEngine`].
#[derive(Debug)]
pub struct CompiledPolicy {
    compiled_rules: Vec<CompiledRule>,
    tests: Vec<AclTest>,
}

impl CompiledPolicy {
    /// Resolve and compile an [`AclPolicy`].
    ///
    /// Runs the built-in tests and returns [`Error::TestsFailed`] if any fail.
    pub fn compile(policy: AclPolicy) -> Result<Self, Error> {
        let hosts = resolve_hosts(&policy.hosts)?;

        let mut compiled_rules = Vec::with_capacity(policy.acls.len());
        for (i, rule) in policy.acls.iter().enumerate() {
            let src = rule
                .src
                .iter()
                .map(|s| parse_src(s, &hosts))
                .collect::<Result<Vec<_>, _>>()
                .map_err(|e| Error::InvalidPolicy(format!("rule {i} src: {e}")))?;

            let dst = rule
                .dst
                .iter()
                .map(|s| parse_dst(s, &hosts))
                .collect::<Result<Vec<_>, _>>()
                .map_err(|e| Error::InvalidPolicy(format!("rule {i} dst: {e}")))?;

            let proto = rule
                .proto
                .as_deref()
                .map(parse_protocol)
                .transpose()
                .map_err(|e| Error::InvalidPolicy(format!("rule {i} proto: {e}")))?;

            compiled_rules.push(CompiledRule { src, dst, proto });
        }

        let engine = Self {
            compiled_rules,
            tests: policy.tests,
        };

        let failures = engine.validate_tests();
        if !failures.is_empty() {
            for f in &failures {
                warn!(
                    src = %f.test.src,
                    dst = %f.test.dst,
                    expected = f.test.allow,
                    reason = %f.reason,
                    "ACL policy test failed"
                );
            }
            return Err(Error::TestsFailed {
                count: failures.len(),
            });
        }

        Ok(engine)
    }

    /// A policy that permits every flow. For an endpoint that does not filter
    /// its inbound — e.g. a wss-relay client decrypting responses to connections
    /// it originated. The shared WG decrypt path is otherwise fail-closed when no
    /// policy is loaded, which would drop the client's return traffic.
    #[must_use]
    pub fn permit_all() -> Self {
        Self {
            compiled_rules: vec![CompiledRule {
                src: vec![SrcMatcher::Any],
                dst: vec![DstMatcher {
                    host: HostMatcher::Any,
                    ports: PortMatcher::Any,
                }],
                proto: None,
            }],
            tests: Vec::new(),
        }
    }

    /// Evaluate whether `request` is allowed by the policy.
    ///
    /// Returns `allowed = true` only when an explicit accept rule matches.
    /// If no rule matches, the result is a default deny.
    pub fn is_allowed(&self, request: &AccessRequest) -> AclDecision {
        for (idx, rule) in self.compiled_rules.iter().enumerate() {
            if rule.matches(request) {
                debug!(
                    src = %request.src_ip,
                    dst = %request.dst_ip,
                    port = request.dst_port,
                    proto = ?request.protocol,
                    rule = idx,
                    "ACL accept"
                );
                return AclDecision {
                    allowed: true,
                    matched_rule_index: Some(idx),
                    reason: format!("accepted by rule {idx}"),
                };
            }
        }

        // `debug!`, not `warn!`: the data path evaluates every packet, so a
        // warning per denied packet would flood the log.
        debug!(
            src = %request.src_ip,
            dst = %request.dst_ip,
            port = request.dst_port,
            proto = ?request.protocol,
            "ACL deny: no matching rule"
        );
        AclDecision {
            allowed: false,
            matched_rule_index: None,
            reason: "denied: no matching accept rule".to_owned(),
        }
    }

    /// Run the built-in policy tests and return a list of failures.
    pub fn validate_tests(&self) -> Vec<AclTestFailure> {
        let mut failures = Vec::new();

        for test in &self.tests {
            let Ok(src_ip) = test.src.parse::<IpAddr>() else {
                failures.push(AclTestFailure {
                    test: test.clone(),
                    reason: format!("cannot parse src IP '{}'", test.src),
                });
                continue;
            };

            let (dst_ip, dst_port) = match parse_test_dst(&test.dst) {
                Ok(pair) => pair,
                Err(reason) => {
                    failures.push(AclTestFailure {
                        test: test.clone(),
                        reason,
                    });
                    continue;
                }
            };

            let protocol = match test.proto.as_deref() {
                Some(raw) => match parse_protocol(raw) {
                    Ok(proto) => proto,
                    Err(reason) => {
                        failures.push(AclTestFailure {
                            test: test.clone(),
                            reason: format!("cannot parse test proto '{raw}': {reason}"),
                        });
                        continue;
                    }
                },
                None => Protocol::Tcp,
            };

            let req = AccessRequest::from_ip(src_ip, dst_ip, dst_port, protocol);
            let decision = self.is_allowed(&req);

            if decision.allowed != test.allow {
                failures.push(AclTestFailure {
                    test: test.clone(),
                    reason: format!(
                        "expected {}, got {} ({})",
                        if test.allow { "allow" } else { "deny" },
                        if decision.allowed { "allow" } else { "deny" },
                        decision.reason,
                    ),
                });
            }
        }

        failures
    }
}

// ── AclEngine ─────────────────────────────────────────────────────────────────

/// Shared ACL engine holding the current [`CompiledPolicy`].
///
/// Fail-closed: until a policy is loaded (and after [`clear`](Self::clear))
/// every request is denied. Reloads swap the policy atomically; evaluation
/// takes no lock, so the engine can be shared through an `Arc` and queried
/// per packet while another thread reloads.
#[derive(Debug, Default)]
pub struct AclEngine {
    policy: ArcSwapOption<CompiledPolicy>,
}

impl AclEngine {
    /// An engine with no policy loaded (denies everything).
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Compile `policy` and make it the active policy.
    ///
    /// On error (invalid policy or failed built-in tests) the previously
    /// loaded policy, if any, stays in effect.
    pub fn load(&self, policy: AclPolicy) -> Result<(), Error> {
        match CompiledPolicy::compile(policy) {
            Ok(compiled) => {
                self.store(Arc::new(compiled));
                Ok(())
            }
            Err(err) => {
                warn!(error = %err, "ACL policy rejected; keeping the previous policy");
                Err(err)
            }
        }
    }

    /// Make an already compiled policy the active policy.
    pub fn store(&self, policy: Arc<CompiledPolicy>) {
        self.policy.store(Some(policy));
    }

    /// Unload the active policy, returning to fail-closed.
    pub fn clear(&self) {
        self.policy.store(None);
    }

    /// Whether a policy is currently loaded.
    pub fn is_loaded(&self) -> bool {
        self.policy.load().is_some()
    }

    /// The active policy, if any.
    pub fn policy(&self) -> Option<Arc<CompiledPolicy>> {
        self.policy.load_full()
    }

    /// Evaluate `request` against the active policy.
    ///
    /// With no policy loaded the request is denied.
    pub fn is_allowed(&self, request: &AccessRequest) -> AclDecision {
        if let Some(policy) = self.policy.load().as_deref() {
            return policy.is_allowed(request);
        }
        debug!(
            src = %request.src_ip,
            dst = %request.dst_ip,
            port = request.dst_port,
            proto = ?request.protocol,
            "ACL deny: no policy loaded"
        );
        AclDecision {
            allowed: false,
            matched_rule_index: None,
            reason: "denied: no policy loaded".to_owned(),
        }
    }
}

// ── helpers ───────────────────────────────────────────────────────────────────

fn resolve_hosts(raw: &HashMap<String, String>) -> Result<HashMap<String, IpNet>, Error> {
    raw.iter()
        .map(|(alias, cidr)| {
            let net = cidr.parse::<IpNet>().map_err(|e| Error::InvalidCidr {
                addr: cidr.clone(),
                reason: e.to_string(),
            })?;
            Ok((alias.clone(), net))
        })
        .collect()
}

/// Parse a test destination string like `"192.168.1.10:5432"`.
fn parse_test_dst(s: &str) -> Result<(IpAddr, u16), String> {
    let colon = s
        .rfind(':')
        .ok_or_else(|| format!("missing ':' in test dst '{s}'"))?;
    let ip_str = &s[..colon];
    let port_str = &s[colon + 1..];
    let ip = ip_str
        .parse::<IpAddr>()
        .map_err(|_| format!("invalid IP '{ip_str}' in test dst '{s}'"))?;
    let port = port_str
        .parse::<u16>()
        .map_err(|_| format!("invalid port '{port_str}' in test dst '{s}'"))?;
    Ok((ip, port))
}

// ── tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy::{AclAction, AclRule, AclTest};

    fn make_policy(acls: Vec<AclRule>, tests: Vec<AclTest>) -> AclPolicy {
        AclPolicy {
            hosts: HashMap::new(),
            acls,
            tests,
        }
    }

    #[test]
    fn permit_all_allows_every_flow() {
        let e = CompiledPolicy::permit_all();
        let a = AccessRequest::from_ip(
            "1.2.3.4".parse().unwrap(),
            "5.6.7.8".parse().unwrap(),
            443,
            Protocol::Tcp,
        );
        assert!(e.is_allowed(&a).allowed);
        let b = AccessRequest::from_ip(
            "10.0.0.112".parse().unwrap(),
            "10.0.0.111".parse().unwrap(),
            18888,
            Protocol::Udp,
        );
        assert!(e.is_allowed(&b).allowed);
    }

    fn accept_rule(src: &[&str], dst: &[&str], proto: Option<&str>) -> AclRule {
        AclRule {
            action: AclAction::Accept,
            src: src.iter().map(ToString::to_string).collect(),
            dst: dst.iter().map(ToString::to_string).collect(),
            proto: proto.map(str::to_owned),
        }
    }

    fn req(src: &str, dst: &str, port: u16, proto: Protocol) -> AccessRequest {
        AccessRequest::from_ip(src.parse().unwrap(), dst.parse().unwrap(), port, proto)
    }

    // ── default deny ──────────────────────────────────────────────────────

    #[test]
    fn empty_policy_denies_everything() {
        let engine = CompiledPolicy::compile(make_policy(vec![], vec![])).unwrap();
        let d = engine.is_allowed(&req("10.0.0.1", "192.168.1.1", 80, Protocol::Tcp));
        assert!(!d.allowed);
        assert!(d.matched_rule_index.is_none());
    }

    // ── wildcard accept ───────────────────────────────────────────────────

    #[test]
    fn wildcard_rule_allows_any_connection() {
        let engine = CompiledPolicy::compile(make_policy(
            vec![accept_rule(&["*"], &["*:*"], None)],
            vec![],
        ))
        .unwrap();
        assert!(
            engine
                .is_allowed(&req("1.2.3.4", "5.6.7.8", 9999, Protocol::Udp))
                .allowed
        );
    }

    // ── CIDR src/dst matching ─────────────────────────────────────────────

    #[test]
    fn cidr_rule_allows_in_range_denies_outside() {
        let engine = CompiledPolicy::compile(make_policy(
            vec![accept_rule(&["10.0.0.0/24"], &["192.168.1.0/24:80"], None)],
            vec![],
        ))
        .unwrap();

        assert!(
            engine
                .is_allowed(&req("10.0.0.5", "192.168.1.5", 80, Protocol::Tcp))
                .allowed
        );
        // src outside range
        assert!(
            !engine
                .is_allowed(&req("10.0.1.5", "192.168.1.5", 80, Protocol::Tcp))
                .allowed
        );
        // dst outside range
        assert!(
            !engine
                .is_allowed(&req("10.0.0.5", "192.168.2.5", 80, Protocol::Tcp))
                .allowed
        );
        // wrong port
        assert!(
            !engine
                .is_allowed(&req("10.0.0.5", "192.168.1.5", 443, Protocol::Tcp))
                .allowed
        );
    }

    // ── host alias resolution ─────────────────────────────────────────────

    #[test]
    fn host_alias_resolves_correctly() {
        let mut policy = make_policy(
            vec![accept_rule(&["10.0.0.0/24"], &["db:5432"], Some("tcp"))],
            vec![],
        );
        policy
            .hosts
            .insert("db".to_owned(), "192.168.1.10/32".to_owned());
        let engine = CompiledPolicy::compile(policy).unwrap();

        assert!(
            engine
                .is_allowed(&req("10.0.0.2", "192.168.1.10", 5432, Protocol::Tcp))
                .allowed
        );
        assert!(
            !engine
                .is_allowed(&req("10.0.0.2", "192.168.1.11", 5432, Protocol::Tcp))
                .allowed
        );
    }

    // ── protocol filtering ────────────────────────────────────────────────

    #[test]
    fn proto_tcp_rule_rejects_udp() {
        let engine = CompiledPolicy::compile(make_policy(
            vec![accept_rule(&["*"], &["*:80"], Some("tcp"))],
            vec![],
        ))
        .unwrap();

        assert!(
            engine
                .is_allowed(&req("1.2.3.4", "5.6.7.8", 80, Protocol::Tcp))
                .allowed
        );
        assert!(
            !engine
                .is_allowed(&req("1.2.3.4", "5.6.7.8", 80, Protocol::Udp))
                .allowed
        );
    }

    #[test]
    fn no_proto_rule_matches_tcp_and_udp() {
        let engine = CompiledPolicy::compile(make_policy(
            vec![accept_rule(&["*"], &["*:53"], None)],
            vec![],
        ))
        .unwrap();

        assert!(
            engine
                .is_allowed(&req("1.2.3.4", "8.8.8.8", 53, Protocol::Tcp))
                .allowed
        );
        assert!(
            engine
                .is_allowed(&req("1.2.3.4", "8.8.8.8", 53, Protocol::Udp))
                .allowed
        );
    }

    // ── port ranges and lists ─────────────────────────────────────────────

    #[test]
    fn port_range_rule() {
        let engine = CompiledPolicy::compile(make_policy(
            vec![accept_rule(&["*"], &["*:8000-8999"], None)],
            vec![],
        ))
        .unwrap();

        assert!(
            engine
                .is_allowed(&req("1.2.3.4", "5.6.7.8", 8080, Protocol::Tcp))
                .allowed
        );
        assert!(
            !engine
                .is_allowed(&req("1.2.3.4", "5.6.7.8", 80, Protocol::Tcp))
                .allowed
        );
    }

    #[test]
    fn port_list_rule() {
        let engine = CompiledPolicy::compile(make_policy(
            vec![accept_rule(&["*"], &["*:80,443"], None)],
            vec![],
        ))
        .unwrap();

        assert!(
            engine
                .is_allowed(&req("1.2.3.4", "5.6.7.8", 80, Protocol::Tcp))
                .allowed
        );
        assert!(
            engine
                .is_allowed(&req("1.2.3.4", "5.6.7.8", 443, Protocol::Tcp))
                .allowed
        );
        assert!(
            !engine
                .is_allowed(&req("1.2.3.4", "5.6.7.8", 8080, Protocol::Tcp))
                .allowed
        );
    }

    // ── priority ordering ─────────────────────────────────────────────────

    #[test]
    fn first_matching_rule_wins() {
        let engine = CompiledPolicy::compile(make_policy(
            vec![
                accept_rule(&["10.0.0.0/24"], &["*:80"], None),
                accept_rule(&["*"], &["*:*"], None),
            ],
            vec![],
        ))
        .unwrap();

        let d = engine.is_allowed(&req("10.0.0.5", "1.2.3.4", 80, Protocol::Tcp));
        assert!(d.allowed);
        assert_eq!(d.matched_rule_index, Some(0));

        let d2 = engine.is_allowed(&req("172.16.0.1", "1.2.3.4", 9090, Protocol::Tcp));
        assert!(d2.allowed);
        assert_eq!(d2.matched_rule_index, Some(1));
    }

    // ── built-in tests ────────────────────────────────────────────────────

    #[test]
    fn builtin_tests_pass_on_valid_policy() {
        let policy = make_policy(
            vec![accept_rule(&["10.0.0.0/24"], &["192.168.1.0/24:80"], None)],
            vec![
                AclTest {
                    src: "10.0.0.2".to_owned(),
                    dst: "192.168.1.5:80".to_owned(),
                    proto: None,
                    allow: true,
                },
                AclTest {
                    src: "10.0.0.2".to_owned(),
                    dst: "192.168.1.5:443".to_owned(),
                    proto: None,
                    allow: false,
                },
            ],
        );
        assert!(CompiledPolicy::compile(policy).is_ok());
    }

    #[test]
    fn builtin_tests_can_validate_udp_policy() {
        let policy = make_policy(
            vec![accept_rule(
                &["10.0.0.0/24"],
                &["192.168.1.0/24:53"],
                Some("udp"),
            )],
            vec![
                AclTest {
                    src: "10.0.0.2".to_owned(),
                    dst: "192.168.1.5:53".to_owned(),
                    proto: Some("udp".to_owned()),
                    allow: true,
                },
                AclTest {
                    src: "10.0.0.2".to_owned(),
                    dst: "192.168.1.5:53".to_owned(),
                    proto: Some("tcp".to_owned()),
                    allow: false,
                },
            ],
        );
        assert!(CompiledPolicy::compile(policy).is_ok());
    }

    #[test]
    fn builtin_tests_fail_returns_error() {
        let policy = make_policy(
            vec![],
            vec![AclTest {
                src: "10.0.0.2".to_owned(),
                dst: "192.168.1.5:80".to_owned(),
                proto: None,
                allow: true, // expects allow, but empty policy denies
            }],
        );
        let err = CompiledPolicy::compile(policy).unwrap_err();
        assert!(matches!(err, crate::Error::TestsFailed { count: 1 }));
    }

    // ── invalid policy ────────────────────────────────────────────────────

    #[test]
    fn invalid_host_alias_in_rule_returns_error() {
        let engine = CompiledPolicy::compile(make_policy(
            vec![accept_rule(&["does-not-exist"], &["*:80"], None)],
            vec![],
        ));
        assert!(engine.is_err());
    }

    #[test]
    fn invalid_cidr_in_hosts_returns_error() {
        let mut policy = make_policy(vec![], vec![]);
        policy
            .hosts
            .insert("bad".to_owned(), "not-a-cidr".to_owned());
        assert!(CompiledPolicy::compile(policy).is_err());
    }

    // ── subject-key source matching ───────────────────────────────────────

    #[test]
    fn source_class_and_anchor_strings() {
        let key = [0xABu8; 32];
        let wg = SourceAssertion::WgPeerKey { pubkey: key };
        assert_eq!(wg.source_class(), "client-wg-key");
        assert_eq!(wg.source_anchor(), format!("key:{}", "ab".repeat(32)));
        let t = SourceAssertion::Terminate {
            binding: TerminateBinding {
                ip: Some("10.0.0.5".parse().unwrap()),
                anchor: "10.0.0.5".into(),
            },
        };
        assert_eq!(t.source_class(), "terminate-binding");
        assert_eq!(t.source_anchor(), "10.0.0.5");
        let e = SourceAssertion::External { idp: "okta".into() };
        assert_eq!(e.source_class(), "external-idp");
        assert_eq!(e.source_anchor(), "idp:okta");
    }

    #[test]
    fn key_principal_rule_matches_wg_peer_key_only() {
        let key = [7u8; 32];
        let key_src = format!("key:{}", "07".repeat(32));
        let engine = CompiledPolicy::compile(make_policy(
            vec![accept_rule(&[&key_src], &["*:*"], None)],
            vec![],
        ))
        .unwrap();

        // A request from the matching WG key is accepted.
        let allowed = engine.is_allowed(&AccessRequest::with_wg_peer_key(
            key,
            "0.0.0.0".parse().unwrap(),
            "10.0.0.2".parse().unwrap(),
            80,
            Protocol::Tcp,
        ));
        assert!(allowed.allowed, "matching client-wg-key must be accepted");

        // A different key is denied (default-deny).
        let other = engine.is_allowed(&AccessRequest::with_wg_peer_key(
            [9u8; 32],
            "0.0.0.0".parse().unwrap(),
            "10.0.0.2".parse().unwrap(),
            80,
            Protocol::Tcp,
        ));
        assert!(!other.allowed, "a non-authorised key must be denied");

        // An IP/terminate source never matches a key principal.
        let ip_src = engine.is_allowed(&req("10.0.0.2", "10.0.0.2", 80, Protocol::Tcp));
        assert!(
            !ip_src.allowed,
            "a CIDR/terminate source must not match a key rule"
        );
    }

    #[test]
    fn cidr_rule_does_not_match_a_keyed_source() {
        let engine = CompiledPolicy::compile(make_policy(
            vec![accept_rule(&["10.0.0.0/24"], &["*:*"], None)],
            vec![],
        ))
        .unwrap();
        // A WgPeerKey source carries no IP → a CIDR rule cannot match it.
        let d = engine.is_allowed(&AccessRequest::with_wg_peer_key(
            [1u8; 32],
            "10.0.0.7".parse().unwrap(),
            "10.0.0.2".parse().unwrap(),
            80,
            Protocol::Tcp,
        ));
        assert!(
            !d.allowed,
            "CIDR rule must not match a key-only source even with a legacy src_ip"
        );
    }

    // ── AclEngine (shared, atomic reload) ─────────────────────────────────

    fn port_policy(port: u16) -> AclPolicy {
        make_policy(
            vec![accept_rule(&["*"], &[&format!("*:{port}")], None)],
            vec![],
        )
    }

    #[test]
    fn engine_is_fail_closed_before_first_load() {
        let engine = AclEngine::new();
        assert!(!engine.is_loaded());
        assert!(engine.policy().is_none());
        let d = engine.is_allowed(&req("10.0.0.1", "10.0.0.2", 80, Protocol::Tcp));
        assert!(!d.allowed);
        assert!(d.matched_rule_index.is_none());
        assert_eq!(d.reason, "denied: no policy loaded");
        assert!(!AclEngine::default().is_loaded());
    }

    #[test]
    fn engine_load_then_allow() {
        let engine = AclEngine::new();
        engine.load(port_policy(80)).unwrap();
        assert!(engine.is_loaded());
        let d = engine.is_allowed(&req("10.0.0.1", "10.0.0.2", 80, Protocol::Tcp));
        assert!(d.allowed);
        assert_eq!(d.matched_rule_index, Some(0));
        assert!(
            !engine
                .is_allowed(&req("10.0.0.1", "10.0.0.2", 443, Protocol::Tcp))
                .allowed
        );
    }

    #[test]
    fn engine_failed_reload_keeps_previous_policy() {
        let engine = AclEngine::new();
        engine.load(port_policy(80)).unwrap();
        let before = engine.policy().unwrap();

        // Built-in test failure.
        let failing = make_policy(
            vec![],
            vec![AclTest {
                src: "10.0.0.2".to_owned(),
                dst: "192.168.1.5:80".to_owned(),
                proto: None,
                allow: true,
            }],
        );
        assert!(matches!(
            engine.load(failing),
            Err(crate::Error::TestsFailed { count: 1 })
        ));
        // Compile failure.
        assert!(
            engine
                .load(make_policy(
                    vec![accept_rule(&["does-not-exist"], &["*:80"], None)],
                    vec![],
                ))
                .is_err()
        );

        let after = engine.policy().unwrap();
        assert!(Arc::ptr_eq(&before, &after));
        assert!(
            engine
                .is_allowed(&req("10.0.0.1", "10.0.0.2", 80, Protocol::Tcp))
                .allowed
        );
    }

    #[test]
    fn engine_store_and_clear() {
        let engine = AclEngine::new();
        engine.store(Arc::new(CompiledPolicy::permit_all()));
        assert!(
            engine
                .is_allowed(&req("1.2.3.4", "5.6.7.8", 9, Protocol::Udp))
                .allowed
        );

        engine.clear();
        assert!(!engine.is_loaded());
        let d = engine.is_allowed(&req("1.2.3.4", "5.6.7.8", 9, Protocol::Udp));
        assert!(!d.allowed);
        assert_eq!(d.reason, "denied: no policy loaded");
    }

    #[test]
    fn engine_concurrent_readers_during_reload() {
        use std::sync::atomic::{AtomicBool, Ordering};

        // Policy A accepts port 80 by rule 0; policy B accepts it by rule 1.
        // Readers must only ever observe one of the two whole policies (or
        // the fail-closed state while cleared), never a mix.
        let policy_a = port_policy(80);
        let policy_b = make_policy(
            vec![
                accept_rule(&["*"], &["*:443"], None),
                accept_rule(&["*"], &["*:80"], None),
            ],
            vec![],
        );
        let engine = AclEngine::new();
        engine.load(policy_a.clone()).unwrap();
        let stop = AtomicBool::new(false);
        let request = req("10.0.0.1", "10.0.0.2", 80, Protocol::Tcp);

        std::thread::scope(|s| {
            let readers: Vec<_> = (0..4)
                .map(|_| {
                    s.spawn(|| {
                        let mut seen = 0u64;
                        loop {
                            let d = engine.is_allowed(&request);
                            if let Some(idx) = d.matched_rule_index {
                                assert!(d.allowed);
                                assert!(idx <= 1, "unexpected rule {idx}");
                                assert_eq!(d.reason, format!("accepted by rule {idx}"));
                            } else {
                                assert!(!d.allowed);
                                assert_eq!(d.reason, "denied: no policy loaded");
                            }
                            // A snapshot stays stable across evaluations.
                            if let Some(p) = engine.policy() {
                                let first = p.is_allowed(&request).matched_rule_index;
                                let second = p.is_allowed(&request).matched_rule_index;
                                assert_eq!(first, second);
                            }
                            seen += 1;
                            if stop.load(Ordering::Relaxed) {
                                break seen;
                            }
                        }
                    })
                })
                .collect();

            for i in 0..2000 {
                match i % 3 {
                    0 => engine.load(policy_b.clone()).unwrap(),
                    1 => engine.load(policy_a.clone()).unwrap(),
                    _ => engine.clear(),
                }
            }
            stop.store(true, Ordering::Relaxed);
            for reader in readers {
                assert!(reader.join().unwrap() > 0);
            }
        });
    }
}
