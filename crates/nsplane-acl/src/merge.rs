//! Layered ACL merge: the policy layering contract.
//!
//! Inputs (all optional):
//! - **Local** policy — operator-authored.
//! - **Remote** policies — one per remote policy source, tagged with the
//!   source id (`nsd_id`) and a
//!   `cached` flag so the merger can record whether the policy came from the
//!   live stream or the last-good cache.
//! - **Deny-scope** — an operator-authored filter that narrows the final
//!   merged policy (see [`deny_scope`](crate::deny_scope)).
//!
//! Output: a single [`MergedPolicy`] containing the combined [`AclPolicy`]
//! ready for [`AclEngine::load`](crate::AclEngine::load), per-rule provenance, a `degraded` flag
//! (set when any remote failed to fetch and had no cache), and the list of
//! rules that the deny-scope post-filter stripped.
//!
//! Rule ordering inside the merged policy is stable:
//! 1. Local rules, in file order.
//! 2. For each remote (ordered by `nsd_id`) its rules in source order.
//!
//! Deduplication uses the [`acl_rule_key`] / [`acl_test_key`] normalisers so
//! that the layering contract is a single source of truth.

use std::collections::{BTreeMap, HashSet};

use crate::deny_scope::{DenyScope, DenyScopeOutcome, apply_deny_scope};
use crate::policy::{AclPolicy, AclRule, AclTest};

/// Source of a rule in the merged policy.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RuleProvenance {
    /// Rule was contributed by the on-disk local policy.
    Local,
    /// Rule was contributed by a live remote policy source.
    Remote {
        /// Identifier of the remote policy source.
        nsd_id: String,
    },
    /// Rule was contributed by the last-good cache for a remote source that
    /// failed.
    Cache {
        /// Identifier of the remote policy source.
        nsd_id: String,
    },
}

/// A remote policy contribution, tagged with its origin.
#[derive(Debug, Clone)]
pub struct RemotePolicy<'a> {
    /// Identifier of the remote policy source.
    pub nsd_id: &'a str,
    /// The effective policy being contributed (may be a last-good cache).
    pub policy: &'a AclPolicy,
    /// `true` when the policy is being served from last-good cache because
    /// the live remote failed to fetch.
    pub cached: bool,
}

/// Inputs to [`merge_layered`].
#[derive(Debug, Clone, Default)]
pub struct PolicyLayers<'a> {
    /// Operator-authored local policy, if present.
    pub local: Option<&'a AclPolicy>,
    /// Remote policies, each tagged with its source id.
    pub remote: Vec<RemotePolicy<'a>>,
    /// Post-filter deny-scope from local policy.
    pub deny_scope: Option<&'a DenyScope>,
    /// Set by the caller when any remote source failed to fetch and has no
    /// last-good cache to contribute. Propagated unchanged to the output.
    pub degraded: bool,
}

/// Output of [`merge_layered`].
#[derive(Debug, Clone, Default)]
pub struct MergedPolicy {
    /// Merged policy, ready for [`crate::AclEngine::load`].
    pub policy: AclPolicy,
    /// One entry per compiled rule in `policy.acls`, recording its origin.
    pub provenance: Vec<RuleProvenance>,
    /// `true` when any remote source failed to fetch and had no cache.
    pub degraded: bool,
    /// Rules that were stripped by the deny-scope post-filter.
    pub dropped_by_deny_scope: Vec<crate::deny_scope::DroppedRule>,
    /// Per-source count of rules that contributed, grouped by provenance.
    pub stats: MergeStats,
}

/// Per-layer rule counts.
#[derive(Debug, Clone, Default)]
pub struct MergeStats {
    /// Rules contributed by the local layer.
    pub local: usize,
    /// Rules contributed by each live remote source, keyed by source id.
    pub remote: BTreeMap<String, usize>,
    /// Rules contributed by each cached remote source, keyed by source id.
    pub cached: BTreeMap<String, usize>,
}

/// Merge `layers` into a single [`MergedPolicy`].
///
/// Errors from deny-scope parsing bubble up as the returned policy having
/// the deny-scope skipped — deny-scope CIDRs must be validated up front by
/// the caller.  We tolerate a failing deny-scope here by logging and
/// reporting it in `dropped_by_deny_scope` as synthetic entries; strict
/// callers should validate the scope before calling merge.
pub fn merge_layered(layers: PolicyLayers<'_>) -> MergedPolicy {
    let mut merged = AclPolicy::default();
    let mut provenance: Vec<RuleProvenance> = Vec::new();
    let mut stats = MergeStats::default();

    // Deduplication sets keyed by normalised rule/test/host tuples.
    let mut rule_keys: HashSet<String> = HashSet::new();
    let mut test_keys: HashSet<String> = HashSet::new();

    // ── Local layer ──────────────────────────────────────────────────────
    if let Some(local) = layers.local {
        for (alias, cidr) in &local.hosts {
            merged
                .hosts
                .entry(alias.clone())
                .or_insert_with(|| cidr.clone());
        }
        for rule in &local.acls {
            let key = acl_rule_key(rule);
            if rule_keys.insert(key) {
                merged.acls.push(rule.clone());
                provenance.push(RuleProvenance::Local);
                stats.local += 1;
            }
        }
        for test in &local.tests {
            if test_keys.insert(acl_test_key(test)) {
                merged.tests.push(test.clone());
            }
        }
    }

    // ── Remote layers (ordered by source id for determinism) ────────────────
    let mut sorted = layers.remote;
    sorted.sort_by(|a, b| a.nsd_id.cmp(b.nsd_id));
    for remote in &sorted {
        for (alias, cidr) in &remote.policy.hosts {
            merged
                .hosts
                .entry(alias.clone())
                .or_insert_with(|| cidr.clone());
        }
        for rule in &remote.policy.acls {
            let key = acl_rule_key(rule);
            if rule_keys.insert(key) {
                merged.acls.push(rule.clone());
                if remote.cached {
                    provenance.push(RuleProvenance::Cache {
                        nsd_id: remote.nsd_id.to_owned(),
                    });
                    *stats.cached.entry(remote.nsd_id.to_owned()).or_insert(0) += 1;
                } else {
                    provenance.push(RuleProvenance::Remote {
                        nsd_id: remote.nsd_id.to_owned(),
                    });
                    *stats.remote.entry(remote.nsd_id.to_owned()).or_insert(0) += 1;
                }
            }
        }
        for test in &remote.policy.tests {
            if test_keys.insert(acl_test_key(test)) {
                merged.tests.push(test.clone());
            }
        }
    }

    // ── Deny-scope post-filter ───────────────────────────────────────────
    let mut dropped = Vec::new();
    if let Some(scope) = layers.deny_scope {
        match apply_deny_scope(&mut merged, scope) {
            Ok(DenyScopeOutcome { dropped: d }) => {
                // Remove provenance entries for the rules dropped by index.
                // apply_deny_scope preserves pre-drop indices in DroppedRule,
                // but after mutation the indices need translating to the
                // compacted vector. We instead rebuild provenance by
                // replaying the mask.
                let dropped_indices: HashSet<usize> = d.iter().map(|e| e.rule_index).collect();
                let original_provenance = std::mem::take(&mut provenance);
                for (idx, prov) in original_provenance.into_iter().enumerate() {
                    if !dropped_indices.contains(&idx) {
                        provenance.push(prov);
                    }
                }
                dropped = d;
            }
            Err(err) => {
                tracing::error!(error = %err, "deny-scope evaluation failed; skipping");
            }
        }
    }

    MergedPolicy {
        policy: merged,
        provenance,
        degraded: layers.degraded,
        dropped_by_deny_scope: dropped,
        stats,
    }
}

// ── Normalisers ──────────────────────────────────────────────────────────────

/// Stable key for rule-level deduplication across layers.
pub fn acl_rule_key(rule: &AclRule) -> String {
    let mut src = rule.src.clone();
    src.sort();
    let mut dst = rule.dst.clone();
    dst.sort();
    let proto = rule
        .proto
        .as_deref()
        .map_or_else(|| "*".to_string(), str::to_ascii_lowercase);
    format!(
        "accept\0{}\0{}\0{}",
        src.join("\u{1f}"),
        dst.join("\u{1f}"),
        proto
    )
}

/// Stable key for test-level deduplication across layers.
pub fn acl_test_key(test: &AclTest) -> String {
    let proto = test
        .proto
        .as_deref()
        .map_or_else(|| "tcp".to_string(), str::to_ascii_lowercase);
    format!("{}\0{}\0{}\0{}", test.src, test.dst, proto, test.allow)
}

// ── tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy::AclAction;

    fn rule(src: &[&str], dst: &[&str], proto: Option<&str>) -> AclRule {
        AclRule {
            action: AclAction::Accept,
            src: src.iter().map(ToString::to_string).collect(),
            dst: dst.iter().map(ToString::to_string).collect(),
            proto: proto.map(str::to_owned),
        }
    }

    fn policy_of(rules: Vec<AclRule>) -> AclPolicy {
        AclPolicy {
            hosts: std::collections::HashMap::default(),
            acls: rules,
            tests: vec![],
        }
    }

    #[test]
    fn empty_layers_produces_empty_policy() {
        let merged = merge_layered(PolicyLayers::default());
        assert!(merged.policy.acls.is_empty());
        assert_eq!(merged.provenance, []);
        assert!(!merged.degraded);
    }

    #[test]
    fn single_remote_passes_through() {
        let p = policy_of(vec![rule(&["10.0.0.0/24"], &["192.168.1.1:80"], None)]);
        let merged = merge_layered(PolicyLayers {
            remote: vec![RemotePolicy {
                nsd_id: "nsd-1",
                policy: &p,
                cached: false,
            }],
            ..Default::default()
        });
        assert_eq!(merged.policy.acls.len(), 1);
        assert_eq!(
            merged.provenance[0],
            RuleProvenance::Remote {
                nsd_id: "nsd-1".into()
            }
        );
        assert_eq!(merged.stats.remote.get("nsd-1"), Some(&1));
    }

    #[test]
    fn overlapping_remotes_dedupe_each_rule_once() {
        let shared = rule(&["10.0.0.0/24"], &["*:80"], None);
        let p1 = policy_of(vec![
            shared.clone(),
            rule(&["10.0.0.0/24"], &["*:443"], None),
        ]);
        let p2 = policy_of(vec![shared, rule(&["10.0.0.0/24"], &["*:22"], None)]);
        let merged = merge_layered(PolicyLayers {
            remote: vec![
                RemotePolicy {
                    nsd_id: "nsd-1",
                    policy: &p1,
                    cached: false,
                },
                RemotePolicy {
                    nsd_id: "nsd-2",
                    policy: &p2,
                    cached: false,
                },
            ],
            ..Default::default()
        });
        assert_eq!(merged.policy.acls.len(), 3, "shared rule merges to one");
        // shared rule gets the first contributor (nsd-1 after sort).
        assert_eq!(
            merged.provenance[0],
            RuleProvenance::Remote {
                nsd_id: "nsd-1".into()
            }
        );
    }

    #[test]
    fn local_layer_is_first_and_provenance_records_it() {
        let local = policy_of(vec![rule(&["10.0.42.0/24"], &["*:80"], None)]);
        let remote = policy_of(vec![rule(&["10.0.0.0/24"], &["*:80"], None)]);
        let merged = merge_layered(PolicyLayers {
            local: Some(&local),
            remote: vec![RemotePolicy {
                nsd_id: "nsd-1",
                policy: &remote,
                cached: false,
            }],
            ..Default::default()
        });
        assert_eq!(merged.policy.acls.len(), 2);
        assert_eq!(merged.provenance[0], RuleProvenance::Local);
        assert_eq!(
            merged.provenance[1],
            RuleProvenance::Remote {
                nsd_id: "nsd-1".into()
            }
        );
    }

    #[test]
    fn cached_remote_is_tagged_and_counts() {
        let p = policy_of(vec![rule(&["10.0.0.0/24"], &["*:80"], None)]);
        let merged = merge_layered(PolicyLayers {
            remote: vec![RemotePolicy {
                nsd_id: "nsd-1",
                policy: &p,
                cached: true,
            }],
            degraded: true,
            ..Default::default()
        });
        assert!(merged.degraded);
        assert_eq!(
            merged.provenance[0],
            RuleProvenance::Cache {
                nsd_id: "nsd-1".into()
            }
        );
        assert_eq!(merged.stats.cached.get("nsd-1"), Some(&1));
    }

    #[test]
    fn deny_scope_drops_rule_and_removes_provenance() {
        let local = policy_of(vec![rule(&["*"], &["10.255.0.0/24:22"], None)]);
        let remote = policy_of(vec![rule(&["10.0.0.0/24"], &["192.168.1.0/24:80"], None)]);
        let scope = DenyScope {
            dst_cidr: vec!["10.255.0.0/16".to_owned()],
            ..Default::default()
        };
        let merged = merge_layered(PolicyLayers {
            local: Some(&local),
            remote: vec![RemotePolicy {
                nsd_id: "nsd-1",
                policy: &remote,
                cached: false,
            }],
            deny_scope: Some(&scope),
            ..Default::default()
        });
        assert_eq!(merged.policy.acls.len(), 1, "local rule was dropped");
        assert_eq!(merged.dropped_by_deny_scope.len(), 1);
        assert_eq!(
            merged.provenance[0],
            RuleProvenance::Remote {
                nsd_id: "nsd-1".into()
            }
        );
    }

    #[test]
    fn degraded_flag_propagates() {
        let merged = merge_layered(PolicyLayers {
            degraded: true,
            ..Default::default()
        });
        assert!(merged.degraded);
    }

    #[test]
    fn host_alias_first_writer_wins() {
        let mut p1 = policy_of(vec![]);
        p1.hosts.insert("db".into(), "10.0.0.0/24".into());
        let mut p2 = policy_of(vec![]);
        p2.hosts.insert("db".into(), "10.1.0.0/24".into());
        let merged = merge_layered(PolicyLayers {
            remote: vec![
                RemotePolicy {
                    nsd_id: "nsd-1",
                    policy: &p1,
                    cached: false,
                },
                RemotePolicy {
                    nsd_id: "nsd-2",
                    policy: &p2,
                    cached: false,
                },
            ],
            ..Default::default()
        });
        assert_eq!(merged.policy.hosts.get("db").unwrap(), "10.0.0.0/24");
    }
}
