//! Rule namespaces: per-source policies, their member labels, outbound rules
//! and directed grants between namespaces.
//!
//! A namespace is the rule set one source of peers contributes; its members
//! are source [`Label`]s. A [`NamespaceKind::Pinholes`] namespace carries no
//! rules: its members get access only through pinholes. The
//! [`AclEngine`](crate::AclEngine) stores
//! namespaces with [`store_namespace`](crate::AclEngine::store_namespace) and
//! grants with [`store_grant`](crate::AclEngine::store_grant); the
//! [`AclFilter`](crate::AclFilter) enforces them. See the crate docs for the
//! evaluation order.

use std::borrow::Borrow;
use std::collections::BTreeSet;
use std::fmt;
use std::sync::Arc;

use serde::{Deserialize, Serialize};

use crate::net::IpNet;
use crate::policy::AclPolicy;
use crate::rules::Label;

/// The opaque identifier of a rule namespace, e.g. `"team-a"`. nsplane
/// compares identifiers for equality and never interprets them.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct NamespaceId(Arc<str>);

impl NamespaceId {
    /// The identifier text.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for NamespaceId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl From<&str> for NamespaceId {
    fn from(id: &str) -> Self {
        Self(Arc::from(id))
    }
}

impl From<String> for NamespaceId {
    fn from(id: String) -> Self {
        Self(Arc::from(id))
    }
}

impl Borrow<str> for NamespaceId {
    fn borrow(&self) -> &str {
        &self.0
    }
}

/// How a namespace governs its members.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub enum NamespaceKind {
    /// Members are governed by the namespace's rules.
    #[default]
    Rules,
    /// No rules: members get access only through pinholes. Such a namespace
    /// never widens permissions on its own: it carries no accept rules and no
    /// [`pinhole_kinds`](NamespacePolicy::pinhole_kinds), and no grant can
    /// name it.
    Pinholes,
}

/// A member of a namespace: a source label and the addresses it owns.
///
/// Every source carrying `label` is a member of the namespace.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct NamespaceMember {
    /// The member label, e.g. `"host:web"`.
    pub label: Label,
    /// The addresses the member owns, used to resolve a destination address
    /// to this member label.
    #[serde(default, with = "ip_nets")]
    pub addresses: Vec<IpNet>,
}

/// An outbound rule: what the local node may send to the members of an
/// outbound-restricted namespace.
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct OutboundRule {
    /// `"tcp"`, `"udp"`, or `None` for both.
    #[serde(default)]
    pub proto: Option<String>,
    /// Destination ports in the rule port syntax: `"*"`, `"22"`, `"80,443"`,
    /// `"8000-8999"`.
    #[serde(default)]
    pub ports: String,
}

/// The policy of one namespace.
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct NamespacePolicy {
    /// How the namespace governs its members. Default
    /// [`NamespaceKind::Rules`].
    #[serde(default)]
    pub kind: NamespaceKind,
    /// The member labels of the namespace.
    #[serde(default)]
    pub members: Vec<NamespaceMember>,
    /// The accept rules applying between the namespace's members and the
    /// local node; its built-in tests must pass for the namespace to be stored.
    #[serde(default)]
    pub policy: AclPolicy,
    /// `None`: outbound traffic to the members is unrestricted. `Some(rules)`:
    /// outbound traffic to the members is restricted to these rules (plus
    /// replies to accepted inbound flows). A source is restricted only when
    /// every namespace it belongs to opts in.
    #[serde(default)]
    pub outbound: Option<Vec<OutboundRule>>,
    /// Pinhole kinds (opaque, e.g. `"transfer"`) that may be opened for the
    /// namespace's members in a [`NamespaceKind::Pinholes`] namespace. Empty
    /// (the default) permits none. Must be empty on a `Pinholes` namespace.
    #[serde(default)]
    pub pinhole_kinds: BTreeSet<String>,
}

/// One end of a directed [`Grant`].
#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
pub enum GrantEnd {
    /// Every member of a [`NamespaceKind::Rules`] namespace.
    Namespace(NamespaceId),
    /// One label: as the source end, a source carrying it; as the
    /// destination end, the destination address owned by this member label.
    Label(Label),
}

/// A directed grant letting the members of one namespace (or one label)
/// reach those of another across the default cross-namespace deny.
///
/// Grants are one-way: traffic from `to` to `from` needs its own grant.
#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
pub struct Grant {
    /// The sending side.
    pub from: GrantEnd,
    /// The receiving side.
    pub to: GrantEnd,
    /// `"tcp"`, `"udp"`, or `None` for both.
    #[serde(default)]
    pub proto: Option<String>,
    /// Destination ports in the rule port syntax, or `None` for any port.
    #[serde(default)]
    pub ports: Option<String>,
}

impl Serialize for NamespaceId {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.0)
    }
}

impl<'de> Deserialize<'de> for NamespaceId {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        String::deserialize(deserializer).map(Self::from)
    }
}

/// Serde for `Vec<IpNet>` as a list of CIDR strings.
pub(crate) mod ip_nets {
    use serde::{Deserialize, Deserializer, Serializer, de::Error as _};

    use crate::net::IpNet;

    pub(crate) fn serialize<S: Serializer>(
        nets: &[IpNet],
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        serializer.collect_seq(nets.iter().map(ToString::to_string))
    }

    pub(crate) fn deserialize<'de, D: Deserializer<'de>>(
        deserializer: D,
    ) -> Result<Vec<IpNet>, D::Error> {
        Vec::<String>::deserialize(deserializer)?
            .iter()
            .map(|s| {
                s.parse()
                    .map_err(|e| D::Error::custom(format!("invalid CIDR '{s}': {e}")))
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn namespace_id_basics() {
        let id = NamespaceId::from("team-a");
        assert_eq!(id.as_str(), "team-a");
        assert_eq!(id.to_string(), "team-a");
        assert_eq!(NamespaceId::from(String::from("team-a")), id);
    }

    #[test]
    fn namespace_policy_serde_defaults() {
        let policy: NamespacePolicy = serde_json::from_str(
            r#"{"members": [{"label": "host:web", "addresses": ["fd00::1", "10.0.0.0/24"]}]}"#,
        )
        .unwrap();
        assert_eq!(policy.kind, NamespaceKind::Rules);
        assert_eq!(policy.members[0].label, Label::from("host:web"));
        assert_eq!(policy.members[0].addresses.len(), 2);
        assert!(policy.outbound.is_none());
        assert!(policy.pinhole_kinds.is_empty());
        assert!(policy.policy.acls.is_empty());

        let json = serde_json::to_string(&policy).unwrap();
        assert!(json.contains("\"fd00::1/128\""), "{json}");
        let back: NamespacePolicy = serde_json::from_str(&json).unwrap();
        assert_eq!(back.members[0].addresses, policy.members[0].addresses);
        let pinholes: NamespacePolicy =
            serde_json::from_str(r#"{"kind": "Pinholes", "pinhole_kinds": []}"#).unwrap();
        assert_eq!(pinholes.kind, NamespaceKind::Pinholes);

        assert!(
            serde_json::from_str::<NamespacePolicy>(r#"{"members": [{"addresses": ["x"]}]}"#)
                .is_err()
        );
    }

    #[test]
    fn grant_serde_round_trip() {
        let grant = Grant {
            from: GrantEnd::Namespace("quick".into()),
            to: GrantEnd::Label("team-a".into()),
            proto: Some("tcp".to_owned()),
            ports: None,
        };
        let json = serde_json::to_string(&grant).unwrap();
        assert_eq!(serde_json::from_str::<Grant>(&json).unwrap(), grant);
    }
}
