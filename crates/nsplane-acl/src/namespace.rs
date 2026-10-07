//! Rule namespaces: per-source policies, their members, outbound rules and
//! directed grants between namespaces.
//!
//! A namespace is the rule set one peer source (an NSD, the Quick allow list,
//! an app session) contributes. The [`AclEngine`](crate::AclEngine) stores
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

/// The identifier of a rule namespace, e.g. `"nsd:<uuid>"`, `"quick"` or
/// `"app:<session>"`.
///
/// Identifiers starting with `app:` name app namespaces (see
/// [`is_app`](Self::is_app)).
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct NamespaceId(Arc<str>);

impl NamespaceId {
    /// The identifier text.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Whether this is an app namespace (the identifier starts with `app:`).
    ///
    /// App namespaces never widen permissions on their own: they carry no
    /// accept rules and allow no app pinholes, and their members get access
    /// only through pinholes.
    #[must_use]
    pub fn is_app(&self) -> bool {
        self.0.starts_with("app:")
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

/// A peer that belongs to a namespace.
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct NamespaceMember {
    /// The peer's principal: its source anchor
    /// ([`SourceAssertion::source_anchor`](crate::SourceAssertion::source_anchor)),
    /// e.g. [`wg_peer_anchor`](crate::wg_peer_anchor) = `key:<hex>`.
    #[serde(default)]
    pub principal: String,
    /// The peer's tunnel addresses (its `node6` /128 etc.), used to resolve a
    /// destination address to this peer.
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
    /// The peers belonging to the namespace.
    #[serde(default)]
    pub members: Vec<NamespaceMember>,
    /// The accept rules applying between the namespace's members and the
    /// local node; its built-in tests must pass for the namespace to be stored.
    #[serde(default)]
    pub policy: AclPolicy,
    /// `None`: outbound traffic to the members is unrestricted. `Some(rules)`:
    /// outbound traffic to the members is restricted to these rules (plus
    /// replies to accepted inbound flows). A peer is restricted only when every
    /// namespace it belongs to opts in.
    #[serde(default)]
    pub outbound: Option<Vec<OutboundRule>>,
    /// App kinds (e.g. `"transfer"`) for which pinholes may be opened to the
    /// namespace's members. Empty (the default) denies every app.
    #[serde(default)]
    pub allow_app_pinholes: BTreeSet<String>,
}

/// One end of a directed [`Grant`].
#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
pub enum GrantEnd {
    /// Every member of a namespace.
    Namespace(NamespaceId),
    /// One peer, by principal.
    Peer(String),
}

/// A directed grant letting peers of one namespace (or one peer) reach peers
/// of another across the default cross-namespace deny.
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
        let id = NamespaceId::from("app:s1");
        assert!(id.is_app());
        assert_eq!(id.as_str(), "app:s1");
        assert_eq!(id.to_string(), "app:s1");
        assert!(!NamespaceId::from(String::from("quick")).is_app());
        assert!(!NamespaceId::from("nsd:app:x").is_app());
    }

    #[test]
    fn namespace_policy_serde_defaults() {
        let policy: NamespacePolicy = serde_json::from_str(
            r#"{"members": [{"principal": "key:00", "addresses": ["fd00::1", "10.0.0.0/24"]}]}"#,
        )
        .unwrap();
        assert_eq!(policy.members[0].addresses.len(), 2);
        assert!(policy.outbound.is_none());
        assert!(policy.allow_app_pinholes.is_empty());
        assert!(policy.policy.acls.is_empty());

        let json = serde_json::to_string(&policy).unwrap();
        assert!(json.contains("\"fd00::1/128\""), "{json}");
        let back: NamespacePolicy = serde_json::from_str(&json).unwrap();
        assert_eq!(back.members[0].addresses, policy.members[0].addresses);

        assert!(
            serde_json::from_str::<NamespacePolicy>(r#"{"members": [{"addresses": ["x"]}]}"#)
                .is_err()
        );
    }

    #[test]
    fn grant_serde_round_trip() {
        let grant = Grant {
            from: GrantEnd::Namespace("quick".into()),
            to: GrantEnd::Peer("key:01".to_owned()),
            proto: Some("tcp".to_owned()),
            ports: None,
        };
        let json = serde_json::to_string(&grant).unwrap();
        assert_eq!(serde_json::from_str::<Grant>(&json).unwrap(), grant);
    }
}
