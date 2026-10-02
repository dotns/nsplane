//! The text-form ACL policy document: host aliases, accept rules and tests.

use std::collections::HashMap;

use serde::{Deserialize, Deserializer, Serialize};

/// The complete ACL policy document.
#[derive(Debug, Clone, Deserialize, Serialize, Default)]
pub struct AclPolicy {
    /// Named host aliases mapping to CIDR strings (e.g. `"web" -> "192.168.1.0/24"`).
    ///
    /// A control plane may send this as either `{}` (empty map) or `[]`
    /// (empty array);
    /// the custom deserializer handles both gracefully.
    #[serde(default, deserialize_with = "deserialize_hosts_map")]
    pub hosts: HashMap<String, String>,

    /// Accept-only access control rules evaluated in order.
    #[serde(default)]
    pub acls: Vec<AclRule>,

    /// Built-in validation tests run when the policy is loaded.
    #[serde(default)]
    pub tests: Vec<AclTest>,
}

/// A single ACL rule. Action is always `accept` — there are no deny rules.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct AclRule {
    /// Must be `accept`; deny rules are not supported.
    pub action: AclAction,

    /// Source matchers: `*`, a CIDR (e.g. `10.0.0.0/24`), or a host alias.
    pub src: Vec<String>,

    /// Destination matchers in `host:ports` format, e.g.
    /// `*:*`, `db:5432`, `web:80,443`, `web:8000-8999`.
    pub dst: Vec<String>,

    /// Optional protocol filter: `"tcp"` or `"udp"`.
    /// When absent the rule matches both protocols.
    #[serde(default)]
    pub proto: Option<String>,
}

/// The only valid rule action (accept-only model).
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum AclAction {
    /// Accept traffic matching the rule.
    Accept,
}

/// A built-in policy test assertion.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct AclTest {
    /// Source IP address as a string.
    pub src: String,

    /// Destination in `"ip:port"` format.
    pub dst: String,

    /// Protocol to evaluate for this assertion: `"tcp"` or `"udp"`.
    /// Defaults to TCP for backwards compatibility with existing policies.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub proto: Option<String>,

    /// Expected result: `true` means the connection should be allowed.
    pub allow: bool,
}

// ── Custom deserializer: accept both `{}` and `[]` for the hosts field ───────

fn deserialize_hosts_map<'de, D>(deserializer: D) -> Result<HashMap<String, String>, D::Error>
where
    D: Deserializer<'de>,
{
    use serde::de;

    struct HostsVisitor;

    impl<'de> de::Visitor<'de> for HostsVisitor {
        type Value = HashMap<String, String>;

        fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.write_str("a map or an empty array")
        }

        fn visit_map<M>(self, mut map: M) -> Result<Self::Value, M::Error>
        where
            M: de::MapAccess<'de>,
        {
            let mut result = HashMap::new();
            while let Some((k, v)) = map.next_entry()? {
                result.insert(k, v);
            }
            Ok(result)
        }

        fn visit_seq<S>(self, mut seq: S) -> Result<Self::Value, S::Error>
        where
            S: de::SeqAccess<'de>,
        {
            // Accept empty array as empty map. Non-empty arrays are an error.
            if seq.next_element::<serde::de::IgnoredAny>()?.is_some() {
                return Err(de::Error::custom(
                    "hosts must be a map or an empty array, got non-empty array",
                ));
            }
            Ok(HashMap::new())
        }
    }

    deserializer.deserialize_any(HostsVisitor)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn policy_deserializes_with_defaults() {
        let json = r#"{"acls": []}"#;
        let policy: AclPolicy = serde_json::from_str(json).unwrap();
        assert!(policy.hosts.is_empty());
        assert!(policy.acls.is_empty());
        assert!(policy.tests.is_empty());
    }

    #[test]
    fn policy_round_trips_full_example() {
        let json = r#"{
            "hosts": { "db": "192.168.1.10/32" },
            "acls": [
                {
                    "action": "accept",
                    "src": ["10.0.0.0/24"],
                    "dst": ["db:5432"],
                    "proto": "tcp"
                }
            ],
            "tests": [
                { "src": "10.0.0.2", "dst": "192.168.1.10:5432", "proto": "tcp", "allow": true }
            ]
        }"#;
        let policy: AclPolicy = serde_json::from_str(json).unwrap();
        assert_eq!(policy.hosts.len(), 1);
        assert_eq!(policy.acls.len(), 1);
        assert_eq!(policy.acls[0].action, AclAction::Accept);
        assert_eq!(policy.tests.len(), 1);
        assert!(policy.tests[0].allow);

        // Round-trip.
        let re: AclPolicy = serde_json::from_str(&serde_json::to_string(&policy).unwrap()).unwrap();
        assert_eq!(re.acls[0].proto, Some("tcp".to_owned()));
        assert_eq!(re.tests[0].proto, Some("tcp".to_owned()));
    }

    #[test]
    fn acl_action_rejects_unknown_variant() {
        let json = r#"{"action":"deny","src":["*"],"dst":["*:*"]}"#;
        assert!(serde_json::from_str::<AclRule>(json).is_err());
    }

    #[test]
    fn policy_deserializes_hosts_as_empty_array() {
        // A control plane may send hosts as [] instead of {}
        let json = r#"{"acls":[],"hosts":[],"tests":[]}"#;
        let policy: AclPolicy = serde_json::from_str(json).unwrap();
        assert!(policy.hosts.is_empty());
    }

    #[test]
    fn policy_deserializes_hosts_as_map() {
        let json = r#"{"acls":[],"hosts":{"web":"10.0.0.1/32"},"tests":[]}"#;
        let policy: AclPolicy = serde_json::from_str(json).unwrap();
        assert_eq!(policy.hosts.get("web").unwrap(), "10.0.0.1/32");
    }
}
