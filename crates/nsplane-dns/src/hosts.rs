//! [`Hosts`]: entries parsed from hosts-format text, as local records or policy rules.

use std::collections::HashMap;
use std::net::IpAddr;

use crate::message::{Record, RecordData, normalize_name};
use crate::policy::{Action, NameMatch, Rule, is_host_name};
use crate::records::StaticRecords;

/// The entries of hosts-format text.
///
/// Each line is an address followed by one or more names, separated by whitespace; `#`
/// starts a comment up to the end of the line and blank lines are skipped. Addresses are
/// IPv4 or IPv6 (without a zone index). Names are normalized ([`normalize_name`]); a name
/// starting with `*.` is a wildcard for every name below the rest (not the rest itself).
/// The addresses of a name from all its lines are kept in order of appearance, duplicates
/// once.
///
/// Parsing never fails as a whole: a line with an invalid address is skipped, an invalid
/// name is skipped while the other names of its line are kept, and each problem is reported
/// in [`errors`](Self::errors). Reading the text from a file is the caller's.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Hosts {
    /// Names (wildcards with their `*.`) and their addresses, in order of first appearance.
    entries: Vec<(String, Vec<IpAddr>)>,
    errors: Vec<HostsError>,
}

/// A problem on one line of hosts text.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("line {line}: {kind}")]
pub struct HostsError {
    /// Line number, from 1.
    pub line: usize,
    /// What is wrong.
    pub kind: HostsErrorKind,
}

/// What is wrong with a line of hosts text.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum HostsErrorKind {
    /// The first field is not an IPv4 or IPv6 address; the line is skipped.
    #[error("invalid address `{0}`")]
    InvalidAddress(String),
    /// An address without names.
    #[error("address without names")]
    NoName,
    /// A name that is not a host name or a `*.` wildcard of one; the name is skipped.
    #[error("invalid name `{0}`")]
    InvalidName(String),
}

impl Hosts {
    /// Parses hosts-format `text`.
    pub fn parse(text: &str) -> Self {
        let mut hosts = Self::default();
        let mut index: HashMap<String, usize> = HashMap::new();
        for (number, line) in text.lines().enumerate() {
            let line_no = number + 1;
            let content = line.split_once('#').map_or(line, |(content, _)| content);
            let mut fields = content.split_whitespace();
            let Some(address) = fields.next() else {
                continue;
            };
            let mut error = |kind| {
                hosts.errors.push(HostsError {
                    line: line_no,
                    kind,
                });
            };
            let Ok(address) = address.parse::<IpAddr>() else {
                error(HostsErrorKind::InvalidAddress(address.to_owned()));
                continue;
            };
            let mut named = false;
            for field in fields {
                named = true;
                let name = normalize_name(field);
                let base = name.strip_prefix("*.").unwrap_or(&name);
                if !is_host_name(base) {
                    error(HostsErrorKind::InvalidName(field.to_owned()));
                    continue;
                }
                let slot = *index.entry(name.clone()).or_insert_with(|| {
                    hosts.entries.push((name, Vec::new()));
                    hosts.entries.len() - 1
                });
                let addresses = &mut hosts.entries[slot].1;
                if !addresses.contains(&address) {
                    addresses.push(address);
                }
            }
            if !named {
                error(HostsErrorKind::NoName);
            }
        }
        hosts
    }

    /// The problems found, in line order.
    pub fn errors(&self) -> &[HostsError] {
        &self.errors
    }

    /// Whether the text had no valid entry.
    pub const fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// The plain (non-wildcard) names as A / AAAA records with `ttl`.
    pub fn static_records(&self, ttl: u32) -> StaticRecords {
        self.entries
            .iter()
            .filter(|(name, _)| !name.starts_with("*."))
            .flat_map(|(name, addresses)| {
                addresses.iter().map(move |&address| match address {
                    IpAddr::V4(v4) => Record::a(name.as_str(), ttl, v4),
                    IpAddr::V6(v6) => Record::aaaa(name.as_str(), ttl, v6),
                })
            })
            .collect()
    }

    /// The wildcard names as [`NameMatch::Wildcard`] rules answering their addresses
    /// ([`Action::Records`]), in order of first appearance.
    pub fn wildcard_rules(&self) -> Vec<Rule> {
        self.rules_where(|name| name.starts_with("*."))
    }

    /// Every name as a rule answering its addresses: plain names as [`NameMatch::Exact`],
    /// wildcards as [`NameMatch::Wildcard`], in order of first appearance.
    pub fn rules(&self) -> Vec<Rule> {
        self.rules_where(|_| true)
    }

    fn rules_where(&self, keep: impl Fn(&str) -> bool) -> Vec<Rule> {
        self.entries
            .iter()
            .filter(|(name, _)| keep(name))
            .map(|(name, addresses)| {
                let matcher = if name.starts_with("*.") {
                    NameMatch::Wildcard(name.clone())
                } else {
                    NameMatch::Exact(name.clone())
                };
                let data = addresses
                    .iter()
                    .map(|&address| match address {
                        IpAddr::V4(v4) => RecordData::A(v4),
                        IpAddr::V6(v6) => RecordData::Aaaa(v6),
                    })
                    .collect();
                Rule::new(matcher, Action::Records(data))
            })
            .collect()
    }
}
