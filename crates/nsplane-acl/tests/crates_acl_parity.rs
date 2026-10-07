//! Differential replay of ns's inbound IPv4 ACL step against [`AclFilter`]
//! in the ns `crates/acl` mode ([`AclFilterConfig::crates_acl`]).
//!
//! The fixture `tests/fixtures/crates_acl_parity.json` holds packet
//! sequences with the verdicts ns gives them: `is_local_node_packet(pkt,
//! tun_ip) || is_icmp_echo_reply(pkt) || acl_check_packet(..)`, the order of
//! `inbound_ipv4` in ns `crates/ns/src/account_engine/filters.rs` (the Node
//! L3 gate and the recovery probe before it are not part of the ACL step;
//! no fixture packet is a recovery probe). For each sequence the test builds
//! one [`AclEngine`] on a manual clock (with the sequence's policy compiled
//! into typed rules by the [test-local compiler](#compiling-the-policies)
//! and installed, or none), one [`PeerLabelMap`] (a `by_source` peer with the
//! address label, a `relay_key` peer with its key label) and one
//! [`AclFilter`], feeds every packet in order with the clock at `t_ms`, and
//! requires [`Verdict::Accept`] exactly when the packet's expected verdict is
//! `allowed` (any drop counts as denied): ns's verdict, except for the
//! [deviations](#deviations). This proves that the label model reproduces
//! the preset (`docs/specs/acl-source-identity.md`).
//!
//! # Compiling the policies
//!
//! The test compiles each document as `docs/specs/acl-generic-api.md` 4.2
//! describes, without the crate's own document compiler:
//!
//! - host aliases are expanded to their CIDR;
//! - a `*` source gives a rule without labels or sources; a `key:<hex>`
//!   source the label `key:<lowercase hex>`; a CIDR or alias source
//!   `sources: [cidr]` plus the address label [`ADDRESS`], which only the
//!   `by_source` peers carry, so such a rule never matches a relay key;
//! - each `host:ports` destination becomes its own rule with
//!   `destinations: [cidr]` (none for `*`) and the ports as a
//!   [`PortSet`] (`*`: any);
//! - `tcp` gives [`ProtocolMatch::Tcp`], `udp` [`ProtocolMatch::Udp`], and
//!   no protocol both;
//! - every typed rule of document rule `i` gets the id `"parity#<i>"`;
//! - the policy tests must pass: [`RuleSet::matching`] on a flow from the
//!   test's source address with the address label.
//!
//! # Deviations
//!
//! ns `parse_five_tuple` reads IHL + 4 bytes; nsplane-acl drops malformed
//! IPv4; verdicts are equal on well-formed packets. nsplane-acl takes the
//! payload as the bytes from the header length to the total length, so a
//! packet is malformed when its total length exceeds the buffer or is below
//! the header length, or when the payload is shorter than the TCP (20 bytes)
//! or UDP (8 bytes) header (trailing bytes beyond the total length are
//! fine). Such packets ns allows are marked in the fixture with their ns
//! verdict and a deviation kind, and expected to be dropped:
//!
//! - `malformed-ipv4`: the malformed packet itself, dropped with
//!   [`reasons::MALFORMED`];
//! - `malformed-first-fragment`: a later fragment ns admits only through
//!   the gate entry of such a malformed first fragment, which nsplane-acl
//!   never recorded, dropped with [`reasons::FRAGMENT`].
//!
//! The test requires exactly [`DEVIATIONS`] marked packets (the fixture's
//! `deviations` count too), each recorded as ns-allowed and dropped with
//! its kind's reason, so no other difference can hide among them.
//!
//! # Fixture schema
//!
//! ```text
//! {
//!   "seed": u64,                 // seed of the generated sequences' LCG
//!   "ns_commit": "<sha>",        // ns commit the verdicts come from
//!   "generator": "<how>",
//!   "deviations": 30,            // number of deviation-marked packets
//!   "sequences": [{
//!     "name": "recorded/..." | "generated/<policy>",
//!     "policy": <crates/acl AclPolicy JSON> | null,   // null: no policy loaded
//!     "local_ip": "a.b.c.d" | null,                   // ns tun_ip; null: no local bypass
//!     "peers": [{ "id": u32, "kind": "by_source" | "relay_key", "key": "<64 hex>" }],
//!     "packets": [
//!       [peer id, t_ms, "0x<packet hex>", allowed],
//!       [peer id, t_ms, "0x<packet hex>", false,      // a deviation
//!        { "ns": true, "deviation": "malformed-ipv4" | "malformed-first-fragment" }],
//!       ...
//!     ]
//!   }]
//! }
//! ```
//!
//! The policies are the JSON form of ns `acl::AclPolicy`, which this crate's
//! [`AclPolicy`] parses unchanged. `key` is the peer's WireGuard key: ns
//! judges a packet by that key when it is in `relay_client_keys` (every
//! `relay_key` peer) and by the packet's source address otherwise. Packets
//! are IPv4 (ns runs the ACL step for IPv4 only), one per line; the `0x`
//! prefix keeps `typos` from reading words in short packets.
//!
//! # Time
//!
//! ns's `acl_check_packet` reads `Instant::now()` for its `FragmentAclGate`
//! (15 s TTL, 4096 entries). The generator reproduces `acl_check_packet`
//! verbatim with ns's own `ipv4_fragment_meta`, `FragmentKey`,
//! `FragmentAclGate`, `parse_five_tuple` and `acl` engine, but passes
//! `start + t_ms` to the gate instead of the wall clock, so the TTL and
//! capacity sequences (`recorded/fragment_ttl`,
//! `recorded/fragment_capacity`) are deterministic. Every sequence spanning
//! less than 15 s is also run through the real
//! `tunnel_wg::acl_check_packet` (with its own gate) and the generator
//! asserts both agree on every packet.
//!
//! # Regenerating the fixture
//!
//! The generator is a throwaway cargo crate under `.tmp/acl-diff/` (never
//! committed, never part of this workspace) built against a read-only copy
//! of ns. From the worktree root, with `df -h /srv` checked first:
//!
//! ```text
//! WT=$(pwd)
//! mkdir -p .tmp/ns .tmp/acl-diff/src
//! git -C /srv/dotns/ns archive refactor/nsplane | tar -x -C .tmp/ns
//! git -C /srv/dotns/ns rev-parse refactor/nsplane      # the ns_commit argument
//! cp .tmp/ns/Cargo.lock .tmp/acl-diff/                 # ns's lock decides versions
//! # write .tmp/acl-diff/Cargo.toml and src/main.rs (see below)
//! docker run --rm --label ai-agent=true -v "$WT:$WT" -w "$WT/.tmp/acl-diff" \
//!   -v nstun-cargo-registry:/usr/local/cargo/registry ai-agent/nstun-dev \
//!   cargo run --release -- "$WT/crates/nsplane-acl/tests/fixtures/crates_acl_parity.json" <ns commit>
//! rm -rf .tmp/acl-diff/target .tmp/ns
//! ```
//!
//! `Cargo.toml`: package `acl-diff` (edition 2024) with an empty
//! `[workspace]` table, path dependencies `acl`, `common`, `nat` and
//! `tunnel-wg` on `../ns/crates/<name>`, plus `arc-swap = "1"` and
//! `serde_json = "1"`. `src/main.rs`:
//!
//! - packet builders: `ipv4(src, dst, proto, id, flags_offset, payload)`
//!   (20-byte header, correct total length and checksum), `tcp(sport,
//!   dport)` (20-byte SYN header), `udp(sport, dport, data)`, `icmp(type,
//!   seq)`;
//! - `PEERS`: ids 1 and 2 `by_source` (keys `[0x01; 32]`, `[0x02; 32]`),
//!   3-5 `relay_key` (`[0xa1; 32]`, `[0xb2; 32]`, `[0xc3; 32]`; 5 is named
//!   by no rule);
//! - `policies()`: `none` (null), `empty` (`{"acls": []}`), `allow_all`,
//!   `aliases` (host aliases, CIDR sources, port lists and ranges, protocol
//!   filters, policy tests), `relay_keys` (`key:<hex>` sources of peers 3
//!   and 4 next to CIDR rules), `ports` (`"hosts": []`, ports 0 and 65535,
//!   ranges, lists, mixed-case protocols);
//! - `recorded()`: hand-written sequences (fail-closed policies and the two
//!   bypasses, no local address, alias and port boundaries per peer kind,
//!   relay keys vs CIDR sources, malformed and short packets, fragments: in
//!   order, out of order, duplicated, interleaved, same id with another
//!   source / destination / protocol, denied first fragments, ICMP and
//!   other-protocol fragments, TTL expiry and refresh, 4096-entry capacity);
//! - `generated(name, policy, lcg, count)`: per policy (400 packets for
//!   `none`, `empty`, `allow_all`, 2200 otherwise, local address
//!   `10.0.1.1`) random peers, sources, destinations and ports from fixed
//!   pools around the policies' boundaries, 0-3 ms apart: TCP, UDP, ICMP
//!   echo requests and replies, other protocols, malformed packets (cut short
//!   or a header length below 20) and fragmented datagrams whose 1-3
//!   continuations are interleaved later in random order, some duplicated or
//!   sent before the first fragment. The LCG is Knuth's MMIX one (as in
//!   `src/differential.rs`), seeded with the fixture's `seed`, shared by
//!   the policies in the order above;
//! - `judge(seq)`: the ns verdicts as described under [Time](#time), and
//!   the [deviations](#deviations): `nsplane_malformed(packet)` applies the
//!   rule above to a packet ns allowed through `acl_check_packet` (not a
//!   bypass) that is not a later fragment (`malformed-ipv4`); a map from
//!   `FragmentKey` to "admitted by a malformed first fragment", set whenever
//!   ns allows a first-of-many fragment, marks the later fragments ns allows
//!   through such an entry (`malformed-first-fragment`). A deviation is
//!   written with `allowed: false` and `{ "ns": true, "deviation": kind }`;
//!   `main` also writes their count as `deviations`;
//! - `main`: writes the fixture in the line-oriented form above.

use std::collections::HashMap;
use std::fmt::Write as _;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::ops::RangeInclusive;
use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Duration, Instant};

use nsplane_acl::{
    AclEngine, AclFilter, AclFilterConfig, AclPolicy, Flow, IpNet, Label, LabelSet, PeerLabelMap,
    PortSet, ProtocolMatch, Rule, RuleSet, reasons,
};
use nsplane_core::{PacketFilter, Verdict};
use nsplane_packet::{PacketBuf, PeerId};
use serde::Deserialize;

const FIXTURE: &str = include_str!("fixtures/crates_acl_parity.json");

/// Mismatches printed in full before the test fails.
const SHOWN: usize = 40;

/// Packets whose expected verdict deviates from ns (see
/// [Deviations](self#deviations)).
const DEVIATIONS: usize = 30;

#[derive(Deserialize)]
struct Fixture {
    seed: u64,
    ns_commit: String,
    deviations: usize,
    sequences: Vec<Sequence>,
}

#[derive(Deserialize)]
struct Sequence {
    name: String,
    policy: Option<AclPolicy>,
    local_ip: Option<Ipv4Addr>,
    peers: Vec<Peer>,
    packets: Vec<Packet>,
}

/// `[peer id, t_ms, "0x<hex>", allowed]`, plus the ns verdict and the
/// deviation kind for a deviation.
#[derive(Deserialize)]
#[serde(untagged)]
enum Packet {
    Equal(u32, u64, String, bool),
    Deviation(u32, u64, String, bool, Deviation),
}

#[derive(Deserialize)]
struct Deviation {
    ns: bool,
    deviation: DeviationKind,
}

#[derive(Deserialize, Clone, Copy, Debug)]
#[serde(rename_all = "kebab-case")]
enum DeviationKind {
    MalformedIpv4,
    MalformedFirstFragment,
}

impl DeviationKind {
    /// The drop reason nsplane-acl gives the packet.
    const fn reason(self) -> &'static str {
        match self {
            Self::MalformedIpv4 => reasons::MALFORMED,
            Self::MalformedFirstFragment => reasons::FRAGMENT,
        }
    }
}

#[derive(Deserialize)]
struct Peer {
    id: u32,
    kind: PeerKind,
    key: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "snake_case")]
enum PeerKind {
    BySource,
    RelayKey,
}

/// The label of the peers judged by their source address; CIDR sources
/// require it.
const ADDRESS: &str = "addr";

/// The key label of a 32-byte key given as hex (either case).
fn key_label(hex: &str) -> Option<Label> {
    let key = unhex(hex).filter(|key| key.len() == 32)?;
    let hex = key.iter().fold(String::new(), |mut hex, b| {
        let _ = write!(hex, "{b:02x}");
        hex
    });
    Some(Label::from(format!("key:{hex}")))
}

/// A host: `*` (`None`), a CIDR or an alias of `hosts`.
fn host(s: &str, hosts: &HashMap<String, IpNet>) -> Result<Option<IpNet>, String> {
    if s == "*" {
        return Ok(None);
    }
    s.parse()
        .ok()
        .or_else(|| hosts.get(s).copied())
        .map(Some)
        .ok_or_else(|| format!("unknown host '{s}'"))
}

/// Ports: `*`, `22`, `80,443` or `8000-8999`.
fn ports(s: &str) -> Result<PortSet, String> {
    let port = |p: &str| {
        p.trim()
            .parse::<u16>()
            .map_err(|_| format!("bad port '{p}'"))
    };
    if s == "*" {
        return Ok(PortSet::Any);
    }
    if let Some((lo, hi)) = s.split_once('-') {
        return Ok(PortSet::Ranges(vec![RangeInclusive::new(
            port(lo)?,
            port(hi)?,
        )]));
    }
    s.split(',')
        .map(port)
        .collect::<Result<Vec<_>, _>>()
        .map(PortSet::list)
}

/// The protocol entries of a document `proto` (`None`: TCP and UDP).
fn protocols(proto: Option<&str>, ports: &PortSet) -> Result<Vec<ProtocolMatch>, String> {
    match proto.map(str::to_lowercase).as_deref() {
        Some("tcp") => Ok(vec![ProtocolMatch::Tcp(ports.clone())]),
        Some("udp") => Ok(vec![ProtocolMatch::Udp(ports.clone())]),
        None => Ok(vec![
            ProtocolMatch::Tcp(ports.clone()),
            ProtocolMatch::Udp(ports.clone()),
        ]),
        Some(other) => Err(format!("bad protocol '{other}'")),
    }
}

/// The typed rules of `policy` (see [Compiling the policies](self#compiling-the-policies)),
/// its tests checked.
fn compile(policy: &AclPolicy) -> Result<RuleSet, String> {
    let hosts = policy
        .hosts
        .iter()
        .map(|(alias, cidr)| Ok((alias.clone(), cidr.parse().map_err(|_| cidr.clone())?)))
        .collect::<Result<HashMap<String, IpNet>, String>>()?;
    let mut rules = Vec::new();
    for (i, acl) in policy.acls.iter().enumerate() {
        for src in &acl.src {
            let source = if src == "*" {
                Rule::new("", Vec::new())
            } else if let Some(hex) = src.strip_prefix("key:") {
                let label = key_label(hex).ok_or_else(|| format!("bad key '{src}'"))?;
                Rule::new("", Vec::new()).with_labels([label])
            } else {
                let net = host(src, &hosts)?.ok_or("'*' is not a source prefix")?;
                Rule::new("", Vec::new())
                    .with_labels([Label::from(ADDRESS)])
                    .with_sources([net])
            };
            for dst in &acl.dst {
                let (host_part, port_part) = dst
                    .rsplit_once(':')
                    .ok_or_else(|| format!("bad dst '{dst}'"))?;
                let ports = ports(port_part)?;
                let mut rule = Rule {
                    id: format!("parity#{i}").into(),
                    protocols: protocols(acl.proto.as_deref(), &ports)?,
                    ..source.clone()
                };
                if let Some(net) = host(host_part, &hosts)? {
                    rule = rule.with_destinations([net]);
                }
                rules.push(rule);
            }
        }
    }
    let rules = RuleSet::new(rules).map_err(|e| e.to_string())?;
    let address = LabelSet::new([Label::from(ADDRESS)]);
    for test in &policy.tests {
        let src: IpAddr = test.src.parse().map_err(|_| test.src.clone())?;
        let dst: SocketAddr = test.dst.parse().map_err(|_| test.dst.clone())?;
        let src = SocketAddr::new(src, 0);
        let flow = match test.proto.as_deref().map(str::to_lowercase).as_deref() {
            Some("udp") => Flow::udp(src, dst),
            _ => Flow::tcp(src, dst),
        };
        if rules.matching(&address, &flow).is_some() != test.allow {
            return Err(format!("policy test {} -> {} failed", test.src, test.dst));
        }
    }
    Ok(rules)
}

/// The bytes of `s` (hex digits, optionally `0x`-prefixed).
fn unhex(s: &str) -> Option<Vec<u8>> {
    let digits = s.strip_prefix("0x").unwrap_or(s);
    if !digits.len().is_multiple_of(2) {
        return None;
    }
    (0..digits.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(digits.get(i..i + 2)?, 16).ok())
        .collect()
}

/// Replays `seq`, returning one line per packet whose verdict differs from
/// the expected one and the number of deviations, or why the sequence cannot
/// be replayed.
fn replay(seq: &Sequence) -> Result<(Vec<String>, usize), String> {
    let start = Instant::now();
    let clock = Arc::new(Mutex::new(start));
    let handle = Arc::clone(&clock);
    let engine = Arc::new(AclEngine::with_clock(move || {
        *handle.lock().unwrap_or_else(PoisonError::into_inner)
    }));
    if let Some(policy) = &seq.policy {
        let rules = compile(policy).map_err(|e| format!("{}: policy rejected: {e}", seq.name))?;
        engine.install(rules);
    }
    let identity = Arc::new(PeerLabelMap::new());
    for peer in &seq.peers {
        let label = match peer.kind {
            PeerKind::BySource => Label::from(ADDRESS),
            PeerKind::RelayKey => {
                key_label(&peer.key).ok_or_else(|| format!("{}: bad key {}", seq.name, peer.key))?
            }
        };
        identity.insert(PeerId::new(peer.id), LabelSet::new([label]));
    }
    let filter =
        AclFilter::with_config(engine, identity, AclFilterConfig::crates_acl(seq.local_ip));

    let mut mismatches = Vec::new();
    let mut deviations = 0;
    for (i, packet) in seq.packets.iter().enumerate() {
        let ((peer, t_ms, hex, allowed), deviation) = match packet {
            Packet::Equal(peer, t_ms, hex, allowed) => ((peer, t_ms, hex, allowed), None),
            Packet::Deviation(peer, t_ms, hex, allowed, deviation) => {
                ((peer, t_ms, hex, allowed), Some(deviation))
            }
        };
        let bytes = unhex(hex).ok_or_else(|| format!("{} #{i}: bad hex {hex}", seq.name))?;
        *clock.lock().unwrap_or_else(PoisonError::into_inner) =
            start + Duration::from_millis(*t_ms);
        let mut packet = PacketBuf::from_packet(&bytes);
        let verdict = filter.inbound(PeerId::new(*peer), &mut packet);
        if let Some(deviation) = deviation {
            deviations += 1;
            let reason = deviation.deviation.reason();
            if !deviation.ns || *allowed || verdict != (Verdict::Drop { reason }) {
                mismatches.push(format!(
                    "{} #{i} peer {peer} t_ms {t_ms} {hex}: deviation {:?} (ns allowed: {}, \
                     expected allowed: {allowed}) needs {reason:?}, nsplane-acl {verdict:?}",
                    seq.name, deviation.deviation, deviation.ns
                ));
            }
        } else if (verdict == Verdict::Accept) != *allowed {
            let ns = if *allowed { "allowed" } else { "denied" };
            mismatches.push(format!(
                "{} #{i} peer {peer} t_ms {t_ms} {hex}: ns {ns}, nsplane-acl {verdict:?}",
                seq.name
            ));
        }
    }
    Ok((mismatches, deviations))
}

#[test]
fn crates_acl_mode_matches_ns_acl_check_packet() {
    let fixture: Fixture = serde_json::from_str(FIXTURE).expect("fixture");
    assert!(!fixture.sequences.is_empty());
    let mut mismatches = Vec::new();
    let mut deviations = 0;
    for seq in &fixture.sequences {
        let (lines, count) = replay(seq).expect("replayable sequence");
        mismatches.extend(lines);
        deviations += count;
    }
    for line in mismatches.iter().take(SHOWN) {
        eprintln!("{line}");
    }
    assert!(
        mismatches.is_empty(),
        "{} packet(s) judged differently from ns {} (seed {})",
        mismatches.len(),
        fixture.ns_commit,
        fixture.seed
    );
    assert_eq!(
        (deviations, fixture.deviations),
        (DEVIATIONS, DEVIATIONS),
        "deviation-marked packets (marked, fixture count)"
    );
}
