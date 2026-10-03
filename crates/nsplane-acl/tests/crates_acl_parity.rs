//! Differential replay of ns's inbound IPv4 ACL step against [`AclFilter`]
//! in the ns `crates/acl` mode ([`AclFilterConfig::crates_acl`]).
//!
//! The fixture `tests/fixtures/crates_acl_parity.json` holds packet
//! sequences with the verdicts ns gives them: `is_local_node_packet(pkt,
//! tun_ip) || is_icmp_echo_reply(pkt) || acl_check_packet(..)`, the order of
//! `inbound_ipv4` in ns `crates/ns/src/account_engine/filters.rs` (the Node
//! L3 gate and the recovery probe before it are not part of the ACL step;
//! no fixture packet is a recovery probe). For each sequence the test builds
//! one [`AclEngine`] on a manual clock (with the sequence's policy loaded, or
//! none), one [`PeerIdentityMap`] (a `by_source` peer through
//! [`PeerIdentityMap::insert_by_source`], a `relay_key` peer with its
//! [`SourceAssertion::WgPeerKey`]) and one [`AclFilter`], feeds every packet
//! in order with the clock at `t_ms`, and requires [`Verdict::Accept`]
//! exactly when ns allowed the packet (any drop counts as denied).
//!
//! # Fixture schema
//!
//! ```text
//! {
//!   "seed": u64,                 // seed of the generated sequences' LCG
//!   "ns_commit": "<sha>",        // ns commit the verdicts come from
//!   "generator": "<how>",
//!   "sequences": [{
//!     "name": "recorded/..." | "generated/<policy>",
//!     "policy": <crates/acl AclPolicy JSON> | null,   // null: no policy loaded
//!     "local_ip": "a.b.c.d" | null,                   // ns tun_ip; null: no local bypass
//!     "peers": [{ "id": u32, "kind": "by_source" | "relay_key", "key": "<64 hex>" }],
//!     "packets": [[peer id, t_ms, "0x<packet hex>", allowed], ...]
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
//! - `judge(seq)`: the ns verdicts as described under [Time](#time);
//! - `main`: writes the fixture in the line-oriented form above.

use std::net::Ipv4Addr;
use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Duration, Instant};

use nsplane_acl::{
    AclEngine, AclFilter, AclFilterConfig, AclPolicy, PeerIdentityMap, SourceAssertion,
};
use nsplane_core::{PacketFilter, Verdict};
use nsplane_packet::{PacketBuf, PeerId};
use serde::Deserialize;

const FIXTURE: &str = include_str!("fixtures/crates_acl_parity.json");

/// Mismatches printed in full before the test fails.
const SHOWN: usize = 40;

#[derive(Deserialize)]
struct Fixture {
    seed: u64,
    ns_commit: String,
    sequences: Vec<Sequence>,
}

#[derive(Deserialize)]
struct Sequence {
    name: String,
    policy: Option<AclPolicy>,
    local_ip: Option<Ipv4Addr>,
    peers: Vec<Peer>,
    packets: Vec<(u32, u64, String, bool)>,
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

/// Replays `seq`, returning one line per packet whose verdict differs, or
/// why the sequence cannot be replayed.
fn replay(seq: &Sequence) -> Result<Vec<String>, String> {
    let start = Instant::now();
    let clock = Arc::new(Mutex::new(start));
    let handle = Arc::clone(&clock);
    let engine = Arc::new(AclEngine::with_clock(move || {
        *handle.lock().unwrap_or_else(PoisonError::into_inner)
    }));
    if let Some(policy) = &seq.policy {
        engine
            .load(policy.clone())
            .map_err(|e| format!("{}: policy rejected: {e}", seq.name))?;
    }
    let identity = Arc::new(PeerIdentityMap::new());
    for peer in &seq.peers {
        let id = PeerId::new(peer.id);
        match peer.kind {
            PeerKind::BySource => identity.insert_by_source(id),
            PeerKind::RelayKey => {
                let pubkey = unhex(&peer.key)
                    .and_then(|key| key.try_into().ok())
                    .ok_or_else(|| format!("{}: bad key {}", seq.name, peer.key))?;
                identity.insert(id, SourceAssertion::WgPeerKey { pubkey });
            }
        }
    }
    let filter =
        AclFilter::with_config(engine, identity, AclFilterConfig::crates_acl(seq.local_ip));

    let mut mismatches = Vec::new();
    for (i, (peer, t_ms, hex, allowed)) in seq.packets.iter().enumerate() {
        let bytes = unhex(hex).ok_or_else(|| format!("{} #{i}: bad hex {hex}", seq.name))?;
        *clock.lock().unwrap_or_else(PoisonError::into_inner) =
            start + Duration::from_millis(*t_ms);
        let mut packet = PacketBuf::from_packet(&bytes);
        let verdict = filter.inbound(PeerId::new(*peer), &mut packet);
        if (verdict == Verdict::Accept) != *allowed {
            let ns = if *allowed { "allowed" } else { "denied" };
            mismatches.push(format!(
                "{} #{i} peer {peer} t_ms {t_ms} {hex}: ns {ns}, nsplane-acl {verdict:?}",
                seq.name
            ));
        }
    }
    Ok(mismatches)
}

#[test]
fn crates_acl_mode_matches_ns_acl_check_packet() {
    let fixture: Fixture = serde_json::from_str(FIXTURE).expect("fixture");
    assert!(!fixture.sequences.is_empty());
    let mut mismatches = Vec::new();
    for seq in &fixture.sequences {
        mismatches.extend(replay(seq).expect("replayable sequence"));
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
}
