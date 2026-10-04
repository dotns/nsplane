//! Reassembly of fragmented IPv4 UDP datagrams without a checksum.
//!
//! IPv6 requires a UDP checksum, and it covers the whole datagram, so a
//! fragmented IPv4 UDP datagram whose checksum is zero can only be translated
//! once all of its fragments are in.
//!
//! Only the first fragment (offset 0) shows the checksum, so a later fragment
//! that arrives before it opens an entry too and is held there. A first
//! fragment with a checksum then joins a held entry (the filter cannot release
//! the held fragments one by one), or, with nothing held, is translated alone
//! and leaves a marker so the rest of its datagram is translated one by one.
//!
//! The fragments are held by a [`Reassembler`]; this state adds what the
//! translator needs on top of it: which datagrams are held, the byte budget
//! of all of them together, and the markers. Entries and markers are bounded
//! in count (and entries in bytes) and expire [`EXPIRY_SECS`] after they were
//! opened. Overlapping fragments drop the whole datagram (`reasons::OVERLAP`).
//!
//! A fragment with the same range as a held one is a duplicate, whatever its
//! payload and MF flag: the first copy wins, so a reassembled datagram never
//! mixes bytes of two copies. This differs from 0.9.0 in three ways: an exact
//! duplicate counts as held and in the byte budget (0.9.0 did not count it); a
//! duplicate with a different payload or MF flag is ignored (0.9.0 dropped the
//! datagram with `reasons::OVERLAP`); and at the byte limit a duplicate is
//! dropped with `reasons::BUDGET_EXCEEDED` (0.9.0 ignored it). The bounds, the
//! markers and the other drop reasons are unchanged.

use std::collections::BTreeMap;
use std::net::Ipv4Addr;
use std::time::{Duration, Instant};

use nsplane_packet::reassembly::{self, Reassembler, ReassemblyConfig};

use super::{Result, reasons};

/// Seconds after which an incomplete datagram is discarded.
pub(super) const EXPIRY_SECS: u64 = 60;

/// Identifies one IPv4 datagram (RFC 791).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub(super) struct Key {
    pub(super) src: Ipv4Addr,
    pub(super) dst: Ipv4Addr,
    pub(super) identification: u16,
    pub(super) protocol: u8,
}

/// What [`Reassembly::observe`] did with a fragment.
#[derive(Debug, PartialEq, Eq)]
pub(super) enum Outcome {
    /// Stored; the datagram is not complete yet.
    Pending,
    /// The datagram is complete: the reassembled IPv4 packet, whose header
    /// is the first fragment's.
    Complete(Vec<u8>),
}

/// Bounds of a [`Reassembly`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct Limits {
    /// Most datagrams held, and most markers.
    pub(super) max_entries: usize,
    /// Most fragment payload bytes held, all datagrams together.
    pub(super) max_bytes: usize,
}

/// Event counts of a [`Reassembly`].
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub(super) struct Counters {
    /// Fragments held or completing their datagram.
    pub(super) accepted: u64,
    pub(super) expired: u64,
    pub(super) budget_drops: u64,
    pub(super) completed: u64,
    /// Markers forgotten at the entry limit.
    pub(super) marker_evictions: u64,
}

/// A datagram the reassembler holds.
#[derive(Debug, Clone, Copy)]
struct Held {
    created_at: u64,
    /// Payload bytes of its fragments so far.
    bytes: usize,
}

/// Bounded reassembly state for zero-checksum UDP datagrams.
#[derive(Debug)]
pub(super) struct Reassembly {
    limits: Limits,
    reassembler: Reassembler,
    /// The reassembler's clock at second 0.
    origin: Instant,
    /// The datagrams the reassembler holds, in step with it.
    held: BTreeMap<Key, Held>,
    bytes: usize,
    /// Datagrams whose first fragment carried a checksum and was translated
    /// alone, with the time it passed.
    passed: BTreeMap<Key, u64>,
    counters: Counters,
}

impl Reassembly {
    pub(super) fn new(limits: Limits) -> Self {
        Self {
            limits,
            reassembler: Reassembler::new(ReassemblyConfig {
                max_datagrams: limits.max_entries,
                timeout: Duration::from_secs(EXPIRY_SECS),
                ..ReassemblyConfig::default()
            }),
            origin: Instant::now(),
            held: BTreeMap::new(),
            bytes: 0,
            passed: BTreeMap::new(),
            counters: Counters::default(),
        }
    }

    pub(super) const fn counters(&self) -> Counters {
        let stats = self.reassembler.stats();
        Counters {
            expired: stats.timeout,
            completed: stats.reassembled,
            ..self.counters
        }
    }

    #[cfg(test)]
    pub(super) fn entry_count(&self) -> usize {
        self.held.len()
    }

    /// Whether a datagram with `key` is being reassembled.
    pub(super) fn contains(&self, key: &Key) -> bool {
        self.held.contains_key(key)
    }

    /// Records that the first fragment of `key` carried a checksum and was
    /// translated alone at `now` (seconds). At the entry limit the oldest
    /// marker is forgotten.
    pub(super) fn mark_passed(&mut self, key: Key, now: u64) {
        if !self.passed.contains_key(&key)
            && self.passed.len() >= self.limits.max_entries
            && let Some(oldest) = self
                .passed
                .iter()
                .min_by_key(|(_, passed_at)| **passed_at)
                .map(|(key, _)| *key)
        {
            self.passed.remove(&oldest);
            self.counters.marker_evictions += 1;
        }
        self.passed.insert(key, now);
    }

    /// Whether the first fragment of `key` was translated alone: its later
    /// fragments are then translated one by one too.
    pub(super) fn passed(&self, key: &Key) -> bool {
        self.passed.contains_key(key)
    }

    /// Drops every entry and marker that expired at `now` (seconds).
    pub(super) fn cleanup(&mut self, now: u64) {
        self.passed
            .retain(|_, passed_at| !is_expired(*passed_at, now));
        // The reassembler expires the same datagrams: both count from the
        // same second.
        self.reassembler.expire(self.at(now));
        let bytes = &mut self.bytes;
        self.held.retain(|_, held| {
            let keep = !is_expired(held.created_at, now);
            if !keep {
                *bytes = bytes.saturating_sub(held.bytes);
            }
            keep
        });
    }

    /// Adds the IPv4 fragment `packet` of the datagram `key`, whose payload
    /// is `len` bytes, at `now` (seconds), opening an entry if there is none.
    pub(super) fn observe(
        &mut self,
        key: Key,
        packet: &[u8],
        len: usize,
        now: u64,
    ) -> Result<Outcome> {
        self.cleanup(now);
        if len == 0 {
            return Err(reasons::MALFORMED_FRAGMENT);
        }
        let over_budget = self
            .bytes
            .checked_add(len)
            .is_none_or(|bytes| bytes > self.limits.max_bytes);
        if over_budget || (!self.contains(&key) && self.held.len() >= self.limits.max_entries) {
            self.counters.budget_drops += 1;
            return Err(reasons::BUDGET_EXCEEDED);
        }
        let (before, pending) = (self.reassembler.stats(), self.reassembler.pending());
        match self.reassembler.push(packet, self.at(now)) {
            reassembly::Outcome::Held => {
                let held = self.held.entry(key).or_insert(Held {
                    created_at: now,
                    bytes: 0,
                });
                held.bytes += len;
                self.bytes += len;
                self.counters.accepted += 1;
                Ok(Outcome::Pending)
            }
            reassembly::Outcome::Complete(packet) => {
                self.remove(&key);
                self.counters.accepted += 1;
                Ok(Outcome::Complete(packet))
            }
            reassembly::Outcome::Pass => Err(reasons::MALFORMED_FRAGMENT),
            reassembly::Outcome::Dropped => {
                // A fragment that ends its datagram removes it; an invalid
                // one leaves it held.
                if self.reassembler.pending() < pending {
                    self.remove(&key);
                }
                let after = self.reassembler.stats();
                if after.overlap > before.overlap {
                    Err(reasons::OVERLAP)
                } else if after.overflow > before.overflow {
                    self.counters.budget_drops += 1;
                    Err(reasons::BUDGET_EXCEEDED)
                } else {
                    Err(reasons::MALFORMED_FRAGMENT)
                }
            }
        }
    }

    /// The reassembler's clock at `now` (seconds).
    fn at(&self, now: u64) -> Instant {
        self.origin
            .checked_add(Duration::from_secs(now))
            .unwrap_or(self.origin)
    }

    fn remove(&mut self, key: &Key) {
        if let Some(held) = self.held.remove(key) {
            self.bytes = self.bytes.saturating_sub(held.bytes);
        }
    }
}

const fn is_expired(created_at: u64, now: u64) -> bool {
    match now.checked_sub(created_at) {
        Some(age) => age >= EXPIRY_SECS,
        None => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const KEY: Key = Key {
        src: Ipv4Addr::new(100, 64, 0, 100),
        dst: Ipv4Addr::new(100, 64, 0, 1),
        identification: 7,
        protocol: 17,
    };

    fn state(max_entries: usize, max_bytes: usize) -> Reassembly {
        Reassembly::new(Limits {
            max_entries,
            max_bytes,
        })
    }

    /// An IPv4 fragment of `KEY` at `offset` (8-byte units).
    fn fragment(offset: u16, more: bool, payload: &[u8]) -> Vec<u8> {
        let total = u16::try_from(20 + payload.len()).unwrap();
        let flags = offset | if more { 0x2000 } else { 0 };
        let mut packet = vec![0x45, 0];
        packet.extend_from_slice(&total.to_be_bytes());
        packet.extend_from_slice(&KEY.identification.to_be_bytes());
        packet.extend_from_slice(&flags.to_be_bytes());
        packet.extend_from_slice(&[64, KEY.protocol, 0, 0]);
        packet.extend_from_slice(&KEY.src.octets());
        packet.extend_from_slice(&KEY.dst.octets());
        packet.extend_from_slice(payload);
        packet
    }

    fn observe(state: &mut Reassembly, packet: &[u8], now: u64) -> Result<Outcome> {
        state.observe(KEY, packet, packet.len() - 20, now)
    }

    const DATA: &[u8; 32] = b"0123456789abcdefghijklmnopqrstuv";

    #[test]
    fn held_entries_follow_the_reassembler() {
        let mut state = state(4, 128);
        assert_eq!(
            observe(&mut state, &fragment(2, false, &DATA[16..]), 0),
            Ok(Outcome::Pending)
        );
        assert!(state.contains(&KEY));
        // An invalid fragment is dropped and leaves the datagram held.
        assert_eq!(
            observe(&mut state, &fragment(0, true, &DATA[..7]), 1),
            Err(reasons::MALFORMED_FRAGMENT)
        );
        assert!(state.contains(&KEY));
        // An overlap drops the datagram.
        assert_eq!(
            observe(&mut state, &fragment(1, true, &DATA[8..24]), 2),
            Err(reasons::OVERLAP)
        );
        assert!(!state.contains(&KEY));
        assert_eq!((state.entry_count(), state.bytes), (0, 0));

        assert_eq!(
            observe(&mut state, &fragment(2, false, &DATA[16..]), 3),
            Ok(Outcome::Pending)
        );
        let Ok(Outcome::Complete(packet)) = observe(&mut state, &fragment(0, true, &DATA[..16]), 4)
        else {
            panic!("not complete");
        };
        assert_eq!(&packet[20..], DATA);
        assert_eq!((state.entry_count(), state.bytes), (0, 0));
        assert_eq!(state.counters().completed, 1);

        // Expiry forgets the entry with the reassembler's.
        assert_eq!(
            observe(&mut state, &fragment(2, false, &DATA[16..]), 10),
            Ok(Outcome::Pending)
        );
        state.cleanup(70);
        assert!(!state.contains(&KEY));
        assert_eq!((state.bytes, state.counters().expired), (0, 1));
    }

    #[test]
    fn markers_expire_and_are_bounded() {
        let mut state = state(2, 64);
        let other = Key {
            identification: 8,
            ..KEY
        };
        let third = Key {
            identification: 9,
            ..KEY
        };
        state.mark_passed(KEY, 0);
        state.mark_passed(other, 10);
        state.mark_passed(third, 20);
        assert!(!state.passed(&KEY) && state.passed(&other) && state.passed(&third));
        assert_eq!(state.counters().marker_evictions, 1);
        state.cleanup(70);
        assert!(!state.passed(&other) && state.passed(&third));
        state.cleanup(80);
        assert!(!state.passed(&third));
        assert_eq!(state.counters().expired, 0);
    }
}
