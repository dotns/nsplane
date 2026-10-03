//! Reassembly of fragmented IPv4 UDP datagrams without a checksum.
//!
//! IPv6 requires a UDP checksum, and it covers the whole datagram, so a
//! fragmented IPv4 UDP datagram whose checksum is zero can only be translated
//! once all of its fragments are in. Fragments of other datagrams are
//! translated one by one and never stored here.
//!
//! An entry is opened by the first fragment (offset 0, zero UDP checksum) and
//! later fragments of the same datagram join it. Entries are bounded in count
//! and bytes and expire [`EXPIRY_SECS`] after they were opened. Exact
//! duplicates are ignored; overlapping fragments drop the whole datagram.

use std::collections::BTreeMap;
use std::net::Ipv4Addr;

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

/// One received fragment.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct Piece {
    /// Offset in 8-byte units.
    pub(super) offset: u16,
    pub(super) more: bool,
    pub(super) tos: u8,
    pub(super) ttl: u8,
    pub(super) payload: Vec<u8>,
}

impl Piece {
    fn start(&self) -> usize {
        usize::from(self.offset) * 8
    }

    fn end(&self) -> usize {
        self.start() + self.payload.len()
    }
}

/// What [`Reassembly::observe`] did with a fragment.
#[derive(Debug, PartialEq, Eq)]
pub(super) enum Outcome {
    /// Stored; the datagram is not complete yet.
    Pending,
    /// The datagram is complete; the header fields come from the first fragment.
    Complete { payload: Vec<u8>, tos: u8, ttl: u8 },
}

/// Bounds of a [`Reassembly`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct Limits {
    pub(super) max_entries: usize,
    pub(super) max_bytes: usize,
}

/// Event counts of a [`Reassembly`].
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub(super) struct Counters {
    pub(super) accepted: u64,
    pub(super) duplicates: u64,
    pub(super) overlaps: u64,
    pub(super) expired: u64,
    pub(super) budget_drops: u64,
    pub(super) completed: u64,
}

#[derive(Debug)]
struct Entry {
    created_at: u64,
    /// Sorted by offset, non-overlapping.
    pieces: Vec<Piece>,
    /// Datagram length, known once the last fragment arrived.
    total: Option<usize>,
}

impl Entry {
    fn is_complete(&self) -> bool {
        let Some(total) = self.total else {
            return false;
        };
        let mut cursor = 0;
        for piece in &self.pieces {
            if piece.start() != cursor {
                return false;
            }
            cursor = piece.end();
        }
        cursor == total
    }

    fn bytes(&self) -> usize {
        self.pieces.iter().map(|piece| piece.payload.len()).sum()
    }
}

/// Bounded reassembly state for zero-checksum UDP datagrams.
#[derive(Debug)]
pub(super) struct Reassembly {
    limits: Limits,
    entries: BTreeMap<Key, Entry>,
    bytes: usize,
    counters: Counters,
}

impl Reassembly {
    pub(super) const fn new(limits: Limits) -> Self {
        Self {
            limits,
            entries: BTreeMap::new(),
            bytes: 0,
            counters: Counters {
                accepted: 0,
                duplicates: 0,
                overlaps: 0,
                expired: 0,
                budget_drops: 0,
                completed: 0,
            },
        }
    }

    pub(super) const fn counters(&self) -> Counters {
        self.counters
    }

    #[cfg(test)]
    pub(super) fn entry_count(&self) -> usize {
        self.entries.len()
    }

    #[cfg(test)]
    pub(super) const fn buffered_bytes(&self) -> usize {
        self.bytes
    }

    /// Whether a datagram with `key` is being reassembled.
    pub(super) fn contains(&self, key: &Key) -> bool {
        self.entries.contains_key(key)
    }

    /// Drops every entry that expired at `now` (seconds).
    pub(super) fn cleanup(&mut self, now: u64) {
        let expired: Vec<_> = self
            .entries
            .iter()
            .filter(|(_, entry)| is_expired(entry.created_at, now))
            .map(|(key, _)| *key)
            .collect();
        for key in expired {
            self.remove(&key);
            self.counters.expired += 1;
        }
    }

    /// Adds `piece` to the datagram `key` at `now` (seconds), opening an entry
    /// if there is none.
    pub(super) fn observe(&mut self, key: Key, piece: Piece, now: u64) -> Result<Outcome> {
        if self
            .entries
            .get(&key)
            .is_some_and(|entry| is_expired(entry.created_at, now))
        {
            self.remove(&key);
            self.counters.expired += 1;
            return Err(reasons::EXPIRED);
        }
        self.cleanup(now);
        if piece.payload.is_empty() || (piece.more && !piece.payload.len().is_multiple_of(8)) {
            return Err(reasons::MALFORMED_FRAGMENT);
        }
        let (start, end) = (piece.start(), piece.end());
        let over_budget = self
            .bytes
            .checked_add(piece.payload.len())
            .is_none_or(|bytes| bytes > self.limits.max_bytes);
        let Some(entry) = self.entries.get(&key) else {
            if self.entries.len() >= self.limits.max_entries || over_budget {
                self.counters.budget_drops += 1;
                return Err(reasons::BUDGET_EXCEEDED);
            }
            return self.insert(key, piece, now);
        };
        for stored in &entry.pieces {
            if start == stored.start()
                && end == stored.end()
                && piece.more == stored.more
                && piece.payload == stored.payload
            {
                self.counters.duplicates += 1;
                return Ok(Outcome::Pending);
            }
            if start < stored.end() && stored.start() < end {
                self.remove(&key);
                self.counters.overlaps += 1;
                return Err(reasons::OVERLAP);
            }
        }
        if entry.total.is_some_and(|total| end > total)
            || (!piece.more
                && (entry.total.is_some_and(|total| total != end)
                    || entry.pieces.iter().any(|stored| stored.end() > end)))
        {
            self.remove(&key);
            return Err(reasons::MALFORMED_FRAGMENT);
        }
        if over_budget {
            self.counters.budget_drops += 1;
            return Err(reasons::BUDGET_EXCEEDED);
        }
        self.insert(key, piece, now)
    }

    /// Stores `piece` (already checked) and completes the datagram if it can.
    fn insert(&mut self, key: Key, piece: Piece, now: u64) -> Result<Outcome> {
        self.bytes += piece.payload.len();
        self.counters.accepted += 1;
        let entry = self.entries.entry(key).or_insert_with(|| Entry {
            created_at: now,
            pieces: Vec::new(),
            total: None,
        });
        if !piece.more {
            entry.total = Some(piece.end());
        }
        let at = entry
            .pieces
            .partition_point(|stored| stored.start() < piece.start());
        entry.pieces.insert(at, piece);
        if !entry.is_complete() {
            return Ok(Outcome::Pending);
        }
        let Some(entry) = self.remove(&key) else {
            return Err(reasons::MALFORMED_FRAGMENT);
        };
        self.counters.completed += 1;
        let (tos, ttl) = entry
            .pieces
            .first()
            .map(|first| (first.tos, first.ttl))
            .ok_or(reasons::MALFORMED_FRAGMENT)?;
        let payload = entry
            .pieces
            .into_iter()
            .flat_map(|piece| piece.payload)
            .collect();
        Ok(Outcome::Complete { payload, tos, ttl })
    }

    fn remove(&mut self, key: &Key) -> Option<Entry> {
        let entry = self.entries.remove(key)?;
        self.bytes = self.bytes.saturating_sub(entry.bytes());
        Some(entry)
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

    fn piece(offset: u16, more: bool, payload: &[u8]) -> Piece {
        Piece {
            offset,
            more,
            tos: 0x10 + u8::try_from(offset).unwrap(),
            ttl: 64 - u8::try_from(offset).unwrap(),
            payload: payload.to_vec(),
        }
    }

    fn state(max_entries: usize, max_bytes: usize) -> Reassembly {
        Reassembly::new(Limits {
            max_entries,
            max_bytes,
        })
    }

    const DATA: &[u8; 32] = b"0123456789abcdefghijklmnopqrstuv";

    #[test]
    fn reassembles_in_any_order_with_first_fragment_header() {
        let pieces = [
            piece(0, true, &DATA[..16]),
            piece(2, true, &DATA[16..24]),
            piece(3, false, &DATA[24..]),
        ];
        for order in [
            [0, 1, 2],
            [0, 2, 1],
            [1, 0, 2],
            [1, 2, 0],
            [2, 0, 1],
            [2, 1, 0],
        ] {
            let mut state = state(1, 64);
            let mut outcomes: Vec<_> = order
                .iter()
                .enumerate()
                .map(|(now, &index)| {
                    state
                        .observe(KEY, pieces[index].clone(), u64::try_from(now).unwrap())
                        .unwrap()
                })
                .collect();
            let last = outcomes.pop().unwrap();
            assert!(outcomes.iter().all(|outcome| *outcome == Outcome::Pending));
            assert_eq!(
                last,
                Outcome::Complete {
                    payload: DATA.to_vec(),
                    tos: 0x10,
                    ttl: 64
                }
            );
            assert_eq!((state.entry_count(), state.buffered_bytes()), (0, 0));
            assert_eq!(state.counters().completed, 1);
        }
    }

    #[test]
    fn duplicates_are_ignored_overlaps_drop_the_datagram() {
        let mut state = state(4, 128);
        let first = piece(0, true, &DATA[..16]);
        assert_eq!(state.observe(KEY, first.clone(), 0), Ok(Outcome::Pending));
        assert_eq!(state.observe(KEY, first, 1), Ok(Outcome::Pending));
        assert_eq!(state.counters().duplicates, 1);
        assert_eq!(
            state.observe(KEY, piece(1, true, &DATA[8..16]), 2),
            Err(reasons::OVERLAP)
        );
        assert_eq!(
            (
                state.entry_count(),
                state.buffered_bytes(),
                state.counters().overlaps
            ),
            (0, 0, 1)
        );
    }

    #[test]
    fn conflicting_more_flag_is_an_overlap() {
        let mut state = state(4, 128);
        assert_eq!(
            state.observe(KEY, piece(0, true, &DATA[..16]), 0),
            Ok(Outcome::Pending)
        );
        assert_eq!(
            state.observe(KEY, piece(0, false, &DATA[..16]), 1),
            Err(reasons::OVERLAP)
        );
        assert_eq!(state.entry_count(), 0);
    }

    #[test]
    fn gaps_stay_pending() {
        let mut state = state(4, 128);
        assert_eq!(
            state.observe(KEY, piece(0, true, &DATA[..16]), 0),
            Ok(Outcome::Pending)
        );
        assert_eq!(
            state.observe(KEY, piece(3, false, &DATA[24..]), 1),
            Ok(Outcome::Pending)
        );
        assert_eq!(state.entry_count(), 1);
    }

    #[test]
    fn rejects_malformed_lengths_and_ends() {
        let mut state = state(4, 128);
        assert_eq!(
            state.observe(KEY, piece(1, true, &[0; 7]), 0),
            Err(reasons::MALFORMED_FRAGMENT)
        );
        assert_eq!(
            state.observe(KEY, piece(0, false, &[]), 0),
            Err(reasons::MALFORMED_FRAGMENT)
        );
        // A fragment beyond the end announced by the last fragment.
        assert_eq!(
            state.observe(KEY, piece(2, false, &DATA[16..24]), 0),
            Ok(Outcome::Pending)
        );
        assert_eq!(
            state.observe(KEY, piece(3, true, &DATA[24..]), 1),
            Err(reasons::MALFORMED_FRAGMENT)
        );
        assert_eq!((state.entry_count(), state.buffered_bytes()), (0, 0));
        // Two different ends.
        assert_eq!(
            state.observe(KEY, piece(2, false, &DATA[16..24]), 2),
            Ok(Outcome::Pending)
        );
        assert_eq!(
            state.observe(KEY, piece(3, false, &DATA[24..]), 3),
            Err(reasons::MALFORMED_FRAGMENT)
        );
    }

    #[test]
    fn entry_and_byte_budgets() {
        let mut state = state(1, 16);
        assert_eq!(
            state.observe(KEY, piece(0, true, &DATA[..8]), 0),
            Ok(Outcome::Pending)
        );
        let other = Key {
            identification: 8,
            ..KEY
        };
        assert_eq!(
            state.observe(other, piece(0, true, &DATA[..8]), 1),
            Err(reasons::BUDGET_EXCEEDED)
        );
        assert_eq!(
            state.observe(KEY, piece(1, true, &DATA[8..24]), 1),
            Err(reasons::BUDGET_EXCEEDED)
        );
        assert_eq!(state.counters().budget_drops, 2);

        let mut bytes = Reassembly::new(Limits {
            max_entries: 4,
            max_bytes: 7,
        });
        assert_eq!(
            bytes.observe(KEY, piece(0, true, &DATA[..8]), 0),
            Err(reasons::BUDGET_EXCEEDED)
        );
        assert_eq!(bytes.counters().budget_drops, 1);
    }

    #[test]
    fn entries_expire_after_sixty_seconds() {
        let mut state = state(1, 64);
        assert_eq!(
            state.observe(KEY, piece(0, true, &DATA[..8]), 0),
            Ok(Outcome::Pending)
        );
        assert_eq!(
            state.observe(KEY, piece(3, false, &DATA[24..]), 59),
            Ok(Outcome::Pending)
        );
        assert_eq!(
            state.observe(KEY, piece(1, true, &DATA[8..24]), 60),
            Err(reasons::EXPIRED)
        );
        assert_eq!(state.counters().expired, 1);
        assert_eq!((state.entry_count(), state.buffered_bytes()), (0, 0));

        // Cleanup frees expired entries of other datagrams too.
        assert_eq!(
            state.observe(KEY, piece(0, true, &DATA[..8]), 100),
            Ok(Outcome::Pending)
        );
        let other = Key {
            identification: 8,
            ..KEY
        };
        assert_eq!(
            state.observe(other, piece(0, true, &DATA[..8]), 160),
            Ok(Outcome::Pending)
        );
        assert_eq!(state.counters().expired, 2);
        assert!(!state.contains(&KEY));
        assert!(state.contains(&other));
    }
}
