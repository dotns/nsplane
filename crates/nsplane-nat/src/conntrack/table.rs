//! The storage behind [`Conntrack`](super::Conntrack): a slab of entries, one
//! index per direction and an intrusive least-recently-seen list.

use std::collections::HashMap;
use std::ops::Range;
use std::time::Instant;

use nsplane_packet::FiveTuple;

use super::{ConntrackStats, Flow, FlowDirection, reverse};

/// The end of the LRU list.
const NIL: usize = usize::MAX;

/// A tracked flow and when it was last seen.
#[derive(Debug)]
pub(super) struct Entry {
    pub(super) flow: Flow,
    pub(super) last_seen: Instant,
}

/// A slab slot, linked into the LRU list while occupied.
#[derive(Debug)]
struct Slot {
    entry: Option<Entry>,
    prev: usize,
    next: usize,
}

/// Event counters, kept under the table lock.
#[derive(Debug, Default)]
pub(super) struct Counters {
    pub(super) inserted: u64,
    pub(super) expired: u64,
    pub(super) evicted: u64,
    pub(super) removed: u64,
    pub(super) hits: u64,
    pub(super) misses: u64,
}

#[derive(Debug)]
pub(super) struct Table {
    slots: Vec<Slot>,
    free: Vec<usize>,
    by_original: HashMap<FiveTuple, usize>,
    by_reply: HashMap<FiveTuple, usize>,
    /// Least recently seen entry.
    head: usize,
    /// Most recently seen entry.
    tail: usize,
    /// Next slot the expiry sweep looks at.
    cursor: usize,
    pub(super) counters: Counters,
}

impl Table {
    pub(super) fn new() -> Self {
        Self {
            slots: Vec::new(),
            free: Vec::new(),
            by_original: HashMap::new(),
            by_reply: HashMap::new(),
            head: NIL,
            tail: NIL,
            cursor: 0,
            counters: Counters::default(),
        }
    }

    pub(super) fn len(&self) -> usize {
        self.by_original.len()
    }

    pub(super) fn stats(&self) -> ConntrackStats {
        let c = &self.counters;
        ConntrackStats {
            entries: self.len(),
            inserted: c.inserted,
            expired: c.expired,
            evicted: c.evicted,
            removed: c.removed,
            hits: c.hits,
            misses: c.misses,
        }
    }

    /// The entry a packet with `tuple` belongs to, and the packet's direction.
    pub(super) fn find(&self, tuple: &FiveTuple) -> Option<(usize, FlowDirection)> {
        if let Some(&index) = self.by_original.get(tuple) {
            return Some((index, FlowDirection::Original));
        }
        self.reply_index(tuple)
            .map(|index| (index, FlowDirection::Reply))
    }

    pub(super) fn reply_index(&self, reply: &FiveTuple) -> Option<usize> {
        self.by_reply.get(reply).copied()
    }

    pub(super) fn entry(&self, index: usize) -> Option<&Entry> {
        self.slots.get(index)?.entry.as_ref()
    }

    pub(super) fn entry_mut(&mut self, index: usize) -> Option<&mut Entry> {
        self.slots.get_mut(index)?.entry.as_mut()
    }

    /// The least recently seen entry.
    pub(super) const fn oldest(&self) -> Option<usize> {
        if self.head == NIL {
            None
        } else {
            Some(self.head)
        }
    }

    /// Every slot index, occupied or not.
    pub(super) const fn indices(&self) -> Range<usize> {
        0..self.slots.len()
    }

    /// The slot the expiry sweep looks at next, advancing the cursor.
    pub(super) const fn next_cursor(&mut self) -> Option<usize> {
        if self.slots.is_empty() {
            return None;
        }
        if self.cursor >= self.slots.len() {
            self.cursor = 0;
        }
        let index = self.cursor;
        self.cursor += 1;
        Some(index)
    }

    /// Stores `entry`, indexed by its original tuple and by `reply`, as the
    /// most recently seen entry.
    pub(super) fn insert(&mut self, entry: Entry, reply: FiveTuple) {
        let original = entry.flow.original;
        let index = if let Some(index) = self.free.pop() {
            if let Some(slot) = self.slots.get_mut(index) {
                slot.entry = Some(entry);
            }
            index
        } else {
            self.slots.push(Slot {
                entry: Some(entry),
                prev: NIL,
                next: NIL,
            });
            self.slots.len() - 1
        };
        self.by_original.insert(original, index);
        self.by_reply.insert(reply, index);
        self.link_tail(index);
    }

    /// Removes the entry at `index` from the slab, the indexes and the list.
    pub(super) fn remove(&mut self, index: usize) -> Option<Entry> {
        let entry = self.slots.get_mut(index)?.entry.take()?;
        self.unlink(index);
        self.by_original.remove(&entry.flow.original);
        self.by_reply.remove(&reverse(&entry.flow.translated));
        self.free.push(index);
        Some(entry)
    }

    /// Marks the entry at `index` as the most recently seen.
    pub(super) fn touch(&mut self, index: usize) {
        if self.tail != index {
            self.unlink(index);
            self.link_tail(index);
        }
    }

    fn link_tail(&mut self, index: usize) {
        let tail = self.tail;
        if let Some(slot) = self.slots.get_mut(index) {
            slot.prev = tail;
            slot.next = NIL;
        }
        match self.slots.get_mut(tail) {
            Some(slot) => slot.next = index,
            None => self.head = index,
        }
        self.tail = index;
    }

    fn unlink(&mut self, index: usize) {
        let Some(slot) = self.slots.get_mut(index) else {
            return;
        };
        let (prev, next) = (slot.prev, slot.next);
        slot.prev = NIL;
        slot.next = NIL;
        match self.slots.get_mut(prev) {
            Some(slot) => slot.next = next,
            None => self.head = next,
        }
        match self.slots.get_mut(next) {
            Some(slot) => slot.prev = prev,
            None => self.tail = prev,
        }
    }
}
