//! [`LruMap`]: a hash map that keeps its entries in recency order, so the
//! filter's bounded tables evict their least recently seen entry in O(1), and
//! [`FlowHash`], the hasher of those tables.

use std::collections::HashMap;
use std::collections::hash_map::RandomState;
use std::hash::{BuildHasher, Hash, Hasher};

/// The hasher of the filter's tables: a multiply-rotate hash over 64-bit
/// words with a random seed per table, several times faster than `SipHash`
/// on a five-tuple. Not cryptographic; the seed keeps remote peers from
/// choosing colliding tuples.
#[derive(Debug, Clone, Copy)]
pub(crate) struct FlowHash(u64);

impl Default for FlowHash {
    fn default() -> Self {
        Self(RandomState::new().hash_one(0_u8))
    }
}

impl BuildHasher for FlowHash {
    type Hasher = FlowHasher;

    fn build_hasher(&self) -> FlowHasher {
        FlowHasher(self.0)
    }
}

pub(crate) struct FlowHasher(u64);

impl FlowHasher {
    const fn mix(&mut self, word: u64) {
        self.0 = (self.0 ^ word)
            .wrapping_mul(0x9e37_79b9_7f4a_7c15)
            .rotate_left(29);
    }
}

impl Hasher for FlowHasher {
    fn write(&mut self, bytes: &[u8]) {
        let (words, rest) = bytes.as_chunks::<8>();
        for word in words {
            self.mix(u64::from_le_bytes(*word));
        }
        let mut word = [0; 8];
        word[..rest.len()].copy_from_slice(rest);
        self.mix(u64::from_le_bytes(word));
    }

    fn write_u8(&mut self, n: u8) {
        self.mix(n.into());
    }

    fn write_u16(&mut self, n: u16) {
        self.mix(n.into());
    }

    fn write_u32(&mut self, n: u32) {
        self.mix(n.into());
    }

    fn write_u64(&mut self, n: u64) {
        self.mix(n);
    }

    fn write_usize(&mut self, n: usize) {
        self.mix(n as u64);
    }

    fn finish(&self) -> u64 {
        // Spread the high bits the multiplication produced to the low ones
        // the table indexes with.
        self.0 ^ (self.0 >> 32)
    }
}

/// No slot.
const NIL: usize = usize::MAX;

#[derive(Debug)]
struct Node<K, V> {
    key: K,
    value: V,
    /// The previous (less recent) and next (more recent) slots.
    prev: usize,
    next: usize,
}

/// A hash map whose entries form a list from the least to the most recently
/// inserted or [touched](Self::touch) one, kept in a slab of slots.
#[derive(Debug)]
pub(crate) struct LruMap<K, V> {
    index: HashMap<K, usize, FlowHash>,
    slots: Vec<Option<Node<K, V>>>,
    free: Vec<usize>,
    /// The least and the most recent slots.
    oldest: usize,
    newest: usize,
}

impl<K, V> Default for LruMap<K, V> {
    fn default() -> Self {
        Self {
            index: HashMap::default(),
            slots: Vec::new(),
            free: Vec::new(),
            oldest: NIL,
            newest: NIL,
        }
    }
}

impl<K: Copy + Eq + Hash, V> LruMap<K, V> {
    pub(crate) fn len(&self) -> usize {
        self.index.len()
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.index.is_empty()
    }

    pub(crate) fn contains_key(&self, key: &K) -> bool {
        self.index.contains_key(key)
    }

    pub(crate) fn get(&self, key: &K) -> Option<&V> {
        let slot = *self.index.get(key)?;
        self.slots[slot].as_ref().map(|node| &node.value)
    }

    pub(crate) fn get_mut(&mut self, key: &K) -> Option<&mut V> {
        let slot = *self.index.get(key)?;
        self.slots[slot].as_mut().map(|node| &mut node.value)
    }

    /// Make `key` the most recent entry.
    pub(crate) fn touch(&mut self, key: &K) {
        if let Some(&slot) = self.index.get(key) {
            self.unlink(slot);
            self.link_newest(slot);
        }
    }

    /// Insert or replace `key`'s value; it becomes the most recent entry.
    /// Returns the previous value.
    pub(crate) fn insert(&mut self, key: K, value: V) -> Option<V> {
        if let Some(&slot) = self.index.get(&key) {
            self.unlink(slot);
            self.link_newest(slot);
            let node = self.slots[slot].as_mut()?;
            return Some(std::mem::replace(&mut node.value, value));
        }
        let node = Node {
            key,
            value,
            prev: NIL,
            next: NIL,
        };
        let slot = if let Some(slot) = self.free.pop() {
            self.slots[slot] = Some(node);
            slot
        } else {
            self.slots.push(Some(node));
            self.slots.len() - 1
        };
        self.link_newest(slot);
        self.index.insert(key, slot);
        None
    }

    pub(crate) fn remove(&mut self, key: &K) -> Option<V> {
        let slot = self.index.remove(key)?;
        self.release(slot).map(|(_, value)| value)
    }

    /// Remove and return the least recent entry.
    pub(crate) fn pop_oldest(&mut self) -> Option<(K, V)> {
        if self.oldest == NIL {
            return None;
        }
        let (key, value) = self.release(self.oldest)?;
        self.index.remove(&key);
        Some((key, value))
    }

    /// Keep only the entries for which `keep` returns `true`. O(len).
    pub(crate) fn retain(&mut self, mut keep: impl FnMut(&K, &V) -> bool) {
        let mut slot = self.oldest;
        while slot != NIL {
            let Some(node) = self.slots[slot].as_ref() else {
                break;
            };
            let next = node.next;
            if !keep(&node.key, &node.value) {
                if let Some((key, _)) = self.release(slot) {
                    self.index.remove(&key);
                }
            }
            slot = next;
        }
    }

    /// Unlink `slot` and free it, returning its entry; `None`, with nothing
    /// changed, when the slot holds no entry.
    fn release(&mut self, slot: usize) -> Option<(K, V)> {
        if !matches!(self.slots.get(slot), Some(Some(_))) {
            return None;
        }
        self.unlink(slot);
        let node = self.slots[slot].take()?;
        self.free.push(slot);
        Some((node.key, node.value))
    }

    fn unlink(&mut self, slot: usize) {
        let Some(node) = self.slots[slot].as_ref() else {
            return;
        };
        let (prev, next) = (node.prev, node.next);
        match self.slots.get_mut(prev).and_then(Option::as_mut) {
            Some(prev) => prev.next = next,
            None => self.oldest = next,
        }
        match self.slots.get_mut(next).and_then(Option::as_mut) {
            Some(next) => next.prev = prev,
            None => self.newest = prev,
        }
    }

    fn link_newest(&mut self, slot: usize) {
        let newest = self.newest;
        if let Some(node) = self.slots[slot].as_mut() {
            node.prev = newest;
            node.next = NIL;
        }
        match self.slots.get_mut(newest).and_then(Option::as_mut) {
            Some(node) => node.next = slot,
            None => self.oldest = slot,
        }
        self.newest = slot;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn keys(map: &mut LruMap<u32, u32>) -> Vec<u32> {
        let mut out = Vec::new();
        while let Some((key, _)) = map.pop_oldest() {
            out.push(key);
        }
        out
    }

    #[test]
    fn evicts_least_recent_first() {
        let mut map = LruMap::default();
        for key in 0..5 {
            assert_eq!(map.insert(key, key * 10), None);
        }
        map.touch(&1);
        assert_eq!(map.insert(3, 33), Some(30));
        assert_eq!(map.remove(&0), Some(0));
        assert_eq!(map.get(&3), Some(&33));
        *map.get_mut(&4).unwrap() = 44;
        assert_eq!(map.len(), 4);
        map.retain(|key, _| *key != 2);
        assert!(!map.contains_key(&2));
        assert_eq!(keys(&mut map), [4, 1, 3]);
        assert!(map.is_empty());
        // Freed slots are reused.
        map.insert(7, 0);
        map.insert(8, 0);
        map.touch(&7);
        assert_eq!(keys(&mut map), [8, 7]);
    }

    #[test]
    fn releasing_an_empty_slot_changes_nothing() {
        let mut map = LruMap::default();
        for key in 0..4 {
            map.insert(key, key);
        }
        assert_eq!(map.remove(&1), Some(1));
        assert_eq!(map.release(1), None);
        assert_eq!(map.release(NIL), None);
        assert_eq!(map.free, [1]);
        assert_eq!(map.len(), 3);
        // The freed slot is reused once, then the slab grows.
        map.insert(5, 5);
        map.insert(6, 6);
        assert_eq!(map.slots.len(), 5);
        assert!(map.free.is_empty());
        assert_eq!(keys(&mut map), [0, 2, 3, 5, 6]);
        assert_eq!(map.release(0), None);
        assert!(map.is_empty());
    }
}
