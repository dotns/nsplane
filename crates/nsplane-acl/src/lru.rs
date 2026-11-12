//! [`LruMap`]: a hash map that keeps its entries in recency order, so the
//! filter's bounded tables evict their least recently seen entry in O(1).
//! Its keys come from traffic, so it is hashed with the keyed
//! [`KeyedState`], like the other maps of the filter and the engine that
//! packets look up.

use std::collections::HashMap;
use std::hash::Hash;

use nsplane_packet::hash::KeyedState;

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
    index: HashMap<K, usize, KeyedState>,
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

    /// Make `key` the most recent entry; `false` when there is none.
    pub(crate) fn touch(&mut self, key: &K) -> bool {
        let Some(&slot) = self.index.get(key) else {
            return false;
        };
        self.unlink(slot);
        self.link_newest(slot);
        true
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

    /// The entries, from the least to the most recent one.
    pub(crate) fn iter(&self) -> impl Iterator<Item = (&K, &V)> {
        let mut slot = self.oldest;
        std::iter::from_fn(move || {
            let node = self.slots.get(slot)?.as_ref()?;
            slot = node.next;
            Some((&node.key, &node.value))
        })
    }

    /// Keep only the entries for which `keep` returns `true`. O(len).
    pub(crate) fn retain(&mut self, mut keep: impl FnMut(&K, &V) -> bool) {
        let mut slot = self.oldest;
        while slot != NIL {
            let Some(node) = self.slots[slot].as_ref() else {
                break;
            };
            let next = node.next;
            if !keep(&node.key, &node.value)
                && let Some((key, _)) = self.release(slot)
            {
                self.index.remove(&key);
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
    use std::collections::HashSet;
    use std::net::Ipv6Addr;

    use std::hash::BuildHasher;

    use super::*;

    /// The hasher of the tables.
    type TableHash = KeyedState;

    /// The tables' former multiply-rotate hasher
    /// (`state = rotl((state ^ word) * odd, 29)`) cancelled a flip of bit 63
    /// of one word with a flip of bit 28 of the next, whatever its seed: the
    /// product carried the first flip in bit 63 alone and the rotation moved
    /// it to bit 28. The same held for the top `n` bits against bits
    /// `29 - n..=28`, which gave sets of `2^n` keys with one hash.
    #[test]
    fn the_table_hasher_has_no_seed_independent_collisions() {
        for seed in 0..16_u64 {
            let hash = TableHash::default();
            for index in 0..64_u64 {
                let (first, second) = (index.wrapping_mul(0x0123_4567_89ab_cdef) ^ seed, !index);
                assert_ne!(
                    hash.hash_one((first, second)),
                    hash.hash_one((first ^ (1 << 63), second ^ (1 << 28))),
                    "words {first:#x}, {second:#x}"
                );
            }
            // The same two bits of an IPv6 address: bit 7 of octet 7 and
            // bit 4 of octet 11.
            let address = Ipv6Addr::new(0xfd00, 1, 2, 3, 4, 5, 6, 7);
            let mut octets = address.octets();
            octets[7] ^= 0x80;
            octets[11] ^= 0x10;
            assert_ne!(
                hash.hash_one(address),
                hash.hash_one(Ipv6Addr::from(octets))
            );
            // The top four bits of one word against bits 25..=28 of the next.
            let hashes: HashSet<u64> = (0..256_u64)
                .map(|bits| hash.hash_one(((bits >> 4) << 60, (bits & 0xf) << 25)))
                .collect();
            assert_eq!(hashes.len(), 256);
        }
    }

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
        assert_eq!(map.free, [] as [usize; 0]);
        assert_eq!(keys(&mut map), [0, 2, 3, 5, 6]);
        assert_eq!(map.release(0), None);
        assert!(map.is_empty());
    }
}
