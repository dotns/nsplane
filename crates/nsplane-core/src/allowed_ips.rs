// Copyright (c) 2019 Cloudflare, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

use std::collections::{BTreeMap, HashMap, VecDeque};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use nsplane_packet::hash::KeyedState;

/// A longest-prefix-match table of IP/cidr networks.
///
/// Each address family runs a binary search on the prefix lengths in use (Waldvogel et al.):
/// one hash table per length holds the networks of that length and markers, the network bits
/// at that length of the longer networks whose search passes it. Every entry holds its best
/// matching network, so a lookup takes at most `ceil(log2(lengths in use + 1))` hash probes
/// (6 for IPv4, 8 for IPv6). The hash tables are [`KeyedState`] maps, keyed with fresh random
/// words each time a family is built, so keys differ per table and per rebuild.
///
/// A write at a prefix length in use updates the levels in place: the network, its markers
/// and the best matches of the markers below it. One that adds the first or removes the last
/// network of a length changes the search itself, so it marks the family dirty, and
/// [`AllowedIps::commit`] rebuilds each dirty family once; until then writes to a dirty family
/// only change its networks. A configuration change that ends in one commit costs at most one
/// rebuild per family. Lookups stay exact on a dirty family, probing every prefix length of
/// the networks, longest first.
pub(crate) struct AllowedIps<D> {
    v4: Table<D>,
    v6: Table<D>,
    /// The family rebuilds the table has run.
    pub(crate) rebuilds: usize,
}

/// A network or a marker in the level of one prefix length.
struct Entry {
    /// The slot and length of its best match: the longest network of this length or shorter
    /// that contains the bits. A network's own entry is the one whose best match has the
    /// length of the level.
    best: Option<(u32, u8)>,
    /// How many longer networks place a marker here.
    markers: u32,
}

impl Entry {
    const EMPTY: Self = Self {
        best: None,
        markers: 0,
    };
}

/// The networks and markers of one prefix length.
struct Level {
    len: u8,
    /// The network bits of `len`, left-aligned.
    mask: u128,
    /// The networks of exactly this length.
    networks: usize,
    /// Networks and markers by their left-aligned bits.
    entries: HashMap<u128, Entry, KeyedState>,
}

/// The networks of one address family.
struct Table<D> {
    /// The lengths in use, ascending: the binary search runs over this list. Up to date
    /// unless `dirty`.
    levels: Vec<Level>,
    /// The networks, `(bits, len)` to their slot.
    networks: BTreeMap<(u128, u8), u32>,
    /// The values, by slot.
    values: Vec<Option<D>>,
    /// Free slots in `values`.
    free: Vec<u32>,
    /// Whether the lengths in use changed since the last rebuild, so `levels` are out of date.
    dirty: bool,
}

/// The left-aligned network bits of a prefix of `len` bits.
fn mask(len: u8) -> u128 {
    u128::MAX.checked_shl(128 - u32::from(len)).unwrap_or(0)
}

/// The family of `addr` (`true` for IPv6) and its bits, left-aligned.
fn bits(addr: IpAddr) -> (bool, u128) {
    match addr {
        IpAddr::V4(a) => (false, u128::from(u32::from(a)) << 96),
        IpAddr::V6(a) => (true, u128::from(a)),
    }
}

/// The address of left-aligned `bits` of a family.
fn addr(v6: bool, bits: u128) -> IpAddr {
    if v6 {
        Ipv6Addr::from(bits).into()
    } else {
        Ipv4Addr::from(u32::try_from(bits >> 96).unwrap_or(0)).into()
    }
}

/// The levels before level `target` where the binary search over `count` levels for
/// `target` goes on to longer lengths: those where the target places a marker.
fn path(count: usize, target: usize) -> impl Iterator<Item = usize> {
    let (mut lo, mut hi) = (0, count);
    std::iter::from_fn(move || {
        if lo >= hi {
            return None;
        }
        let mid = lo + (hi - lo) / 2;
        if mid == target {
            lo = hi;
            return None;
        }
        if mid < target {
            lo = mid + 1;
        } else {
            hi = mid;
        }
        Some(mid)
    })
    .filter(move |&mid| mid < target)
}

impl<D> Table<D> {
    const fn new() -> Self {
        Self {
            levels: Vec::new(),
            networks: BTreeMap::new(),
            values: Vec::new(),
            free: Vec::new(),
            dirty: false,
        }
    }

    /// The position of the level of `len`.
    fn level(&self, len: u8) -> Option<usize> {
        self.levels
            .binary_search_by_key(&len, |level| level.len)
            .ok()
    }

    /// The slot and length of the longest network that contains `bits`, among the levels
    /// below `limit`: the search runs over all levels and takes those from `limit` on as
    /// empty, so it meets the markers where they are placed.
    fn search(&self, bits: u128, limit: usize) -> Option<(u32, u8)> {
        let (mut lo, mut hi) = (0, self.levels.len());
        let mut best = None;
        while lo < hi {
            let mid = lo + (hi - lo) / 2;
            let entry = self
                .levels
                .get(mid)
                .filter(|_| mid < limit)
                .and_then(|level| level.entries.get(&(bits & level.mask)));
            match entry {
                Some(entry) => {
                    best = entry.best.or(best);
                    lo = mid + 1;
                }
                None => hi = mid,
            }
        }
        best
    }

    /// The value of the longest network that contains `bits`; `max` is the address length.
    fn find(&self, bits: u128, max: u8) -> Option<&D> {
        let slot = if self.dirty {
            (0..=max)
                .rev()
                .find_map(|len| self.networks.get(&(bits & mask(len), len)).copied())?
        } else {
            self.search(bits, usize::MAX)?.0
        };
        self.values.get(usize::try_from(slot).ok()?)?.as_ref()
    }

    fn get(&self, bits: u128, len: u8) -> Option<&D> {
        let slot = *self.networks.get(&(bits & mask(len), len))?;
        self.values.get(usize::try_from(slot).ok()?)?.as_ref()
    }

    fn value_mut(&mut self, slot: u32) -> Option<&mut Option<D>> {
        self.values.get_mut(usize::try_from(slot).ok()?)
    }

    fn insert(&mut self, bits: u128, len: u8, data: D) -> Option<D> {
        let net = bits & mask(len);
        if let Some(&slot) = self.networks.get(&(net, len)) {
            // A new value for a known network: the levels stay valid.
            return self.value_mut(slot)?.replace(data);
        }
        let slot = if let Some(slot) = self.free.pop() {
            *self.value_mut(slot)? = Some(data);
            slot
        } else {
            let slot = u32::try_from(self.values.len()).ok()?;
            self.values.push(Some(data));
            slot
        };
        self.networks.insert((net, len), slot);
        if !self.dirty {
            match self.level(len) {
                Some(t) => self.place(net, t, slot),
                None => self.dirty = true,
            }
        }
        None
    }

    /// Adds network `net` of level `t`, stored in `slot`, to the levels.
    fn place(&mut self, net: u128, t: usize, slot: u32) {
        for mid in path(self.levels.len(), t) {
            let Some(key) = self.levels.get(mid).map(|level| net & level.mask) else {
                continue;
            };
            if let Some(entry) = self
                .levels
                .get_mut(mid)
                .and_then(|level| level.entries.get_mut(&key))
            {
                entry.markers += 1;
                continue;
            }
            let best = self.search(key, mid);
            if let Some(level) = self.levels.get_mut(mid) {
                level.entries.insert(key, Entry { best, markers: 1 });
            }
        }
        let Some(level) = self.levels.get_mut(t) else {
            return;
        };
        let len = level.len;
        let best = Some((slot, len));
        level.networks += 1;
        level.entries.entry(net).or_insert(Entry::EMPTY).best = best;
        // The markers below the network that matched a shorter one now match it.
        self.rematch(net, t, best, |old| old.is_none_or(|(_, old)| old < len));
    }

    fn remove_network(&mut self, bits: u128, len: u8) -> Option<D> {
        let net = bits & mask(len);
        let slot = self.networks.remove(&(net, len))?;
        self.free.push(slot);
        if !self.dirty {
            self.unplace(net, len, slot);
        }
        self.value_mut(slot)?.take()
    }

    /// Takes network `net/len`, stored in `slot` and already out of the networks, out of the
    /// levels; the last network of a length marks the family dirty instead.
    fn unplace(&mut self, net: u128, len: u8, slot: u32) {
        let Some(t) = self
            .level(len)
            .filter(|&t| self.levels.get(t).is_some_and(|level| level.networks > 1))
        else {
            self.dirty = true;
            return;
        };
        let next = self.search(net, t);
        if let Some(level) = self.levels.get_mut(t) {
            level.networks -= 1;
            if let Some(entry) = level.entries.get_mut(&net) {
                entry.best = next;
                if entry.markers == 0 {
                    level.entries.remove(&net);
                }
            }
        }
        for mid in path(self.levels.len(), t) {
            let Some(level) = self.levels.get_mut(mid) else {
                continue;
            };
            let key = net & level.mask;
            if let Some(entry) = level.entries.get_mut(&key) {
                entry.markers -= 1;
                if entry.markers == 0 && entry.best.is_none_or(|(_, best)| best != level.len) {
                    level.entries.remove(&key);
                }
            }
        }
        // The markers below the network that matched it now match the next shorter one.
        let removed = Some((slot, len));
        self.rematch(net, t, next, |old| old == removed);
    }

    /// Sets the best match of the markers above level `t` inside `net` to `best` where
    /// `stale` holds for it. Those markers are on the paths of the longer networks inside
    /// `net`.
    fn rematch(
        &mut self,
        net: u128,
        t: usize,
        best: Option<(u32, u8)>,
        stale: impl Fn(Option<(u32, u8)>) -> bool,
    ) {
        let Some(len) = self.levels.get(t).map(|level| level.len) else {
            return;
        };
        let count = self.levels.len();
        let Self {
            levels, networks, ..
        } = self;
        // Every network in this range is longer than `len`.
        for &(sub, sub_len) in networks
            .range((net, len + 1)..=(net | !mask(len), u8::MAX))
            .map(|(key, _)| key)
        {
            let Ok(sub_t) = levels.binary_search_by_key(&sub_len, |level| level.len) else {
                continue;
            };
            for mid in path(count, sub_t).filter(|&mid| mid > t) {
                let Some(level) = levels.get_mut(mid) else {
                    continue;
                };
                if let Some(entry) = level.entries.get_mut(&(sub & level.mask))
                    && stale(entry.best)
                {
                    entry.best = best;
                }
            }
        }
    }

    fn remove(&mut self, predicate: &dyn Fn(&D) -> bool) {
        let removed: Vec<(u128, u8)> = self
            .networks
            .iter()
            .filter(|&(_, &slot)| {
                usize::try_from(slot)
                    .ok()
                    .and_then(|i| self.values.get(i)?.as_ref())
                    .is_some_and(predicate)
            })
            .map(|(&key, _)| key)
            .collect();
        if !self.dirty {
            // In place, unless the networks are the last of a length.
            let mut counts = [0_usize; 129];
            for &(_, len) in &removed {
                if let Some(count) = counts.get_mut(usize::from(len)) {
                    *count += 1;
                }
            }
            self.dirty = self.levels.iter().any(|level| {
                counts
                    .get(usize::from(level.len))
                    .is_some_and(|&count| count >= level.networks)
            });
        }
        for (net, len) in removed {
            self.remove_network(net, len);
        }
    }

    /// Rebuilds the levels from the networks.
    fn rebuild(&mut self) {
        let mut lens: Vec<u8> = self.networks.keys().map(|&(_, len)| len).collect();
        lens.sort_unstable();
        lens.dedup();
        self.levels = lens
            .into_iter()
            .map(|len| Level {
                len,
                mask: mask(len),
                networks: 0,
                entries: HashMap::default(),
            })
            .collect();
        let count = self.levels.len();
        // Networks with their own slot and markers without a best match yet, then the best
        // match of the markers, shortest level first so each search below finds complete
        // levels.
        for (&(net, len), &slot) in &self.networks {
            let Some(t) = self.level(len) else {
                continue;
            };
            for mid in path(count, t) {
                if let Some(level) = self.levels.get_mut(mid) {
                    level
                        .entries
                        .entry(net & level.mask)
                        .or_insert(Entry::EMPTY)
                        .markers += 1;
                }
            }
            if let Some(level) = self.levels.get_mut(t) {
                level.networks += 1;
                level.entries.entry(net).or_insert(Entry::EMPTY).best = Some((slot, len));
            }
        }
        for mid in 0..count {
            let markers: Vec<u128> = self
                .levels
                .get(mid)
                .map(|level| {
                    level
                        .entries
                        .iter()
                        .filter(|(_, entry)| entry.best.is_none())
                        .map(|(&key, _)| key)
                        .collect()
                })
                .unwrap_or_default();
            for key in markers {
                let best = self.search(key, mid);
                if let Some(entry) = self
                    .levels
                    .get_mut(mid)
                    .and_then(|level| level.entries.get_mut(&key))
                {
                    entry.best = best;
                }
            }
        }
        self.dirty = false;
    }

    /// Appends `(value, network address, prefix length)` of every network, in the order of
    /// the stride-4 tree bitmap the table replaced (`ip_network_table`): a node's prefixes
    /// (shorter first, then by address) before its children, children by address.
    fn collect<'a>(&'a self, v6: bool, out: &mut Vec<(&'a D, IpAddr, u8)>) {
        let mut entries: Vec<(u128, u8, &D)> = self
            .networks
            .iter()
            .filter_map(|(&(net, len), &slot)| {
                let value = self.values.get(usize::try_from(slot).ok()?)?.as_ref()?;
                Some((net, len, value))
            })
            .collect();
        entries.sort_unstable_by(|&(a, a_len, _), &(b, b_len, _)| tree_order(a, a_len, b, b_len));
        out.extend(
            entries
                .into_iter()
                .map(|(net, len, data)| (data, addr(v6, net), len)),
        );
    }
}

/// The order of networks `a/a_len` and `b/b_len` in a pre-order walk of a stride-4 trie.
fn tree_order(a: u128, a_len: u8, b: u128, b_len: u8) -> std::cmp::Ordering {
    // The depth of the node a network sits in.
    let (a_node, b_node) = (a_len / 4 * 4, b_len / 4 * 4);
    let common = mask(a_node.min(b_node));
    (a & common)
        .cmp(&(b & common))
        .then(a_node.cmp(&b_node))
        .then(a_len.cmp(&b_len))
        .then(a.cmp(&b))
}

impl<D> Default for AllowedIps<D> {
    fn default() -> Self {
        Self::new()
    }
}

impl<D> AllowedIps<D> {
    /// Creates an empty table.
    pub(crate) const fn new() -> Self {
        Self {
            v4: Table::new(),
            v6: Table::new(),
            rebuilds: 0,
        }
    }

    /// The table of `key`'s family, with `key`'s bits, if `cidr` fits the family.
    fn split(&self, key: IpAddr, cidr: u8) -> Option<(&Table<D>, u128)> {
        match bits(key) {
            (false, bits) if cidr <= 32 => Some((&self.v4, bits)),
            (true, bits) if cidr <= 128 => Some((&self.v6, bits)),
            _ => None,
        }
    }

    fn split_mut(&mut self, key: IpAddr, cidr: u8) -> Option<(&mut Table<D>, u128)> {
        match bits(key) {
            (false, bits) if cidr <= 32 => Some((&mut self.v4, bits)),
            (true, bits) if cidr <= 128 => Some((&mut self.v6, bits)),
            _ => None,
        }
    }

    /// Removes all entries; nothing is left to rebuild.
    pub(crate) fn clear(&mut self) {
        self.v4 = Table::new();
        self.v6 = Table::new();
    }

    /// Inserts `data` for `key/cidr` and returns the value previously stored for that network.
    /// A `cidr` longer than the address is ignored and yields `None`.
    pub(crate) fn insert(&mut self, key: IpAddr, cidr: u8, data: D) -> Option<D> {
        // These are networks, it doesn't make sense for host bits to be set, so the table
        // truncates them.
        let (table, bits) = self.split_mut(key, cidr)?;
        table.insert(bits, cidr, data)
    }

    /// Returns the value stored for exactly the network `key/cidr`; `None` for a `cidr`
    /// longer than the address.
    pub(crate) fn get(&self, key: IpAddr, cidr: u8) -> Option<&D> {
        let (table, bits) = self.split(key, cidr)?;
        table.get(bits, cidr)
    }

    /// Removes the entry for exactly the network `key/cidr` and returns its value.
    pub(crate) fn remove_network(&mut self, key: IpAddr, cidr: u8) -> Option<D> {
        let (table, bits) = self.split_mut(key, cidr)?;
        table.remove_network(bits, cidr)
    }

    /// Whether the table holds no entry.
    pub(crate) fn is_empty(&self) -> bool {
        self.v4.networks.is_empty() && self.v6.networks.is_empty()
    }

    /// Returns the value of the longest prefix that contains `key`.
    pub(crate) fn find(&self, key: IpAddr) -> Option<&D> {
        match bits(key) {
            (false, bits) => self.v4.find(bits, 32),
            (true, bits) => self.v6.find(bits, 128),
        }
    }

    /// Removes every entry whose value matches `predicate`.
    pub(crate) fn remove(&mut self, predicate: &dyn Fn(&D) -> bool) {
        self.v4.remove(predicate);
        self.v6.remove(predicate);
    }

    /// Rebuilds each dirty family, once, and returns [`rebuilds`](Self::rebuilds). The end of
    /// every configuration change calls it.
    pub(crate) fn commit(&mut self) -> usize {
        for table in [&mut self.v4, &mut self.v6] {
            if table.dirty {
                table.rebuild();
                self.rebuilds += 1;
            }
        }
        self.rebuilds
    }

    /// Iterates over `(value, network address, prefix length)`: IPv4 first, each family in
    /// the pre-order of the stride-4 trie the table replaced.
    pub(crate) fn iter(&self) -> Iter<'_, D> {
        let mut entries = Vec::new();
        self.v4.collect(false, &mut entries);
        self.v6.collect(true, &mut entries);
        Iter(entries.into())
    }
}

/// Iterator over the entries of an [`AllowedIps`] table.
pub(crate) struct Iter<'a, D: 'a>(VecDeque<(&'a D, IpAddr, u8)>);

impl<D> std::fmt::Debug for Iter<'_, D> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Iter")
            .field("remaining", &self.0.len())
            .finish()
    }
}

impl<D> std::fmt::Debug for AllowedIps<D> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_list()
            .entries(self.iter().map(|(_, ip, cidr)| format!("{ip}/{cidr}")))
            .finish()
    }
}

impl<'a, D> Iterator for Iter<'a, D> {
    type Item = (&'a D, IpAddr, u8);
    fn next(&mut self) -> Option<Self::Item> {
        self.0.pop_front()
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn test_allowed_ips_insert_find() {
        use super::*;

        let mut map: AllowedIps<char> = AllowedIps::default();
        map.insert(IpAddr::from([127, 0, 0, 1]), 32, '1');
        map.insert(IpAddr::from([45, 25, 15, 1]), 30, '6');
        map.insert(IpAddr::from([127, 0, 15, 1]), 16, '2');
        map.insert(IpAddr::from([127, 1, 15, 1]), 24, '3');
        map.insert(IpAddr::from([255, 1, 15, 1]), 24, '4');
        map.insert(IpAddr::from([60, 25, 15, 1]), 32, '5');
        map.insert(IpAddr::from([553, 0, 0, 1, 0, 0, 0, 0]), 128, '7');
        assert_eq!(map.find(IpAddr::from([127, 0, 0, 1])), Some(&'1'));
        assert_eq!(map.find(IpAddr::from([127, 0, 255, 255])), Some(&'2'));
        assert_eq!(map.find(IpAddr::from([127, 1, 255, 255])), None);
        assert_eq!(map.find(IpAddr::from([127, 0, 255, 255])), Some(&'2'));
        assert_eq!(map.find(IpAddr::from([127, 1, 15, 255])), Some(&'3'));
        assert_eq!(map.find(IpAddr::from([127, 0, 255, 255])), Some(&'2'));
        assert_eq!(map.find(IpAddr::from([127, 1, 15, 255])), Some(&'3'));
        assert_eq!(map.find(IpAddr::from([255, 1, 15, 2])), Some(&'4'));
        assert_eq!(map.find(IpAddr::from([60, 25, 15, 1])), Some(&'5'));
        assert_eq!(map.find(IpAddr::from([20, 0, 0, 100])), None);
        assert_eq!(
            map.find(IpAddr::from([553, 0, 0, 1, 0, 0, 0, 0])),
            Some(&'7')
        );
        assert_eq!(map.find(IpAddr::from([553, 0, 0, 1, 0, 0, 0, 1])), None);
        assert_eq!(map.find(IpAddr::from([45, 25, 15, 1])), Some(&'6'));
    }

    #[test]
    fn test_allowed_ips_remove() {
        use super::*;

        let mut map: AllowedIps<char> = AllowedIps::default();
        map.insert(IpAddr::from([127, 0, 0, 1]), 32, '1');
        map.insert(IpAddr::from([45, 25, 15, 1]), 30, '6');
        map.insert(IpAddr::from([127, 0, 15, 1]), 16, '2');
        map.insert(IpAddr::from([127, 1, 15, 1]), 24, '3');
        map.insert(IpAddr::from([255, 1, 15, 1]), 24, '4');
        map.insert(IpAddr::from([60, 25, 15, 1]), 32, '5');
        map.insert(IpAddr::from([553, 0, 0, 1, 0, 0, 0, 0]), 128, '7');
        map.remove(&|c| *c == '5' || *c == '1' || *c == '7');

        let mut map_iter = map.iter();
        assert_eq!(
            map_iter.next(),
            Some((&'6', IpAddr::from([45, 25, 15, 0]), 30))
        );
        assert_eq!(
            map_iter.next(),
            Some((&'2', IpAddr::from([127, 0, 0, 0]), 16))
        );
        assert_eq!(
            map_iter.next(),
            Some((&'3', IpAddr::from([127, 1, 15, 0]), 24))
        );
        assert_eq!(
            map_iter.next(),
            Some((&'4', IpAddr::from([255, 1, 15, 0]), 24))
        );
        assert_eq!(map_iter.next(), None);
    }

    #[test]
    fn exact_prefixes_are_found_and_removed() {
        use super::*;

        let mut map: AllowedIps<char> = AllowedIps::default();
        map.insert(IpAddr::from([127, 0, 0, 1]), 32, '1');
        map.insert(IpAddr::from([45, 25, 15, 1]), 30, '6');
        map.insert(IpAddr::from([127, 0, 15, 1]), 16, '2');
        map.insert(IpAddr::from([127, 1, 15, 1]), 24, '3');
        map.insert(IpAddr::from([255, 1, 15, 1]), 24, '4');
        map.insert(IpAddr::from([60, 25, 15, 1]), 32, '5');
        map.insert(IpAddr::from([553, 0, 0, 1, 0, 0, 0, 0]), 128, '7');
        assert_eq!(map.get(IpAddr::from([127, 0, 9, 9]), 16), Some(&'2'));
        assert_eq!(map.get(IpAddr::from([127, 0, 0, 0]), 24), None);
        assert_eq!(map.get(IpAddr::from([127, 0, 0, 0]), 33), None);
        assert_eq!(
            map.remove_network(IpAddr::from([127, 0, 0, 0]), 16),
            Some('2')
        );
        assert_eq!(map.find(IpAddr::from([127, 0, 255, 255])), None);
        assert_eq!(map.find(IpAddr::from([127, 0, 0, 1])), Some(&'1'));
        assert!(!map.is_empty());
        map.clear();
        assert!(map.is_empty());
    }

    #[test]
    fn test_allowed_ips_iter() {
        use super::*;

        let mut map: AllowedIps<char> = AllowedIps::default();
        map.insert(IpAddr::from([127, 0, 0, 1]), 32, '1');
        map.insert(IpAddr::from([45, 25, 15, 1]), 30, '6');
        map.insert(IpAddr::from([127, 0, 15, 1]), 16, '2');
        map.insert(IpAddr::from([127, 1, 15, 1]), 24, '3');
        map.insert(IpAddr::from([255, 1, 15, 1]), 24, '4');
        map.insert(IpAddr::from([60, 25, 15, 1]), 32, '5');
        map.insert(IpAddr::from([553, 0, 0, 1, 0, 0, 0, 0]), 128, '7');
        let mut map_iter = map.iter();
        assert_eq!(
            map_iter.next(),
            Some((&'6', IpAddr::from([45, 25, 15, 0]), 30))
        );
        assert_eq!(
            map_iter.next(),
            Some((&'5', IpAddr::from([60, 25, 15, 1]), 32))
        );
        assert_eq!(
            map_iter.next(),
            Some((&'2', IpAddr::from([127, 0, 0, 0]), 16))
        );
        assert_eq!(
            map_iter.next(),
            Some((&'1', IpAddr::from([127, 0, 0, 1]), 32))
        );
        assert_eq!(
            map_iter.next(),
            Some((&'3', IpAddr::from([127, 1, 15, 0]), 24))
        );
        assert_eq!(
            map_iter.next(),
            Some((&'4', IpAddr::from([255, 1, 15, 0]), 24))
        );
        assert_eq!(
            map_iter.next(),
            Some((&'7', IpAddr::from([553, 0, 0, 1, 0, 0, 0, 0]), 128))
        );
        assert_eq!(map_iter.next(), None);
    }

    #[test]
    fn test_allowed_ips_v4_kernel_compatibility() {
        use super::*;

        // Test case from wireguard-go
        let mut map: AllowedIps<char> = AllowedIps::default();

        map.insert(IpAddr::from([192, 168, 4, 0]), 24, 'a');
        map.insert(IpAddr::from([192, 168, 4, 4]), 32, 'b');
        map.insert(IpAddr::from([192, 168, 0, 0]), 16, 'c');
        map.insert(IpAddr::from([192, 95, 5, 64]), 27, 'd');
        map.insert(IpAddr::from([192, 95, 5, 65]), 27, 'c');
        map.insert(IpAddr::from([0, 0, 0, 0]), 0, 'e');
        map.insert(IpAddr::from([64, 15, 112, 0]), 20, 'g');
        map.insert(IpAddr::from([64, 15, 123, 211]), 25, 'h');
        map.insert(IpAddr::from([10, 0, 0, 0]), 25, 'a');
        map.insert(IpAddr::from([10, 0, 0, 128]), 25, 'b');
        map.insert(IpAddr::from([10, 1, 0, 0]), 30, 'a');
        map.insert(IpAddr::from([10, 1, 0, 4]), 30, 'b');
        map.insert(IpAddr::from([10, 1, 0, 8]), 29, 'c');
        map.insert(IpAddr::from([10, 1, 0, 16]), 29, 'd');

        assert_eq!(Some(&'a'), map.find(IpAddr::from([192, 168, 4, 20])));
        assert_eq!(Some(&'a'), map.find(IpAddr::from([192, 168, 4, 0])));
        assert_eq!(Some(&'b'), map.find(IpAddr::from([192, 168, 4, 4])));
        assert_eq!(Some(&'c'), map.find(IpAddr::from([192, 168, 200, 182])));
        assert_eq!(Some(&'c'), map.find(IpAddr::from([192, 95, 5, 68])));
        assert_eq!(Some(&'e'), map.find(IpAddr::from([192, 95, 5, 96])));
        assert_eq!(Some(&'g'), map.find(IpAddr::from([64, 15, 116, 26])));
        assert_eq!(Some(&'g'), map.find(IpAddr::from([64, 15, 127, 3])));

        map.insert(IpAddr::from([1, 0, 0, 0]), 32, 'a');
        map.insert(IpAddr::from([64, 0, 0, 0]), 32, 'a');
        map.insert(IpAddr::from([128, 0, 0, 0]), 32, 'a');
        map.insert(IpAddr::from([192, 0, 0, 0]), 32, 'a');
        map.insert(IpAddr::from([255, 0, 0, 0]), 32, 'a');

        assert_eq!(Some(&'a'), map.find(IpAddr::from([1, 0, 0, 0])));
        assert_eq!(Some(&'a'), map.find(IpAddr::from([64, 0, 0, 0])));
        assert_eq!(Some(&'a'), map.find(IpAddr::from([128, 0, 0, 0])));
        assert_eq!(Some(&'a'), map.find(IpAddr::from([192, 0, 0, 0])));
        assert_eq!(Some(&'a'), map.find(IpAddr::from([255, 0, 0, 0])));

        map.remove(&|c| *c == 'a');

        assert_ne!(Some(&'a'), map.find(IpAddr::from([1, 0, 0, 0])));
        assert_ne!(Some(&'a'), map.find(IpAddr::from([64, 0, 0, 0])));
        assert_ne!(Some(&'a'), map.find(IpAddr::from([128, 0, 0, 0])));
        assert_ne!(Some(&'a'), map.find(IpAddr::from([192, 0, 0, 0])));
        assert_ne!(Some(&'a'), map.find(IpAddr::from([255, 0, 0, 0])));

        map.clear();

        map.insert(IpAddr::from([192, 168, 0, 0]), 16, 'a');
        map.insert(IpAddr::from([192, 168, 0, 0]), 24, 'a');

        map.remove(&|c| *c == 'a');

        assert_ne!(Some(&'a'), map.find(IpAddr::from([192, 168, 0, 1])));
    }

    #[test]
    #[allow(clippy::too_many_lines, reason = "verbatim wireguard-go test vector")]
    fn test_allowed_ips_v6_kernel_compatibility() {
        use super::*;

        // Test case from wireguard-go
        let mut map: AllowedIps<char> = AllowedIps::default();

        map.insert(
            IpAddr::from([
                0x2607, 0x5300, 0x6000, 0x6b00, 0x0000, 0x0000, 0xc05f, 0x0543,
            ]),
            128,
            'd',
        );
        map.insert(
            IpAddr::from([
                0x2607, 0x5300, 0x6000, 0x6b00, 0x0000, 0x0000, 0x0000, 0x0000,
            ]),
            64,
            'c',
        );
        map.insert(
            IpAddr::from([
                0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000,
            ]),
            0,
            'e',
        );
        map.insert(
            IpAddr::from([
                0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000,
            ]),
            0,
            'f',
        );
        map.insert(
            IpAddr::from([
                0x2404, 0x6800, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000,
            ]),
            32,
            'g',
        );
        map.insert(
            IpAddr::from([
                0x2404, 0x6800, 0x4004, 0x0800, 0xdead, 0xbeef, 0xdead, 0xbeef,
            ]),
            64,
            'h',
        );
        map.insert(
            IpAddr::from([
                0x2404, 0x6800, 0x4004, 0x0800, 0xdead, 0xbeef, 0xdead, 0xbeef,
            ]),
            128,
            'a',
        );
        map.insert(
            IpAddr::from([
                0x2444, 0x6800, 0x40e4, 0x0800, 0xdeae, 0xbeef, 0x0def, 0xbeef,
            ]),
            128,
            'c',
        );
        map.insert(
            IpAddr::from([
                0x2444, 0x6800, 0xf0e4, 0x0800, 0xeeae, 0xbeef, 0x0000, 0x0000,
            ]),
            98,
            'b',
        );

        assert_eq!(
            Some(&'d'),
            map.find(IpAddr::from([
                0x2607, 0x5300, 0x6000, 0x6b00, 0x0000, 0x0000, 0xc05f, 0x0543
            ]))
        );
        assert_eq!(
            Some(&'c'),
            map.find(IpAddr::from([
                0x2607, 0x5300, 0x6000, 0x6b00, 0, 0, 0xc02e, 0x01ee
            ]))
        );
        assert_eq!(
            Some(&'f'),
            map.find(IpAddr::from([0x2607, 0x5300, 0x6000, 0x6b01, 0, 0, 0, 0]))
        );
        assert_eq!(
            Some(&'g'),
            map.find(IpAddr::from([
                0x2404, 0x6800, 0x4004, 0x0806, 0, 0, 0, 0x1006
            ]))
        );
        assert_eq!(
            Some(&'g'),
            map.find(IpAddr::from([
                0x2404, 0x6800, 0x4004, 0x0806, 0, 0x1234, 0, 0x5678
            ]))
        );
        assert_eq!(
            Some(&'f'),
            map.find(IpAddr::from([
                0x2404, 0x67ff, 0x4004, 0x0806, 0, 0x1234, 0, 0x5678
            ]))
        );
        assert_eq!(
            Some(&'f'),
            map.find(IpAddr::from([
                0x2404, 0x6801, 0x4004, 0x0806, 0, 0x1234, 0, 0x5678
            ]))
        );
        assert_eq!(
            Some(&'h'),
            map.find(IpAddr::from([
                0x2404, 0x6800, 0x4004, 0x0800, 0, 0x1234, 0, 0x5678
            ]))
        );
        assert_eq!(
            Some(&'h'),
            map.find(IpAddr::from([0x2404, 0x6800, 0x4004, 0x0800, 0, 0, 0, 0]))
        );
        assert_eq!(
            Some(&'h'),
            map.find(IpAddr::from([
                0x2404, 0x6800, 0x4004, 0x0800, 0x1010, 0x1010, 0x1010, 0x1010
            ]))
        );
        assert_eq!(
            Some(&'a'),
            map.find(IpAddr::from([
                0x2404, 0x6800, 0x4004, 0x0800, 0xdead, 0xbeef, 0xdead, 0xbeef
            ]))
        );
    }

    #[test]
    fn test_allowed_ips_iter_zero_leaf_bits() {
        use super::*;

        let mut map: AllowedIps<char> = AllowedIps::default();
        map.insert(IpAddr::from([10, 111, 0, 1]), 32, '1');
        map.insert(IpAddr::from([10, 111, 0, 2]), 32, '2');
        map.insert(IpAddr::from([10, 111, 0, 3]), 32, '3');

        let mut map_iter = map.iter();
        assert_eq!(
            map_iter.next(),
            Some((&'1', IpAddr::from([10, 111, 0, 1]), 32))
        );
        assert_eq!(
            map_iter.next(),
            Some((&'2', IpAddr::from([10, 111, 0, 2]), 32))
        );
        assert_eq!(
            map_iter.next(),
            Some((&'3', IpAddr::from([10, 111, 0, 3]), 32))
        );
        assert_eq!(map_iter.next(), None);
    }

    #[test]
    fn matches_the_trie_on_random_tables() {
        use super::*;
        use ip_network::IpNetwork;
        use ip_network_table::IpNetworkTable;
        use std::collections::BTreeSet;

        // splitmix64 with a fixed seed: every run checks the same tables.
        let mut state = 0x6e73_706c_616e_6532_u64;
        let mut next = move || {
            state = state.wrapping_add(0x9e37_79b9_7f4a_7c15);
            let mut z = state;
            z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
            z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
            z ^ (z >> 31)
        };
        let to_addr = |v6: bool, bits: u128| -> IpAddr {
            if v6 {
                IpAddr::from(bits.to_be_bytes())
            } else {
                IpAddr::from(u32::try_from(bits >> 96).unwrap().to_be_bytes())
            }
        };
        // The prefix lengths in use, per family.
        let lengths = |trie: &IpNetworkTable<u8>| -> [BTreeSet<u8>; 2] {
            let mut lengths = [BTreeSet::new(), BTreeSet::new()];
            for (net, _) in trie.iter() {
                lengths[usize::from(net.network_address().is_ipv6())].insert(net.netmask());
            }
            lengths
        };
        for round in 0..300 {
            let mut ours: AllowedIps<u8> = AllowedIps::new();
            let mut trie: IpNetworkTable<u8> = IpNetworkTable::new();
            // A few base addresses per family, so networks nest and overlap.
            let bases: Vec<u128> = (0..4)
                .map(|_| (u128::from(next()) << 64) | u128::from(next()))
                .collect();
            // Most networks take one of a few lengths, so most writes hit a length in use
            // and update the levels in place.
            let palette: Vec<u64> = (0..4).map(|_| next()).collect();
            // A third of the rounds end a configuration change after every step, so every
            // write starts on a table without pending rebuilds.
            let every_step = round % 3 == 0;
            let steps = if round % 10 == 1 { 1000 } else { 200 };
            for _ in 0..steps {
                let v6 = next() % 2 == 1;
                let max: u8 = if v6 { 128 } else { 32 };
                let len = match next() % 16 {
                    0 => 0,
                    1 => max,
                    2 => u8::try_from(next() % (u64::from(max) + 1)).unwrap(),
                    _ => {
                        let pick = palette[usize::try_from(next() % 4).unwrap()];
                        u8::try_from(pick % (u64::from(max) + 1)).unwrap()
                    }
                };
                let noise =
                    ((u128::from(next()) << 64) | u128::from(next())) >> (next() % 129).min(127);
                let base = bases[usize::try_from(next() % 4).unwrap()];
                let addr = to_addr(v6, base ^ noise);
                let value = u8::try_from(next() % 8).unwrap();
                let net = IpNetwork::new_truncate(addr, len).unwrap();
                let before = lengths(&trie);
                let mut cleared = false;
                match next() % 16 {
                    0..=8 => assert_eq!(ours.insert(addr, len, value), trie.insert(net, value)),
                    9..=12 => assert_eq!(ours.remove_network(addr, len), trie.remove(net)),
                    13 => {
                        ours.remove(&|v| *v == value);
                        trie.retain(|_, v| *v != value);
                    }
                    14 if next() % 32 == 0 => {
                        ours.clear();
                        trie = IpNetworkTable::new();
                        cleared = true;
                    }
                    _ => {
                        assert_eq!(ours.insert(addr, max + 1, value), None);
                        assert_eq!(ours.get(addr, max + 1), None);
                    }
                }
                // A configuration change ends at random points, so lookups run on tables
                // with and without pending rebuilds.
                if every_step || next() % 2 == 0 {
                    let rebuilds = ours.rebuilds;
                    ours.commit();
                    if every_step && !cleared {
                        // Only a family whose set of lengths changed rebuilds, once.
                        let after = lengths(&trie);
                        let changed = (0..2).filter(|&f| before[f] != after[f]).count();
                        assert_eq!(ours.rebuilds - rebuilds, changed);
                    }
                }
                assert_eq!(ours.get(addr, len), trie.exact_match(net));
                assert_eq!(ours.is_empty(), trie.is_empty());
                for probe in [addr, to_addr(v6, base), to_addr(!v6, base ^ noise)] {
                    assert_eq!(
                        ours.find(probe),
                        trie.longest_match(probe).map(|(_, v)| v),
                        "{probe}"
                    );
                }
                let expected: Vec<_> = trie
                    .iter()
                    .map(|(net, v)| (v, net.network_address(), net.netmask()))
                    .collect();
                assert_eq!(ours.iter().collect::<Vec<_>>(), expected);
            }
        }
    }

    #[test]
    fn a_change_rebuilds_each_family_at_most_once() {
        use super::*;

        let v4 = |i: u32, len: u8| (IpAddr::from((0x0a00_0000 | (i << 8)).to_be_bytes()), len);
        let v6 = |i: u128, len: u8| (IpAddr::from(((0xfd00_u128 << 112) | i).to_be_bytes()), len);
        let mut map: AllowedIps<u32> = AllowedIps::new();
        assert_eq!(map.commit(), 0);

        // Networks of both families in one change: one rebuild each.
        for i in 0..64 {
            let (addr, len) = v4(i, 24);
            map.insert(addr, len, i);
            let (addr, len) = v6(u128::from(i) << 64, 64);
            map.insert(addr, len, i);
        }
        // Until the commit lookups are exact all the same.
        assert_eq!(map.find(v4(5, 32).0), Some(&5));
        assert_eq!(map.commit(), 2);
        assert_eq!(map.commit(), 2);
        assert_eq!(map.find(v4(5, 32).0), Some(&5));
        assert_eq!(map.find(v6((7 << 64) | 1, 128).0), Some(&7));

        // The worst load order: 10 k /128 networks, then one network of each other length.
        for i in 0..10_000 {
            let (addr, len) = v6(i, 128);
            map.insert(addr, len, 1000);
        }
        for len in 0..128 {
            let (addr, _) = v6(0, len);
            map.insert(addr, len, u32::from(len) + 2000);
        }
        assert_eq!(map.commit(), 3);
        assert_eq!(map.find(v6(9999, 128).0), Some(&1000));
        assert_eq!(map.find(v6(10_000, 128).0), Some(&2114));
        assert_eq!(
            map.find(IpAddr::from([0x2001, 0xdb8, 0, 0, 0, 0, 0, 1])),
            Some(&2000)
        );
        // The same load on a family that already uses every length: all in place.
        for i in 10_000..20_000 {
            let (addr, len) = v6(i, 128);
            map.insert(addr, len, 1001);
        }
        for len in 0..128 {
            let (addr, _) = v6(1 << 64, len);
            map.insert(addr, len, u32::from(len) + 3000);
        }
        assert_eq!(map.commit(), 3);
        assert_eq!(map.find(v6(19_999, 128).0), Some(&1001));
        assert_eq!(map.find(v6(20_000, 128).0), Some(&2113));
        assert_eq!(map.find(v6((1 << 64) | 1, 128).0), Some(&3127));
        assert_eq!(map.find(v6(3 << 64, 128).0), Some(&3));
        assert_eq!(map.find(v6(1 << 62, 128).0), Some(&2065));

        // A new value for a network changes no lookup level.
        map.insert(v4(5, 24).0, 24, 105);
        assert_eq!(map.commit(), 3);
        assert_eq!(map.find(v4(5, 32).0), Some(&105));

        // Removing by value leaves every length in use: in place.
        map.remove(&|v| *v == 6);
        assert_eq!(map.commit(), 3);
        assert_eq!(map.find(v4(6, 32).0), None);
        assert_eq!(map.find(v6((6 << 64) | 1, 128).0), Some(&3061));
        // Removing the values of all /128 but one empties no length either.
        map.remove(&|v| *v == 1000);
        assert_eq!(map.commit(), 3);
        assert_eq!(map.find(v6(9999, 128).0), Some(&2114));
        // The last /128 networks: one rebuild of their family.
        map.remove(&|v| *v == 1001);
        assert_eq!(map.commit(), 4);
        assert_eq!(map.find(v6(19_999, 128).0), Some(&2113));
        map.remove(&|v| *v == 1001);
        assert_eq!(map.commit(), 4);

        // Exact removes at a length in use and an insert of a new length in one change.
        assert_eq!(map.remove_network(v4(7, 24).0, 24), Some(7));
        assert_eq!(map.remove_network(v4(7, 24).0, 24), None);
        map.insert(v4(7, 32).0, 32, 207);
        assert_eq!(map.commit(), 5);
        assert_eq!(map.find(v4(7, 32).0), Some(&207));
        assert_eq!(map.find(IpAddr::from([10, 0, 7, 1])), None);

        // Clearing leaves nothing to rebuild.
        map.clear();
        assert!(map.is_empty());
        assert_eq!(map.commit(), 5);
        assert_eq!(map.find(v4(5, 32).0), None);
    }

    #[test]
    fn writes_at_lengths_in_use_rebuild_nothing() {
        use super::*;

        let v4 = |i: u32| IpAddr::from((0x0a00_0000 | (i << 8)).to_be_bytes());
        let v6 = |i: u128| IpAddr::from(((0xfd00_u128 << 112) | (i << 64)).to_be_bytes());
        let mut map: AllowedIps<u32> = AllowedIps::new();
        for i in 0..64 {
            map.insert(v4(i), 24, i);
            map.insert(v6(i.into()), 64, i);
        }
        // Shorter networks above them, so in-place writes change their best matches.
        map.insert(IpAddr::from([10, 0, 0, 0]), 16, 100);
        map.insert(IpAddr::from([10, 255, 0, 0]), 16, 101);
        map.insert(v6(0), 16, 100);
        assert_eq!(map.commit(), 2);

        // An insert and a remove at a length in use, each its own change.
        assert_eq!(map.insert(v4(100), 24, 200), None);
        assert_eq!(map.commit(), 2);
        assert_eq!(map.find(IpAddr::from([10, 0, 100, 1])), Some(&200));
        assert_eq!(map.insert(v6(100), 64, 200), None);
        assert_eq!(map.commit(), 2);
        assert_eq!(map.find(v6(100)), Some(&200));
        assert_eq!(map.remove_network(v4(100), 24), Some(200));
        assert_eq!(map.commit(), 2);
        assert_eq!(map.find(IpAddr::from([10, 0, 100, 1])), Some(&100));
        assert_eq!(map.remove_network(v6(100), 64), Some(200));
        assert_eq!(map.commit(), 2);
        assert_eq!(map.find(v6(100)), Some(&100));

        // The network above the others, out and back in place.
        assert_eq!(
            map.remove_network(IpAddr::from([10, 0, 0, 0]), 16),
            Some(100)
        );
        assert_eq!(map.commit(), 2);
        assert_eq!(map.find(IpAddr::from([10, 0, 200, 1])), None);
        assert_eq!(map.find(IpAddr::from([10, 0, 5, 1])), Some(&5));
        assert_eq!(map.insert(IpAddr::from([10, 0, 0, 0]), 16, 102), None);
        assert_eq!(map.commit(), 2);
        assert_eq!(map.find(IpAddr::from([10, 0, 200, 1])), Some(&102));
        assert_eq!(map.find(IpAddr::from([10, 0, 5, 1])), Some(&5));

        // A new length: one rebuild of its family.
        map.insert(IpAddr::from([10, 0, 5, 7]), 32, 300);
        assert_eq!(map.find(IpAddr::from([10, 0, 5, 7])), Some(&300));
        assert_eq!(map.commit(), 3);
        assert_eq!(map.find(IpAddr::from([10, 0, 5, 7])), Some(&300));
        // An emptied length: one rebuild.
        assert_eq!(
            map.remove_network(IpAddr::from([10, 0, 5, 7]), 32),
            Some(300)
        );
        assert_eq!(map.find(IpAddr::from([10, 0, 5, 7])), Some(&5));
        assert_eq!(map.commit(), 4);
        assert_eq!(map.find(IpAddr::from([10, 0, 5, 7])), Some(&5));

        // Writes on a family with a pending rebuild only change its networks: one rebuild.
        map.insert(IpAddr::from([10, 0, 5, 7]), 32, 301);
        map.insert(v4(101), 24, 201);
        assert_eq!(map.remove_network(v4(5), 24), Some(5));
        assert_eq!(map.find(IpAddr::from([10, 0, 101, 1])), Some(&201));
        assert_eq!(map.find(IpAddr::from([10, 0, 5, 1])), Some(&102));
        assert_eq!(map.commit(), 5);
        assert_eq!(map.find(IpAddr::from([10, 0, 5, 7])), Some(&301));
        assert_eq!(map.find(IpAddr::from([10, 0, 101, 1])), Some(&201));
        assert_eq!(map.find(IpAddr::from([10, 0, 5, 1])), Some(&102));
    }

    #[test]
    fn remove_by_value_rebuilds_only_for_an_emptied_length() {
        use super::*;

        let v4 = |i: u32| IpAddr::from((0x0a00_0000 | (i << 8)).to_be_bytes());
        let v6 = |i: u128| IpAddr::from(((0xfd00_u128 << 112) | (i << 64)).to_be_bytes());
        let mut map: AllowedIps<u32> = AllowedIps::new();
        for i in 0..64 {
            map.insert(v4(i), 24, i % 4);
            map.insert(v6(i.into()), 64, i % 4);
        }
        map.insert(IpAddr::from([10, 0, 0, 0]), 16, 10);
        map.insert(IpAddr::from([10, 0, 0, 1]), 32, 11);
        map.insert(v6(0), 16, 10);
        map.insert(IpAddr::from([0xfd01, 0, 0, 0, 0, 0, 0, 0]), 16, 12);
        assert_eq!(map.commit(), 2);

        // One value's networks leave every length in use: in place in both families.
        map.remove(&|v| *v == 1);
        assert_eq!(map.commit(), 2);
        assert_eq!(map.find(IpAddr::from([10, 0, 1, 1])), Some(&10));
        assert_eq!(map.find(IpAddr::from([10, 0, 2, 1])), Some(&2));
        assert_eq!(map.find(v6(1)), Some(&10));
        assert_eq!(map.find(v6(2)), Some(&2));
        // A value without networks.
        map.remove(&|v| *v == 99);
        assert_eq!(map.commit(), 2);
        // The last network of a length: one rebuild of its family.
        map.remove(&|v| *v == 11);
        assert_eq!(map.commit(), 3);
        assert_eq!(map.find(IpAddr::from([10, 0, 0, 1])), Some(&0));
        // A length emptied in one family, kept in the other: one rebuild.
        map.remove(&|v| *v == 10);
        assert_eq!(map.commit(), 4);
        assert_eq!(map.find(IpAddr::from([10, 0, 1, 1])), None);
        assert_eq!(map.find(v6(1)), None);
        assert_eq!(
            map.find(IpAddr::from([0xfd01, 0, 0, 0, 0, 0, 0, 1])),
            Some(&12)
        );
        // On a family with a pending rebuild: that one rebuild.
        map.insert(IpAddr::from([10, 0, 0, 0]), 8, 13);
        map.remove(&|v| *v == 2);
        assert_eq!(map.find(IpAddr::from([10, 0, 2, 1])), Some(&13));
        assert_eq!(map.commit(), 5);
        assert_eq!(map.find(IpAddr::from([10, 0, 2, 1])), Some(&13));
        assert_eq!(map.find(IpAddr::from([10, 0, 3, 1])), Some(&3));
        // Lengths emptied in both families: one rebuild each.
        map.remove(&|v| *v != 13);
        assert_eq!(map.commit(), 7);
        assert_eq!(map.find(IpAddr::from([10, 0, 3, 1])), Some(&13));
        assert_eq!(map.find(v6(3)), None);
    }
}
