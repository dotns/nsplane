// Copyright (c) 2019 Cloudflare, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

use ip_network::IpNetwork;
use ip_network_table::IpNetworkTable;

use std::collections::VecDeque;
use std::net::IpAddr;

/// A trie of IP/cidr addresses
pub(crate) struct AllowedIps<D> {
    ips: IpNetworkTable<D>,
}

impl<D> Default for AllowedIps<D> {
    fn default() -> Self {
        Self::new()
    }
}

impl<D> AllowedIps<D> {
    /// Creates an empty table.
    pub(crate) fn new() -> Self {
        Self {
            ips: IpNetworkTable::new(),
        }
    }

    /// Removes all entries.
    pub(crate) fn clear(&mut self) {
        self.ips = IpNetworkTable::new();
    }

    /// Inserts `data` for `key/cidr` and returns the value previously stored for that network.
    /// A `cidr` longer than the address is ignored and yields `None`.
    pub(crate) fn insert(&mut self, key: IpAddr, cidr: u8, data: D) -> Option<D> {
        // These are networks, it doesn't make sense for host bits to be set, so
        // use new_truncate().
        let network = IpNetwork::new_truncate(key, cidr).ok()?;
        self.ips.insert(network, data)
    }

    /// Returns the value stored for exactly the network `key/cidr`; `None` for a `cidr`
    /// longer than the address.
    pub(crate) fn get(&self, key: IpAddr, cidr: u8) -> Option<&D> {
        let network = IpNetwork::new_truncate(key, cidr).ok()?;
        self.ips.exact_match(network)
    }

    /// Removes the entry for exactly the network `key/cidr` and returns its value.
    pub(crate) fn remove_network(&mut self, key: IpAddr, cidr: u8) -> Option<D> {
        let network = IpNetwork::new_truncate(key, cidr).ok()?;
        self.ips.remove(network)
    }

    /// Whether the table holds no entry.
    pub(crate) fn is_empty(&self) -> bool {
        self.ips.is_empty()
    }

    /// Returns the value of the longest prefix that contains `key`.
    pub(crate) fn find(&self, key: IpAddr) -> Option<&D> {
        self.ips.longest_match(key).map(|(_net, data)| data)
    }

    /// Removes every entry whose value matches `predicate`.
    pub(crate) fn remove(&mut self, predicate: &dyn Fn(&D) -> bool) {
        self.ips.retain(|_, v| !predicate(v));
    }

    /// Iterates over `(value, network address, prefix length)`.
    pub(crate) fn iter(&self) -> Iter<'_, D> {
        Iter(
            self.ips
                .iter()
                .map(|(ipa, d)| (d, ipa.network_address(), ipa.netmask()))
                .collect(),
        )
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
        for round in 0..300 {
            let mut ours: AllowedIps<u8> = AllowedIps::new();
            let mut trie: IpNetworkTable<u8> = IpNetworkTable::new();
            // A few base addresses per family, so networks nest and overlap.
            let bases: Vec<u128> = (0..4)
                .map(|_| (u128::from(next()) << 64) | u128::from(next()))
                .collect();
            let steps = if round % 10 == 0 { 2000 } else { 200 };
            for _ in 0..steps {
                let v6 = next() % 2 == 1;
                let max: u8 = if v6 { 128 } else { 32 };
                let len = match next() % 8 {
                    0 => 0,
                    1 | 2 => max,
                    _ => u8::try_from(next() % (u64::from(max) + 1)).unwrap(),
                };
                let noise =
                    ((u128::from(next()) << 64) | u128::from(next())) >> (next() % 129).min(127);
                let base = bases[usize::try_from(next() % 4).unwrap()];
                let addr = to_addr(v6, base ^ noise);
                let value = u8::try_from(next() % 8).unwrap();
                match next() % 16 {
                    0..=8 => {
                        let net = IpNetwork::new_truncate(addr, len).unwrap();
                        assert_eq!(ours.insert(addr, len, value), trie.insert(net, value));
                    }
                    9..=12 => {
                        let net = IpNetwork::new_truncate(addr, len).unwrap();
                        assert_eq!(ours.remove_network(addr, len), trie.remove(net));
                    }
                    13 => {
                        ours.remove(&|v| *v == value);
                        trie.retain(|_, v| *v != value);
                    }
                    14 if next() % 32 == 0 => {
                        ours.clear();
                        trie = IpNetworkTable::new();
                    }
                    _ => {
                        assert_eq!(ours.insert(addr, max + 1, value), None);
                        assert_eq!(ours.get(addr, max + 1), None);
                    }
                }
                // A configuration change ends at random points, so lookups run on tables
                // with and without pending rebuilds.
                if next() % 2 == 0 {
                    ours.commit();
                }
                let net = IpNetwork::new_truncate(addr, len).unwrap();
                assert_eq!(ours.get(addr, len), trie.exact_match(net));
                assert_eq!(ours.is_empty(), trie.is_empty());
                for probe in [addr, to_addr(v6, base), to_addr(!v6, base ^ noise)] {
                    assert_eq!(
                        ours.find(probe),
                        trie.longest_match(probe).map(|(_, v)| v),
                        "{probe}"
                    );
                }
            }
            let expected: Vec<_> = trie
                .iter()
                .map(|(net, v)| (v, net.network_address(), net.netmask()))
                .collect();
            assert_eq!(ours.iter().collect::<Vec<_>>(), expected);
            ours.commit();
            assert_eq!(ours.iter().collect::<Vec<_>>(), expected);
        }
    }

    #[test]
    fn a_change_rebuilds_each_family_once() {
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

        // A new value for a network changes no lookup level.
        map.insert(v4(5, 24).0, 24, 105);
        assert_eq!(map.commit(), 3);
        assert_eq!(map.find(v4(5, 32).0), Some(&105));

        // Removing by value rebuilds the families that lost a network, once each.
        map.remove(&|v| *v == 6);
        assert_eq!(map.commit(), 5);
        map.remove(&|v| *v == 1000);
        assert_eq!(map.commit(), 6);
        assert_eq!(map.find(v6(9999, 128).0), Some(&2114));
        map.remove(&|v| *v == 1000);
        assert_eq!(map.commit(), 6);

        // Exact removes and inserts in one change, and a remove of no network.
        assert_eq!(map.remove_network(v4(7, 24).0, 24), Some(7));
        assert_eq!(map.remove_network(v4(7, 24).0, 24), None);
        map.insert(v4(7, 32).0, 32, 207);
        assert_eq!(map.commit(), 7);
        assert_eq!(map.find(v4(7, 32).0), Some(&207));
        assert_eq!(map.find(IpAddr::from([10, 0, 7, 1])), None);

        // Clearing leaves nothing to rebuild.
        map.clear();
        assert!(map.is_empty());
        assert_eq!(map.commit(), 7);
        assert_eq!(map.find(v4(5, 32).0), None);
    }
}
