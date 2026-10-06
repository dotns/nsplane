//! A fast keyed hasher for hash maps on per-packet lookup paths.
//!
//! [`KeyedState`] is a [`BuildHasher`] for short fixed-size keys such as
//! addresses, ports and flow tuples, several times cheaper than std's
//! `SipHash` on them. Each input word is folded into the keyed state with
//! one 64x64->128-bit multiply whose high and low halves are combined with
//! XOR (the wyhash construction), and the result is folded once more.
//!
//! Keys in such maps often come from traffic, so the hash is keyed against
//! hash flooding: every state draws two fresh random words from std's
//! [`RandomState`] when it is created and never exposes them (the `Debug`
//! output omits them). Without the keys an outside party cannot predict
//! which inputs collide. It is intended for maps whose contents are not
//! chosen by the party that drives the lookups, or whose size is otherwise
//! bounded per party. It is not a cryptographic hash.

use std::collections::hash_map::RandomState;
use std::fmt;
use std::hash::{BuildHasher, Hasher};

/// Odd multiplier with well-spread bits (PCG's).
const MULTIPLE: u64 = 0x5851_f42d_4c95_7f2d;

/// Builds [`KeyedHasher`]s keyed with two random words.
///
/// Every [`KeyedState::default`] draws new keys, so two maps hash the same
/// key differently; a clone keeps its keys.
#[derive(Clone, Copy)]
pub struct KeyedState {
    seed: u64,
    pad: u64,
}

impl Default for KeyedState {
    /// A state keyed with random words derived from a fresh std
    /// [`RandomState`].
    fn default() -> Self {
        let random = RandomState::new();
        Self {
            seed: random.hash_one(0_u8),
            pad: random.hash_one(1_u8) | 1,
        }
    }
}

impl fmt::Debug for KeyedState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("KeyedState").finish_non_exhaustive()
    }
}

impl BuildHasher for KeyedState {
    type Hasher = KeyedHasher;

    fn build_hasher(&self) -> KeyedHasher {
        KeyedHasher {
            buffer: self.seed,
            pad: self.pad,
        }
    }
}

/// The hasher of [`KeyedState`].
#[derive(Clone)]
pub struct KeyedHasher {
    buffer: u64,
    pad: u64,
}

impl KeyedHasher {
    fn mix(&mut self, word: u64) {
        self.buffer = folded_multiply(word ^ self.buffer, MULTIPLE);
    }
}

impl fmt::Debug for KeyedHasher {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("KeyedHasher").finish_non_exhaustive()
    }
}

impl Hasher for KeyedHasher {
    fn write(&mut self, bytes: &[u8]) {
        let (words, rest) = bytes.as_chunks::<8>();
        for word in words {
            self.mix(u64::from_le_bytes(*word));
        }
        if !rest.is_empty() {
            let mut word = [0; 8];
            word[..rest.len()].copy_from_slice(rest);
            // The length keeps a short tail distinct from its zero padding.
            word[7] = u8::try_from(rest.len()).unwrap_or(u8::MAX);
            self.mix(u64::from_le_bytes(word));
        }
    }

    fn write_u8(&mut self, value: u8) {
        self.mix(u64::from(value));
    }

    fn write_u16(&mut self, value: u16) {
        self.mix(u64::from(value));
    }

    fn write_u32(&mut self, value: u32) {
        self.mix(u64::from(value));
    }

    fn write_u64(&mut self, value: u64) {
        self.mix(value);
    }

    /// Both halves go through one keyed multiply.
    fn write_u128(&mut self, value: u128) {
        let low = u64::try_from(value & u128::from(u64::MAX)).unwrap_or(0);
        let high = u64::try_from(value >> 64).unwrap_or(0);
        self.buffer = folded_multiply(low ^ self.buffer, high ^ self.pad);
    }

    fn finish(&self) -> u64 {
        folded_multiply(self.buffer, self.pad)
    }
}

/// The high and low halves of the full product, folded.
fn folded_multiply(a: u64, b: u64) -> u64 {
    let full = u128::from(a) * u128::from(b);
    let low = u64::try_from(full & u128::from(u64::MAX)).unwrap_or(0);
    let high = u64::try_from(full >> 64).unwrap_or(0);
    low ^ high
}

#[cfg(test)]
mod tests {
    use std::collections::HashSet;
    use std::net::Ipv6Addr;

    use super::*;

    fn v6(s: &str) -> Ipv6Addr {
        s.parse().unwrap()
    }

    #[test]
    fn keyed_per_state() {
        let (a, b) = (KeyedState::default(), KeyedState::default());
        assert_ne!((a.seed, a.pad), (b.seed, b.pad));
        let addr = v6("fd00::1").to_bits();
        assert_ne!(a.hash_one(addr), b.hash_one(addr));
        assert_ne!(a.hash_one(42_u32), b.hash_one(42_u32));
        // A clone keeps its keys.
        assert_eq!(a.clone().hash_one(addr), a.hash_one(addr));
    }

    #[test]
    fn deterministic_per_state() {
        let state = KeyedState::default();
        let addr = v6("2001:db8::42");
        assert_eq!(
            state.hash_one(addr.to_bits()),
            state.hash_one(addr.to_bits())
        );
        assert_ne!(
            state.hash_one(addr.to_bits()),
            state.hash_one(v6("2001:db8::43").to_bits())
        );
        // Byte input goes through `write`, also deterministically.
        assert_eq!(state.hash_one(addr), state.hash_one(addr));
        assert_eq!(state.hash_one((7_u16, 9_u8)), state.hash_one((7_u16, 9_u8)));
    }

    #[test]
    fn short_tail_differs_from_padding() {
        let state = KeyedState::default();
        let hash = |bytes: &[u8]| {
            let mut hasher = state.build_hasher();
            hasher.write(bytes);
            hasher.finish()
        };
        assert_ne!(hash(&[1]), hash(&[1, 0]));
        assert_ne!(hash(&[1; 8]), hash(&[1; 9]));
    }

    #[test]
    fn debug_hides_keys() {
        let state = KeyedState::default();
        assert_eq!(format!("{state:?}"), "KeyedState { .. }");
        assert_eq!(format!("{:?}", state.build_hasher()), "KeyedHasher { .. }");
    }

    #[test]
    fn spreads_sequential_addresses() {
        // 4096 addresses that differ in a few low bits, as one subnet or a
        // block of host addresses does. A uniform hash puts 64 in each of 64
        // buckets (sd 8); the bounds are 5 sd wide.
        let state = KeyedState::default();
        let base = v6("fd00:1:2:3::").to_bits();
        let hashes: Vec<u64> = (0..4096_u128)
            .map(|n| state.hash_one(base | (n << 64) | n))
            .collect();
        let unique: HashSet<u64> = hashes.iter().copied().collect();
        assert_eq!(unique.len(), hashes.len());
        // Low bits pick a bucket, the top 7 bits are hashbrown's tag.
        for shift in [0, 57] {
            let mut buckets = [0_u32; 64];
            for hash in &hashes {
                buckets[usize::try_from((hash >> shift) & 63).unwrap()] += 1;
            }
            assert!(
                buckets.iter().all(|&count| (24..=104).contains(&count)),
                "shift {shift}: {buckets:?}"
            );
        }
    }
}
