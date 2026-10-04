//! A fast keyed hasher for the maps packet paths look up.
//!
//! Flow, fragment and binding keys carry attacker-chosen addresses and ports,
//! so the hasher is keyed: every map draws two fresh random words from std's
//! [`RandomState`] when it is created. Each input word is folded into the
//! state with one 64x64->128-bit multiply (the construction of the `ahash`
//! fallback), which is several times cheaper than `SipHash` on the short
//! fixed-size keys used here. The per-peer state limits bound how many
//! entries one peer can place in a shard.

use std::collections::hash_map::RandomState;
use std::collections::{HashMap, HashSet};
use std::hash::{BuildHasher, Hasher};

/// A [`HashMap`] hashed with [`FastState`].
pub(super) type FastMap<K, V> = HashMap<K, V, FastState>;

/// A [`HashSet`] hashed with [`FastState`].
pub(super) type FastSet<K> = HashSet<K, FastState>;

/// Odd multiplier with well-spread bits (PCG's).
const MULTIPLE: u64 = 0x5851_f42d_4c95_7f2d;

/// Builds [`FastHasher`]s keyed with two random words.
#[derive(Debug, Clone, Copy)]
pub(super) struct FastState {
    seed: u64,
    pad: u64,
}

impl Default for FastState {
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

impl BuildHasher for FastState {
    type Hasher = FastHasher;

    fn build_hasher(&self) -> FastHasher {
        FastHasher {
            buffer: self.seed,
            pad: self.pad,
        }
    }
}

/// The hasher of [`FastState`].
#[derive(Debug, Clone)]
pub(super) struct FastHasher {
    buffer: u64,
    pad: u64,
}

impl FastHasher {
    fn mix(&mut self, word: u64) {
        self.buffer = folded_multiply(word ^ self.buffer, MULTIPLE);
    }
}

impl Hasher for FastHasher {
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
