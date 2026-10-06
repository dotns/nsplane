//! The maps packet paths look up, hashed with the shared keyed hasher.
//!
//! Flow, fragment and binding keys carry attacker-chosen addresses and ports,
//! so they use [`KeyedState`], keyed per map. The per-peer state limits bound
//! how many entries one peer can place in a shard.

use std::collections::{HashMap, HashSet};

use nsplane_packet::hash::KeyedState;

/// A [`HashMap`] hashed with [`KeyedState`].
pub(super) type FastMap<K, V> = HashMap<K, V, KeyedState>;

/// A [`HashSet`] hashed with [`KeyedState`].
pub(super) type FastSet<K> = HashSet<K, KeyedState>;
