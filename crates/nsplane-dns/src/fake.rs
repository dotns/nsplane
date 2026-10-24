//! [`FakePool`]: answers A / AAAA with addresses handed out from configured prefixes.

use std::collections::{BTreeMap, HashMap};
use std::future::Future;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::{Mutex, MutexGuard, PoisonError};
use std::time::Duration;

use tokio::time::Instant;

use crate::message::{Answer, CLASS_IN, Query, Record, RecordType, ResponseCode, normalize_name};
use crate::resolver::Resolver;

/// Default [`FakePoolConfig::capacity`].
pub const DEFAULT_FAKE_CAPACITY: usize = 65536;

/// Default [`FakePoolConfig::ttl`].
pub const DEFAULT_FAKE_TTL: Duration = Duration::from_secs(60);

/// Configuration of a [`FakePool`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FakePoolConfig {
    /// IPv4 prefix (network address, prefix length) to hand out A addresses from.
    pub ipv4: Option<(Ipv4Addr, u8)>,
    /// IPv6 prefix (network address, prefix length) to hand out AAAA addresses from.
    pub ipv6: Option<(Ipv6Addr, u8)>,
    /// Maximum number of bindings; also bounded by the prefix sizes.
    pub capacity: usize,
    /// TTL of the answered records, and the minimum lifetime of a binding after its last use.
    pub ttl: Duration,
}

impl Default for FakePoolConfig {
    /// No prefixes, [`DEFAULT_FAKE_CAPACITY`] and [`DEFAULT_FAKE_TTL`].
    fn default() -> Self {
        Self {
            ipv4: None,
            ipv6: None,
            capacity: DEFAULT_FAKE_CAPACITY,
            ttl: DEFAULT_FAKE_TTL,
        }
    }
}

/// Why a [`FakePoolConfig`] is rejected.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum FakePoolConfigError {
    /// Neither an IPv4 nor an IPv6 prefix is configured.
    #[error("no IPv4 or IPv6 prefix configured")]
    NoPrefix,
    /// A prefix length exceeds the address width.
    #[error("invalid prefix length {0}")]
    InvalidPrefixLength(u8),
    /// A prefix address has bits set beyond its prefix length.
    #[error("prefix address has host bits set")]
    HostBitsSet,
    /// The capacity is zero or a prefix has no usable address.
    #[error("pool has no usable address")]
    Empty,
}

/// Counters of a [`FakePool`], since it was created.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct FakePoolStats {
    /// Bindings created on a never used address.
    pub allocated: u64,
    /// Bindings created by evicting an expired binding and reusing its address.
    pub reused: u64,
    /// Queries answered `SERVFAIL` because every binding was still within its TTL.
    pub exhausted: u64,
}

/// A resolver answering `NODATA` (an empty [`Answer::Records`]) to every query; the default
/// for the query types a [`FakePool`] does not answer itself.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct NoData;

impl Resolver for NoData {
    fn resolve(&self, _query: &Query, _client: SocketAddr) -> impl Future<Output = Answer> + Send {
        std::future::ready(Answer::Records(Vec::new()))
    }
}

/// Answers A and AAAA queries with addresses allocated from configured prefixes, one binding
/// per name, and maps the addresses back to names.
///
/// A name gets one binding holding a host index into the prefixes: its IPv4 and IPv6
/// addresses share the index, so A and AAAA of a name stay stable together. Indexes are
/// handed out sequentially, skipping the network address (and for IPv4 the broadcast address
/// below /31). Names match normalized (case-insensitive, no trailing dot).
///
/// Every answer refreshes the binding's last use. When no fresh index is left (capacity or
/// prefix exhausted), the least recently used binding unused for at least
/// [`ttl`](FakePoolConfig::ttl) is evicted and its addresses go to the new name. A binding is
/// never evicted earlier, so the pool answers `SERVFAIL` instead while every binding is in
/// use.
///
/// Class IN A queries get one A record with TTL `ttl`, AAAA likewise; a family without a
/// prefix answers `NODATA`. Every other query goes to `F`: [`NoData`] by default, another
/// resolver with [`with_fallback`](Self::with_fallback).
#[derive(Debug)]
pub struct FakePool<F = NoData> {
    ipv4: Option<(Ipv4Addr, u8)>,
    ipv6: Option<(Ipv6Addr, u8)>,
    ttl: Duration,
    record_ttl: u32,
    capacity: usize,
    /// `capacity` as the highest host index.
    slots: u64,
    state: Mutex<State>,
    other: F,
}

#[derive(Debug, Default)]
struct State {
    /// Normalized name -> host index.
    names: HashMap<String, u64>,
    /// Host index -> binding.
    bindings: HashMap<u64, Binding>,
    /// (last use, sequence) -> host index, oldest first.
    lru: BTreeMap<(Instant, u64), u64>,
    /// Next never used host index.
    next_index: u64,
    seq: u64,
    stats: FakePoolStats,
}

#[derive(Debug)]
struct Binding {
    name: String,
    key: (Instant, u64),
}

impl FakePool {
    /// A pool for `config`.
    pub fn new(config: FakePoolConfig) -> Result<Self, FakePoolConfigError> {
        if config.ipv4.is_none() && config.ipv6.is_none() {
            return Err(FakePoolConfigError::NoPrefix);
        }
        let mut usable = u64::try_from(config.capacity).unwrap_or(u64::MAX);
        if let Some((addr, len)) = config.ipv4 {
            usable = usable.min(ipv4_usable(u32::from(addr), len)?);
        }
        if let Some((addr, len)) = config.ipv6 {
            usable = usable.min(ipv6_usable(u128::from(addr), len)?);
        }
        if usable == 0 {
            return Err(FakePoolConfigError::Empty);
        }
        Ok(Self {
            ipv4: config.ipv4,
            ipv6: config.ipv6,
            ttl: config.ttl,
            record_ttl: u32::try_from(config.ttl.as_secs()).unwrap_or(u32::MAX),
            // `usable` is at most `config.capacity`.
            capacity: usize::try_from(usable).unwrap_or(config.capacity),
            slots: usable,
            state: Mutex::new(State {
                next_index: 1,
                ..State::default()
            }),
            other: NoData,
        })
    }
}

impl<F> FakePool<F> {
    /// Hands the queries this pool does not answer itself (other types and classes) to
    /// `fallback` instead of answering `NODATA`.
    pub fn with_fallback<R>(self, fallback: R) -> FakePool<R> {
        FakePool {
            ipv4: self.ipv4,
            ipv6: self.ipv6,
            ttl: self.ttl,
            record_ttl: self.record_ttl,
            capacity: self.capacity,
            slots: self.slots,
            state: self.state,
            other: fallback,
        }
    }

    /// Maximum number of bindings: the configured capacity bounded by the prefix sizes.
    pub const fn capacity(&self) -> usize {
        self.capacity
    }

    /// Number of bindings.
    pub fn len(&self) -> usize {
        self.lock().names.len()
    }

    /// Whether the pool has no bindings.
    pub fn is_empty(&self) -> bool {
        self.lock().names.is_empty()
    }

    /// A snapshot of the counters.
    pub fn stats(&self) -> FakePoolStats {
        self.lock().stats
    }

    /// The name bound to `addr`, in either family. Does not refresh the binding.
    pub fn lookup(&self, addr: IpAddr) -> Option<String> {
        let index = match addr {
            IpAddr::V4(addr) => {
                let (net, len) = self.ipv4?;
                host_index(
                    u128::from(u32::from(addr)),
                    u128::from(u32::from(net)),
                    len,
                    32,
                )?
            }
            IpAddr::V6(addr) => {
                let (net, len) = self.ipv6?;
                host_index(u128::from(addr), u128::from(net), len, 128)?
            }
        };
        self.lock().bindings.get(&index).map(|b| b.name.clone())
    }

    /// The addresses bound to `name`, one per configured family, without allocating or
    /// refreshing; `None` when the name has no binding.
    pub fn lookup_name(&self, name: &str) -> Option<(Option<Ipv4Addr>, Option<Ipv6Addr>)> {
        let index = *self.lock().names.get(&normalize_name(name))?;
        Some((self.ipv4_at(index), self.ipv6_at(index)))
    }

    /// The answer to an A or AAAA query of class IN, allocating or refreshing the binding.
    fn answer(&self, query: &Query) -> Answer {
        let name = query.name();
        let wants_v4 = query.record_type() == RecordType::A;
        if (wants_v4 && self.ipv4.is_none()) || (!wants_v4 && self.ipv6.is_none()) {
            return Answer::Records(Vec::new());
        }
        let Some(index) = self.bind(name) else {
            return Answer::Code(ResponseCode::ServFail);
        };
        let record = if wants_v4 {
            self.ipv4_at(index)
                .map(|addr| Record::a(name, self.record_ttl, addr))
        } else {
            self.ipv6_at(index)
                .map(|addr| Record::aaaa(name, self.record_ttl, addr))
        };
        Answer::Records(record.into_iter().collect())
    }

    /// The host index bound to `name`, refreshed, or a new binding; `None` when exhausted.
    fn bind(&self, name: &str) -> Option<u64> {
        let now = Instant::now();
        let mut state = self.lock();
        let state = &mut *state;
        state.seq += 1;
        let key = (now, state.seq);

        if let Some(&index) = state.names.get(name) {
            if let Some(binding) = state.bindings.get_mut(&index) {
                state.lru.remove(&binding.key);
                binding.key = key;
                state.lru.insert(key, index);
            }
            return Some(index);
        }

        let index = if state.next_index <= self.slots {
            state.next_index += 1;
            state.stats.allocated += 1;
            state.next_index - 1
        } else {
            let (&oldest, &index) = state.lru.first_key_value()?;
            if now.saturating_duration_since(oldest.0) < self.ttl {
                state.stats.exhausted += 1;
                return None;
            }
            state.lru.remove(&oldest);
            if let Some(old) = state.bindings.remove(&index) {
                state.names.remove(&old.name);
            }
            state.stats.reused += 1;
            index
        };
        state.names.insert(name.to_owned(), index);
        state.bindings.insert(
            index,
            Binding {
                name: name.to_owned(),
                key,
            },
        );
        state.lru.insert(key, index);
        Some(index)
    }

    fn ipv4_at(&self, index: u64) -> Option<Ipv4Addr> {
        let (net, _) = self.ipv4?;
        // The index fits the prefix, checked at construction.
        let offset = u32::try_from(index).ok()?;
        Some(Ipv4Addr::from(u32::from(net) | offset))
    }

    fn ipv6_at(&self, index: u64) -> Option<Ipv6Addr> {
        let (net, _) = self.ipv6?;
        Some(Ipv6Addr::from(u128::from(net) | u128::from(index)))
    }

    fn lock(&self) -> MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

impl<F: Resolver> Resolver for FakePool<F> {
    async fn resolve(&self, query: &Query, client: SocketAddr) -> Answer {
        let ty = query.record_type();
        if query.class() == CLASS_IN && (ty == RecordType::A || ty == RecordType::AAAA) {
            self.answer(query)
        } else {
            self.other.resolve(query, client).await
        }
    }
}

/// Usable host indexes of an IPv4 prefix: all but the network and, below /31, the broadcast
/// address.
fn ipv4_usable(addr: u32, len: u8) -> Result<u64, FakePoolConfigError> {
    let size = prefix_size(u128::from(addr), len, 32)?;
    let skipped = if len < 31 { 2 } else { 1 };
    Ok(u64::try_from(size.saturating_sub(skipped)).unwrap_or(u64::MAX))
}

/// Usable host indexes of an IPv6 prefix: all but the network address.
fn ipv6_usable(addr: u128, len: u8) -> Result<u64, FakePoolConfigError> {
    let size = prefix_size(addr, len, 128)?;
    Ok(u64::try_from(size.saturating_sub(1)).unwrap_or(u64::MAX))
}

/// Number of addresses in the prefix, saturating at `u128::MAX`; checks length and host bits.
fn prefix_size(addr: u128, len: u8, width: u8) -> Result<u128, FakePoolConfigError> {
    if len > width {
        return Err(FakePoolConfigError::InvalidPrefixLength(len));
    }
    let host_bits = u32::from(width - len);
    let host_mask = 1u128.checked_shl(host_bits).map_or(u128::MAX, |n| n - 1);
    if addr & host_mask != 0 {
        return Err(FakePoolConfigError::HostBitsSet);
    }
    Ok(host_mask.saturating_add(1))
}

/// The host index of `addr` in the prefix `net`/`len`, if inside it.
fn host_index(addr: u128, net: u128, len: u8, width: u8) -> Option<u64> {
    let host_bits = u32::from(width - len);
    let host_mask = 1u128.checked_shl(host_bits).map_or(u128::MAX, |n| n - 1);
    if addr & !host_mask != net {
        return None;
    }
    u64::try_from(addr & host_mask).ok()
}
