//! [`FakePool`]: answers A / AAAA with addresses handed out from configured prefixes.

use std::collections::{BTreeMap, BTreeSet, HashMap};
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
/// Every answer and every [`lookup`](Self::lookup) refreshes the binding's last use. When no
/// fresh index is left (capacity or prefix exhausted), the least recently used binding unused
/// for at least [`ttl`](FakePoolConfig::ttl) is evicted and its addresses go to the new name. A
/// binding is never evicted earlier, so the pool answers `SERVFAIL` instead while every binding
/// is in use.
///
/// A binding belongs to the client address (the IP of the resolver's `client`, any port)
/// whose query created it; a name another client asks for later is shared and stays with its
/// first client. One client holds at most [`client_limit`](Self::client_limit) bindings, half
/// of the capacity unless [`with_client_limit`](Self::with_client_limit) sets another bound
/// (the capacity or more for none): at the limit a new name takes the client's own least recently used binding if that one is
/// unused for at least `ttl`, and is answered `SERVFAIL` otherwise
/// ([`client_limited`](Self::client_limited)), so one client asking for many names cannot
/// take the pool from the others.
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
    client_limit: usize,
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
    /// Client address -> the `lru` keys of the bindings it created, oldest first.
    owned: HashMap<IpAddr, BTreeSet<(Instant, u64)>>,
    /// Next never used host index.
    next_index: u64,
    seq: u64,
    stats: FakePoolStats,
    /// Queries answered `SERVFAIL` at the client limit.
    client_limited: u64,
}

#[derive(Debug)]
struct Binding {
    name: String,
    key: (Instant, u64),
    /// The client whose query created the binding.
    owner: IpAddr,
}

impl State {
    /// Moves the binding at `index` to `key`, its new last use.
    fn touch(&mut self, index: u64, key: (Instant, u64)) {
        let Some(binding) = self.bindings.get_mut(&index) else {
            return;
        };
        self.lru.remove(&binding.key);
        if let Some(owned) = self.owned.get_mut(&binding.owner) {
            owned.remove(&binding.key);
            owned.insert(key);
        }
        binding.key = key;
        self.lru.insert(key, index);
    }

    /// Evicts the binding last used at `key` if it is unused for at least `ttl` at `now`:
    /// its host index, free for a new name.
    fn release(&mut self, key: (Instant, u64), now: Instant, ttl: Duration) -> Option<u64> {
        if now.saturating_duration_since(key.0) < ttl {
            return None;
        }
        let index = self.lru.remove(&key)?;
        if let Some(old) = self.bindings.remove(&index) {
            self.names.remove(&old.name);
            if let Some(owned) = self.owned.get_mut(&old.owner) {
                owned.remove(&key);
                if owned.is_empty() {
                    self.owned.remove(&old.owner);
                }
            }
        }
        self.stats.reused += 1;
        Some(index)
    }
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
            client_limit: usize::try_from(usable.div_ceil(2)).unwrap_or(config.capacity),
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
            client_limit: self.client_limit,
            state: self.state,
            other: fallback,
        }
    }

    /// Sets the most bindings one client address holds, at least 1; the default is half of
    /// the [capacity](Self::capacity), rounded up. A limit of the capacity or more lets one
    /// client take the whole pool, as a pool with a single client may want.
    #[must_use]
    pub fn with_client_limit(mut self, limit: usize) -> Self {
        self.client_limit = limit.max(1);
        self
    }

    /// Most bindings one client address holds, see [`with_client_limit`](Self::with_client_limit).
    pub const fn client_limit(&self) -> usize {
        self.client_limit
    }

    /// Queries answered `SERVFAIL` since the pool was created because their client held
    /// [`client_limit`](Self::client_limit) bindings, all within their TTL.
    pub fn client_limited(&self) -> u64 {
        self.lock().client_limited
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

    /// The name bound to `addr`, in either family. Refreshes the binding's last use like an
    /// answer does: an address that connections keep being opened to stays with its name.
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
        let now = Instant::now();
        let mut state = self.lock();
        state.seq += 1;
        let key = (now, state.seq);
        state.touch(index, key);
        state.bindings.get(&index).map(|b| b.name.clone())
    }

    /// The addresses bound to `name`, one per configured family, without allocating or
    /// refreshing; `None` when the name has no binding.
    pub fn lookup_name(&self, name: &str) -> Option<(Option<Ipv4Addr>, Option<Ipv6Addr>)> {
        let index = *self.lock().names.get(&normalize_name(name))?;
        Some((self.ipv4_at(index), self.ipv6_at(index)))
    }

    /// The answer to an A or AAAA query of class IN, allocating or refreshing the binding.
    fn answer(&self, query: &Query, client: IpAddr) -> Answer {
        let name = query.name();
        let wants_v4 = query.record_type() == RecordType::A;
        if (wants_v4 && self.ipv4.is_none()) || (!wants_v4 && self.ipv6.is_none()) {
            return Answer::Records(Vec::new());
        }
        let Some(index) = self.bind(name, client) else {
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

    /// The host index bound to `name`, refreshed, or a new binding of `client`; `None` when
    /// the pool is exhausted or the client at its limit.
    fn bind(&self, name: &str, client: IpAddr) -> Option<u64> {
        let now = Instant::now();
        let mut state = self.lock();
        let state = &mut *state;
        state.seq += 1;
        let key = (now, state.seq);

        if let Some(&index) = state.names.get(name) {
            state.touch(index, key);
            return Some(index);
        }

        // The client's least recently used binding, once it holds as many as it may; a
        // limit of the whole pool is none.
        let own = state
            .owned
            .get(&client)
            .filter(|owned| self.client_limit < self.capacity && owned.len() >= self.client_limit)
            .and_then(|owned| owned.first().copied());
        let index = if let Some(own) = own {
            let Some(index) = state.release(own, now, self.ttl) else {
                state.client_limited += 1;
                return None;
            };
            index
        } else if state.next_index <= self.slots {
            state.next_index += 1;
            state.stats.allocated += 1;
            state.next_index - 1
        } else {
            let oldest = state.lru.first_key_value().map(|(&oldest, _)| oldest)?;
            let Some(index) = state.release(oldest, now, self.ttl) else {
                state.stats.exhausted += 1;
                return None;
            };
            index
        };
        state.names.insert(name.to_owned(), index);
        state.bindings.insert(
            index,
            Binding {
                name: name.to_owned(),
                key,
                owner: client,
            },
        );
        state.lru.insert(key, index);
        state.owned.entry(client).or_default().insert(key);
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
            self.answer(query, client.ip().to_canonical())
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
