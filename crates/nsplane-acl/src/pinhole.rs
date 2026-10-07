//! Pinholes: short-lived, source-gated openings for one session.
//!
//! A [`NamespaceKind::Pinholes`](crate::namespace::NamespaceKind::Pinholes)
//! namespace never widens a source's permissions on its own. Traffic to or
//! from one of its members passes only through a pinhole opened with
//! [`AclEngine::open_pinhole`](crate::AclEngine::open_pinhole): one label, one
//! direction, one protocol and one destination port, until the returned
//! [`PinholeGuard`] is dropped or the pinhole expires. See the crate docs for
//! the lifecycle.

use std::fmt;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Weak};
use std::time::Instant;

use thiserror::Error;

use crate::engine::AclEngine;
use crate::namespace::NamespaceId;
use crate::net::Protocol;
use crate::rules::Label;

/// The identifier of an open pinhole, unique within its engine.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct PinholeId(u64);

impl PinholeId {
    pub(crate) const fn new(id: u64) -> Self {
        Self(id)
    }

    /// The numeric identifier.
    #[must_use]
    pub const fn get(self) -> u64 {
        self.0
    }
}

impl fmt::Display for PinholeId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Which way the flows a pinhole opens go.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Direction {
    /// From the remote peer to the local node's `dst_port`.
    Inbound,
    /// From the local node to the remote peer's `dst_port`.
    Outbound,
}

/// What a pinhole opens.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PinholeSpec {
    /// The source label the pinhole serves (e.g. `"host:web"`): it must be a
    /// member of the pinhole namespace, and a source carrying it uses the
    /// pinhole.
    pub label: Label,
    /// The pinhole kind (opaque, e.g. `"transfer"`), checked against the
    /// [`pinhole_kinds`](crate::NamespacePolicy::pinhole_kinds) of the
    /// label's [`Rules`](crate::namespace::NamespaceKind::Rules) namespaces.
    pub kind: String,
    /// The transport protocol of the opened flows.
    pub protocol: Protocol,
    /// The direction of the opened flows.
    pub direction: Direction,
    /// The destination port of the opened flows: a local port for
    /// [`Direction::Inbound`], a port of the remote peer for
    /// [`Direction::Outbound`].
    pub dst_port: u16,
    /// When the pinhole closes at the latest, per the engine clock
    /// ([`AclEngine::with_clock`]). A safety net for sessions that never drop
    /// their guard.
    pub expires_at: Instant,
}

/// Why [`AclEngine::open_pinhole`](crate::AclEngine::open_pinhole) refused to
/// open a pinhole. Nothing changes in the engine.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum PinholeError {
    /// The namespace is not stored.
    #[error("unknown namespace")]
    UnknownNamespace,
    /// The namespace is not a
    /// [`Pinholes`](crate::namespace::NamespaceKind::Pinholes) namespace.
    #[error("not a pinhole namespace")]
    NotPinholeNamespace,
    /// The label is not a member of the pinhole namespace.
    #[error("label is not a member of the pinhole namespace")]
    NotMember,
    /// None of the label's rule namespaces permits the pinhole kind.
    #[error("no rule namespace of the label permits this pinhole kind")]
    NotPermitted,
    /// `expires_at` is not in the future.
    #[error("pinhole expiry is not in the future")]
    Expired,
}

/// Pinhole counters of an [`AclEngine`], in pinholes.
///
/// Every opened pinhole is eventually counted under exactly one close reason.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct PinholeStats {
    /// Pinholes opened.
    pub opened: u64,
    /// Pinholes closed by their guard (dropped or [`PinholeGuard::close`]).
    pub closed: u64,
    /// Pinholes that reached their expiry.
    pub expired: u64,
    /// Pinholes closed because their pinhole namespace was removed.
    pub namespace_removed: u64,
    /// Pinholes closed because the label left the pinhole namespace, its
    /// rule namespaces no longer permit the pinhole kind, or the namespace is
    /// no longer a pinhole namespace.
    pub revoked: u64,
    /// Pinholes closed by [`AclEngine::clear_all`].
    pub cleared: u64,
    /// Open requests refused with [`PinholeError::NotPermitted`].
    pub not_permitted: u64,
}

#[derive(Debug, Default)]
pub(crate) struct PinholeCounters {
    pub(crate) next_id: AtomicU64,
    pub(crate) opened: AtomicU64,
    pub(crate) closed: AtomicU64,
    pub(crate) expired: AtomicU64,
    pub(crate) namespace_removed: AtomicU64,
    pub(crate) revoked: AtomicU64,
    pub(crate) cleared: AtomicU64,
    pub(crate) not_permitted: AtomicU64,
}

impl PinholeCounters {
    pub(crate) fn add(counter: &AtomicU64, n: u64) {
        counter.fetch_add(n, Ordering::Relaxed);
    }

    pub(crate) fn stats(&self) -> PinholeStats {
        let load = |counter: &AtomicU64| counter.load(Ordering::Relaxed);
        PinholeStats {
            opened: load(&self.opened),
            closed: load(&self.closed),
            expired: load(&self.expired),
            namespace_removed: load(&self.namespace_removed),
            revoked: load(&self.revoked),
            cleared: load(&self.cleared),
            not_permitted: load(&self.not_permitted),
        }
    }
}

/// An open pinhole, as stored in the engine snapshot.
#[derive(Debug)]
pub(crate) struct Pinhole {
    pub(crate) id: PinholeId,
    pub(crate) namespace: NamespaceId,
    pub(crate) spec: PinholeSpec,
    /// The label was a member of a rule namespace when the pinhole opened,
    /// so it must stay in one.
    pub(crate) source_gated: bool,
}

impl Pinhole {
    pub(crate) fn is_open_at(&self, now: Instant) -> bool {
        now < self.spec.expires_at
    }

    pub(crate) fn matches(&self, direction: Direction, protocol: Protocol, port: u16) -> bool {
        self.spec.direction == direction
            && self.spec.protocol == protocol
            && self.spec.dst_port == port
    }
}

/// Keeps a pinhole open: dropping it (or [`close`](Self::close)) closes the
/// pinhole, so the session's traffic stops when the session ends.
///
/// The guard holds only a weak reference to its engine; a guard outliving
/// the engine is harmless.
#[derive(Debug)]
#[must_use = "dropping the guard closes the pinhole"]
pub struct PinholeGuard {
    engine: Weak<AclEngine>,
    id: PinholeId,
}

impl PinholeGuard {
    pub(crate) fn new(engine: &Arc<AclEngine>, id: PinholeId) -> Self {
        Self {
            engine: Arc::downgrade(engine),
            id,
        }
    }

    /// The pinhole's identifier.
    pub const fn id(&self) -> PinholeId {
        self.id
    }

    /// Whether the pinhole still accepts new flows: not closed, revoked or
    /// expired.
    pub fn is_open(&self) -> bool {
        self.engine
            .upgrade()
            .is_some_and(|engine| engine.is_pinhole_open(self.id))
    }

    /// Close the pinhole now (the same as dropping the guard).
    pub fn close(self) {
        drop(self);
    }
}

impl Drop for PinholeGuard {
    fn drop(&mut self) {
        if let Some(engine) = self.engine.upgrade() {
            engine.close_pinhole(self.id);
        }
    }
}
