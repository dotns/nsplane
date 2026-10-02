//! App pinholes: short-lived, source-gated openings for one app session.
//!
//! An app namespace ([`NamespaceId::is_app`]) never widens a peer's
//! permissions on its own. App traffic to or from one of its members passes
//! only through a pinhole opened with
//! [`AclEngine::open_pinhole`](crate::AclEngine::open_pinhole): one peer, one
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
    /// From the peer to the local node's `dst_port`.
    Inbound,
    /// From the local node to the peer's `dst_port`.
    Outbound,
}

/// What a pinhole opens.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PinholeSpec {
    /// The peer, by principal (its source anchor, e.g. `key:<hex>`). It must
    /// be a member of the app namespace.
    pub peer: String,
    /// The app kind (e.g. `"transfer"`), checked against the
    /// [`allow_app_pinholes`](crate::NamespacePolicy::allow_app_pinholes) of
    /// the peer's source namespaces.
    pub kind: String,
    /// The transport protocol of the opened flows.
    pub protocol: Protocol,
    /// The direction of the opened flows.
    pub direction: Direction,
    /// The destination port of the opened flows: a local port for
    /// [`Direction::Inbound`], a port of the peer for [`Direction::Outbound`].
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
    /// The app namespace is not stored.
    #[error("unknown namespace")]
    UnknownNamespace,
    /// The namespace is not an app namespace.
    #[error("not an app namespace")]
    NotAppNamespace,
    /// The peer is not a member of the app namespace.
    #[error("peer is not a member of the app namespace")]
    NotMember,
    /// None of the peer's source namespaces allows pinholes for the app kind.
    #[error("no source namespace of the peer allows this app kind")]
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
    /// Pinholes closed because their app namespace was removed.
    pub namespace_removed: u64,
    /// Pinholes closed because the peer left the app namespace or its source
    /// namespaces no longer allow the app kind.
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
    pub(crate) app_namespace: NamespaceId,
    pub(crate) spec: PinholeSpec,
    /// The peer was a member of a source namespace when the pinhole opened,
    /// so it must stay in one.
    pub(crate) source_gated: bool,
}

impl Pinhole {
    pub(crate) fn is_open_at(&self, now: Instant) -> bool {
        now < self.spec.expires_at
    }

    pub(crate) fn matches(
        &self,
        principal: &str,
        direction: Direction,
        protocol: Protocol,
        port: u16,
    ) -> bool {
        self.spec.direction == direction
            && self.spec.protocol == protocol
            && self.spec.dst_port == port
            && self.spec.peer == principal
    }
}

/// Keeps a pinhole open: dropping it (or [`close`](Self::close)) closes the
/// pinhole, so app traffic stops when the session ends.
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
