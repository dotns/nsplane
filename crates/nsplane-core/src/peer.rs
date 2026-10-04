// Copyright (c) 2019 Cloudflare, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

use std::ops::{Deref, DerefMut};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::{Duration, Instant};

use nsplane_noise::noise::{Tunn, TunnResult};
use nsplane_noise::x25519::PublicKey;
use nsplane_packet::Path;

/// Where a peer keeps its tunnel, chosen once by the core.
enum Tunnel {
    /// Owned by the peer, reached without a lock: the core hands out no [`CryptoJob`]s.
    ///
    /// [`CryptoJob`]: crate::CryptoJob
    // Boxed, so that a peer stays as small as with a shared tunnel.
    Owned(Box<Tunn>),
    /// Shared with the peer's [`CryptoJob`]s, behind a lock.
    ///
    /// [`CryptoJob`]: crate::CryptoJob
    Shared(Arc<Mutex<Tunn>>),
}

/// Exclusive access to a peer's tunnel: a plain borrow of an owned tunnel, or the lock of a
/// shared one.
pub(crate) enum TunnelMut<'a> {
    Owned(&'a mut Tunn),
    Locked(MutexGuard<'a, Tunn>),
}

impl Deref for TunnelMut<'_> {
    type Target = Tunn;

    fn deref(&self) -> &Tunn {
        match self {
            Self::Owned(tunnel) => tunnel,
            Self::Locked(guard) => guard,
        }
    }
}

impl DerefMut for TunnelMut<'_> {
    fn deref_mut(&mut self) -> &mut Tunn {
        match self {
            Self::Owned(tunnel) => tunnel,
            Self::Locked(guard) => guard,
        }
    }
}

/// Locks a shared tunnel. A job that panicked while sealing or opening leaves a usable tunnel
/// behind.
fn lock(tunnel: &Mutex<Tunn>) -> MutexGuard<'_, Tunn> {
    tunnel.lock().unwrap_or_else(PoisonError::into_inner)
}

/// A peer of the core: its tunnel and current path. Allowed IPs live in the peer table.
pub(crate) struct Peer {
    /// The associated tunnel struct.
    tunnel: Tunnel,
    public_key: PublicKey,
    /// The index the tunnel uses
    index: u32,
    path: Option<Path>,
    preshared_key: Option<[u8; 32]>,
    /// Bytes received on the wire: the full datagram of every handshake initiation, handshake
    /// response and transport data message (keepalives included) accepted from this peer.
    /// Cookie replies and datagrams dropped before authentication are not counted.
    rx: u64,
    /// Bytes sent on the wire: the full datagram of every handshake initiation, handshake
    /// response and transport data message (keepalives included) transmitted to this peer.
    /// Cookie replies are not counted.
    tx: u64,
    /// Decrypted payload bytes delivered from this peer.
    data_rx: u64,
    /// Whether the core reported the current expiry of the tunnel's sessions.
    pub(crate) expired: bool,
    /// The tunnel's handshake count when the core last reported completed handshakes.
    handshakes: u64,
    /// Whether a handshake initiation was transmitted and no handshake completed since.
    initiation_outstanding: bool,
    /// Handshake initiations transmitted to this peer that got no response.
    unanswered_handshakes: u64,
}

impl std::fmt::Debug for Peer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Peer")
            .field("index", &self.index)
            .field("path", &self.path)
            .finish_non_exhaustive()
    }
}

impl Peer {
    /// Creates a peer around `tunnel`; a `shared` tunnel goes behind a lock, so that
    /// [`CryptoJob`]s can use it.
    ///
    /// [`CryptoJob`]: crate::CryptoJob
    pub(crate) fn new(
        tunnel: Tunn,
        shared: bool,
        public_key: PublicKey,
        index: u32,
        path: Option<Path>,
        preshared_key: Option<[u8; 32]>,
    ) -> Self {
        let handshakes = tunnel.handshake_count();
        let tunnel = if shared {
            Tunnel::Shared(Arc::new(Mutex::new(tunnel)))
        } else {
            Tunnel::Owned(Box::new(tunnel))
        };
        Self {
            tunnel,
            public_key,
            index,
            path,
            preshared_key,
            rx: 0,
            tx: 0,
            data_rx: 0,
            expired: false,
            handshakes,
            initiation_outstanding: false,
            unanswered_handshakes: 0,
        }
    }

    /// The tunnel; a shared one is locked, uncontended unless a [`CryptoJob`] of this peer
    /// runs elsewhere.
    ///
    /// [`CryptoJob`]: crate::CryptoJob
    pub(crate) fn tunnel_mut(&mut self) -> TunnelMut<'_> {
        match &mut self.tunnel {
            Tunnel::Owned(tunnel) => TunnelMut::Owned(tunnel),
            Tunnel::Shared(tunnel) => TunnelMut::Locked(lock(tunnel)),
        }
    }

    /// Reads the tunnel with `f`; a shared one is locked meanwhile.
    fn with_tunnel<R>(&self, f: impl FnOnce(&Tunn) -> R) -> R {
        match &self.tunnel {
            Tunnel::Owned(tunnel) => f(tunnel),
            Tunnel::Shared(tunnel) => f(&lock(tunnel)),
        }
    }

    /// The shared tunnel, for a [`CryptoJob`]; `None` if the peer owns its tunnel.
    ///
    /// [`CryptoJob`]: crate::CryptoJob
    pub(crate) fn shared_tunnel(&self) -> Option<Arc<Mutex<Tunn>>> {
        match &self.tunnel {
            Tunnel::Owned(_) => None,
            Tunnel::Shared(tunnel) => Some(Arc::clone(tunnel)),
        }
    }

    /// Replaces the preshared key; the next handshake uses it.
    pub(crate) fn set_preshared_key(&mut self, preshared_key: Option<[u8; 32]>) {
        self.preshared_key = preshared_key;
        self.tunnel_mut().set_preshared_key(preshared_key);
    }

    /// Sets the persistent keepalive interval in seconds; `0` disables it.
    pub(crate) fn set_persistent_keepalive(&mut self, interval: u16) {
        self.tunnel_mut()
            .set_persistent_keepalive((interval > 0).then_some(interval));
    }

    /// Runs the timers of the tunnel at `now`; see [`Tunn::update_timers_at`].
    pub(crate) fn update_timers<'a>(&mut self, now: Instant, dst: &'a mut [u8]) -> TunnResult<'a> {
        self.tunnel_mut().update_timers_at(now, dst)
    }

    /// The current path.
    pub(crate) const fn path(&self) -> Option<Path> {
        self.path
    }

    /// Replaces the current path.
    pub(crate) const fn set_path(&mut self, path: Path) {
        self.path = Some(path);
    }

    /// Counts a datagram of `bytes` accepted from this peer.
    pub(crate) const fn add_rx(&mut self, bytes: u64) {
        self.rx = self.rx.saturating_add(bytes);
    }

    /// Counts a datagram of `bytes` transmitted to this peer.
    pub(crate) const fn add_tx(&mut self, bytes: u64) {
        self.tx = self.tx.saturating_add(bytes);
    }

    /// Bytes received on the wire from this peer.
    pub(crate) const fn rx(&self) -> u64 {
        self.rx
    }

    /// Bytes sent on the wire to this peer.
    pub(crate) const fn tx(&self) -> u64 {
        self.tx
    }

    /// Counts `bytes` of decrypted payload delivered from this peer.
    pub(crate) const fn add_data_rx(&mut self, bytes: u64) {
        self.data_rx = self.data_rx.saturating_add(bytes);
    }

    /// Decrypted payload bytes delivered from this peer.
    pub(crate) const fn data_rx(&self) -> u64 {
        self.data_rx
    }

    /// Plaintext payload bytes sealed for this peer, as counted by the tunnel.
    pub(crate) fn data_tx(&self) -> u64 {
        self.with_tunnel(|t| t.stats().1 as u64)
    }

    /// Handshakes the tunnel completed since the last call; the core reports each of them.
    pub(crate) fn take_completed_handshakes(&mut self) -> u64 {
        let count = self.with_tunnel(Tunn::handshake_count);
        self.take_handshakes_up_to(count)
    }

    /// Handshakes up to the tunnel's handshake count `count` that were not reported yet. The
    /// count of a [`CryptoJob`] may lag behind one already taken: it then reports none.
    ///
    /// [`CryptoJob`]: crate::CryptoJob
    pub(crate) fn take_handshakes_up_to(&mut self, count: u64) -> u64 {
        let completed = count.saturating_sub(self.handshakes);
        self.handshakes = self.handshakes.max(count);
        completed
    }

    /// Records a handshake initiation transmitted to this peer: the previous one, if still
    /// outstanding, got no response.
    pub(crate) const fn initiation_sent(&mut self) {
        if self.initiation_outstanding {
            self.unanswered_handshakes = self.unanswered_handshakes.saturating_add(1);
        }
        self.initiation_outstanding = true;
    }

    /// Records a completed handshake: the outstanding initiation, if any, was answered.
    pub(crate) const fn initiation_answered(&mut self) {
        self.initiation_outstanding = false;
    }

    /// Records that the tunnel gave up its handshake attempt: the outstanding initiation, if
    /// any, got no response.
    pub(crate) const fn initiation_abandoned(&mut self) {
        if self.initiation_outstanding {
            self.unanswered_handshakes = self.unanswered_handshakes.saturating_add(1);
        }
        self.initiation_outstanding = false;
    }

    /// Handshake initiations transmitted to this peer that got no response.
    pub(crate) const fn unanswered_handshakes(&self) -> u64 {
        self.unanswered_handshakes
    }

    /// Time from the establishment of the current session to `now`.
    pub(crate) fn time_since_last_handshake(&self, now: Instant) -> Option<Duration> {
        self.with_tunnel(|t| t.time_since_last_handshake_at(now))
    }

    /// The persistent keepalive interval in seconds.
    pub(crate) fn persistent_keepalive(&self) -> Option<u16> {
        self.with_tunnel(Tunn::persistent_keepalive)
    }

    /// The preshared key, if set.
    pub(crate) const fn preshared_key(&self) -> Option<&[u8; 32]> {
        self.preshared_key.as_ref()
    }

    /// The public key of the peer.
    pub(crate) const fn public_key(&self) -> &PublicKey {
        &self.public_key
    }

    /// The receiver index of the current session's transport data messages, if any.
    pub(crate) fn remote_index(&self) -> Option<u32> {
        self.with_tunnel(Tunn::remote_index)
    }

    /// The index the tunnel uses for its sessions.
    pub(crate) const fn index(&self) -> u32 {
        self.index
    }
}
