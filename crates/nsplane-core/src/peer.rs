// Copyright (c) 2019 Cloudflare, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::{Duration, Instant};

use nsplane_noise::noise::{Tunn, TunnResult};
use nsplane_noise::x25519::PublicKey;
use nsplane_packet::Path;

/// A peer of the core: its tunnel and current path. Allowed IPs live in the peer table.
pub(crate) struct Peer {
    /// The associated tunnel struct, shared with the peer's [`CryptoJob`]s.
    ///
    /// [`CryptoJob`]: crate::CryptoJob
    tunnel: Arc<Mutex<Tunn>>,
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
    /// Creates a peer around `tunnel`.
    pub(crate) fn new(
        tunnel: Tunn,
        public_key: PublicKey,
        index: u32,
        path: Option<Path>,
        preshared_key: Option<[u8; 32]>,
    ) -> Self {
        let handshakes = tunnel.handshake_count();
        Self {
            tunnel: Arc::new(Mutex::new(tunnel)),
            public_key,
            index,
            path,
            preshared_key,
            rx: 0,
            tx: 0,
            data_rx: 0,
            expired: false,
            handshakes,
        }
    }

    /// The tunnel, locked; uncontended unless a [`CryptoJob`] of this peer runs elsewhere.
    ///
    /// [`CryptoJob`]: crate::CryptoJob
    pub(crate) fn tunnel(&self) -> MutexGuard<'_, Tunn> {
        // A job that panicked while sealing or opening leaves a usable tunnel behind.
        self.tunnel.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// The shared tunnel, for a [`CryptoJob`].
    ///
    /// [`CryptoJob`]: crate::CryptoJob
    pub(crate) fn shared_tunnel(&self) -> Arc<Mutex<Tunn>> {
        Arc::clone(&self.tunnel)
    }

    /// Replaces the preshared key; the next handshake uses it.
    pub(crate) fn set_preshared_key(&mut self, preshared_key: Option<[u8; 32]>) {
        self.preshared_key = preshared_key;
        self.tunnel().set_preshared_key(preshared_key);
    }

    /// Sets the persistent keepalive interval in seconds; `0` disables it.
    pub(crate) fn set_persistent_keepalive(&self, interval: u16) {
        self.tunnel()
            .set_persistent_keepalive((interval > 0).then_some(interval));
    }

    /// Runs the timers of the tunnel at `now`; see [`Tunn::update_timers_at`].
    pub(crate) fn update_timers<'a>(&self, now: Instant, dst: &'a mut [u8]) -> TunnResult<'a> {
        self.tunnel().update_timers_at(now, dst)
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
        self.tunnel().stats().1 as u64
    }

    /// Handshakes the tunnel completed since the last call; the core reports each of them.
    pub(crate) fn take_completed_handshakes(&mut self) -> u64 {
        let count = self.tunnel().handshake_count();
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

    /// Time from the establishment of the current session to `now`.
    pub(crate) fn time_since_last_handshake(&self, now: Instant) -> Option<Duration> {
        self.tunnel().time_since_last_handshake_at(now)
    }

    /// The persistent keepalive interval in seconds.
    pub(crate) fn persistent_keepalive(&self) -> Option<u16> {
        self.tunnel().persistent_keepalive()
    }

    /// The preshared key, if set.
    pub(crate) const fn preshared_key(&self) -> Option<&[u8; 32]> {
        self.preshared_key.as_ref()
    }

    /// The public key of the peer.
    pub(crate) const fn public_key(&self) -> &PublicKey {
        &self.public_key
    }

    /// The index the tunnel uses for its sessions.
    pub(crate) const fn index(&self) -> u32 {
        self.index
    }
}
