// Copyright (c) 2019 Cloudflare, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

use std::time::Duration;

use nsplane_noise::noise::{Tunn, TunnResult};
use nsplane_noise::x25519::PublicKey;
use nsplane_packet::Path;

/// A peer of the core: its tunnel and current path. Allowed IPs live in the peer table.
pub(crate) struct Peer {
    /// The associated tunnel struct
    pub(crate) tunnel: Tunn,
    public_key: PublicKey,
    /// The index the tunnel uses
    index: u32,
    path: Option<Path>,
    preshared_key: Option<[u8; 32]>,
    /// Decrypted payload bytes delivered from this peer.
    data_rx: u64,
    /// Whether the core reported the current expiry of the tunnel's sessions.
    pub(crate) expired: bool,
    /// Receiver index of the last transport data checked for a completed handshake, while
    /// no handshake is pending; `None` when the next transport data must be checked.
    rx_session: Option<u32>,
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
    pub(crate) const fn new(
        tunnel: Tunn,
        public_key: PublicKey,
        index: u32,
        path: Option<Path>,
        preshared_key: Option<[u8; 32]>,
    ) -> Self {
        Self {
            tunnel,
            public_key,
            index,
            path,
            preshared_key,
            data_rx: 0,
            expired: false,
            rx_session: None,
        }
    }

    /// Replaces the preshared key; the next handshake uses it.
    pub(crate) const fn set_preshared_key(&mut self, preshared_key: Option<[u8; 32]>) {
        self.preshared_key = preshared_key;
        self.tunnel.set_preshared_key(preshared_key);
    }

    /// Sets the persistent keepalive interval in seconds; `0` disables it.
    pub(crate) fn set_persistent_keepalive(&mut self, interval: u16) {
        self.tunnel
            .set_persistent_keepalive((interval > 0).then_some(interval));
    }

    /// Runs the timers of the tunnel; see [`Tunn::update_timers`].
    pub(crate) fn update_timers<'a>(&mut self, dst: &'a mut [u8]) -> TunnResult<'a> {
        self.tunnel.update_timers(dst)
    }

    /// The current path.
    pub(crate) const fn path(&self) -> Option<Path> {
        self.path
    }

    /// Replaces the current path.
    pub(crate) const fn set_path(&mut self, path: Path) {
        self.path = Some(path);
    }

    /// Counts `bytes` of decrypted payload delivered from this peer.
    pub(crate) const fn add_data_rx(&mut self, bytes: u64) {
        self.data_rx = self.data_rx.saturating_add(bytes);
    }

    /// Decrypted payload bytes delivered from this peer.
    pub(crate) const fn data_rx(&self) -> u64 {
        self.data_rx
    }

    /// Whether transport data for `receiver_idx` may complete a handshake: it arrives on a new
    /// session (a new session has a new local index), or a handshake may have changed the
    /// sessions since the last check.
    pub(crate) fn is_new_session(&self, receiver_idx: u32) -> bool {
        self.rx_session != Some(receiver_idx)
    }

    /// Records that transport data for `receiver_idx` was checked for a completed handshake.
    pub(crate) const fn set_rx_session(&mut self, receiver_idx: u32) {
        self.rx_session = Some(receiver_idx);
    }

    /// Makes the next transport data check for a completed handshake: the sessions of the
    /// tunnel may change (a handshake message, a handshake initiation, timers, a new key).
    pub(crate) const fn reset_rx_session(&mut self) {
        self.rx_session = None;
    }

    /// Time since the current session was established.
    pub(crate) fn time_since_last_handshake(&self) -> Option<Duration> {
        self.tunnel.time_since_last_handshake()
    }

    /// The persistent keepalive interval in seconds.
    pub(crate) const fn persistent_keepalive(&self) -> Option<u16> {
        self.tunnel.persistent_keepalive()
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
