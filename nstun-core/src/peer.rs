// Copyright (c) 2019 Cloudflare, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

use std::time::Duration;

use boringtun::noise::{Tunn, TunnResult};
use boringtun::x25519::PublicKey;
use nstun_packet::Path;

/// A peer of the core: its tunnel and current path. Allowed IPs live in the peer table.
#[cfg_attr(not(test), expect(dead_code, reason = "used by Core in subtask C2"))]
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
    #[cfg_attr(not(test), expect(dead_code, reason = "used by Core in subtask C2"))]
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
        }
    }

    /// Replaces the preshared key; the next handshake uses it.
    #[cfg_attr(not(test), expect(dead_code, reason = "used by Core in subtask C2"))]
    pub(crate) const fn set_preshared_key(&mut self, preshared_key: Option<[u8; 32]>) {
        self.preshared_key = preshared_key;
        self.tunnel.set_preshared_key(preshared_key);
    }

    /// Sets the persistent keepalive interval in seconds; `0` disables it.
    #[cfg_attr(not(test), expect(dead_code, reason = "used by Core in subtask C2"))]
    pub(crate) fn set_persistent_keepalive(&mut self, interval: u16) {
        self.tunnel
            .set_persistent_keepalive((interval > 0).then_some(interval));
    }

    /// Runs the timers of the tunnel; see [`Tunn::update_timers`].
    #[cfg_attr(not(test), expect(dead_code, reason = "used by Core in subtask C2"))]
    pub(crate) fn update_timers<'a>(&mut self, dst: &'a mut [u8]) -> TunnResult<'a> {
        self.tunnel.update_timers(dst)
    }

    /// The current path.
    #[cfg_attr(not(test), expect(dead_code, reason = "used by Core in subtask C2"))]
    pub(crate) const fn path(&self) -> Option<Path> {
        self.path
    }

    /// Replaces the current path.
    #[cfg_attr(not(test), expect(dead_code, reason = "used by Core in subtask C2"))]
    pub(crate) const fn set_path(&mut self, path: Path) {
        self.path = Some(path);
    }

    /// Counts `bytes` of decrypted payload delivered from this peer.
    #[cfg_attr(not(test), expect(dead_code, reason = "used by Core in subtask C2"))]
    pub(crate) const fn add_data_rx(&mut self, bytes: u64) {
        self.data_rx = self.data_rx.saturating_add(bytes);
    }

    /// Decrypted payload bytes delivered from this peer.
    #[cfg_attr(not(test), expect(dead_code, reason = "used by Core in subtask C2"))]
    pub(crate) const fn data_rx(&self) -> u64 {
        self.data_rx
    }

    /// Time since the current session was established.
    #[cfg_attr(not(test), expect(dead_code, reason = "used by Core in subtask C2"))]
    pub(crate) fn time_since_last_handshake(&self) -> Option<Duration> {
        self.tunnel.time_since_last_handshake()
    }

    /// The persistent keepalive interval in seconds.
    #[cfg_attr(not(test), expect(dead_code, reason = "used by Core in subtask C2"))]
    pub(crate) const fn persistent_keepalive(&self) -> Option<u16> {
        self.tunnel.persistent_keepalive()
    }

    /// The preshared key, if set.
    #[cfg_attr(not(test), expect(dead_code, reason = "used by Core in subtask C2"))]
    pub(crate) const fn preshared_key(&self) -> Option<&[u8; 32]> {
        self.preshared_key.as_ref()
    }

    /// The public key of the peer.
    #[cfg_attr(not(test), expect(dead_code, reason = "used by Core in subtask C2"))]
    pub(crate) const fn public_key(&self) -> &PublicKey {
        &self.public_key
    }

    /// The index the tunnel uses for its sessions.
    #[cfg_attr(not(test), expect(dead_code, reason = "used by Core in subtask C2"))]
    pub(crate) const fn index(&self) -> u32 {
        self.index
    }
}
