// Copyright (c) 2019 Cloudflare, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

//! The timers and forced handshakes.

use std::mem;
use std::time::Instant;

use nsplane_noise::noise::TunnResult;
use nsplane_noise::noise::errors::WireGuardError;
use nsplane_packet::{Ecn, HEADROOM, Path, PeerId};

use super::send::{Fixed, transmit};
use super::{BUF_SIZE, Core, RATE_LIMITER_RESET, TICK, handshakes_completed, message_kind};
use crate::policy::{MessageKind, PathPolicy};
use crate::types::{Event, Output};

impl Core {
    /// Runs the timers that are due at `now`: handshake retries, keepalives, session expiry,
    /// rate limiter resets and periodic `Event::PeerStats`.
    pub fn handle_timeout(&mut self, now: Instant) {
        let schedule = self.start_schedule(now);
        if now < schedule.tick {
            return;
        }

        let mut buf = self.pool.get_len(BUF_SIZE);
        for (id, peer) in self.peers.iter_mut() {
            let result = peer.update_timers(now, &mut buf.with_headroom_mut()[HEADROOM..]);
            let completed = peer.take_completed_handshakes();
            if completed > 0 {
                peer.expired = false;
                peer.initiation_answered();
                handshakes_completed(&mut self.outputs, id, completed, None, None);
            }
            match result {
                TunnResult::Done => peer.expired = false,
                TunnResult::Err(WireGuardError::ConnectionExpired) => {
                    peer.initiation_abandoned();
                    if !mem::replace(&mut peer.expired, true) {
                        self.outputs
                            .push_back(Output::Event(Event::SessionExpired { peer: id }));
                    }
                }
                TunnResult::Err(e) => {
                    peer.expired = false;
                    tracing::debug!(message = "Timer error", error = ?e);
                }
                TunnResult::WriteToNetwork(packet) => {
                    peer.expired = false;
                    let len = packet.len();
                    buf.set_len(len);
                    let kind = message_kind(buf.as_packet());
                    let data = mem::replace(&mut buf, self.pool.get_len(BUF_SIZE));
                    transmit(
                        &mut self.outputs,
                        &mut self.pool,
                        self.policy.as_ref(),
                        id,
                        peer,
                        kind,
                        data,
                    );
                }
                TunnResult::WriteToTunnelV4(..) | TunnResult::WriteToTunnelV6(..) => {
                    tracing::debug!("Unexpected result from update_timers");
                }
            }
        }
        self.pool.put(buf);

        let mut schedule = schedule;
        if now >= schedule.rate_limiter_reset {
            self.peers.reset_handshake_budget(now);
            schedule.rate_limiter_reset = now + RATE_LIMITER_RESET;
        }
        if let (Some(due), Some(interval)) = (schedule.stats, self.stats_interval)
            && now >= due
        {
            for (peer, p) in self.peers.iter() {
                self.outputs.push_back(Output::Event(Event::PeerStats {
                    peer,
                    rx: p.rx(),
                    tx: p.tx(),
                    data_rx: p.data_rx(),
                    data_tx: p.data_tx(),
                    last_handshake: p.time_since_last_handshake(now),
                }));
            }
            schedule.stats = Some(now + interval);
        }
        schedule.tick = now + TICK;
        self.schedule = Some(schedule);
    }

    /// Starts a handshake with `peer` now, even if one is in progress. A `path` becomes the
    /// peer's path first, without an `Event::PathAdopted`. Unknown peers are ignored.
    pub fn force_handshake(&mut self, peer: PeerId, path: Option<Path>, now: Instant) {
        self.start_schedule(now);
        if let (Some(p), Some(path)) = (self.peers.peer_mut(peer), path) {
            p.set_path(path);
        }
        self.initiate(peer, None);
    }

    /// Sends a handshake initiation to `peer` on `path` now, even if a handshake is in
    /// progress, without changing the peer's path: e.g. to open a session through a
    /// candidate path. The rest of the handshake (retries included) follows the policy and
    /// the peer's path. Unknown peers are ignored.
    pub fn force_handshake_on(&mut self, peer: PeerId, path: Path, now: Instant) {
        self.start_schedule(now);
        self.initiate(peer, Some(path));
    }

    /// Formats a handshake initiation for `peer` and transmits it on `on`, or as the policy
    /// selects.
    fn initiate(&mut self, peer: PeerId, on: Option<Path>) {
        let Some(p) = self.peers.peer_mut(peer) else {
            return;
        };

        let mut buf = self.pool.get_len(BUF_SIZE);
        let initiation = p
            .tunnel_mut()
            .format_handshake_initiation(&mut buf.with_headroom_mut()[HEADROOM..], true);
        match initiation {
            TunnResult::WriteToNetwork(packet) => {
                let len = packet.len();
                buf.set_len(len);
                let fixed;
                let policy: &dyn PathPolicy = match on {
                    Some(path) => {
                        fixed = Fixed(Path {
                            ecn: Ecn::NotEct,
                            ..path
                        });
                        &fixed
                    }
                    None => self.policy.as_ref(),
                };
                transmit(
                    &mut self.outputs,
                    &mut self.pool,
                    policy,
                    peer,
                    p,
                    MessageKind::HandshakeInit,
                    buf,
                );
            }
            result => {
                tracing::debug!(message = "Handshake initiation failed", ?result);
                self.pool.put(buf);
            }
        }
    }
}
