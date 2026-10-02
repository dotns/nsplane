// Copyright (c) 2019 Cloudflare, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

use super::errors::WireGuardError;
use super::session::REKEY_AFTER_MESSAGES;
use crate::noise::{Tunn, TunnResult};
use std::mem;
use std::ops::{Index, IndexMut};

use rand_core::{OsRng, RngCore};

use std::time::{Duration, Instant};

// Some constants, represent time in seconds
// https://www.wireguard.com/papers/wireguard.pdf#page=14
pub(super) const REKEY_AFTER_TIME: Duration = Duration::from_secs(120);
const REJECT_AFTER_TIME: Duration = Duration::from_secs(180);
const REKEY_ATTEMPT_TIME: Duration = Duration::from_secs(90);
pub(super) const REKEY_TIMEOUT: Duration = Duration::from_secs(5);
const KEEPALIVE_TIMEOUT: Duration = Duration::from_secs(10);
const COOKIE_EXPIRATION_TIME: Duration = Duration::from_secs(120);
/// `REJECT_AFTER_TIME - KEEPALIVE_TIMEOUT - REKEY_TIMEOUT`
const REKEY_ON_RECEIVE_TIME: Duration = Duration::from_secs(180 - 10 - 5);

#[derive(Debug)]
pub(super) enum TimerName {
    /// Current time, updated each call to `update_timers`
    TimeCurrent,
    /// Time when last handshake was completed
    TimeSessionEstablished,
    /// Time the last attempt for a new handshake began
    TimeLastHandshakeStarted,
    /// Time we last received and authenticated a packet
    TimeLastPacketReceived,
    /// Time we last send a packet
    TimeLastPacketSent,
    /// Time we last received and authenticated a DATA packet
    TimeLastDataPacketReceived,
    /// Time we last send a DATA packet
    TimeLastDataPacketSent,
    /// Time we last received a cookie
    TimeCookieReceived,
    Top,
}

use self::TimerName::{
    TimeCookieReceived, TimeCurrent, TimeLastDataPacketReceived, TimeLastDataPacketSent,
    TimeLastHandshakeStarted, TimeLastPacketReceived, TimeLastPacketSent, TimeSessionEstablished,
};

/// A random delay of 0 to 333 ms added to every handshake retry, so peers that lost their
/// handshakes at the same time do not retry in lockstep.
pub(super) fn handshake_jitter() -> Duration {
    Duration::from_millis(u64::from(OsRng.next_u32() % 334))
}

#[derive(Debug)]
#[allow(
    clippy::struct_field_names,
    reason = "mirrors the timer state of the WireGuard whitepaper"
)]
pub(super) struct Timers {
    /// Is the owner of the timer the initiator or the responder for the last handshake?
    is_initiator: bool,
    /// Origin of the timers' time base: the `now` of the first `update_timers_at` call. Every
    /// timer is a `Duration` since it; before the first call all of them are zero.
    origin: Option<Instant>,
    timers: [Duration; TimerName::Top as usize],
    pub(super) session_timers: [Duration; super::N_SESSIONS],
    /// First data received since we last sent anything: a passive keepalive is due
    /// `KEEPALIVE_TIMEOUT` later.
    keepalive_due_from: Option<Duration>,
    /// First data sent since we last heard from the peer: a new handshake is due
    /// `KEEPALIVE_TIMEOUT + REKEY_TIMEOUT` later.
    handshake_due_from: Option<Duration>,
    persistent_keepalive: u16,
    /// Send a persistent keepalive right away (the interval was just enabled).
    persistent_keepalive_pending: bool,
    /// Jitter added to the retry of the handshake in flight
    handshake_jitter: Duration,
    /// When the handshake initiation in flight was sent
    pub(super) handshake_init_sent: Duration,
    /// Should this timer call reset rr function (if not a shared rr instance)
    pub(super) should_reset_rr: bool,
    /// Number of completed handshakes so far; never reset.
    handshakes: u64,
    /// Local index of the session we established as responder that the initiator has not
    /// confirmed with a data message yet.
    unconfirmed_session: Option<usize>,
}

impl Timers {
    pub(super) fn new(persistent_keepalive: Option<u16>, reset_rr: bool) -> Self {
        let persistent_keepalive = persistent_keepalive.unwrap_or(0);
        Self {
            is_initiator: false,
            origin: None,
            timers: Default::default(),
            session_timers: Default::default(),
            keepalive_due_from: None,
            handshake_due_from: None,
            persistent_keepalive,
            persistent_keepalive_pending: persistent_keepalive > 0,
            handshake_jitter: Duration::ZERO,
            handshake_init_sent: Duration::ZERO,
            should_reset_rr: reset_rr,
            handshakes: 0,
            unconfirmed_session: None,
        }
    }

    pub(super) fn set_persistent_keepalive(&mut self, interval: Option<u16>) {
        self.persistent_keepalive = interval.unwrap_or(0);
        self.persistent_keepalive_pending = self.persistent_keepalive > 0;
    }

    /// Picks a new retry jitter; called whenever a handshake initiation is sent.
    pub(super) fn new_handshake_jitter(&mut self) {
        self.handshake_jitter = handshake_jitter();
    }

    const fn is_initiator(&self) -> bool {
        self.is_initiator
    }

    // We don't really clear the timers, but we set them to the current time to
    // so the reference time frame is the same
    pub(super) fn clear(&mut self) {
        let now = self[TimeCurrent];
        for t in &mut self.timers[..] {
            *t = now;
        }
        self.keepalive_due_from = None;
        self.handshake_due_from = None;
    }
}

impl Index<TimerName> for Timers {
    type Output = Duration;
    fn index(&self, index: TimerName) -> &Duration {
        &self.timers[index as usize]
    }
}

impl IndexMut<TimerName> for Timers {
    fn index_mut(&mut self, index: TimerName) -> &mut Duration {
        &mut self.timers[index as usize]
    }
}

impl Tunn {
    /// `now` on the time base of the timers, which starts at the first call. A `now` before
    /// the origin counts as the origin, and the time base never goes backwards, so callers
    /// whose clock jumps (e.g. paused test time) cannot make a timer misfire or panic.
    fn time_base(&mut self, now: Instant) -> Duration {
        let origin = *self.timers.origin.get_or_insert(now);
        now.saturating_duration_since(origin)
            .max(self.timers[TimeCurrent])
    }

    pub(super) fn timer_tick(&mut self, timer_name: TimerName) {
        let time = self.timers[TimeCurrent];
        match timer_name {
            // Hearing from the peer answers our data; sending anything answers theirs.
            TimeLastPacketReceived => self.timers.handshake_due_from = None,
            TimeLastPacketSent => self.timers.keepalive_due_from = None,
            TimeLastDataPacketReceived => {
                self.timers.keepalive_due_from.get_or_insert(time);
            }
            TimeLastDataPacketSent => {
                self.timers.handshake_due_from.get_or_insert(time);
            }
            _ => {}
        }

        self.timers[timer_name] = time;
    }

    pub(super) fn timer_tick_session_established(
        &mut self,
        is_initiator: bool,
        session_idx: usize,
    ) {
        self.timer_tick(TimeSessionEstablished);
        self.timers.session_timers[session_idx % crate::noise::N_SESSIONS] =
            self.timers[TimeCurrent];
        self.timers.is_initiator = is_initiator;
        if is_initiator {
            self.timers.handshakes += 1;
        } else {
            self.timers.unconfirmed_session = Some(session_idx);
        }
    }

    /// Counts the handshake that established session `session_idx` as responder once the
    /// initiator confirms it with its first data message.
    pub(super) fn timer_tick_session_confirmed(&mut self, session_idx: usize) {
        if self.timers.unconfirmed_session == Some(session_idx) {
            self.timers.unconfirmed_session = None;
            self.timers.handshakes += 1;
        }
    }

    // We don't really clear the timers, but we set them to the current time to
    // so the reference time frame is the same
    fn clear_all(&mut self) {
        for session in &mut self.sessions {
            *session = None;
        }

        self.packet_queue.clear();

        self.timers.clear();
    }

    fn update_session_timers(&mut self, time_now: Duration) {
        let timers = &mut self.timers;

        for (i, t) in timers.session_timers.iter_mut().enumerate() {
            if time_now.saturating_sub(*t) > REJECT_AFTER_TIME {
                if let Some(session) = self.sessions[i].take() {
                    tracing::debug!(
                        message = "SESSION_EXPIRED(REJECT_AFTER_TIME)",
                        session = session.receiving_index
                    );
                }
                *t = time_now;
            }
        }
    }

    /// Expires the connection when keys are too old or handshakes keep failing.
    fn check_expiry(&mut self, now: Duration) -> Result<(), WireGuardError> {
        if self.handshake.is_expired() {
            return Err(WireGuardError::ConnectionExpired);
        }

        // Clear cookie after COOKIE_EXPIRATION_TIME
        if self.handshake.has_cookie()
            && now.saturating_sub(self.timers[TimeCookieReceived]) >= COOKIE_EXPIRATION_TIME
        {
            self.handshake.clear_cookie();
        }

        // All ephemeral private keys and symmetric session keys are zeroed out after
        // (REJECT_AFTER_TIME * 3) ms if no new keys have been exchanged.
        if now.saturating_sub(self.timers[TimeSessionEstablished]) >= REJECT_AFTER_TIME * 3 {
            tracing::error!("CONNECTION_EXPIRED(REJECT_AFTER_TIME * 3)");
            self.handshake.set_expired();
            self.clear_all();
            return Err(WireGuardError::ConnectionExpired);
        }

        // After REKEY_ATTEMPT_TIME ms of trying to initiate a new handshake,
        // the retries give up and cease, and clear all existing packets queued
        // up to be sent. If a packet is explicitly queued up to be sent, then
        // this timer is reset.
        if self.handshake.is_init_sent()
            && now.saturating_sub(self.timers[TimeLastHandshakeStarted]) >= REKEY_ATTEMPT_TIME
        {
            tracing::error!("CONNECTION_EXPIRED(REKEY_ATTEMPT_TIME)");
            self.handshake.set_expired();
            self.clear_all();
            return Err(WireGuardError::ConnectionExpired);
        }
        Ok(())
    }

    /// Whether a handshake initiation is due.
    fn handshake_due(&mut self, now: Duration) -> bool {
        if self.handshake.is_init_sent() {
            // A handshake initiation is retried after REKEY_TIMEOUT + jitter ms,
            // if a response has not been received, where jitter is some random
            // value between 0 and 333 ms.
            let due = now.saturating_sub(self.timers.handshake_init_sent)
                >= REKEY_TIMEOUT + self.timers.handshake_jitter;
            if due {
                tracing::warn!("HANDSHAKE(REKEY_TIMEOUT)");
            }
            return due;
        }

        // A sending key that encrypted Rekey-After-Messages messages is replaced,
        // whichever side initiated the session.
        if self.sessions[self.current % super::N_SESSIONS]
            .as_ref()
            .is_some_and(|s| s.sending_counter() >= REKEY_AFTER_MESSAGES)
        {
            tracing::debug!("HANDSHAKE(REKEY_AFTER_MESSAGES)");
            return true;
        }

        let session_established = self.timers[TimeSessionEstablished];
        let session_age = now.saturating_sub(session_established);
        if self.timers.is_initiator() {
            // After sending a packet, if the sender was the original initiator
            // of the handshake and if the current session key is REKEY_AFTER_TIME
            // ms old, we initiate a new handshake. If the sender was the original
            // responder of the handshake, it does not re-initiate a new handshake
            // after REKEY_AFTER_TIME ms like the original initiator does.
            if session_established < self.timers[TimeLastDataPacketSent]
                && session_age >= REKEY_AFTER_TIME
            {
                tracing::debug!("HANDSHAKE(REKEY_AFTER_TIME (on send))");
                return true;
            }

            // After receiving a packet, if the receiver was the original initiator
            // of the handshake and if the current session key is REJECT_AFTER_TIME
            // - KEEPALIVE_TIMEOUT - REKEY_TIMEOUT ms old, we initiate a new
            // handshake.
            if session_established < self.timers[TimeLastDataPacketReceived]
                && session_age >= REKEY_ON_RECEIVE_TIME
            {
                tracing::warn!(
                    "HANDSHAKE(REJECT_AFTER_TIME - KEEPALIVE_TIMEOUT - REKEY_TIMEOUT (on receive))"
                );
                return true;
            }
        }

        // If we have sent data to a given peer but have not received a packet from that peer
        // for (KEEPALIVE + REKEY_TIMEOUT) ms since, we initiate a new handshake.
        if self
            .timers
            .handshake_due_from
            .is_some_and(|sent| now.saturating_sub(sent) >= KEEPALIVE_TIMEOUT + REKEY_TIMEOUT)
        {
            tracing::warn!("HANDSHAKE(KEEPALIVE + REKEY_TIMEOUT)");
            self.timers.handshake_due_from = None;
            return true;
        }
        false
    }

    /// Whether a keepalive is due.
    fn keepalive_due(&mut self, now: Duration) -> bool {
        // If data has been received from a given peer, but we have not sent anything back
        // for KEEPALIVE ms since, we send an empty packet.
        if self
            .timers
            .keepalive_due_from
            .is_some_and(|received| now.saturating_sub(received) >= KEEPALIVE_TIMEOUT)
        {
            tracing::debug!("KEEPALIVE(KEEPALIVE_TIMEOUT)");
            self.timers.keepalive_due_from = None;
            return true;
        }

        // Persistent KEEPALIVE: sent once when enabled, then whenever the tunnel was silent
        // in both directions for the interval.
        let interval = self.timers.persistent_keepalive;
        if interval == 0 {
            return false;
        }
        let last_traffic = self.timers[TimeLastPacketSent].max(self.timers[TimeLastPacketReceived]);
        if mem::take(&mut self.timers.persistent_keepalive_pending)
            || now.saturating_sub(last_traffic) >= Duration::from_secs(u64::from(interval))
        {
            tracing::debug!("KEEPALIVE(PERSISTENT_KEEPALIVE)");
            return true;
        }
        false
    }

    /// Advances the timers to the crate clock (`std::time::Instant::now()`); see
    /// [`Tunn::update_timers_at`].
    pub fn update_timers<'a>(&mut self, dst: &'a mut [u8]) -> TunnResult<'a> {
        self.update_timers_at(Instant::now(), dst)
    }

    /// Advances the timers to `now`; returns a handshake or keepalive to send, if one is due.
    ///
    /// Every timer decision of the tunnel uses the `now` passed here: the timers count from
    /// the `now` of the first call, and events between two calls are timed at the earlier
    /// one. A `now` before the latest one is treated as the latest one. Callers must pass
    /// instants from one clock: mixing this method with [`Tunn::update_timers`] or
    /// [`Tunn::time_since_last_handshake`] is only sound if `now` comes from the crate clock.
    pub fn update_timers_at<'a>(&mut self, now: Instant, dst: &'a mut [u8]) -> TunnResult<'a> {
        if self.timers.should_reset_rr {
            self.rate_limiter.reset_count_at(now);
        }

        let now = self.time_base(now);
        self.timers[TimeCurrent] = now;

        self.update_session_timers(now);

        if let Err(e) = self.check_expiry(now) {
            return TunnResult::Err(e);
        }

        if self.handshake_due(now) {
            return self.format_handshake_initiation(dst, true);
        }

        // Keepalives only make sense outside of a handshake in progress.
        if !self.handshake.is_init_sent() && self.keepalive_due(now) {
            return self.encapsulate(&[], dst);
        }

        TunnResult::Done
    }

    /// Time since the current session was established, on the crate clock; see
    /// [`Tunn::time_since_last_handshake_at`].
    pub fn time_since_last_handshake(&self) -> Option<Duration> {
        self.time_since_last_handshake_at(Instant::now())
    }

    /// Time from the establishment of the current session to `now`.
    ///
    /// `now` must come from the clock passed to [`Tunn::update_timers_at`]; the session was
    /// established at the time of the last timer update before it.
    pub fn time_since_last_handshake_at(&self, now: Instant) -> Option<Duration> {
        let current_session = self.current;
        if self.sessions[current_session % super::N_SESSIONS].is_some() {
            let since_origin = self.timers.origin.map_or(Duration::ZERO, |origin| {
                now.saturating_duration_since(origin)
            });
            let duration_since_session_established = self.timers[TimeSessionEstablished];

            Some(since_origin.saturating_sub(duration_since_session_established))
        } else {
            None
        }
    }

    /// Number of handshakes completed by this tunnel, as initiator or responder.
    ///
    /// Monotonic: it grows by one when the initiator accepts a handshake response, and when
    /// the responder receives the first data message (or keepalive) on the session it
    /// established, which confirms the handshake. A caller comparing it with the last value
    /// it saw detects every completed handshake, even several between two looks.
    pub const fn handshake_count(&self) -> u64 {
        self.timers.handshakes
    }

    /// The persistent keepalive interval in seconds.
    pub const fn persistent_keepalive(&self) -> Option<u16> {
        let keepalive = self.timers.persistent_keepalive;

        if keepalive > 0 { Some(keepalive) } else { None }
    }
}
