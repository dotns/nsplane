// Copyright (c) 2019 Cloudflare, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

/// Errors of the protocol state machine.
pub mod errors;
/// The `Noise_IKpsk2` handshake.
pub mod handshake;
/// `mac1`/`mac2` verification and cookie replies under load.
pub mod rate_limiter;

mod session;
mod timers;

use crate::noise::errors::WireGuardError;
use crate::noise::handshake::Handshake;
use crate::noise::rate_limiter::RateLimiter;
use crate::noise::timers::{TimerName, Timers};
use crate::x25519;

use std::collections::VecDeque;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

/// The default value to use for rate limiting, when no other rate limiter is defined
const PEER_HANDSHAKE_RATE_LIMIT: u64 = 10;

const IPV4_MIN_HEADER_SIZE: usize = 20;
const IPV4_LEN_OFF: usize = 2;
const IPV4_SRC_IP_OFF: usize = 12;
const IPV4_DST_IP_OFF: usize = 16;
const IPV4_IP_SZ: usize = 4;

const IPV6_MIN_HEADER_SIZE: usize = 40;
const IPV6_LEN_OFF: usize = 4;
const IPV6_SRC_IP_OFF: usize = 8;
const IPV6_DST_IP_OFF: usize = 24;
const IPV6_IP_SZ: usize = 16;

const IP_LEN_SZ: usize = 2;

const MAX_QUEUE_DEPTH: usize = 256;
/// number of sessions in the ring, better keep a `PoT`
const N_SESSIONS: usize = 8;

#[derive(Debug)]
/// What the caller has to do after feeding a packet to a [`Tunn`].
pub enum TunnResult<'a> {
    /// Nothing to do.
    Done,
    /// The packet was rejected.
    Err(WireGuardError),
    /// Send the buffer to the peer.
    WriteToNetwork(&'a mut [u8]),
    /// Write the IPv4 packet with the given source to the TUN interface.
    WriteToTunnelV4(&'a mut [u8], Ipv4Addr),
    /// Write the IPv6 packet with the given source to the TUN interface.
    WriteToTunnelV6(&'a mut [u8], Ipv6Addr),
}

impl From<WireGuardError> for TunnResult<'_> {
    fn from(err: WireGuardError) -> Self {
        TunnResult::Err(err)
    }
}

/// Tunnel represents a point-to-point WireGuard connection
#[derive(Debug)]
pub struct Tunn {
    /// The handshake currently in progress
    handshake: handshake::Handshake,
    /// The `N_SESSIONS` most recent sessions, index is session id modulo `N_SESSIONS`
    sessions: [Option<session::Session>; N_SESSIONS],
    /// Index of most recently used session
    current: usize,
    /// Queue to store blocked packets
    packet_queue: VecDeque<Vec<u8>>,
    /// Keeps tabs on the expiring timers
    timers: timers::Timers,
    tx_bytes: usize,
    rx_bytes: usize,
    rate_limiter: Arc<RateLimiter>,
}

type MessageType = u32;
const HANDSHAKE_INIT: MessageType = 1;
const HANDSHAKE_RESP: MessageType = 2;
const COOKIE_REPLY: MessageType = 3;
const DATA: MessageType = 4;

const HANDSHAKE_INIT_SZ: usize = 148;
const HANDSHAKE_RESP_SZ: usize = 92;
const COOKIE_REPLY_SZ: usize = 64;
const DATA_OVERHEAD_SZ: usize = 32;

#[derive(Debug)]
/// A parsed handshake initiation message.
pub struct HandshakeInit<'a> {
    sender_idx: u32,
    unencrypted_ephemeral: &'a [u8; 32],
    encrypted_static: &'a [u8],
    encrypted_timestamp: &'a [u8],
}

#[derive(Debug)]
/// A parsed handshake response message.
pub struct HandshakeResponse<'a> {
    sender_idx: u32,
    /// Index of the initiator's handshake this message answers.
    pub receiver_idx: u32,
    unencrypted_ephemeral: &'a [u8; 32],
    encrypted_nothing: &'a [u8],
}

#[derive(Debug)]
/// A parsed cookie reply message.
pub struct PacketCookieReply<'a> {
    /// Index of the handshake this cookie belongs to.
    pub receiver_idx: u32,
    nonce: &'a [u8],
    encrypted_cookie: &'a [u8],
}

#[derive(Debug)]
/// A parsed transport data message.
pub struct PacketData<'a> {
    /// Index of the receiving session.
    pub receiver_idx: u32,
    counter: u64,
    encrypted_encapsulated_packet: &'a [u8],
}

/// Describes a packet from network
#[derive(Debug)]
pub enum Packet<'a> {
    /// Handshake initiation.
    HandshakeInit(HandshakeInit<'a>),
    /// Handshake response.
    HandshakeResponse(HandshakeResponse<'a>),
    /// Cookie reply.
    PacketCookieReply(PacketCookieReply<'a>),
    /// Transport data.
    PacketData(PacketData<'a>),
}

/// Borrows `N` bytes of `src` starting at `offset`.
fn array_at<const N: usize>(src: &[u8], offset: usize) -> Option<&[u8; N]> {
    src.get(offset..offset.checked_add(N)?)?.try_into().ok()
}

fn u32_le_at(src: &[u8], offset: usize) -> Result<u32, WireGuardError> {
    array_at(src, offset)
        .map(|b| u32::from_le_bytes(*b))
        .ok_or(WireGuardError::InvalidPacket)
}

impl Tunn {
    #[inline]
    /// Parses a datagram into a WireGuard message without copying.
    pub fn parse_incoming_packet(src: &[u8]) -> Result<Packet<'_>, WireGuardError> {
        // Checks the type, as well as the reserved zero fields
        let packet_type = u32_le_at(src, 0)?;
        let field = |from: usize, to: usize| src.get(from..to).ok_or(WireGuardError::InvalidPacket);

        Ok(match (packet_type, src.len()) {
            (HANDSHAKE_INIT, HANDSHAKE_INIT_SZ) => Packet::HandshakeInit(HandshakeInit {
                sender_idx: u32_le_at(src, 4)?,
                unencrypted_ephemeral: array_at(src, 8).ok_or(WireGuardError::InvalidPacket)?,
                encrypted_static: field(40, 88)?,
                encrypted_timestamp: field(88, 116)?,
            }),
            (HANDSHAKE_RESP, HANDSHAKE_RESP_SZ) => Packet::HandshakeResponse(HandshakeResponse {
                sender_idx: u32_le_at(src, 4)?,
                receiver_idx: u32_le_at(src, 8)?,
                unencrypted_ephemeral: array_at(src, 12).ok_or(WireGuardError::InvalidPacket)?,
                encrypted_nothing: field(44, 60)?,
            }),
            (COOKIE_REPLY, COOKIE_REPLY_SZ) => Packet::PacketCookieReply(PacketCookieReply {
                receiver_idx: u32_le_at(src, 4)?,
                nonce: field(8, 32)?,
                encrypted_cookie: field(32, 64)?,
            }),
            (DATA, DATA_OVERHEAD_SZ..) => Packet::PacketData(PacketData {
                receiver_idx: u32_le_at(src, 4)?,
                counter: array_at(src, 8)
                    .map(|b| u64::from_le_bytes(*b))
                    .ok_or(WireGuardError::InvalidPacket)?,
                encrypted_encapsulated_packet: field(16, src.len())?,
            }),
            _ => return Err(WireGuardError::InvalidPacket),
        })
    }

    /// Returns whether the tunnel gave up on handshakes and needs to be recreated.
    pub const fn is_expired(&self) -> bool {
        self.handshake.is_expired()
    }

    /// Returns the destination address of an IP packet.
    pub fn dst_address(packet: &[u8]) -> Option<IpAddr> {
        match packet.first()? >> 4 {
            4 if packet.len() >= IPV4_MIN_HEADER_SIZE => {
                array_at::<IPV4_IP_SZ>(packet, IPV4_DST_IP_OFF).map(|a| IpAddr::from(*a))
            }
            6 if packet.len() >= IPV6_MIN_HEADER_SIZE => {
                array_at::<IPV6_IP_SZ>(packet, IPV6_DST_IP_OFF).map(|a| IpAddr::from(*a))
            }
            _ => None,
        }
    }

    /// Create a new tunnel using own private key and the peer public key
    pub fn new(
        static_private: x25519::StaticSecret,
        peer_static_public: x25519::PublicKey,
        preshared_key: Option<[u8; 32]>,
        persistent_keepalive: Option<u16>,
        index: u32,
        rate_limiter: Option<Arc<RateLimiter>>,
    ) -> Self {
        let static_public = x25519::PublicKey::from(&static_private);

        Self {
            handshake: Handshake::new(
                static_private,
                static_public,
                peer_static_public,
                index << 8,
                preshared_key,
            ),
            sessions: Default::default(),
            current: Default::default(),
            tx_bytes: Default::default(),
            rx_bytes: Default::default(),

            packet_queue: VecDeque::new(),
            timers: Timers::new(persistent_keepalive, rate_limiter.is_none()),

            rate_limiter: rate_limiter.unwrap_or_else(|| {
                Arc::new(RateLimiter::new(&static_public, PEER_HANDSHAKE_RATE_LIMIT))
            }),
        }
    }

    /// Update the private key and clear existing sessions
    pub fn set_static_private(
        &mut self,
        static_private: x25519::StaticSecret,
        static_public: x25519::PublicKey,
        rate_limiter: Option<Arc<RateLimiter>>,
    ) {
        self.timers.should_reset_rr = rate_limiter.is_none();
        self.rate_limiter = rate_limiter.unwrap_or_else(|| {
            Arc::new(RateLimiter::new(&static_public, PEER_HANDSHAKE_RATE_LIMIT))
        });
        self.handshake
            .set_static_private(static_private, static_public);
        for s in &mut self.sessions {
            *s = None;
        }
    }

    /// Replaces the preshared key. Established sessions keep working; the next handshake
    /// uses the new key.
    pub const fn set_preshared_key(&mut self, preshared_key: Option<[u8; 32]>) {
        self.handshake.set_preshared_key(preshared_key);
    }

    /// Sets the persistent keepalive interval in seconds; `None` or `Some(0)` disables it.
    pub fn set_persistent_keepalive(&mut self, interval: Option<u16>) {
        self.timers.set_persistent_keepalive(interval);
    }

    /// Encapsulate a single packet from the tunnel interface.
    /// Returns `TunnResult`.
    ///
    /// Size of dst should be at least `src.len()` + 32, and no less than 148 bytes,
    /// otherwise `WireGuardError::DestinationBufferTooSmall` is returned. The plaintext is
    /// padded to a multiple of 16 bytes when dst has room for up to 15 more bytes.
    pub fn encapsulate<'a>(&mut self, src: &[u8], dst: &'a mut [u8]) -> TunnResult<'a> {
        let current = self.current % N_SESSIONS;
        // A sending key that is worn out (Reject-After-Messages) is dropped, so the packet is
        // queued and a handshake starts, as if there were no session.
        if self.sessions[current]
            .as_ref()
            .is_some_and(session::Session::is_exhausted)
        {
            self.sessions[current] = None;
        }

        if let Some(session) = &self.sessions[current] {
            // Send the packet using an established session
            let packet = match session.format_packet_data(src, dst) {
                Ok(packet) => packet,
                Err(e) => return TunnResult::Err(e),
            };
            self.timer_tick(TimerName::TimeLastPacketSent);
            // Exclude Keepalive packets from timer update.
            if !src.is_empty() {
                self.timer_tick(TimerName::TimeLastDataPacketSent);
            }
            self.tx_bytes += src.len();
            return TunnResult::WriteToNetwork(packet);
        }

        // If there is no session, queue the packet for future retry
        self.queue_packet(src);
        // Initiate a new handshake if none is in progress
        self.format_handshake_initiation(dst, false)
    }

    /// Receives a UDP datagram from the network and parses it.
    /// Returns `TunnResult`.
    ///
    /// If the result is of type `TunnResult::WriteToNetwork`, should repeat the call with empty datagram,
    /// until `TunnResult::Done` is returned. If batch processing packets, it is OK to defer until last
    /// packet is processed.
    pub fn decapsulate<'a>(
        &mut self,
        src_addr: Option<SocketAddr>,
        datagram: &[u8],
        dst: &'a mut [u8],
    ) -> TunnResult<'a> {
        if datagram.is_empty() {
            // Indicates a repeated call
            return self.send_queued_packet(dst);
        }

        let mut cookie = [0u8; COOKIE_REPLY_SZ];
        let packet = match self
            .rate_limiter
            .verify_packet(src_addr, datagram, &mut cookie)
        {
            Ok(packet) => packet,
            Err(TunnResult::WriteToNetwork(cookie)) => {
                dst[..cookie.len()].copy_from_slice(cookie);
                return TunnResult::WriteToNetwork(&mut dst[..cookie.len()]);
            }
            Err(TunnResult::Err(e)) => return TunnResult::Err(e),
            _ => unreachable!(),
        };

        self.handle_verified_packet(packet, dst)
    }

    pub(crate) fn handle_verified_packet<'a>(
        &mut self,
        packet: Packet<'_>,
        dst: &'a mut [u8],
    ) -> TunnResult<'a> {
        match packet {
            Packet::HandshakeInit(p) => self.handle_handshake_init(&p, dst),
            Packet::HandshakeResponse(p) => self.handle_handshake_response(&p, dst),
            Packet::PacketCookieReply(p) => self.handle_cookie_reply(&p),
            Packet::PacketData(p) => self.handle_data(&p, dst),
        }
        .unwrap_or_else(TunnResult::from)
    }

    fn handle_handshake_init<'a>(
        &mut self,
        p: &HandshakeInit<'_>,
        dst: &'a mut [u8],
    ) -> Result<TunnResult<'a>, WireGuardError> {
        tracing::debug!(
            message = "Received handshake_initiation",
            remote_idx = p.sender_idx
        );

        let (packet, session) = self.handshake.receive_handshake_initialization(p, dst)?;

        // Store new session in ring buffer
        let index = session.local_index();
        self.sessions[index % N_SESSIONS] = Some(session);

        self.timer_tick(TimerName::TimeLastPacketReceived);
        self.timer_tick(TimerName::TimeLastPacketSent);
        self.timer_tick_session_established(false, index); // New session established, we are not the initiator

        tracing::debug!(message = "Sending handshake_response", local_idx = index);

        Ok(TunnResult::WriteToNetwork(packet))
    }

    fn handle_handshake_response<'a>(
        &mut self,
        p: &HandshakeResponse<'_>,
        dst: &'a mut [u8],
    ) -> Result<TunnResult<'a>, WireGuardError> {
        tracing::debug!(
            message = "Received handshake_response",
            local_idx = p.receiver_idx,
            remote_idx = p.sender_idx
        );

        let session = self.handshake.receive_handshake_response(p)?;

        let keepalive_packet = session.format_packet_data(&[], dst)?;
        // Store new session in ring buffer
        let l_idx = session.local_index();
        let index = l_idx % N_SESSIONS;
        self.sessions[index] = Some(session);

        self.timer_tick(TimerName::TimeLastPacketReceived);
        self.timer_tick_session_established(true, index); // New session established, we are the initiator
        self.set_current_session(l_idx);

        tracing::debug!("Sending keepalive");

        Ok(TunnResult::WriteToNetwork(keepalive_packet)) // Send a keepalive as a response
    }

    fn handle_cookie_reply<'a>(
        &mut self,
        p: &PacketCookieReply<'_>,
    ) -> Result<TunnResult<'a>, WireGuardError> {
        tracing::debug!(
            message = "Received cookie_reply",
            local_idx = p.receiver_idx
        );

        self.handshake.receive_cookie_reply(p)?;
        self.timer_tick(TimerName::TimeLastPacketReceived);
        self.timer_tick(TimerName::TimeCookieReceived);

        tracing::debug!("Did set cookie");

        Ok(TunnResult::Done)
    }

    /// Update the index of the currently used session, if needed
    fn set_current_session(&mut self, new_idx: usize) {
        let cur_idx = self.current;
        if cur_idx == new_idx {
            // There is nothing to do, already using this session, this is the common case
            return;
        }
        if self.sessions[cur_idx % N_SESSIONS].is_none()
            || self.timers.session_timers[new_idx % N_SESSIONS]
                >= self.timers.session_timers[cur_idx % N_SESSIONS]
        {
            self.current = new_idx;
            tracing::debug!(message = "New session", session = new_idx);
        }
    }

    /// Decrypts a data packet, and stores the decapsulated packet in dst.
    fn handle_data<'a>(
        &mut self,
        packet: &PacketData<'_>,
        dst: &'a mut [u8],
    ) -> Result<TunnResult<'a>, WireGuardError> {
        let r_idx = packet.receiver_idx as usize;
        let idx = r_idx % N_SESSIONS;

        // Get the (probably) right session
        let decapsulated_packet = {
            let session = self.sessions[idx].as_ref();
            let session = session.ok_or_else(|| {
                tracing::trace!(message = "No current session available", remote_idx = r_idx);
                WireGuardError::NoCurrentSession
            })?;
            session.receive_packet_data(packet, dst)?
        };

        self.set_current_session(r_idx);

        self.timer_tick(TimerName::TimeLastPacketReceived);

        Ok(self.validate_decapsulated_packet(decapsulated_packet))
    }

    /// Formats a new handshake initiation message and store it in dst. If `force_resend` is true will send
    /// a new handshake, even if a handshake is already in progress (for example when a handshake times out)
    pub fn format_handshake_initiation<'a>(
        &mut self,
        dst: &'a mut [u8],
        force_resend: bool,
    ) -> TunnResult<'a> {
        if self.handshake.is_in_progress() && !force_resend {
            return TunnResult::Done;
        }

        if self.handshake.is_expired() {
            self.timers.clear();
        }

        let starting_new_handshake = !self.handshake.is_in_progress();

        match self.handshake.format_handshake_initiation(dst) {
            Ok(packet) => {
                tracing::debug!("Sending handshake_initiation");

                if starting_new_handshake {
                    self.timer_tick(TimerName::TimeLastHandshakeStarted);
                }
                self.timers.new_handshake_jitter();
                self.timer_tick(TimerName::TimeLastPacketSent);
                TunnResult::WriteToNetwork(packet)
            }
            Err(e) => TunnResult::Err(e),
        }
    }

    /// Check if an IP packet is v4 or v6, truncate to the length indicated by the length field
    /// Returns the truncated packet and the source IP as `TunnResult`
    fn validate_decapsulated_packet<'a>(&mut self, packet: &'a mut [u8]) -> TunnResult<'a> {
        let (computed_len, src_ip_address) = match packet.len() {
            0 => return TunnResult::Done, // This is keepalive, and not an error
            _ if packet[0] >> 4 == 4 && packet.len() >= IPV4_MIN_HEADER_SIZE => match (
                array_at::<IP_LEN_SZ>(packet, IPV4_LEN_OFF),
                array_at::<IPV4_IP_SZ>(packet, IPV4_SRC_IP_OFF),
            ) {
                (Some(len), Some(addr)) => {
                    (usize::from(u16::from_be_bytes(*len)), IpAddr::from(*addr))
                }
                _ => return TunnResult::Err(WireGuardError::InvalidPacket),
            },
            _ if packet[0] >> 4 == 6 && packet.len() >= IPV6_MIN_HEADER_SIZE => match (
                array_at::<IP_LEN_SZ>(packet, IPV6_LEN_OFF),
                array_at::<IPV6_IP_SZ>(packet, IPV6_SRC_IP_OFF),
            ) {
                (Some(len), Some(addr)) => (
                    usize::from(u16::from_be_bytes(*len)) + IPV6_MIN_HEADER_SIZE,
                    IpAddr::from(*addr),
                ),
                _ => return TunnResult::Err(WireGuardError::InvalidPacket),
            },
            _ => return TunnResult::Err(WireGuardError::InvalidPacket),
        };

        if computed_len > packet.len() {
            return TunnResult::Err(WireGuardError::InvalidPacket);
        }

        self.timer_tick(TimerName::TimeLastDataPacketReceived);
        self.rx_bytes += computed_len;

        match src_ip_address {
            IpAddr::V4(addr) => TunnResult::WriteToTunnelV4(&mut packet[..computed_len], addr),
            IpAddr::V6(addr) => TunnResult::WriteToTunnelV6(&mut packet[..computed_len], addr),
        }
    }

    /// Get a packet from the queue, and try to encapsulate it
    fn send_queued_packet<'a>(&mut self, dst: &'a mut [u8]) -> TunnResult<'a> {
        if let Some(packet) = self.dequeue_packet() {
            match self.encapsulate(&packet, dst) {
                TunnResult::Err(_) => {
                    // On error, return packet to the queue
                    self.requeue_packet(packet);
                }
                r => return r,
            }
        }
        TunnResult::Done
    }

    /// Push packet to the back of the queue
    fn queue_packet(&mut self, packet: &[u8]) {
        if self.packet_queue.len() < MAX_QUEUE_DEPTH {
            // Drop if too many are already in queue
            self.packet_queue.push_back(packet.to_vec());
        }
    }

    /// Push packet to the front of the queue
    fn requeue_packet(&mut self, packet: Vec<u8>) {
        if self.packet_queue.len() < MAX_QUEUE_DEPTH {
            // Drop if too many are already in queue
            self.packet_queue.push_front(packet);
        }
    }

    fn dequeue_packet(&mut self) -> Option<Vec<u8>> {
        self.packet_queue.pop_front()
    }

    #[allow(
        clippy::cast_precision_loss,
        reason = "the loss estimate is approximate"
    )]
    fn estimate_loss(&self) -> f32 {
        let session_idx = self.current;

        let mut weight = 9.0;
        let mut cur_avg = 0.0;
        let mut total_weight = 0.0;

        for i in 0..N_SESSIONS {
            if let Some(ref session) = self.sessions[(session_idx.wrapping_sub(i)) % N_SESSIONS] {
                let (expected, received) = session.current_packet_cnt();

                let loss = if expected == 0 {
                    0.0
                } else {
                    1.0 - received as f32 / expected as f32
                };

                cur_avg = f32::mul_add(loss, weight, cur_avg);
                total_weight += weight;
                weight /= 3.0;
            }
        }

        if total_weight == 0.0 {
            0.0
        } else {
            cur_avg / total_weight
        }
    }

    /// Return stats from the tunnel:
    /// * Time since last handshake in seconds
    /// * Data bytes sent
    /// * Data bytes received
    pub fn stats(&self) -> (Option<Duration>, usize, usize, f32, Option<u32>) {
        let time = self.time_since_last_handshake();
        let tx_bytes = self.tx_bytes;
        let rx_bytes = self.rx_bytes;
        let loss = self.estimate_loss();
        let rtt = self.handshake.last_rtt;

        (time, tx_bytes, rx_bytes, loss, rtt)
    }
}

#[cfg(test)]
mod tests {
    #[cfg(feature = "mock-instant")]
    use crate::noise::timers::{REKEY_AFTER_TIME, REKEY_TIMEOUT};

    use super::*;
    use rand_core::{OsRng, RngCore};

    fn create_two_tuns() -> (Tunn, Tunn) {
        let my_secret_key = x25519_dalek::StaticSecret::random_from_rng(OsRng);
        let my_public_key = x25519_dalek::PublicKey::from(&my_secret_key);
        let my_idx = OsRng.next_u32();

        let their_secret_key = x25519_dalek::StaticSecret::random_from_rng(OsRng);
        let their_public_key = x25519_dalek::PublicKey::from(&their_secret_key);
        let their_idx = OsRng.next_u32();

        let my_tun = Tunn::new(my_secret_key, their_public_key, None, None, my_idx, None);

        let their_tun = Tunn::new(their_secret_key, my_public_key, None, None, their_idx, None);

        (my_tun, their_tun)
    }

    fn create_handshake_init(tun: &mut Tunn) -> Vec<u8> {
        let mut dst = vec![0u8; 2048];
        let handshake_init = tun.format_handshake_initiation(&mut dst, false);
        assert!(matches!(handshake_init, TunnResult::WriteToNetwork(_)));
        let TunnResult::WriteToNetwork(sent) = handshake_init else {
            unreachable!();
        };
        let handshake_init = sent;

        handshake_init.into()
    }

    fn create_handshake_response(tun: &mut Tunn, handshake_init: &[u8]) -> Vec<u8> {
        let mut dst = vec![0u8; 2048];
        let handshake_resp = tun.decapsulate(None, handshake_init, &mut dst);
        assert!(matches!(handshake_resp, TunnResult::WriteToNetwork(_)));

        let TunnResult::WriteToNetwork(sent) = handshake_resp else {
            unreachable!();
        };
        let handshake_resp = sent;

        handshake_resp.into()
    }

    fn parse_handshake_resp(tun: &mut Tunn, handshake_resp: &[u8]) -> Vec<u8> {
        let mut dst = vec![0u8; 2048];
        let keepalive = tun.decapsulate(None, handshake_resp, &mut dst);
        assert!(matches!(keepalive, TunnResult::WriteToNetwork(_)));

        let TunnResult::WriteToNetwork(sent) = keepalive else {
            unreachable!();
        };
        let keepalive = sent;

        keepalive.into()
    }

    fn parse_keepalive(tun: &mut Tunn, keepalive: &[u8]) {
        let mut dst = vec![0u8; 2048];
        let keepalive = tun.decapsulate(None, keepalive, &mut dst);
        assert!(matches!(keepalive, TunnResult::Done));
    }

    fn create_two_tuns_and_handshake() -> (Tunn, Tunn) {
        let (mut my_tun, mut their_tun) = create_two_tuns();
        let init = create_handshake_init(&mut my_tun);
        let resp = create_handshake_response(&mut their_tun, &init);
        let keepalive = parse_handshake_resp(&mut my_tun, &resp);
        parse_keepalive(&mut their_tun, &keepalive);

        (my_tun, their_tun)
    }

    fn create_ipv4_udp_packet() -> Vec<u8> {
        let header =
            etherparse::PacketBuilder::ipv4([192, 168, 1, 2], [192, 168, 1, 3], 5).udp(5678, 23);
        let payload = [0, 1, 2, 3];
        let mut packet = Vec::<u8>::with_capacity(header.size(payload.len()));
        header.write(&mut packet, &payload).unwrap();
        packet
    }

    #[cfg(feature = "mock-instant")]
    fn update_timer_results_in_handshake(tun: &mut Tunn) {
        let mut dst = vec![0u8; 2048];
        let result = tun.update_timers(&mut dst);
        assert!(matches!(result, TunnResult::WriteToNetwork(_)));
        let TunnResult::WriteToNetwork(data) = result else {
            unreachable!();
        };
        let packet_data = data;
        let packet = Tunn::parse_incoming_packet(packet_data).unwrap();
        assert!(matches!(packet, Packet::HandshakeInit(_)));
    }

    #[test]
    fn create_two_tunnels_linked_to_eachother() {
        let (_my_tun, _their_tun) = create_two_tuns();
    }

    #[test]
    fn handshake_init() {
        let (mut my_tun, _their_tun) = create_two_tuns();
        let init = create_handshake_init(&mut my_tun);
        let packet = Tunn::parse_incoming_packet(&init).unwrap();
        assert!(matches!(packet, Packet::HandshakeInit(_)));
    }

    #[test]
    fn handshake_init_and_response() {
        let (mut my_tun, mut their_tun) = create_two_tuns();
        let init = create_handshake_init(&mut my_tun);
        let resp = create_handshake_response(&mut their_tun, &init);
        let packet = Tunn::parse_incoming_packet(&resp).unwrap();
        assert!(matches!(packet, Packet::HandshakeResponse(_)));
    }

    #[test]
    fn full_handshake() {
        let (mut my_tun, mut their_tun) = create_two_tuns();
        let init = create_handshake_init(&mut my_tun);
        let resp = create_handshake_response(&mut their_tun, &init);
        let keepalive = parse_handshake_resp(&mut my_tun, &resp);
        let packet = Tunn::parse_incoming_packet(&keepalive).unwrap();
        assert!(matches!(packet, Packet::PacketData(_)));
    }

    #[test]
    fn full_handshake_plus_timers() {
        let (mut my_tun, mut their_tun) = create_two_tuns_and_handshake();
        // Time has not yet advanced so their is nothing to do
        assert!(matches!(my_tun.update_timers(&mut []), TunnResult::Done));
        assert!(matches!(their_tun.update_timers(&mut []), TunnResult::Done));
    }

    #[test]
    #[cfg(feature = "mock-instant")]
    fn new_handshake_after_two_mins() {
        let (mut my_tun, mut their_tun) = create_two_tuns_and_handshake();
        let mut my_dst = [0u8; 1024];

        // Advance time 1 second and "send" 1 packet so that we send a handshake
        // after the timeout
        mock_instant::MockClock::advance(Duration::from_secs(1));
        assert!(matches!(their_tun.update_timers(&mut []), TunnResult::Done));
        assert!(matches!(
            my_tun.update_timers(&mut my_dst),
            TunnResult::Done
        ));
        let sent_packet_buf = create_ipv4_udp_packet();
        let data = my_tun.encapsulate(&sent_packet_buf, &mut my_dst);
        assert!(matches!(data, TunnResult::WriteToNetwork(_)));

        //Advance to timeout
        mock_instant::MockClock::advance(REKEY_AFTER_TIME);
        assert!(matches!(their_tun.update_timers(&mut []), TunnResult::Done));
        update_timer_results_in_handshake(&mut my_tun);
    }

    #[test]
    #[cfg(feature = "mock-instant")]
    fn handshake_no_resp_rekey_timeout() {
        let (mut my_tun, _their_tun) = create_two_tuns();

        let init = create_handshake_init(&mut my_tun);
        let packet = Tunn::parse_incoming_packet(&init).unwrap();
        assert!(matches!(packet, Packet::HandshakeInit(_)));

        // Retries wait REKEY_TIMEOUT plus up to 333 ms of jitter.
        mock_instant::MockClock::advance(REKEY_TIMEOUT + Duration::from_millis(334));
        update_timer_results_in_handshake(&mut my_tun);
    }

    #[test]
    fn one_ip_packet() {
        let (mut my_tun, mut their_tun) = create_two_tuns_and_handshake();
        let mut my_dst = [0u8; 1024];
        let mut their_dst = [0u8; 1024];

        let sent_packet_buf = create_ipv4_udp_packet();

        let data = my_tun.encapsulate(&sent_packet_buf, &mut my_dst);
        assert!(matches!(data, TunnResult::WriteToNetwork(_)));
        let TunnResult::WriteToNetwork(sent) = data else {
            unreachable!();
        };
        let data = sent;

        let data = their_tun.decapsulate(None, data, &mut their_dst);
        assert!(matches!(data, TunnResult::WriteToTunnelV4(..)));
        let TunnResult::WriteToTunnelV4(recv, _addr) = data else {
            unreachable!();
        };
        let recv_packet_buf = recv;
        assert_eq!(sent_packet_buf, recv_packet_buf);
    }

    fn current_session(tun: &Tunn) -> &session::Session {
        tun.sessions[tun.current % N_SESSIONS]
            .as_ref()
            .expect("an established session")
    }

    fn is_handshake_init(result: &TunnResult<'_>) -> bool {
        matches!(
            result,
            TunnResult::WriteToNetwork(p)
                if matches!(Tunn::parse_incoming_packet(p), Ok(Packet::HandshakeInit(_)))
        )
    }

    #[test]
    fn rekey_after_messages_starts_a_handshake() {
        // Both the initiator and the responder rekey once their sending key is worn out.
        let (mut my_tun, mut their_tun) = create_two_tuns_and_handshake();
        let mut dst = vec![0u8; 2048];
        for tun in [&mut my_tun, &mut their_tun] {
            current_session(tun).set_sending_counter(session::REKEY_AFTER_MESSAGES);
            assert!(is_handshake_init(&tun.update_timers(&mut dst)));
        }
    }

    #[test]
    fn exhausted_session_queues_the_packet_and_handshakes() {
        let (mut my_tun, _their_tun) = create_two_tuns_and_handshake();
        current_session(&my_tun).set_sending_counter(session::REJECT_AFTER_MESSAGES);
        let mut dst = vec![0u8; 2048];
        let packet = create_ipv4_udp_packet();
        assert!(is_handshake_init(&my_tun.encapsulate(&packet, &mut dst)));
        assert_eq!(my_tun.packet_queue.len(), 1);
    }

    fn create_ipv4_udp_packet_with_payload(payload: &[u8]) -> Vec<u8> {
        let header =
            etherparse::PacketBuilder::ipv4([192, 168, 1, 2], [192, 168, 1, 3], 5).udp(5678, 23);
        let mut packet = Vec::<u8>::with_capacity(header.size(payload.len()));
        header.write(&mut packet, payload).unwrap();
        packet
    }

    #[test]
    fn data_packets_are_padded_to_a_multiple_of_16() {
        let (mut my_tun, mut their_tun) = create_two_tuns_and_handshake();
        let sent = create_ipv4_udp_packet_with_payload(&[7]);
        assert_eq!(sent.len(), 29);

        let mut dst = vec![0u8; 2048];
        let TunnResult::WriteToNetwork(encrypted) = my_tun.encapsulate(&sent, &mut dst) else {
            unreachable!();
        };
        // header (16) + plaintext padded to 32 + tag (16)
        assert_eq!(encrypted.len(), 16 + 32 + 16);

        let encrypted = encrypted.to_vec();
        let mut their_dst = vec![0u8; 2048];
        let TunnResult::WriteToTunnelV4(received, _) =
            their_tun.decapsulate(None, &encrypted, &mut their_dst)
        else {
            unreachable!();
        };
        // The receiver strips the padding using the IP length field.
        assert_eq!(received, &sent[..]);
    }

    /// Runs a full handshake, initiated by `initiator`; returns whether it completed.
    fn rehandshake(initiator: &mut Tunn, responder: &mut Tunn) -> bool {
        // The responder rejects initiations whose timestamp does not advance.
        #[cfg(feature = "mock-instant")]
        mock_instant::MockClock::advance(Duration::from_millis(1));
        let mut dst = vec![0u8; 2048];
        let TunnResult::WriteToNetwork(init) =
            initiator.format_handshake_initiation(&mut dst, true)
        else {
            return false;
        };
        let init = init.to_vec();
        let TunnResult::WriteToNetwork(resp) = responder.decapsulate(None, &init, &mut dst) else {
            return false;
        };
        let resp = resp.to_vec();
        matches!(
            initiator.decapsulate(None, &resp, &mut dst),
            TunnResult::WriteToNetwork(_)
        )
    }

    #[test]
    fn preshared_key_change_applies_to_the_next_handshake() {
        let (mut my_tun, mut their_tun) = create_two_tuns_and_handshake();

        // Only one side knows the new key: the handshake cannot complete.
        my_tun.set_preshared_key(Some([7; 32]));
        assert!(!rehandshake(&mut my_tun, &mut their_tun));

        their_tun.set_preshared_key(Some([7; 32]));
        assert!(rehandshake(&mut my_tun, &mut their_tun));
    }

    #[test]
    fn preshared_key_change_keeps_the_live_session() {
        let (mut my_tun, mut their_tun) = create_two_tuns_and_handshake();
        my_tun.set_preshared_key(Some([7; 32]));

        let packet = create_ipv4_udp_packet();
        let mut dst = vec![0u8; 2048];
        let TunnResult::WriteToNetwork(data) = my_tun.encapsulate(&packet, &mut dst) else {
            unreachable!();
        };
        let data = data.to_vec();
        let mut their_dst = vec![0u8; 2048];
        assert!(matches!(
            their_tun.decapsulate(None, &data, &mut their_dst),
            TunnResult::WriteToTunnelV4(..)
        ));
    }

    #[test]
    fn persistent_keepalive_can_be_changed() {
        let (mut my_tun, _their_tun) = create_two_tuns();
        assert_eq!(my_tun.persistent_keepalive(), None);
        my_tun.set_persistent_keepalive(Some(25));
        assert_eq!(my_tun.persistent_keepalive(), Some(25));
        my_tun.set_persistent_keepalive(None);
        assert_eq!(my_tun.persistent_keepalive(), None);
    }

    /// Advances the clock and runs the timers, as the device does every 250 ms; nothing may be
    /// due.
    #[cfg(feature = "mock-instant")]
    fn advance(d: Duration, tuns: &mut [&mut Tunn]) {
        mock_instant::MockClock::advance(d);
        let mut dst = vec![0u8; 2048];
        for tun in tuns {
            assert!(matches!(tun.update_timers(&mut dst), TunnResult::Done));
        }
    }

    /// Sends one data packet from `from` to `to`.
    #[cfg(feature = "mock-instant")]
    fn send_data(from: &mut Tunn, to: &mut Tunn) {
        let packet = create_ipv4_udp_packet();
        let mut dst = vec![0u8; 2048];
        let TunnResult::WriteToNetwork(data) = from.encapsulate(&packet, &mut dst) else {
            panic!("expected a data packet");
        };
        let data = data.to_vec();
        assert!(matches!(
            to.decapsulate(None, &data, &mut dst),
            TunnResult::WriteToTunnelV4(..)
        ));
    }

    fn is_keepalive(result: &TunnResult<'_>) -> bool {
        matches!(result, TunnResult::WriteToNetwork(p) if p.len() == 32)
    }

    #[test]
    #[cfg(feature = "mock-instant")]
    fn passive_keepalive_is_timed_from_the_received_data() {
        let (mut my_tun, mut their_tun) = create_two_tuns_and_handshake();
        let mut dst = vec![0u8; 2048];

        // A long idle period, then the peer sends data.
        advance(Duration::from_secs(60), &mut [&mut my_tun, &mut their_tun]);
        send_data(&mut their_tun, &mut my_tun);

        // The keepalive is due KEEPALIVE_TIMEOUT after the data, not right away.
        advance(Duration::from_secs(9), &mut [&mut my_tun]);
        mock_instant::MockClock::advance(Duration::from_secs(1));
        assert!(is_keepalive(&my_tun.update_timers(&mut dst)));
    }

    #[test]
    #[cfg(feature = "mock-instant")]
    fn handshake_after_unanswered_data_is_timed_from_the_sent_data() {
        let (mut my_tun, mut their_tun) = create_two_tuns_and_handshake();
        let mut dst = vec![0u8; 2048];

        // A long idle period, then we send data the peer does not answer.
        advance(Duration::from_secs(60), &mut [&mut my_tun, &mut their_tun]);
        let packet = create_ipv4_udp_packet();
        assert!(matches!(
            my_tun.encapsulate(&packet, &mut dst),
            TunnResult::WriteToNetwork(_)
        ));

        // The handshake is due KEEPALIVE_TIMEOUT + REKEY_TIMEOUT after the data.
        advance(Duration::from_secs(14), &mut [&mut my_tun]);
        mock_instant::MockClock::advance(Duration::from_secs(1));
        assert!(is_handshake_init(&my_tun.update_timers(&mut dst)));
    }

    #[test]
    fn persistent_keepalive_is_sent_when_enabled() {
        let (mut my_tun, _their_tun) = create_two_tuns_and_handshake();
        let mut dst = vec![0u8; 2048];
        my_tun.set_persistent_keepalive(Some(25));
        assert!(is_keepalive(&my_tun.update_timers(&mut dst)));
        assert!(matches!(my_tun.update_timers(&mut dst), TunnResult::Done));
    }

    #[test]
    #[cfg(feature = "mock-instant")]
    fn persistent_keepalive_is_not_sent_while_traffic_flows() {
        let (mut my_tun, mut their_tun) = create_two_tuns_and_handshake();
        let mut dst = vec![0u8; 2048];
        my_tun.set_persistent_keepalive(Some(25));
        assert!(is_keepalive(&my_tun.update_timers(&mut dst)));

        // Data out, keepalive back, every 10 s: the 25 s interval never elapses.
        for _ in 0..4 {
            advance(Duration::from_secs(10), &mut [&mut my_tun]);
            send_data(&mut my_tun, &mut their_tun);
            let TunnResult::WriteToNetwork(keepalive) = their_tun.encapsulate(&[], &mut dst) else {
                panic!("expected a keepalive");
            };
            let keepalive = keepalive.to_vec();
            assert!(matches!(
                my_tun.decapsulate(None, &keepalive, &mut dst),
                TunnResult::Done
            ));
        }

        // Once the tunnel is idle for the interval, the keepalive is sent.
        advance(Duration::from_secs(24), &mut [&mut my_tun]);
        mock_instant::MockClock::advance(Duration::from_secs(1));
        assert!(is_keepalive(&my_tun.update_timers(&mut dst)));
    }

    #[test]
    fn handshake_retry_jitter_is_at_most_333ms() {
        for _ in 0..1000 {
            assert!(timers::handshake_jitter() <= Duration::from_millis(333));
        }
    }
}
