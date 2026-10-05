// Copyright (c) 2019 Cloudflare, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

use super::handshake::chacha20_poly1305_key;
use super::wire::{DATA, DataHeader};
use crate::noise::errors::WireGuardError;
use aws_lc_rs::aead::{Aad, LessSafeKey, Nonce};
use parking_lot::Mutex;
use portable_atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use zerocopy::FromBytes;

pub(super) struct Session {
    pub(crate) receiving_index: u32,
    sending_index: u32,
    receiver: LessSafeKey,
    sender: LessSafeKey,
    /// The same keys for [`SealTicket`]s and [`OpenTicket`]s, which seal and open off the
    /// tunnel; its identity also tells whether a ticket still belongs to this session.
    shared: Arc<SharedKeys>,
    sending_key_counter: AtomicU64,
    receiving_key_counter: Mutex<ReceivingKeyCounterValidator>,
}

/// The keys of a session, shared with its tickets.
struct SharedKeys {
    receiver: LessSafeKey,
    sender: LessSafeKey,
}

/// One transport data message reserved in a session.
///
/// It holds the session's sending key, the counter (nonce) reserved for the message and its
/// layout. Sealing it needs no access to
/// the tunnel, so it can run on any thread; a reserved counter is never handed out again,
/// whether the ticket is sealed or not.
pub struct SealTicket {
    keys: Arc<SharedKeys>,
    /// Slot of the session in the tunnel's ring.
    slot: usize,
    receiver_index: u32,
    counter: u64,
    len: usize,
    padded_len: usize,
}

impl std::fmt::Debug for SealTicket {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SealTicket")
            .field("receiver_index", &self.receiver_index)
            .field("counter", &self.counter)
            .field("len", &self.len)
            .finish_non_exhaustive()
    }
}

impl SealTicket {
    /// Seals the plaintext in `buf[DATA_HEADER_SZ..DATA_HEADER_SZ + len]` in place with the
    /// reserved counter and writes the data header in front of it; returns the datagram, a
    /// prefix of `buf`. `buf` must be the buffer the ticket was reserved for.
    pub fn seal<'a>(&self, buf: &'a mut [u8]) -> Result<&'a mut [u8], WireGuardError> {
        if buf.len() < DATA_OFFSET + self.padded_len + AEAD_SIZE {
            return Err(WireGuardError::DestinationBufferTooSmall);
        }
        seal(
            &self.keys.sender,
            self.receiver_index,
            self.counter,
            buf,
            self.len,
            self.padded_len,
        )
    }

    /// The counter (nonce) reserved for the message.
    pub const fn counter(&self) -> u64 {
        self.counter
    }

    /// Whether this ticket was reserved in `session`.
    pub(super) fn of(&self, session: &Session) -> bool {
        Arc::ptr_eq(&self.keys, &session.shared)
    }

    /// Slot of the ticket's session in the tunnel's ring.
    pub(super) const fn slot(&self) -> usize {
        self.slot
    }
}

/// One received transport data message that passed a session's replay check.
///
/// It holds the session's receiving key and the message's counter. Opening it needs no
/// access to the tunnel, so it can run on any thread; the counter is only marked as received
/// when the tunnel commits the opened message ([`super::Tunn::commit_open`]).
pub struct OpenTicket {
    keys: Arc<SharedKeys>,
    receiver_index: u32,
    counter: u64,
}

impl std::fmt::Debug for OpenTicket {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OpenTicket")
            .field("receiver_index", &self.receiver_index)
            .field("counter", &self.counter)
            .finish_non_exhaustive()
    }
}

impl OpenTicket {
    /// Opens the transport data message in `datagram` in place: the plaintext replaces the
    /// encrypted packet behind the data header. Returns the length of the plaintext (with
    /// its padding), which starts at `DATA_HEADER_SZ`.
    pub fn open(&self, datagram: &mut [u8]) -> Result<usize, WireGuardError> {
        let ciphertext = datagram
            .get_mut(DATA_OFFSET..)
            .ok_or(WireGuardError::InvalidPacket)?;
        open(&self.keys.receiver, self.counter, ciphertext).map(|plaintext| plaintext.len())
    }

    /// The message's counter.
    pub const fn counter(&self) -> u64 {
        self.counter
    }

    /// The index of the receiving session.
    pub(super) const fn receiver_index(&self) -> u32 {
        self.receiver_index
    }

    /// Whether this ticket was handed out by `session`.
    pub(super) fn of(&self, session: &Session) -> bool {
        Arc::ptr_eq(&self.keys, &session.shared)
    }
}

impl std::fmt::Debug for Session {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "Session: {}<- ->{}",
            self.receiving_index, self.sending_index
        )
    }
}

/// Once a key has encrypted this many messages, a new handshake is started
/// (`Rekey-After-Messages`, 2^60).
pub(super) const REKEY_AFTER_MESSAGES: u64 = 1 << 60;
/// A key never encrypts or accepts this many messages, so its nonce cannot repeat
/// (`Reject-After-Messages`, 2^64 - 2^13 - 1).
pub(super) const REJECT_AFTER_MESSAGES: u64 = u64::MAX - (1 << 13);

/// The AEAD nonce for a message counter: 32 zero bits, then the little-endian counter.
fn nonce(counter: u64) -> Nonce {
    let mut nonce = [0u8; 12];
    nonce[4..].copy_from_slice(&counter.to_le_bytes());
    Nonce::assume_unique_for_key(nonce)
}

/// Length of a plaintext of `len` bytes after padding to a multiple of 16.
const fn padded_len(len: usize) -> usize {
    len.next_multiple_of(16)
}

/// The padded length of a plaintext of `len` bytes sealed in a buffer of `buf_len` bytes:
/// padded to a multiple of 16 as far as the buffer has room and not past `pad_limit`.
fn sealed_plaintext_len(
    buf_len: usize,
    len: usize,
    pad_limit: usize,
) -> Result<usize, WireGuardError> {
    let room = buf_len
        .checked_sub(DATA_OFFSET + AEAD_SIZE)
        .filter(|&room| room >= len)
        .ok_or(WireGuardError::DestinationBufferTooSmall)?;
    // The spec pads the plaintext with zeros to a multiple of 16 bytes.
    Ok(padded_len(len).min(room).min(pad_limit.max(len)))
}

/// Seals the plaintext in `buf[DATA_OFFSET..DATA_OFFSET + len]`, zero-padded to
/// `padded_len`, with `key` and `counter`, and writes the data header for `receiver_index`
/// in front of it; returns the datagram. `buf` has room for the padded plaintext and the tag.
#[inline]
fn seal<'a>(
    key: &LessSafeKey,
    receiver_index: u32,
    counter: u64,
    buf: &'a mut [u8],
    len: usize,
    padded_len: usize,
) -> Result<&'a mut [u8], WireGuardError> {
    let (header, payload) = DataHeader::mut_from_prefix(&mut *buf)
        .map_err(|_| WireGuardError::DestinationBufferTooSmall)?;
    header.message_type = DATA.into();
    header.receiver_index = receiver_index.into();
    header.counter = counter.into();

    payload[len..padded_len].fill(0);
    let tag = key
        .seal_in_place_separate_tag(nonce(counter), Aad::empty(), &mut payload[..padded_len])
        .map_err(|_| WireGuardError::DestinationBufferTooSmall)?;
    payload[padded_len..padded_len + AEAD_SIZE].copy_from_slice(tag.as_ref());

    Ok(&mut buf[..DATA_OFFSET + padded_len + AEAD_SIZE])
}

/// Opens the encrypted packet and tag in `ciphertext` in place with `key` and `counter`;
/// returns the plaintext, a prefix of `ciphertext`.
#[inline]
fn open<'a>(
    key: &LessSafeKey,
    counter: u64,
    ciphertext: &'a mut [u8],
) -> Result<&'a mut [u8], WireGuardError> {
    key.open_in_place(nonce(counter), Aad::empty(), ciphertext)
        .map_err(|_| WireGuardError::InvalidAeadTag)
}

/// Where encrypted data resides in a data packet
const DATA_OFFSET: usize = 16;
/// The overhead of the AEAD
const AEAD_SIZE: usize = 16;

// Receiving buffer constants
const WORD_SIZE: u64 = 64;
const N_WORDS: usize = 128; // Reorder up to 64*128 = 8192 packets, like Linux and wireguard-go
const N_BITS: u64 = WORD_SIZE * N_WORDS as u64;

#[derive(Debug, Clone)]
struct ReceivingKeyCounterValidator {
    /// In order to avoid replays while allowing for some reordering of the packets, we keep a
    /// bitmap of received packets, and the value of the highest counter
    next: u64,
    /// Used to estimate packet loss
    receive_cnt: u64,
    bitmap: [u64; N_WORDS],
}

impl Default for ReceivingKeyCounterValidator {
    fn default() -> Self {
        Self {
            next: 0,
            receive_cnt: 0,
            bitmap: [0; N_WORDS],
        }
    }
}

impl ReceivingKeyCounterValidator {
    #[inline]
    const fn set_bit(&mut self, idx: u64) {
        let bit_idx = idx % N_BITS;
        let word = (bit_idx / WORD_SIZE) as usize;
        let bit = (bit_idx % WORD_SIZE) as usize;
        self.bitmap[word] |= 1 << bit;
    }

    #[inline]
    const fn clear_bit(&mut self, idx: u64) {
        let bit_idx = idx % N_BITS;
        let word = (bit_idx / WORD_SIZE) as usize;
        let bit = (bit_idx % WORD_SIZE) as usize;
        self.bitmap[word] &= !(1u64 << bit);
    }

    /// Clear the word that contains idx
    #[inline]
    const fn clear_word(&mut self, idx: u64) {
        let bit_idx = idx % N_BITS;
        let word = (bit_idx / WORD_SIZE) as usize;
        self.bitmap[word] = 0;
    }

    /// Returns true if bit is set, false otherwise
    #[inline]
    const fn check_bit(&self, idx: u64) -> bool {
        let bit_idx = idx % N_BITS;
        let word = (bit_idx / WORD_SIZE) as usize;
        let bit = (bit_idx % WORD_SIZE) as usize;
        ((self.bitmap[word] >> bit) & 1) == 1
    }

    /// Returns true if the counter was not yet received, and is not too far back
    #[inline]
    const fn will_accept(&self, counter: u64) -> Result<(), WireGuardError> {
        if counter >= REJECT_AFTER_MESSAGES {
            return Err(WireGuardError::InvalidCounter);
        }
        if counter >= self.next {
            // As long as the counter is growing no replay took place for sure
            return Ok(());
        }
        if counter + N_BITS < self.next {
            // Drop if too far back
            return Err(WireGuardError::InvalidCounter);
        }
        if self.check_bit(counter) {
            Err(WireGuardError::DuplicateCounter)
        } else {
            Ok(())
        }
    }

    /// Marks the counter as received, and returns true if it is still good (in case during
    /// decryption something changed)
    #[inline]
    fn mark_did_receive(&mut self, counter: u64) -> Result<(), WireGuardError> {
        if counter >= REJECT_AFTER_MESSAGES || counter + N_BITS < self.next {
            // Drop if too far back
            return Err(WireGuardError::InvalidCounter);
        }
        if counter == self.next {
            // Usually the packets arrive in order, in that case we simply mark the bit and
            // increment the counter
            self.set_bit(counter);
            self.next += 1;
            return Ok(());
        }
        if counter < self.next {
            // A packet arrived out of order, check if it is valid, and mark
            if self.check_bit(counter) {
                return Err(WireGuardError::InvalidCounter);
            }
            self.set_bit(counter);
            return Ok(());
        }
        // Packets where dropped, or maybe reordered, skip them and mark unused
        if counter - self.next >= N_BITS {
            // Too far ahead, clear all the bits
            self.bitmap.fill(0);
        } else {
            let mut i = self.next;
            while !i.is_multiple_of(WORD_SIZE) && i < counter {
                // Clear until i aligned to word size
                self.clear_bit(i);
                i += 1;
            }
            while i + WORD_SIZE < counter {
                // Clear whole word at a time
                self.clear_word(i);
                i = (i + WORD_SIZE) & 0u64.wrapping_sub(WORD_SIZE);
            }
            while i < counter {
                // Clear any remaining bits
                self.clear_bit(i);
                i += 1;
            }
        }
        self.set_bit(counter);
        self.next = counter + 1;
        Ok(())
    }
}

impl Session {
    pub(super) fn new(
        local_index: u32,
        peer_index: u32,
        receiving_key: [u8; 32],
        sending_key: [u8; 32],
    ) -> Self {
        Self {
            receiving_index: local_index,
            sending_index: peer_index,
            receiver: chacha20_poly1305_key(&receiving_key),
            sender: chacha20_poly1305_key(&sending_key),
            shared: Arc::new(SharedKeys {
                receiver: chacha20_poly1305_key(&receiving_key),
                sender: chacha20_poly1305_key(&sending_key),
            }),
            sending_key_counter: AtomicU64::new(0),
            receiving_key_counter: Mutex::new(ReceivingKeyCounterValidator::default()),
        }
    }

    /// The index the peer assigned to this session, carried as the receiver index of every
    /// transport data message sent in it.
    pub(super) const fn remote_index(&self) -> u32 {
        self.sending_index
    }

    pub(super) const fn local_index(&self) -> usize {
        self.receiving_index as usize
    }

    /// Returns true if receiving counter is good to use
    fn receiving_counter_quick_check(&self, counter: u64) -> Result<(), WireGuardError> {
        let counter_validator = self.receiving_key_counter.lock();
        counter_validator.will_accept(counter)
    }

    /// Returns true if receiving counter is good to use, and marks it as used {
    fn receiving_counter_mark(&self, counter: u64) -> Result<(), WireGuardError> {
        let mut counter_validator = self.receiving_key_counter.lock();
        let ret = counter_validator.mark_did_receive(counter);
        if ret.is_ok() {
            counter_validator.receive_cnt += 1;
        }
        ret
    }

    /// Seals the plaintext in `buf[DATA_OFFSET..DATA_OFFSET + len]` in place and writes the
    /// data header in front of it; returns the datagram, a prefix of `buf`.
    ///
    /// The plaintext is zero-padded to a multiple of 16 bytes as far as `buf` has room behind
    /// it and, like the kernel's padding to the MTU, not past `pad_limit` bytes (a plaintext
    /// of at least `pad_limit` bytes is not padded); `buf` needs at least
    /// `DATA_OFFSET + len + AEAD_SIZE` bytes.
    pub(super) fn seal_in_place<'a>(
        &self,
        buf: &'a mut [u8],
        len: usize,
        pad_limit: usize,
    ) -> Result<&'a mut [u8], WireGuardError> {
        let padded_len = sealed_plaintext_len(buf.len(), len, pad_limit)?;
        let counter = self.reserve_counter()?;
        seal(
            &self.sender,
            self.sending_index,
            counter,
            buf,
            len,
            padded_len,
        )
    }

    /// Reserves the next counter for a message like [`Session::seal_in_place`] would seal it
    /// in a buffer of `buf_len` bytes, to be sealed with the returned ticket; the session is
    /// at `slot` in the tunnel's ring.
    pub(super) fn reserve(
        &self,
        slot: usize,
        buf_len: usize,
        len: usize,
        pad_limit: usize,
    ) -> Result<SealTicket, WireGuardError> {
        let padded_len = sealed_plaintext_len(buf_len, len, pad_limit)?;
        let counter = self.reserve_counter()?;
        Ok(SealTicket {
            keys: Arc::clone(&self.shared),
            slot,
            receiver_index: self.sending_index,
            counter,
            len,
            padded_len,
        })
    }

    /// Hands out the next sending counter. Never one at or past Reject-After-Messages: the
    /// nonce must not repeat.
    #[inline]
    fn reserve_counter(&self) -> Result<u64, WireGuardError> {
        self.sending_key_counter
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |c| {
                (c < REJECT_AFTER_MESSAGES).then_some(c + 1)
            })
            .map_err(|_| WireGuardError::ConnectionExpired)
    }

    /// src - an IP packet from the interface
    /// dst - pre-allocated space to hold the encapsulating UDP packet to send over the network
    /// returns the formatted packet
    pub(super) fn format_packet_data<'a>(
        &self,
        src: &[u8],
        dst: &'a mut [u8],
    ) -> Result<&'a mut [u8], WireGuardError> {
        if dst.len() < src.len() + super::DATA_OVERHEAD_SZ {
            return Err(WireGuardError::DestinationBufferTooSmall);
        }
        dst[DATA_OFFSET..DATA_OFFSET + src.len()].copy_from_slice(src);
        self.seal_in_place(dst, src.len(), usize::MAX)
    }

    /// Opens the encrypted packet and tag in `ciphertext` in place; returns the plaintext, a
    /// prefix of `ciphertext`.
    pub(super) fn open_in_place<'a>(
        &self,
        receiver_idx: u32,
        counter: u64,
        ciphertext: &'a mut [u8],
    ) -> Result<&'a mut [u8], WireGuardError> {
        if receiver_idx != self.receiving_index {
            return Err(WireGuardError::WrongIndex);
        }
        // Don't reuse counters, in case this is a replay attack we want to quickly check the counter without running expensive decryption
        self.receiving_counter_quick_check(counter)?;

        let plaintext = open(&self.receiver, counter, ciphertext)?;

        // After decryption is done, check counter again, and mark as received
        self.receiving_counter_mark(counter)?;
        Ok(plaintext)
    }

    /// Checks a received message like [`Session::open_in_place`] before decrypting it, and
    /// returns a ticket to open it with; the counter is marked as received by
    /// [`Session::commit`] once the message is opened.
    pub(super) fn open_ticket(
        &self,
        receiver_idx: u32,
        counter: u64,
    ) -> Result<OpenTicket, WireGuardError> {
        if receiver_idx != self.receiving_index {
            return Err(WireGuardError::WrongIndex);
        }
        self.receiving_counter_quick_check(counter)?;
        Ok(OpenTicket {
            keys: Arc::clone(&self.shared),
            receiver_index: receiver_idx,
            counter,
        })
    }

    /// Marks the counter of a message opened with a ticket as received; fails for a replay.
    pub(super) fn commit(&self, counter: u64) -> Result<(), WireGuardError> {
        self.receiving_counter_mark(counter)
    }

    /// Whether the sending key reached Reject-After-Messages and must not be used again.
    pub(super) fn is_exhausted(&self) -> bool {
        self.sending_counter() >= REJECT_AFTER_MESSAGES
    }

    /// Number of messages encrypted with the sending key so far.
    pub(super) fn sending_counter(&self) -> u64 {
        self.sending_key_counter.load(Ordering::Relaxed)
    }

    #[cfg(test)]
    pub(super) fn set_sending_counter(&self, counter: u64) {
        self.sending_key_counter.store(counter, Ordering::Relaxed);
    }

    /// Returns the estimated downstream packet loss for this session
    pub(super) fn current_packet_cnt(&self) -> (u64, u64) {
        let counter_validator = self.receiving_key_counter.lock();
        (counter_validator.next, counter_validator.receive_cnt)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_replay_counter() {
        let mut c = ReceivingKeyCounterValidator::default();

        assert!(c.mark_did_receive(0).is_ok());
        assert!(c.mark_did_receive(0).is_err());
        assert!(c.mark_did_receive(1).is_ok());
        assert!(c.mark_did_receive(1).is_err());
        assert!(c.mark_did_receive(63).is_ok());
        assert!(c.mark_did_receive(63).is_err());
        assert!(c.mark_did_receive(15).is_ok());
        assert!(c.mark_did_receive(15).is_err());

        for i in 64..N_BITS + 128 {
            assert!(c.mark_did_receive(i).is_ok());
            assert!(c.mark_did_receive(i).is_err());
        }

        assert!(c.mark_did_receive(N_BITS * 3).is_ok());
        for i in 0..=N_BITS * 2 {
            assert!(matches!(
                c.will_accept(i),
                Err(WireGuardError::InvalidCounter)
            ));
            assert!(c.mark_did_receive(i).is_err());
        }
        for i in N_BITS * 2 + 1..N_BITS * 3 {
            assert!(c.will_accept(i).is_ok());
        }
        assert!(matches!(
            c.will_accept(N_BITS * 3),
            Err(WireGuardError::DuplicateCounter)
        ));

        for i in (N_BITS * 2 + 1..N_BITS * 3).rev() {
            assert!(c.mark_did_receive(i).is_ok());
            assert!(c.mark_did_receive(i).is_err());
        }

        assert!(c.mark_did_receive(N_BITS * 3 + 70).is_ok());
        assert!(c.mark_did_receive(N_BITS * 3 + 71).is_ok());
        assert!(c.mark_did_receive(N_BITS * 3 + 72).is_ok());
        assert!(c.mark_did_receive(N_BITS * 3 + 72 + 125).is_ok());
        assert!(c.mark_did_receive(N_BITS * 3 + 63).is_ok());

        assert!(c.mark_did_receive(N_BITS * 3 + 70).is_err());
        assert!(c.mark_did_receive(N_BITS * 3 + 71).is_err());
        assert!(c.mark_did_receive(N_BITS * 3 + 72).is_err());
    }

    #[test]
    fn refuses_to_send_at_reject_after_messages() {
        let session = Session::new(1, 2, [1; 32], [2; 32]);
        session
            .sending_key_counter
            .store(REJECT_AFTER_MESSAGES, Ordering::Relaxed);
        let mut dst = [0u8; 64];
        assert!(matches!(
            session.format_packet_data(&[], &mut dst),
            Err(WireGuardError::ConnectionExpired)
        ));
        // The counter must not move past the limit, so it can never wrap around.
        assert_eq!(
            session.sending_key_counter.load(Ordering::Relaxed),
            REJECT_AFTER_MESSAGES
        );
    }

    #[test]
    fn rejects_received_counters_at_reject_after_messages() {
        let mut c = ReceivingKeyCounterValidator::default();
        assert!(c.will_accept(REJECT_AFTER_MESSAGES).is_err());
        assert!(c.mark_did_receive(REJECT_AFTER_MESSAGES).is_err());
        assert!(c.will_accept(REJECT_AFTER_MESSAGES - 1).is_ok());
    }

    #[test]
    fn replay_window_tolerates_8192_reordered_packets() {
        let mut c = ReceivingKeyCounterValidator::default();
        assert!(c.mark_did_receive(8000).is_ok());
        assert!(c.mark_did_receive(5).is_ok());
        assert!(c.mark_did_receive(5).is_err());
    }

    #[test]
    fn tickets_seal_and_open_byte_for_byte_like_the_session() {
        let inline = Session::new(1, 2, [1; 32], [2; 32]);
        let split = Session::new(1, 2, [1; 32], [2; 32]);
        let peer = Session::new(2, 1, [2; 32], [1; 32]);
        for (len, pad_limit) in [(0, usize::MAX), (37, usize::MAX), (37, 40), (64, 50)] {
            let mut a = [0u8; 128];
            a[DATA_OFFSET..DATA_OFFSET + len].fill(0xab);
            let mut b = a;
            let sealed = inline.seal_in_place(&mut a, len, pad_limit).unwrap().len();
            let ticket = split.reserve(1, b.len(), len, pad_limit).unwrap();
            assert_eq!(ticket.seal(&mut b).unwrap().len(), sealed);
            assert_eq!(a[..sealed], b[..sealed]);

            let header = DataHeader::ref_from_prefix(&a[..]).unwrap().0;
            let counter = header.counter.get();
            let mut c = b;
            let plaintext = peer
                .open_in_place(2, counter, &mut a[DATA_OFFSET..sealed])
                .unwrap();
            let expected = plaintext.to_vec();
            let open = peer.open_ticket(2, counter).unwrap_err();
            assert!(matches!(open, WireGuardError::DuplicateCounter));
            let other = Session::new(2, 1, [2; 32], [1; 32]);
            let ticket = other.open_ticket(2, counter).unwrap();
            let plain_len = ticket.open(&mut c[..sealed]).unwrap();
            assert_eq!(c[DATA_OFFSET..DATA_OFFSET + plain_len], expected[..]);
            assert!(other.commit(counter).is_ok());
            assert!(other.commit(counter).is_err());
        }
    }

    #[test]
    fn a_ticket_never_takes_a_counter_past_reject_after_messages() {
        let session = Session::new(1, 2, [1; 32], [2; 32]);
        session.set_sending_counter(REJECT_AFTER_MESSAGES - 1);
        let ticket = session.reserve(0, 64, 0, usize::MAX).unwrap();
        assert_eq!(ticket.counter(), REJECT_AFTER_MESSAGES - 1);
        assert!(matches!(
            session.reserve(0, 64, 0, usize::MAX),
            Err(WireGuardError::ConnectionExpired)
        ));
        assert_eq!(session.sending_counter(), REJECT_AFTER_MESSAGES);
        // A buffer without room reserves nothing.
        assert!(matches!(
            session.reserve(0, 16, 0, usize::MAX),
            Err(WireGuardError::DestinationBufferTooSmall)
        ));
    }
}
