// Copyright (c) 2019 Cloudflare, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

use super::handshake::chacha20_poly1305_key;
use super::wire::{DATA, DataHeader};
use crate::noise::errors::WireGuardError;
use aws_lc_rs::aead::{Aad, LessSafeKey, Nonce};
use parking_lot::Mutex;
use portable_atomic::{AtomicU64, Ordering};
use zerocopy::FromBytes;

pub(super) struct Session {
    pub(crate) receiving_index: u32,
    sending_index: u32,
    receiver: LessSafeKey,
    sender: LessSafeKey,
    sending_key_counter: AtomicU64,
    receiving_key_counter: Mutex<ReceivingKeyCounterValidator>,
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
    /// it; `buf` needs at least `DATA_OFFSET + len + AEAD_SIZE` bytes.
    pub(super) fn seal_in_place<'a>(
        &self,
        buf: &'a mut [u8],
        len: usize,
    ) -> Result<&'a mut [u8], WireGuardError> {
        let room = buf
            .len()
            .checked_sub(DATA_OFFSET + AEAD_SIZE)
            .filter(|&room| room >= len)
            .ok_or(WireGuardError::DestinationBufferTooSmall)?;
        // The spec pads the plaintext with zeros to a multiple of 16 bytes.
        let padded_len = padded_len(len).min(room);

        // Never hand out a counter at or past Reject-After-Messages: the nonce must not repeat.
        let sending_key_counter = self
            .sending_key_counter
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |c| {
                (c < REJECT_AFTER_MESSAGES).then_some(c + 1)
            })
            .map_err(|_| WireGuardError::ConnectionExpired)?;

        let (header, payload) = DataHeader::mut_from_prefix(&mut *buf)
            .map_err(|_| WireGuardError::DestinationBufferTooSmall)?;
        header.message_type = DATA.into();
        header.receiver_index = self.sending_index.into();
        header.counter = sending_key_counter.into();

        payload[len..padded_len].fill(0);
        let tag = self
            .sender
            .seal_in_place_separate_tag(
                nonce(sending_key_counter),
                Aad::empty(),
                &mut payload[..padded_len],
            )
            .map_err(|_| WireGuardError::DestinationBufferTooSmall)?;
        payload[padded_len..padded_len + AEAD_SIZE].copy_from_slice(tag.as_ref());

        Ok(&mut buf[..DATA_OFFSET + padded_len + AEAD_SIZE])
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
        self.seal_in_place(dst, src.len())
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

        let plaintext = self
            .receiver
            .open_in_place(nonce(counter), Aad::empty(), ciphertext)
            .map_err(|_| WireGuardError::InvalidAeadTag)?;

        // After decryption is done, check counter again, and mark as received
        self.receiving_counter_mark(counter)?;
        Ok(plaintext)
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
}
