// Copyright (c) 2019 Cloudflare, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

#[derive(Debug)]
/// Errors of the WireGuard protocol state machine.
pub enum WireGuardError {
    /// The output buffer is too small.
    DestinationBufferTooSmall,
    /// A message has the wrong length.
    IncorrectPacketLength,
    /// A message arrived in a state that does not expect it.
    UnexpectedPacket,
    /// Unknown message type.
    WrongPacketType,
    /// The receiver index does not match.
    WrongIndex,
    /// The handshake was made with an unexpected static key.
    WrongKey,
    /// The handshake timestamp cannot be parsed.
    InvalidTai64nTimestamp,
    /// The handshake timestamp is not newer than the last one (replay).
    WrongTai64nTimestamp,
    /// mac1 or mac2 is invalid.
    InvalidMac,
    /// Decryption failed.
    InvalidAeadTag,
    /// The packet counter is outside the replay window.
    InvalidCounter,
    /// The packet counter was already received (replay).
    DuplicateCounter,
    /// The message is malformed.
    InvalidPacket,
    /// No session is established for this index.
    NoCurrentSession,
    /// A lock could not be taken.
    LockFailed,
    /// The connection expired and needs a new handshake.
    ConnectionExpired,
    /// The responder is under load and requires a cookie.
    UnderLoad,
}
