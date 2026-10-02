// SPDX-License-Identifier: BSD-3-Clause

//! Byte layouts of the four WireGuard messages.
//!
//! The structs are `#[repr(C)]` views over datagram bytes: parsing borrows the received
//! buffer and formatting writes through a view of the output buffer, so neither copies.

use zerocopy::byteorder::little_endian::{U32, U64};
use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout, Unaligned};

/// Message type of a handshake initiation (with the three reserved zero bytes).
pub(super) const HANDSHAKE_INIT: u32 = 1;
/// Message type of a handshake response.
pub(super) const HANDSHAKE_RESP: u32 = 2;
/// Message type of a cookie reply.
pub(super) const COOKIE_REPLY: u32 = 3;
/// Message type of transport data.
pub(super) const DATA: u32 = 4;

/// `msg.mac1 || msg.mac2` at the end of both handshake messages.
#[repr(C)]
#[derive(Debug, FromBytes, IntoBytes, KnownLayout, Immutable, Unaligned)]
pub(super) struct Macs {
    pub(super) mac1: [u8; 16],
    pub(super) mac2: [u8; 16],
}

/// Handshake initiation, 148 bytes.
#[repr(C)]
#[derive(Debug, FromBytes, IntoBytes, KnownLayout, Immutable, Unaligned)]
pub(super) struct HandshakeInitMsg {
    pub(super) message_type: U32,
    pub(super) sender_index: U32,
    pub(super) unencrypted_ephemeral: [u8; 32],
    pub(super) encrypted_static: [u8; 32 + 16],
    pub(super) encrypted_timestamp: [u8; 12 + 16],
    pub(super) macs: Macs,
}

/// Handshake response, 92 bytes.
#[repr(C)]
#[derive(Debug, FromBytes, IntoBytes, KnownLayout, Immutable, Unaligned)]
pub(super) struct HandshakeRespMsg {
    pub(super) message_type: U32,
    pub(super) sender_index: U32,
    pub(super) receiver_index: U32,
    pub(super) unencrypted_ephemeral: [u8; 32],
    pub(super) encrypted_nothing: [u8; 16],
    pub(super) macs: Macs,
}

/// Cookie reply, 64 bytes.
#[repr(C)]
#[derive(Debug, FromBytes, IntoBytes, KnownLayout, Immutable, Unaligned)]
pub(super) struct CookieReplyMsg {
    pub(super) message_type: U32,
    pub(super) receiver_index: U32,
    pub(super) nonce: [u8; 24],
    pub(super) encrypted_cookie: [u8; 16 + 16],
}

/// Header of a transport data message, followed by the encrypted packet and its tag.
#[repr(C)]
#[derive(Debug, FromBytes, IntoBytes, KnownLayout, Immutable, Unaligned)]
pub(super) struct DataHeader {
    pub(super) message_type: U32,
    pub(super) receiver_index: U32,
    pub(super) counter: U64,
}

const _: () = {
    assert!(size_of::<HandshakeInitMsg>() == 148);
    assert!(size_of::<HandshakeRespMsg>() == 92);
    assert!(size_of::<CookieReplyMsg>() == 64);
    assert!(size_of::<DataHeader>() == 16);
};
