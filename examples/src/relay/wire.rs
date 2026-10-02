//! Framing on the shared relay UDP port.
//!
//! Every datagram on the port is classified by its first four bytes read as a little-endian
//! `u32`, the way WireGuard (and the Linux kernel) reads the message type:
//!
//! - `1..=4` with the length WireGuard requires for that type is a WireGuard message;
//! - a first byte in [`CONTROL_TYPES`], three zero bytes and a version byte is a control
//!   message: `[type u8][0u8; 3][version u8 = 1][payload]`;
//! - anything else is [`Frame::Invalid`].
//!
//! The two ranges cannot overlap: a control word is at least `0xF0`, a WireGuard word at
//! most 4, and non-zero reserved bytes after a type of 1-4 never select a control message.
//!
//! ```
//! use nsplane_examples::relay::wire::{self, ControlType, Frame};
//!
//! let frame = wire::encode_control(ControlType::ReflexiveRequest, b"cbor");
//! assert_eq!(wire::classify(&frame), Frame::Control { msg_type: 0xF2, version: 1 });
//! assert_eq!(wire::decode_control(&frame), Ok((ControlType::ReflexiveRequest, &b"cbor"[..])));
//! ```

use std::fmt;
use std::ops::RangeInclusive;

/// Length of the control header: type, three zero bytes and the version.
pub const CONTROL_HEADER_LEN: usize = 5;

/// The control version this module encodes and accepts.
pub const CONTROL_VERSION: u8 = 1;

/// First bytes reserved for control messages. Types without a [`ControlType`] are reserved.
pub const CONTROL_TYPES: RangeInclusive<u8> = 0xF0..=0xFF;

/// Length of a WireGuard handshake initiation.
pub const HANDSHAKE_INIT_LEN: usize = 148;
/// Length of a WireGuard handshake response.
pub const HANDSHAKE_RESPONSE_LEN: usize = 92;
/// Length of a WireGuard cookie reply.
pub const COOKIE_REPLY_LEN: usize = 64;
/// Minimum length of a WireGuard transport data message: the 16-byte header and the
/// 16-byte authentication tag of an empty (keepalive) payload.
pub const TRANSPORT_DATA_MIN_LEN: usize = 32;

const INDEX_OFFSET: usize = 4;
const RESPONSE_RECEIVER_INDEX_OFFSET: usize = 8;

/// A WireGuard message type, as the first little-endian `u32` of the message.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum WgKind {
    /// Type 1: handshake initiation.
    HandshakeInit,
    /// Type 2: handshake response.
    HandshakeResponse,
    /// Type 3: cookie reply.
    CookieReply,
    /// Type 4: transport data.
    TransportData,
}

impl WgKind {
    /// The message type word.
    pub const fn wire_type(self) -> u32 {
        match self {
            Self::HandshakeInit => 1,
            Self::HandshakeResponse => 2,
            Self::CookieReply => 3,
            Self::TransportData => 4,
        }
    }

    /// The shortest message of this type the classifier accepts.
    pub const fn min_len(self) -> usize {
        match self {
            Self::HandshakeInit => HANDSHAKE_INIT_LEN,
            Self::HandshakeResponse => HANDSHAKE_RESPONSE_LEN,
            Self::CookieReply => COOKIE_REPLY_LEN,
            Self::TransportData => TRANSPORT_DATA_MIN_LEN,
        }
    }

    const fn from_wire_type(word: u32) -> Option<Self> {
        match word {
            1 => Some(Self::HandshakeInit),
            2 => Some(Self::HandshakeResponse),
            3 => Some(Self::CookieReply),
            4 => Some(Self::TransportData),
            _ => None,
        }
    }
}

/// A control message type. The payload of each is the ns encoding, unchanged.
///
/// | Byte   | Message                              | Payload                                   |
/// |--------|--------------------------------------|-------------------------------------------|
/// | `0xF0` | `wg_relay.register_source` request   | CBOR `ControlEnvelope` (signed request)   |
/// | `0xF1` | reserved (ns has no registration ack)| -                                         |
/// | `0xF2` | `gateway.reflexive` request          | CBOR `ControlEnvelope` (signed request)   |
/// | `0xF3` | `gateway.reflexive` response         | CBOR `GatewayReflexiveResponse` (unsigned)|
/// | `0xF4`-`0xFF` | reserved                      | -                                         |
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ControlType {
    /// `0xF0`: `wg_relay.register_source`, peer to relay.
    RegisterSource,
    /// `0xF2`: `gateway.reflexive` request, peer to relay.
    ReflexiveRequest,
    /// `0xF3`: `gateway.reflexive` response, relay to peer.
    ReflexiveResponse,
}

impl ControlType {
    /// The type byte.
    pub const fn byte(self) -> u8 {
        match self {
            Self::RegisterSource => 0xF0,
            Self::ReflexiveRequest => 0xF2,
            Self::ReflexiveResponse => 0xF3,
        }
    }

    /// The control type of a type byte, or `None` for a reserved byte.
    pub const fn from_byte(byte: u8) -> Option<Self> {
        match byte {
            0xF0 => Some(Self::RegisterSource),
            0xF2 => Some(Self::ReflexiveRequest),
            0xF3 => Some(Self::ReflexiveResponse),
            _ => None,
        }
    }
}

/// What a datagram on the shared port is.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Frame {
    /// A WireGuard message of a valid type and length.
    WireGuard(WgKind),
    /// A control header with a type byte in [`CONTROL_TYPES`] and zero reserved bytes. The
    /// type may be reserved and the version unknown; [`decode_control`] checks both.
    Control {
        /// The type byte.
        msg_type: u8,
        /// The version byte.
        version: u8,
    },
    /// Neither: too short, an unknown type word, or non-zero reserved bytes.
    Invalid,
}

/// Classifies a datagram received on the shared port.
pub fn classify(datagram: &[u8]) -> Frame {
    let Some(word) = read_u32_le(datagram, 0) else {
        return Frame::Invalid;
    };
    if let Some(kind) = WgKind::from_wire_type(word) {
        return if datagram.len() >= kind.min_len() {
            Frame::WireGuard(kind)
        } else {
            Frame::Invalid
        };
    }
    match datagram {
        [msg_type, 0, 0, 0, version, ..] if CONTROL_TYPES.contains(msg_type) => Frame::Control {
            msg_type: *msg_type,
            version: *version,
        },
        _ => Frame::Invalid,
    }
}

/// Why a datagram is not a control message this module understands.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WireError {
    /// The datagram is not a control frame (see [`classify`]).
    NotControl,
    /// The type byte is in the control range but reserved.
    UnknownType(u8),
    /// The version byte is not [`CONTROL_VERSION`].
    UnsupportedVersion(u8),
}

impl fmt::Display for WireError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotControl => f.write_str("not a control frame"),
            Self::UnknownType(byte) => write!(f, "reserved control type {byte:#04x}"),
            Self::UnsupportedVersion(version) => write!(f, "unsupported control version {version}"),
        }
    }
}

impl std::error::Error for WireError {}

/// Frames `payload` as a control message of type `msg_type`.
pub fn encode_control(msg_type: ControlType, payload: &[u8]) -> Vec<u8> {
    let mut frame = Vec::with_capacity(CONTROL_HEADER_LEN + payload.len());
    frame.extend_from_slice(&[msg_type.byte(), 0, 0, 0, CONTROL_VERSION]);
    frame.extend_from_slice(payload);
    frame
}

/// Splits a control message into its type and payload.
pub fn decode_control(datagram: &[u8]) -> Result<(ControlType, &[u8]), WireError> {
    let Frame::Control { msg_type, version } = classify(datagram) else {
        return Err(WireError::NotControl);
    };
    if version != CONTROL_VERSION {
        return Err(WireError::UnsupportedVersion(version));
    }
    let msg_type = ControlType::from_byte(msg_type).ok_or(WireError::UnknownType(msg_type))?;
    let payload = datagram.get(CONTROL_HEADER_LEN..).unwrap_or_default();
    Ok((msg_type, payload))
}

/// The sender index of a handshake initiation or response, `None` for anything else.
pub fn sender_index(packet: &[u8]) -> Option<u32> {
    match classify(packet) {
        Frame::WireGuard(WgKind::HandshakeInit | WgKind::HandshakeResponse) => {
            read_u32_le(packet, INDEX_OFFSET)
        }
        _ => None,
    }
}

/// The receiver index of a handshake response, cookie reply or transport data message,
/// `None` for anything else.
pub fn receiver_index(packet: &[u8]) -> Option<u32> {
    match classify(packet) {
        Frame::WireGuard(WgKind::HandshakeResponse) => {
            read_u32_le(packet, RESPONSE_RECEIVER_INDEX_OFFSET)
        }
        Frame::WireGuard(WgKind::CookieReply | WgKind::TransportData) => {
            read_u32_le(packet, INDEX_OFFSET)
        }
        _ => None,
    }
}

fn read_u32_le(packet: &[u8], offset: usize) -> Option<u32> {
    let bytes = packet.get(offset..offset.checked_add(4)?)?;
    Some(u32::from_le_bytes(bytes.try_into().ok()?))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn wg(kind: WgKind, len: usize) -> Vec<u8> {
        let mut packet = vec![0u8; len];
        packet[..4].copy_from_slice(&kind.wire_type().to_le_bytes());
        packet
    }

    const KINDS: [WgKind; 4] = [
        WgKind::HandshakeInit,
        WgKind::HandshakeResponse,
        WgKind::CookieReply,
        WgKind::TransportData,
    ];

    #[test]
    fn each_wireguard_type_at_its_minimum_length() {
        for kind in KINDS {
            assert_eq!(classify(&wg(kind, kind.min_len())), Frame::WireGuard(kind));
            assert_eq!(
                classify(&wg(kind, kind.min_len() + 100)),
                Frame::WireGuard(kind)
            );
        }
    }

    #[test]
    fn short_wireguard_messages_are_invalid() {
        for kind in KINDS {
            assert_eq!(classify(&wg(kind, kind.min_len() - 1)), Frame::Invalid);
        }
        assert_eq!(classify(&[]), Frame::Invalid);
        assert_eq!(classify(&[1, 0, 0]), Frame::Invalid);
    }

    #[test]
    fn non_zero_reserved_bytes_are_invalid() {
        for kind in KINDS {
            for reserved in 1..4 {
                let mut packet = wg(kind, kind.min_len());
                packet[reserved] = 1;
                assert_eq!(
                    classify(&packet),
                    Frame::Invalid,
                    "{kind:?} byte {reserved}"
                );
            }
        }
        // A control type byte with non-zero reserved bytes is no control message either.
        assert_eq!(classify(&[0xF0, 0, 1, 0, 1]), Frame::Invalid);
        assert_eq!(classify(&[0xF2, 1, 0, 0, 1]), Frame::Invalid);
    }

    #[test]
    fn unknown_type_words_are_invalid() {
        for first in [0u8, 5, 0x7F, 0xEF] {
            assert_eq!(classify(&[first, 0, 0, 0, 1, 0, 0, 0]), Frame::Invalid);
        }
    }

    #[test]
    fn each_control_type_round_trips() {
        for msg_type in [
            ControlType::RegisterSource,
            ControlType::ReflexiveRequest,
            ControlType::ReflexiveResponse,
        ] {
            let frame = encode_control(msg_type, b"payload");
            assert_eq!(&frame[..5], &[msg_type.byte(), 0, 0, 0, 1]);
            assert_eq!(
                classify(&frame),
                Frame::Control {
                    msg_type: msg_type.byte(),
                    version: CONTROL_VERSION
                }
            );
            assert_eq!(decode_control(&frame), Ok((msg_type, &b"payload"[..])));
            assert_eq!(ControlType::from_byte(msg_type.byte()), Some(msg_type));
        }
        let empty = encode_control(ControlType::RegisterSource, &[]);
        assert_eq!(
            decode_control(&empty),
            Ok((ControlType::RegisterSource, &[][..]))
        );
    }

    #[test]
    fn reserved_control_types_classify_but_do_not_decode() {
        for byte in [0xF1u8, 0xF4, 0xFF] {
            let frame = [byte, 0, 0, 0, 1];
            assert_eq!(
                classify(&frame),
                Frame::Control {
                    msg_type: byte,
                    version: 1
                }
            );
            assert_eq!(decode_control(&frame), Err(WireError::UnknownType(byte)));
        }
    }

    #[test]
    fn unknown_control_version_is_rejected() {
        let frame = [0xF0, 0, 0, 0, 2, 0xAA];
        assert_eq!(
            classify(&frame),
            Frame::Control {
                msg_type: 0xF0,
                version: 2
            }
        );
        assert_eq!(
            decode_control(&frame),
            Err(WireError::UnsupportedVersion(2))
        );
        assert_eq!(
            decode_control(&[0xF0, 0, 0, 0, 0]),
            Err(WireError::UnsupportedVersion(0))
        );
    }

    #[test]
    fn short_control_headers_are_invalid() {
        assert_eq!(classify(&[0xF0, 0, 0, 0]), Frame::Invalid);
        assert_eq!(decode_control(&[0xF0, 0, 0, 0]), Err(WireError::NotControl));
        assert_eq!(
            decode_control(&wg(WgKind::TransportData, 32)),
            Err(WireError::NotControl)
        );
    }

    #[test]
    fn index_accessors() {
        let mut init = wg(WgKind::HandshakeInit, HANDSHAKE_INIT_LEN);
        init[4..8].copy_from_slice(&0x1122_3344u32.to_le_bytes());
        assert_eq!(sender_index(&init), Some(0x1122_3344));
        assert_eq!(receiver_index(&init), None);

        let mut response = wg(WgKind::HandshakeResponse, HANDSHAKE_RESPONSE_LEN);
        response[4..8].copy_from_slice(&7u32.to_le_bytes());
        response[8..12].copy_from_slice(&9u32.to_le_bytes());
        assert_eq!(sender_index(&response), Some(7));
        assert_eq!(receiver_index(&response), Some(9));

        for kind in [WgKind::CookieReply, WgKind::TransportData] {
            let mut packet = wg(kind, kind.min_len());
            packet[4..8].copy_from_slice(&42u32.to_le_bytes());
            assert_eq!(sender_index(&packet), None);
            assert_eq!(receiver_index(&packet), Some(42));
        }

        let control = encode_control(ControlType::RegisterSource, &[0; 16]);
        assert_eq!(sender_index(&control), None);
        assert_eq!(receiver_index(&control), None);
    }
}
