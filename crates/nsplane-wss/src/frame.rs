//! The `WsFrame` codec of the stream carrier, byte-identical to ns `tunnel-ws` and NSGW.
//!
//! Every binary WebSocket message is one frame (big-endian):
//!
//! ```text
//! [stream_id: u32][command: u8][payload ...]
//! ```
//!
//! | Command | Byte | Payload |
//! |---|---|---|
//! | [`OPEN_V4`] | `0x01` | 4 B IPv4 address, 2 B port, 1 B [protocol](Protocol) |
//! | [`OPEN_V6`] | `0x02` | 16 B IPv6 address, 2 B port, 1 B [protocol](Protocol) |
//! | [`DATA`] | `0x10` | the stream's bytes, or one datagram |
//! | [`CLOSE`] | `0x20` | none |
//! | [`CLOSE_ACK`] | `0x21` | none |
//!
//! As in ns, decoding ignores bytes after a complete OPEN, CLOSE or `CLOSE_ACK`, and any
//! protocol byte but [`PROTO_UDP`] is TCP.

use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};

use bytes::{BufMut as _, Bytes, BytesMut};
use thiserror::Error;

/// Open a stream to an IPv4 target.
pub const OPEN_V4: u8 = 0x01;
/// Open a stream to an IPv6 target.
pub const OPEN_V6: u8 = 0x02;
/// Bytes of a stream.
pub const DATA: u8 = 0x10;
/// Close a stream.
pub const CLOSE: u8 = 0x20;
/// Acknowledge a [`CLOSE`].
pub const CLOSE_ACK: u8 = 0x21;

/// The protocol byte of TCP.
pub const PROTO_TCP: u8 = 0x00;
/// The protocol byte of UDP.
pub const PROTO_UDP: u8 = 0x01;

/// The length of the stream id and the command byte that start every frame.
pub const HEADER_LEN: usize = 5;

/// The length of an [`OPEN_V4`] frame.
const OPEN_V4_LEN: usize = HEADER_LEN + 4 + 2 + 1;
/// The length of an [`OPEN_V6`] frame.
const OPEN_V6_LEN: usize = HEADER_LEN + 16 + 2 + 1;

/// The transport protocol of an opened stream.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Protocol {
    /// A byte stream ([`PROTO_TCP`]).
    Tcp,
    /// Datagrams, one per [`DATA`] frame ([`PROTO_UDP`]).
    Udp,
}

impl Protocol {
    /// The protocol byte.
    pub const fn to_byte(self) -> u8 {
        match self {
            Self::Tcp => PROTO_TCP,
            Self::Udp => PROTO_UDP,
        }
    }

    /// The protocol of `byte`: [`PROTO_UDP`] is UDP, anything else TCP.
    pub const fn from_byte(byte: u8) -> Self {
        if byte == PROTO_UDP {
            Self::Udp
        } else {
            Self::Tcp
        }
    }
}

/// The command of a [`WsFrame`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FrameCommand {
    /// Open a stream to `target` ([`OPEN_V4`] or [`OPEN_V6`] by its address family; the
    /// flow info and scope id of an IPv6 target are not carried).
    Open {
        /// Where the stream goes.
        target: SocketAddr,
        /// Its protocol.
        protocol: Protocol,
    },
    /// The payload belongs to the stream ([`DATA`]).
    Data,
    /// Close the stream ([`CLOSE`]).
    Close,
    /// Acknowledge a close ([`CLOSE_ACK`]).
    CloseAck,
}

/// Why bytes are not a [`WsFrame`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
#[non_exhaustive]
pub enum FrameError {
    /// Shorter than the stream id and the command byte.
    #[error("frame too short: {len} bytes")]
    TooShort {
        /// The length of the bytes.
        len: usize,
    },
    /// An OPEN shorter than its address, port and protocol.
    #[error("open frame (command 0x{command:02x}) too short: {len} bytes")]
    OpenTooShort {
        /// [`OPEN_V4`] or [`OPEN_V6`].
        command: u8,
        /// The length of the frame.
        len: usize,
    },
    /// An unknown command byte.
    #[error("unknown command byte: 0x{0:02x}")]
    UnknownCommand(u8),
}

/// One frame of the stream carrier; see the [module documentation](self).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WsFrame {
    /// The stream the frame belongs to.
    pub stream_id: u32,
    /// The command.
    pub command: FrameCommand,
    /// The payload of a [`FrameCommand::Data`] frame; empty, and not encoded, for the
    /// other commands.
    pub payload: Bytes,
}

impl WsFrame {
    /// An OPEN of `stream_id` to `target`.
    pub const fn open(stream_id: u32, target: SocketAddr, protocol: Protocol) -> Self {
        Self {
            stream_id,
            command: FrameCommand::Open { target, protocol },
            payload: Bytes::new(),
        }
    }

    /// A DATA frame of `stream_id` carrying `payload`.
    pub const fn data(stream_id: u32, payload: Bytes) -> Self {
        Self {
            stream_id,
            command: FrameCommand::Data,
            payload,
        }
    }

    /// A CLOSE of `stream_id`.
    pub const fn close(stream_id: u32) -> Self {
        Self {
            stream_id,
            command: FrameCommand::Close,
            payload: Bytes::new(),
        }
    }

    /// A `CLOSE_ACK` of `stream_id`.
    pub const fn close_ack(stream_id: u32) -> Self {
        Self {
            stream_id,
            command: FrameCommand::CloseAck,
            payload: Bytes::new(),
        }
    }

    /// The length of the encoded frame.
    pub const fn encoded_len(&self) -> usize {
        match self.command {
            FrameCommand::Open { target, .. } => match target {
                SocketAddr::V4(_) => OPEN_V4_LEN,
                SocketAddr::V6(_) => OPEN_V6_LEN,
            },
            FrameCommand::Data => HEADER_LEN + self.payload.len(),
            FrameCommand::Close | FrameCommand::CloseAck => HEADER_LEN,
        }
    }

    /// Appends the encoded frame to `buf`.
    pub fn encode_into(&self, buf: &mut BytesMut) {
        buf.reserve(self.encoded_len());
        buf.put_u32(self.stream_id);
        match self.command {
            FrameCommand::Open { target, protocol } => {
                match target {
                    SocketAddr::V4(addr) => {
                        buf.put_u8(OPEN_V4);
                        buf.put_slice(&addr.ip().octets());
                    }
                    SocketAddr::V6(addr) => {
                        buf.put_u8(OPEN_V6);
                        buf.put_slice(&addr.ip().octets());
                    }
                }
                buf.put_u16(target.port());
                buf.put_u8(protocol.to_byte());
            }
            FrameCommand::Data => {
                buf.put_u8(DATA);
                buf.put_slice(&self.payload);
            }
            FrameCommand::Close => buf.put_u8(CLOSE),
            FrameCommand::CloseAck => buf.put_u8(CLOSE_ACK),
        }
    }

    /// The encoded frame.
    pub fn encode(&self) -> Bytes {
        let mut buf = BytesMut::with_capacity(self.encoded_len());
        self.encode_into(&mut buf);
        buf.freeze()
    }

    /// Decodes a frame; the payload of a DATA frame shares `data`'s buffer.
    pub fn decode(data: &Bytes) -> Result<Self, FrameError> {
        if data.len() < HEADER_LEN {
            return Err(FrameError::TooShort { len: data.len() });
        }
        let stream_id = u32::from_be_bytes([data[0], data[1], data[2], data[3]]);
        let command = data[4];
        let command = match command {
            OPEN_V4 | OPEN_V6 => {
                let ip_len = if command == OPEN_V4 { 4 } else { 16 };
                if data.len() < HEADER_LEN + ip_len + 3 {
                    return Err(FrameError::OpenTooShort {
                        command,
                        len: data.len(),
                    });
                }
                let ip = &data[HEADER_LEN..HEADER_LEN + ip_len];
                let rest = &data[HEADER_LEN + ip_len..];
                let port = u16::from_be_bytes([rest[0], rest[1]]);
                let target = if command == OPEN_V4 {
                    let mut v4 = [0; 4];
                    v4.copy_from_slice(ip);
                    SocketAddr::from((Ipv4Addr::from(v4), port))
                } else {
                    let mut v6 = [0; 16];
                    v6.copy_from_slice(ip);
                    SocketAddr::from((Ipv6Addr::from(v6), port))
                };
                FrameCommand::Open {
                    target,
                    protocol: Protocol::from_byte(rest[2]),
                }
            }
            DATA => {
                return Ok(Self::data(stream_id, data.slice(HEADER_LEN..)));
            }
            CLOSE => FrameCommand::Close,
            CLOSE_ACK => FrameCommand::CloseAck,
            _ => return Err(FrameError::UnknownCommand(command)),
        };
        Ok(Self {
            stream_id,
            command,
            payload: Bytes::new(),
        })
    }
}

/// Encodes a DATA frame of `stream_id` carrying `payload` in one allocation: what
/// [`WsFrame::data`] and [`WsFrame::encode`] give, without first copying the payload into
/// a [`Bytes`].
pub fn encode_data(stream_id: u32, payload: &[u8]) -> Bytes {
    let mut buf = BytesMut::with_capacity(HEADER_LEN + payload.len());
    buf.put_u32(stream_id);
    buf.put_u8(DATA);
    buf.put_slice(payload);
    buf.freeze()
}

#[cfg(test)]
mod tests;
