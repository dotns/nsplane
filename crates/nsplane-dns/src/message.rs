//! Owned DNS message types and the wire codec.
//!
//! [`Query::decode`] parses a client query; [`encode_response`] and [`encode_error`] build the
//! answer. The codec handles exactly one question per message, the EDNS OPT record (its UDP
//! payload size) and truncation; it does not handle zone transfers, updates or DNSSEC.

use std::fmt;
use std::net::{Ipv4Addr, Ipv6Addr};

use bytes::Bytes;
use simple_dns::rdata::{A, AAAA, CNAME, OPT, PTR, RData, TXT};
use simple_dns::{CLASS, Name, OPCODE, Packet, PacketFlag, RCODE, ResourceRecord, header_buffer};

/// Length of the fixed DNS header.
const HEADER_LEN: usize = 12;

/// Largest UDP response without EDNS (RFC 1035).
pub const MIN_UDP_RESPONSE_SIZE: usize = 512;

/// UDP payload size a server advertises by default (the DNS flag day 2020 value).
pub const DEFAULT_UDP_PAYLOAD_SIZE: u16 = 1232;

/// Class IN (Internet).
pub const CLASS_IN: u16 = 1;

/// A DNS record type (`QTYPE` / `TYPE`), any 16-bit value.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct RecordType(pub u16);

impl RecordType {
    /// IPv4 address.
    pub const A: Self = Self(1);
    /// Authoritative name server.
    pub const NS: Self = Self(2);
    /// Canonical name of an alias.
    pub const CNAME: Self = Self(5);
    /// Start of a zone of authority.
    pub const SOA: Self = Self(6);
    /// Domain name pointer.
    pub const PTR: Self = Self(12);
    /// Mail exchange.
    pub const MX: Self = Self(15);
    /// Text strings.
    pub const TXT: Self = Self(16);
    /// IPv6 address.
    pub const AAAA: Self = Self(28);
    /// Service locator.
    pub const SRV: Self = Self(33);
    /// EDNS OPT pseudo-record.
    pub const OPT: Self = Self(41);
    /// Service binding for HTTPS.
    pub const HTTPS: Self = Self(65);
    /// Any type (query only).
    pub const ANY: Self = Self(255);

    const MNEMONICS: [(Self, &'static str); 12] = [
        (Self::A, "A"),
        (Self::NS, "NS"),
        (Self::CNAME, "CNAME"),
        (Self::SOA, "SOA"),
        (Self::PTR, "PTR"),
        (Self::MX, "MX"),
        (Self::TXT, "TXT"),
        (Self::AAAA, "AAAA"),
        (Self::SRV, "SRV"),
        (Self::OPT, "OPT"),
        (Self::HTTPS, "HTTPS"),
        (Self::ANY, "ANY"),
    ];
}

impl fmt::Display for RecordType {
    /// The mnemonic (`AAAA`), or `TYPE<n>` (RFC 3597) for other values.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match Self::MNEMONICS.iter().find(|(t, _)| t == self) {
            Some((_, name)) => f.write_str(name),
            None => write!(f, "TYPE{}", self.0),
        }
    }
}

/// A response code (`RCODE`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum ResponseCode {
    /// No error.
    NoError,
    /// The query could not be interpreted.
    FormErr,
    /// The server failed to process the query.
    ServFail,
    /// The name does not exist.
    NxDomain,
    /// The kind of query is not supported.
    NotImp,
    /// The server refuses to answer.
    Refused,
}

impl ResponseCode {
    /// The numeric value carried in the header.
    pub const fn value(self) -> u8 {
        match self {
            Self::NoError => 0,
            Self::FormErr => 1,
            Self::ServFail => 2,
            Self::NxDomain => 3,
            Self::NotImp => 4,
            Self::Refused => 5,
        }
    }

    const fn rcode(self) -> RCODE {
        match self {
            Self::NoError => RCODE::NoError,
            Self::FormErr => RCODE::FormatError,
            Self::ServFail => RCODE::ServerFailure,
            Self::NxDomain => RCODE::NameError,
            Self::NotImp => RCODE::NotImplemented,
            Self::Refused => RCODE::Refused,
        }
    }
}

/// The data of a [`Record`].
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum RecordData {
    /// An IPv4 address.
    A(Ipv4Addr),
    /// An IPv6 address.
    Aaaa(Ipv6Addr),
    /// The canonical name of an alias.
    Cname(String),
    /// A domain name pointer.
    Ptr(String),
    /// Text strings, each at most 255 bytes.
    Txt(Vec<String>),
}

impl RecordData {
    /// The record type of this data.
    pub const fn record_type(&self) -> RecordType {
        match self {
            Self::A(_) => RecordType::A,
            Self::Aaaa(_) => RecordType::AAAA,
            Self::Cname(_) => RecordType::CNAME,
            Self::Ptr(_) => RecordType::PTR,
            Self::Txt(_) => RecordType::TXT,
        }
    }
}

/// An answer record of class IN.
///
/// Names (the owner and the CNAME / PTR targets) are host names: labels of letters, digits,
/// `-` and `_`, separated by dots. A response whose records cannot be encoded is answered
/// with `SERVFAIL`.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Record {
    /// Owner name.
    pub name: String,
    /// Time to live in seconds.
    pub ttl: u32,
    /// Record data.
    pub data: RecordData,
}

impl Record {
    /// A record with the given data.
    pub fn new(name: impl Into<String>, ttl: u32, data: RecordData) -> Self {
        Self {
            name: name.into(),
            ttl,
            data,
        }
    }

    /// An `A` record.
    pub fn a(name: impl Into<String>, ttl: u32, addr: Ipv4Addr) -> Self {
        Self::new(name, ttl, RecordData::A(addr))
    }

    /// An `AAAA` record.
    pub fn aaaa(name: impl Into<String>, ttl: u32, addr: Ipv6Addr) -> Self {
        Self::new(name, ttl, RecordData::Aaaa(addr))
    }

    /// A `CNAME` record.
    pub fn cname(name: impl Into<String>, ttl: u32, target: impl Into<String>) -> Self {
        Self::new(name, ttl, RecordData::Cname(target.into()))
    }

    /// A `PTR` record.
    pub fn ptr(name: impl Into<String>, ttl: u32, target: impl Into<String>) -> Self {
        Self::new(name, ttl, RecordData::Ptr(target.into()))
    }

    /// A `TXT` record.
    pub fn txt(name: impl Into<String>, ttl: u32, strings: Vec<String>) -> Self {
        Self::new(name, ttl, RecordData::Txt(strings))
    }

    /// The record type of its data.
    pub const fn record_type(&self) -> RecordType {
        self.data.record_type()
    }
}

/// What a resolver answers to a query.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Answer {
    /// `NOERROR` with these answer records; an empty list is `NODATA`.
    Records(Vec<Record>),
    /// No answer records, with this response code.
    Code(ResponseCode),
    /// A complete DNS response obtained elsewhere, passed through with only its ID replaced
    /// by the query's.
    Raw(Bytes),
}

/// A decoded client query with exactly one question.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Query {
    id: u16,
    name: String,
    record_type: RecordType,
    class: u16,
    recursion_desired: bool,
    udp_payload_size: Option<u16>,
    raw: Bytes,
}

impl Query {
    /// Decodes a query message.
    ///
    /// The message must be a query (`QR` = 0) with opcode `QUERY` and exactly one question.
    /// Records in the other sections are parsed but ignored, except the OPT record.
    ///
    /// # Errors
    ///
    /// A [`DecodeError`] whose [`response_code`](DecodeError::response_code) tells whether and
    /// how to answer.
    pub fn decode(message: &[u8]) -> Result<Self, DecodeError> {
        let (Ok(id), Ok(response)) = (
            header_buffer::id(message),
            header_buffer::has_flags(message, PacketFlag::RESPONSE),
        ) else {
            return Err(DecodeError::Short);
        };
        if response {
            return Err(DecodeError::Response { id });
        }
        if !matches!(header_buffer::opcode(message), Ok(OPCODE::StandardQuery)) {
            return Err(DecodeError::Opcode { id });
        }
        let packet = Packet::parse(message).map_err(|_| DecodeError::Malformed { id })?;
        let [question] = packet.questions.as_slice() else {
            return Err(DecodeError::QuestionCount {
                id,
                count: packet.questions.len(),
            });
        };
        Ok(Self {
            id,
            name: normalize_name(&question.qname.to_string()),
            record_type: RecordType(question.qtype.into()),
            class: question.qclass.into(),
            recursion_desired: packet.has_flags(PacketFlag::RECURSION_DESIRED),
            udp_payload_size: packet.opt().map(|opt| opt.udp_packet_size),
            raw: Bytes::copy_from_slice(message),
        })
    }

    /// The message ID.
    pub const fn id(&self) -> u16 {
        self.id
    }

    /// The question name, ASCII-lowercase and without a trailing dot (the root is `""`).
    pub fn name(&self) -> &str {
        &self.name
    }

    /// The question type.
    pub const fn record_type(&self) -> RecordType {
        self.record_type
    }

    /// The question class ([`CLASS_IN`] for the Internet).
    pub const fn class(&self) -> u16 {
        self.class
    }

    /// Whether the client set `RD` (recursion desired).
    pub const fn recursion_desired(&self) -> bool {
        self.recursion_desired
    }

    /// The UDP payload size of the client's EDNS OPT record, `None` without one.
    pub const fn udp_payload_size(&self) -> Option<u16> {
        self.udp_payload_size
    }

    /// The message bytes as received, for forwarding.
    pub const fn raw(&self) -> &Bytes {
        &self.raw
    }
}

/// Normalizes a domain name for comparison: ASCII-lowercase, one trailing dot removed.
pub fn normalize_name(name: &str) -> String {
    name.strip_suffix('.').unwrap_or(name).to_ascii_lowercase()
}

/// Why a message is not a query this codec answers.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum DecodeError {
    /// Shorter than the DNS header.
    #[error("message shorter than the DNS header")]
    Short,
    /// A response (`QR` = 1), not a query.
    #[error("message {id} is a response")]
    Response {
        /// Message ID.
        id: u16,
    },
    /// An opcode other than `QUERY`.
    #[error("message {id} has an unsupported opcode")]
    Opcode {
        /// Message ID.
        id: u16,
    },
    /// The message does not parse.
    #[error("message {id} is malformed")]
    Malformed {
        /// Message ID.
        id: u16,
    },
    /// Not exactly one question.
    #[error("message {id} has {count} questions, expected one")]
    QuestionCount {
        /// Message ID.
        id: u16,
        /// Number of questions.
        count: usize,
    },
}

impl DecodeError {
    /// The message ID, when the header was readable.
    pub const fn id(&self) -> Option<u16> {
        match self {
            Self::Short => None,
            Self::Response { id }
            | Self::Opcode { id }
            | Self::Malformed { id }
            | Self::QuestionCount { id, .. } => Some(*id),
        }
    }

    /// The code to answer with ([`encode_error`]), or `None` when the message is dropped
    /// silently (too short, or a response).
    pub const fn response_code(&self) -> Option<ResponseCode> {
        match self {
            Self::Short | Self::Response { .. } => None,
            Self::Opcode { .. } => Some(ResponseCode::NotImp),
            Self::Malformed { .. } | Self::QuestionCount { .. } => Some(ResponseCode::FormErr),
        }
    }
}

/// Server-side encoding options.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct EncodeOptions {
    /// UDP payload size advertised in the OPT record of responses to EDNS queries, and the
    /// upper bound of [`max_udp_response_size`]. Default [`DEFAULT_UDP_PAYLOAD_SIZE`].
    pub udp_payload_size: u16,
}

impl Default for EncodeOptions {
    fn default() -> Self {
        Self {
            udp_payload_size: DEFAULT_UDP_PAYLOAD_SIZE,
        }
    }
}

/// The largest UDP response a query may receive: 512 bytes without EDNS, else the client's
/// payload size clamped to `512..=options.udp_payload_size`.
pub fn max_udp_response_size(query: &Query, options: EncodeOptions) -> usize {
    query
        .udp_payload_size
        .map_or(MIN_UDP_RESPONSE_SIZE, |client| {
            usize::from(client)
                .min(usize::from(options.udp_payload_size))
                .max(MIN_UDP_RESPONSE_SIZE)
        })
}

/// Encodes the response to `query`.
///
/// The response echoes the ID, `RD` and the question as the client sent it, and sets `QR`
/// and `RA`. [`Answer::Records`] and [`Answer::Code`] are local answers (`AA` = 1); an EDNS
/// query gets an OPT record advertising `options.udp_payload_size`. [`Answer::Raw`] is
/// passed through with the ID replaced. A response longer than `max_size` is replaced by a
/// truncated one (`TC` = 1): the header, the question and the OPT record, no answers, so it
/// fits any `max_size` of at least 512. Records that cannot be encoded (an invalid name, a
/// TXT string over 255 bytes) give `SERVFAIL`.
pub fn encode_response(
    query: &Query,
    answer: &Answer,
    max_size: usize,
    options: EncodeOptions,
) -> Bytes {
    let full = match answer {
        Answer::Records(records) => {
            build_reply(query, options, ResponseCode::NoError, records, false)
        }
        Answer::Code(code) => build_reply(query, options, *code, &[], false),
        Answer::Raw(raw) => (raw.len() >= HEADER_LEN).then(|| {
            let mut out = raw.to_vec();
            out[..2].copy_from_slice(&query.id.to_be_bytes());
            out
        }),
    };
    let full = full.or_else(|| build_reply(query, options, ResponseCode::ServFail, &[], false));
    match full {
        Some(bytes) if bytes.len() <= max_size => Bytes::from(bytes),
        _ => build_reply(query, options, ResponseCode::NoError, &[], true)
            .map(Bytes::from)
            .unwrap_or_default(),
    }
}

/// Encodes an error response without a question, for a message that did not decode but
/// whose header was readable ([`DecodeError::id`] and [`DecodeError::response_code`]).
pub fn encode_error(id: u16, code: ResponseCode) -> Bytes {
    let mut packet = Packet::new_reply(id);
    *packet.rcode_mut() = code.rcode();
    packet
        .build_bytes_vec()
        .map(Bytes::from)
        .unwrap_or_default()
}

/// Builds a reply from the query's own question. `None` when a record does not encode.
fn build_reply(
    query: &Query,
    options: EncodeOptions,
    code: ResponseCode,
    records: &[Record],
    truncated: bool,
) -> Option<Vec<u8>> {
    // The question is taken from the received bytes, so its name keeps the client's case.
    let request = Packet::parse(&query.raw).ok()?;
    let mut packet = Packet::new_reply(query.id);
    packet.questions = request.questions;
    let mut flags = PacketFlag::RECURSION_AVAILABLE;
    if query.recursion_desired {
        flags |= PacketFlag::RECURSION_DESIRED;
    }
    if truncated {
        flags |= PacketFlag::TRUNCATION;
    } else {
        flags |= PacketFlag::AUTHORITATIVE_ANSWER;
    }
    packet.set_flags(flags);
    *packet.rcode_mut() = code.rcode();
    if query.udp_payload_size.is_some() {
        *packet.opt_mut() = Some(OPT {
            opt_codes: Vec::new(),
            udp_packet_size: options.udp_payload_size,
            version: 0,
        });
    }
    for record in records {
        packet.answers.push(resource_record(record)?);
    }
    packet.build_bytes_vec_compressed().ok()
}

fn resource_record(record: &Record) -> Option<ResourceRecord<'_>> {
    let rdata = match &record.data {
        RecordData::A(addr) => RData::A(A::from(*addr)),
        RecordData::Aaaa(addr) => RData::AAAA(AAAA::from(*addr)),
        RecordData::Cname(target) => RData::CNAME(CNAME(host_name(target)?)),
        RecordData::Ptr(target) => RData::PTR(PTR(host_name(target)?)),
        RecordData::Txt(strings) => {
            let mut txt = TXT::new();
            for s in strings {
                txt.add_string(s).ok()?;
            }
            RData::TXT(txt)
        }
    };
    Some(ResourceRecord::new(
        host_name(&record.name)?,
        CLASS::IN,
        record.ttl,
        rdata,
    ))
}

fn host_name(name: &str) -> Option<Name<'_>> {
    Name::new(name.strip_suffix('.').unwrap_or(name)).ok()
}
