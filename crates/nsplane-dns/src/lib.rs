#![forbid(unsafe_code)]

//! DNS serving for nsplane: wire codec, async [`Resolver`] trait and resolver building
//! blocks.
//!
//! The crate answers DNS clients with what the embedder decides: local records, addresses
//! it hands out, or responses forwarded from elsewhere. It is not a full DNS server: no
//! zones, no DNSSEC, no recursion, no zone transfers or updates. Resolution policy stays with
//! the embedder.
//!
//! - **Messages and codec** ([`message`]): owned types ([`Query`], [`Record`],
//!   [`RecordData`], [`RecordType`], [`ResponseCode`], [`Answer`]) and the wire codec:
//!   [`Query::decode`] (one question, opcode `QUERY`), [`encode_response`] (EDNS OPT and
//!   truncation), [`encode_error`] and [`max_udp_response_size`].
//! - **Resolvers** ([`resolver`]): the async [`Resolver`] trait, called concurrently with the
//!   decoded query and the client's address, and [`Fallback`], which asks a second resolver
//!   when the first answers `NXDOMAIN`.
//! - **Static records** ([`records`]): [`StaticRecords`], a fixed name -> records table.
//! - **Forwarding** ([`forward`]): [`Forwarder`], which passes queries to upstream servers
//!   over UDP (TCP for truncated responses), without caching or policy.
//! - **Fake addresses** ([`fake`]): [`FakePool`], which answers A / AAAA with addresses
//!   allocated per name from configured prefixes and maps them back to names.
//!
//! ```
//! use std::net::{Ipv4Addr, SocketAddr};
//!
//! use nsplane_dns::{Answer, Query, Record, RecordType, Resolver, StaticRecords};
//!
//! # #[tokio::main(flavor = "current_thread")]
//! # async fn main() {
//! let records: StaticRecords = [Record::a("printer.lan", 300, Ipv4Addr::new(10, 0, 0, 7))]
//!     .into_iter()
//!     .collect();
//!
//! // A query for `Printer.LAN. A`, as a client sends it.
//! let mut message = vec![0x12, 0x34, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0];
//! message.extend_from_slice(b"\x07Printer\x03LAN\x00\x00\x01\x00\x01");
//!
//! let query = Query::decode(&message).unwrap();
//! assert_eq!(query.name(), "printer.lan");
//! assert_eq!(query.record_type(), RecordType::A);
//!
//! let client = SocketAddr::from(([10, 0, 0, 2], 5353));
//! let answer = records.resolve(&query, client).await;
//! assert_eq!(
//!     answer,
//!     Answer::Records(vec![Record::a("printer.lan", 300, Ipv4Addr::new(10, 0, 0, 7))])
//! );
//! # }
//! ```

pub mod fake;
pub mod forward;
pub mod message;
pub mod records;
pub mod resolver;

pub use fake::{
    DEFAULT_FAKE_CAPACITY, DEFAULT_FAKE_TTL, FakePool, FakePoolConfig, FakePoolConfigError,
    FakePoolStats, NoData,
};
pub use forward::{Forwarder, ForwarderConfig, ForwarderError, ForwarderStats};
pub use message::{
    Answer, CLASS_IN, DEFAULT_UDP_PAYLOAD_SIZE, DecodeError, EncodeOptions, MIN_UDP_RESPONSE_SIZE,
    Query, Record, RecordData, RecordType, ResponseCode, encode_error, encode_response,
    max_udp_response_size, normalize_name,
};
pub use records::StaticRecords;
pub use resolver::{Fallback, Resolver};
