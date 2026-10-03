#![forbid(unsafe_code)]

//! IPv4/IPv6 translation and service-publishing NAT packet filters for nsplane.
//!
//! Applications that only speak IPv4 reach IPv6-only peers through local
//! aliases: every peer owns a /127 IPv6 group (`node6` and `node4`), and this
//! node presents it as an IPv6 alias (`alias6 <-> node6`) and an IPv4 alias
//! (`alias4 <-> node4`). The node itself is reachable as `self4 <-> node4`,
//! and IPv4 LAN prefixes map to IPv6 /96 prefixes by placing the IPv4 address
//! in the low 32 bits (`lan4 <-> lan6`).
//!
//! - **Translation table** ([`TranslationTable`]): the immutable, validated
//!   address model above, with O(1) / O(log n) lookups. Built with
//!   [`TranslationTableBuilder`]; replaced as a whole when the model changes.
//! - **Translator** ([`translate`]): a stateless IPv4 <-> IPv6 translation
//!   filter (RFC 7915 style, including ICMP/ICMPv6 and ICMP error inner
//!   packets) driven by a [`TranslationTable`], as an
//!   `nsplane_core::PacketFilter`.
//! - **Conntrack and port map** ([`conntrack`], [`port_map`]): a bounded
//!   connection table and the DNAT/SNAT filter that publishes local services,
//!   as an `nsplane_core::PacketFilter`.
//! - **NAT64 to a LAN** ([`nat64_lan`]): a stateful NAPT ([`Nat64Lan`])
//!   from IPv6 addresses of a mapped /96 to the IPv4 LAN hosts they embed,
//!   with SNAT ports reserved per flow through [`SnatPorts`]. It is not a
//!   `PacketFilter`: LAN replies are addressed to the SNAT source, which no
//!   peer's allowed IPs contain, so the translation sits on the local side
//!   (`forward` / `reverse` on a `PacketBuf`). On the gateway, wrap the
//!   engine's local side: `EngineBuilder::new(Nat64LanSource::new(tun_source,
//!   nat.clone()), Nat64LanSink::new(tun_sink, nat))` ([`Nat64LanSource`],
//!   [`Nat64LanSink`]). Each IPv6 client's allowed IPs of the gateway peer
//!   must contain the mapped /96, so the client routes it to the gateway;
//!   the gateway's allowed IPs of each client contain the client's IPv6
//!   source as usual.
//! - **Local-side redirect** ([`redirect`]): a per-flow DNAT ([`Redirect`])
//!   of local IPv4 TCP/UDP packets to an endpoint a caller-supplied closure
//!   picks (e.g. a user-space stack), with the reverse SNAT of the replies
//!   to the original destination. Like [`Nat64Lan`], it sits on the local
//!   side (`forward` / `reverse` on a `PacketBuf`).
//! - **Filter order**: the core's filter chain is installed from the wire side
//!   to the local side (inbound in install order, outbound in reverse); the
//!   recommended stack is `[AclFilter, PortMap, Translator]`, so the ACL and
//!   the port map see overlay IPv6 in both directions.
//! - **Allowed IPs**: the core routes local packets and checks the sources of
//!   decrypted packets before the filters run, so each peer's allowed IPs
//!   must contain its `alias4/32`, the LAN IPv4 prefixes behind it, its
//!   `alias6`, `node4`, `node6` and the `lan6` prefixes behind it.
//! - **Buffer room**: a translated IPv4 packet grows by 20 bytes (28 with a
//!   fragment header) inside its buffer. To keep translated packets within
//!   the MTU, install the engine's fragmentation stage
//!   (`nsplane::EngineBuilder::fragmenter`) with
//!   [`Translator::ipv4_translated_predicate`].
//! - **Checksums** ([`checksum`]): RFC 1624 incremental checksum updates for
//!   rewritten words, addresses and pseudo-headers, plus the UDP zero
//!   checksum rule.

pub mod checksum;
pub mod conntrack;
pub mod nat64_lan;
pub mod port_map;
pub mod redirect;
pub mod table;
pub mod translate;

pub use conntrack::{
    Conntrack, ConntrackConfig, ConntrackError, ConntrackStats, Flow, FlowDirection, FlowMatch,
    TcpState,
};
pub use nat64_lan::{
    DefaultSnatPorts, LanRoute, Nat64Lan, Nat64LanConfig, Nat64LanError, Nat64LanSink,
    Nat64LanSource, Nat64LanStats, Nat64Verdict, SnatPorts,
};
pub use port_map::{PortMap, PortMapError, PortMapProtocol, PortMapRule};
pub use redirect::{Redirect, RedirectDecision, RedirectStats, RedirectVerdict};
pub use table::{
    LanPrefix, PeerMapping, SelfMapping, TableError, TranslationTable, TranslationTableBuilder,
};
pub use translate::{Translator, TranslatorStats};
