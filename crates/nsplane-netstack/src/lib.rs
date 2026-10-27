//! User-space TCP/IP stack for the nsplane data plane, built on smoltcp.
//!
//! A [`NetStack`] is the endpoint for the plaintext IP packets an `nsplane` engine decrypts
//! and presents them as async TCP connections and UDP flows, for IPv4 and IPv6. It plugs into
//! the engine through the local-side traits: [`NetStack::split`] yields a
//! [`NetStackSource`] ([`nsplane::PacketSource`], the stack's egress) and a
//! [`NetStackSink`] ([`nsplane::PacketSink`], packets into the stack), the pair an
//! `nsplane::EngineBuilder` takes in place of a TUN device.
//!
//! The [`NetStackHandle`] is the application's side:
//! [`incoming_tcp`](NetStackHandle::incoming_tcp) accepts connections to any port of the
//! stack's addresses, [`incoming_udp`](NetStackHandle::incoming_udp) reports one
//! [`UdpFlow`] per `(remote, local)` tuple, and [`connect_tcp`](NetStackHandle::connect_tcp),
//! [`bind_udp`](NetStackHandle::bind_udp) and [`connect_udp`](NetStackHandle::connect_udp)
//! open the reverse direction.
//! Every connection, flow and socket has a [`FlowControl`] that revokes it alone, without
//! stopping the stack; its [`RetirementReceipt`] tells when nothing of the flow can leave
//! the stack any more. [`FlowControl::bind_context`] labels a flow with an opaque
//! [`FlowContext`] (the caller's isolation domain and an instance the stack never hands
//! out twice); the stack never reads it, and a new flow on the same tuple never takes
//! over a revoked flow's queues, replies or held fragments. Both cover the stack only:
//! packets already taken from [`NetStackSource`] are outside. With
//! [`Admission::Decide`] in [`NetStackConfig::admission`], every new connection or flow is
//! first offered as a [`PendingFlow`], whose [`control`](PendingFlow::control) covers the
//! lifetime from its first input to its handle; [`FlowControl::delivery`] tells whether the
//! handle was handed out.
//! [`owns`](NetStackHandle::owns) tells whether an ingress packet is the stack's
//! ([`Ownership`]), for a local side that shares one decrypted stream with other consumers.
//!
//! # Driver
//!
//! One task owns smoltcp. Each iteration takes a bounded batch of ingress packets, sizes
//! the TCP listener pool to the batch's SYNs, then ingests packet by packet with one
//! smoltcp egress turn after each (`poll_ingress_single` / `poll_egress`), bridges
//! connection bytes and flushes egress. UDP bypasses smoltcp on its own dispatch path.
//! Every queue is bounded; everything the stack discards is counted in
//! [`NetStackHandle::stats`].
//!
//! # MTU, MSS and windows
//!
//! smoltcp sees the configured MTU as its device MTU, so it advertises an MSS of
//! `mtu - 40` (IPv4) or `mtu - 60` (IPv6) and no packet the stack emits exceeds the MTU.
//! A peer then never sends segments that are black-holed once the tunnel wraps them
//! (small packets pass and the first full-size segment stalls). Each socket's send and
//! receive buffers hold 512 IPv4-sized segments by default, so the advertised window scales
//! with the MSS; [`NetStackConfig::tcp_rx_buffer`] and [`NetStackConfig::tcp_tx_buffer`]
//! set other sizes. The receive buffer is the window, and smoltcp derives the window-scale
//! option from it.

#![forbid(unsafe_code)]

mod config;
mod device;
mod events;
mod flow;
mod ownership;
mod pending;
mod pmtu;
mod stack;
mod stats;
mod tcp;
mod udp;

pub use config::{Admission, DEFAULT_MTU, MIN_MTU, NetStackConfig, TransparentConfig};
pub use events::{FlowEvent, FlowEventReason, FlowEventsConfig};
pub use flow::{
    DeliveryOutcome, DeliveryReceipt, FlowContext, FlowControl, RetirementOutcome,
    RetirementReceipt, Undelivered,
};
pub use nsplane_packet::reassembly::ReassemblyConfig;
pub use ownership::Ownership;
pub use pending::{PendingFlow, PendingProtocol};
pub use stack::{NetStack, NetStackHandle, NetStackSink, NetStackSource};
pub use stats::NetStackStats;
pub use tcp::TcpConnection;
pub use udp::{UdpFlow, UdpReply, UdpSocket};
