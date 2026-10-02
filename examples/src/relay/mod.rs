//! The single-port relay wire format: one UDP port carries WireGuard to the relay's own
//! engine, blindly relayed WireGuard, and control messages.
//!
//! This module is the contract (no sockets, no engine): [`wire`] classifies and frames
//! datagrams, [`mac1`] routes handshakes by WireGuard mac1, [`envelope`] is the ns signed
//! control envelope and the machine key, and [`messages`] are the ns relay messages
//! (`wg_relay.register_source`, `gateway.reflexive`). The design and the mapping to ns and
//! nsgw are in `docs/decisions/2026-10-02-single-port-relay.md`.
//!
//! On top of the contract: [`router`] is the relay's sans-I/O demultiplexer and
//! [`server`] its wrapping transport and configuration; [`client`] is the node side
//! (capability discovery, registration, the extension-aware transport) and [`ladder`] the
//! direct-first, relay-fallback path policy.

pub mod client;
pub mod envelope;
pub mod ladder;
pub mod mac1;
pub mod messages;
pub mod router;
pub mod server;
pub mod wire;
