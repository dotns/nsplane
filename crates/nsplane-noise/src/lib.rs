// Copyright (c) 2019 Cloudflare, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

#![warn(missing_docs)]

//! Simple implementation of the client-side of the WireGuard protocol.

/// The transport-agnostic WireGuard protocol state machine.
pub mod noise;

#[cfg(not(feature = "mock-instant"))]
pub(crate) mod sleepyinstant;

/// Re-export of the x25519 types
pub mod x25519 {
    pub use x25519_dalek::{
        EphemeralSecret, PublicKey, ReusableSecret, SharedSecret, StaticSecret,
    };
}
