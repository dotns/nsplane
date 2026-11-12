//! Safe wrappers over the few OS calls the nsplane crates need and no safe dependency
//! provides.
//!
//! The crates that use these calls forbid `unsafe` code, so the `unsafe` blocks live here,
//! one per call. Every function is safe for every argument: it takes typed handles and
//! slices, never descriptor numbers or pointers, and reports a failed call as an
//! [`io::Error`](std::io::Error). A function exists only on the platform its call belongs
//! to, so the crate is empty elsewhere.
//!
//! | Function | Platform | Call |
//! |---|---|---|
//! | `set_exclusive_address_use` | Windows | `setsockopt` with `SO_EXCLUSIVEADDRUSE` |
//! | `set_supplementary_groups` | Apple | `setgroups` |

#[cfg(target_vendor = "apple")]
mod apple;
#[cfg(windows)]
mod windows;

#[cfg(target_vendor = "apple")]
pub use apple::set_supplementary_groups;
#[cfg(windows)]
pub use windows::set_exclusive_address_use;
