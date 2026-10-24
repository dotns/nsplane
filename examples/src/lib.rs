//! Shared code of the nsplane examples.
//!
//! Every node example assembles its engine the same way through [`node`] (keys, peers,
//! transports, logging), serves and checks echo traffic through [`echo`], writes a JSON
//! snapshot through [`status`] and prints result lines through [`out`]. The binaries live
//! in `src/bin/`; run one with `cargo run -p nsplane-examples --bin <name> -- --help`.

#![forbid(unsafe_code)]

pub mod echo;
pub mod node;
pub mod out;
pub mod relay;
pub mod status;
pub mod vm;

/// The usage guide; its complete programs run as doctests.
#[cfg(doctest)]
#[doc = include_str!("../../docs/guide.md")]
mod guide {}

/// The Chinese usage guide; its complete programs run as doctests.
#[cfg(doctest)]
#[doc = include_str!("../../docs/guide.zh-CN.md")]
mod guide_zh_cn {}
