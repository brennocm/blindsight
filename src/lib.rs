//! `blindsight` verifies Safe multisig transactions offline.
//!
//! Given the parameters of a Safe transaction, it computes the EIP-712 domain
//! hash, message hash and safeTxHash that a hardware wallet displays, decodes
//! the calldata and reports risky operations. It never uses the network.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

/// Version of this crate, as declared in `Cargo.toml`.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

pub mod decode;
pub mod input;
pub mod registry;
pub mod safe;
pub mod sanitize;
pub mod units;
