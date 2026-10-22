//! Data embedded at build time: chains, official Safe contracts and tokens.
//! Each file in `data/` records its upstream source and commit. Nothing is
//! ever fetched at run time (ADR 0002).
//!
//! Every table is parsed once, on first use (`LazyLock`). If embedded data
//! were invalid, the accessor returns a [`RegistryError`] and blindsight
//! stops: running without its registry would silently treat official
//! contracts as unknown.

mod chains;
mod contracts;
mod tokens;

use alloy_primitives::Address;
use thiserror::Error;

pub use chains::{Chain, ChainTable, chains};
pub use contracts::{OfficialContract, Role, SafeContracts, safe_contracts};
pub use tokens::{Token, TokenList, tokens};

/// Embedded data failed to load. This is a build defect, not an input error.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
#[error("internal error: embedded data file {file} is invalid: {reason}")]
pub struct RegistryError {
    /// The `data/` file concerned.
    pub file: &'static str,
    /// What is wrong with it.
    pub reason: String,
}

impl RegistryError {
    fn new(file: &'static str, reason: String) -> Self {
        RegistryError { file, reason }
    }
}

/// Parses an embedded address, which must carry a valid EIP-55 checksum (or
/// be all lowercase): a corrupted address in the registry would make the tool
/// trust the wrong contract.
fn parse_checksummed(file: &'static str, text: &str) -> Result<Address, RegistryError> {
    let address: Address = text
        .parse()
        .map_err(|_| RegistryError::new(file, format!("invalid address {text}")))?;
    let hex = text.get(2..).unwrap_or_default();
    let mixed_case =
        hex.chars().any(|c| c.is_ascii_uppercase()) && hex.chars().any(|c| c.is_ascii_lowercase());
    if mixed_case && address.to_checksum(None) != text {
        return Err(RegistryError::new(file, format!("bad checksum on {text}")));
    }
    Ok(address)
}
