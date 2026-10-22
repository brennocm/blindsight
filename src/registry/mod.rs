//! Data embedded at build time: chains, official Safe contracts, tokens and
//! the Permit2 contract.
//! Each file in `data/` records its upstream source and commit. Nothing is
//! ever fetched at run time (ADR 0002).
//!
//! Every table is parsed once, on first use (`LazyLock`). If embedded data
//! were invalid, the accessor returns a [`RegistryError`] and blindsight
//! stops: running without its registry would silently treat official
//! contracts as unknown.

mod chains;
mod contracts;
mod permit2;
mod tokens;

use alloy_primitives::Address;
use thiserror::Error;

pub use chains::{Chain, ChainTable, chains};
pub use contracts::{OfficialContract, Role, SafeContracts, safe_contracts};
pub use permit2::{Permit2, permit2};
pub use tokens::{Token, TokenList, tokens};

/// All embedded tables, loaded together.
#[derive(Debug, Clone, Copy)]
pub struct Registry {
    /// Chains with an official Safe deployment.
    pub chains: &'static ChainTable,
    /// Official Safe contracts.
    pub contracts: &'static SafeContracts,
    /// Curated tokens.
    pub tokens: &'static TokenList,
    /// The Permit2 contract.
    pub permit2: &'static Permit2,
}

impl Registry {
    /// Loads (on first use) and returns every table.
    ///
    /// # Errors
    ///
    /// Only if embedded data is corrupt, which the tests rule out.
    pub fn load() -> Result<Registry, RegistryError> {
        Ok(Registry {
            chains: chains()?,
            contracts: safe_contracts()?,
            tokens: tokens()?,
            permit2: permit2()?,
        })
    }
}

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
