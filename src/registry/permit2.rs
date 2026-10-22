//! The Uniswap Permit2 contract, from `data/permit2.json`.
//!
//! Permit2 holds token allowances on behalf of other contracts. An approval
//! there is as powerful as an ERC-20 approval and easier to overlook.

use std::sync::LazyLock;

use alloy_primitives::Address;
use serde::Deserialize;

use super::{RegistryError, parse_checksummed};

const PERMIT2_JSON: &str = include_str!("../../data/permit2.json");
const FILE: &str = "permit2.json";

/// Where Permit2 is deployed.
#[derive(Debug)]
pub struct Permit2 {
    /// Where the address comes from.
    pub source: String,
    /// Its address (the same on every chain listed).
    pub address: Address,
    chain_ids: Vec<u64>,
}

impl Permit2 {
    /// Whether `address` is Permit2 on `chain_id` (only chains where its code
    /// was checked are listed).
    pub fn is_at(&self, chain_id: u64, address: Address) -> bool {
        address == self.address && self.chain_ids.contains(&chain_id)
    }
}

#[derive(Deserialize)]
struct Permit2File {
    source: String,
    address: String,
    chain_ids: Vec<u64>,
}

fn parse(json: &str) -> Result<Permit2, RegistryError> {
    let file: Permit2File =
        serde_json::from_str(json).map_err(|e| RegistryError::new(FILE, e.to_string()))?;
    Ok(Permit2 {
        source: file.source,
        address: parse_checksummed(FILE, &file.address)?,
        chain_ids: file.chain_ids,
    })
}

static PERMIT2: LazyLock<Result<Permit2, RegistryError>> = LazyLock::new(|| parse(PERMIT2_JSON));

/// The embedded Permit2 location, parsed on first use.
///
/// # Errors
///
/// Only if the embedded data is corrupt, which the tests rule out.
pub fn permit2() -> Result<&'static Permit2, RegistryError> {
    PERMIT2.as_ref().map_err(Clone::clone)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn embedded_data_is_valid() {
        let p = permit2().unwrap();
        let address: Address = "0x000000000022D473030F116dDEE9F6B43aC78BA3"
            .parse()
            .unwrap();
        assert!(p.is_at(1, address));
        assert!(p.is_at(8453, address));
        assert!(!p.is_at(100, address)); // not checked on Gnosis
        assert!(!p.is_at(1, Address::ZERO));
    }
}
