//! A short, curated list of tokens per chain, from `data/tokens.json`.
//!
//! Source: the Uniswap Labs default token list; every entry was confirmed by
//! reading `symbol()` and `decimals()` from the token contract itself
//! (`scripts/fixtures/gen_tokens.py`). Being in this list makes an ERC-20
//! call's meaning verified: the target is a known token, so `transfer` really
//! is a token transfer.

use std::collections::BTreeMap;
use std::sync::LazyLock;

use alloy_primitives::Address;
use serde::Deserialize;

use super::{RegistryError, parse_checksummed};

const TOKENS_JSON: &str = include_str!("../../data/tokens.json");
const FILE: &str = "tokens.json";

/// A known ERC-20 token.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Token {
    /// Chain id.
    pub chain_id: u64,
    /// Contract address.
    pub address: Address,
    /// Ticker, e.g. `USDC`.
    pub symbol: String,
    /// Full name.
    pub name: String,
    /// Decimals used to display amounts.
    pub decimals: u8,
}

/// Known tokens, by `(chain id, address)`.
#[derive(Debug)]
pub struct TokenList {
    by_location: BTreeMap<(u64, Address), Token>,
}

impl TokenList {
    /// The token at `address` on `chain_id`, if known.
    pub fn get(&self, chain_id: u64, address: Address) -> Option<&Token> {
        self.by_location.get(&(chain_id, address))
    }

    /// Number of tokens.
    pub fn len(&self) -> usize {
        self.by_location.len()
    }

    /// Whether the list is empty (never, for the embedded data).
    pub fn is_empty(&self) -> bool {
        self.by_location.is_empty()
    }

    /// Iterates over the tokens.
    pub fn iter(&self) -> impl Iterator<Item = &Token> {
        self.by_location.values()
    }
}

#[derive(Deserialize)]
struct TokensFile {
    tokens: Vec<TokenEntry>,
}

#[derive(Deserialize)]
struct TokenEntry {
    chain_id: u64,
    address: String,
    symbol: String,
    name: String,
    decimals: u8,
}

fn parse(json: &str) -> Result<TokenList, RegistryError> {
    let file: TokensFile =
        serde_json::from_str(json).map_err(|e| RegistryError::new(FILE, e.to_string()))?;
    let mut by_location = BTreeMap::new();
    for entry in file.tokens {
        let address = parse_checksummed(FILE, &entry.address)?;
        let token = Token {
            chain_id: entry.chain_id,
            address,
            symbol: entry.symbol,
            name: entry.name,
            decimals: entry.decimals,
        };
        if by_location
            .insert((entry.chain_id, address), token)
            .is_some()
        {
            return Err(RegistryError::new(
                FILE,
                format!("duplicate token {address} on chain {}", entry.chain_id),
            ));
        }
    }
    Ok(TokenList { by_location })
}

static TOKENS: LazyLock<Result<TokenList, RegistryError>> = LazyLock::new(|| parse(TOKENS_JSON));

/// The embedded token list, parsed on first use.
///
/// # Errors
///
/// Only if the embedded data is corrupt, which the tests rule out.
pub fn tokens() -> Result<&'static TokenList, RegistryError> {
    TOKENS.as_ref().map_err(Clone::clone)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::registry::chains;

    #[test]
    fn embedded_list_is_valid() {
        let list = tokens().unwrap();
        assert_eq!(list.len(), 31);
        let table = chains().unwrap();
        for t in list.iter() {
            assert!(table.get(t.chain_id).is_some());
            assert!(t.symbol.chars().all(|c| c.is_ascii_alphanumeric()));
            assert!(t.decimals <= 18);
        }
    }

    #[test]
    fn finds_tokens_used_by_the_real_vectors() {
        let list = tokens().unwrap();
        let usdc_eth: Address = "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48"
            .parse()
            .unwrap();
        let usdc = list.get(1, usdc_eth).unwrap();
        assert_eq!((usdc.symbol.as_str(), usdc.decimals), ("USDC", 6));
        // Same address, other chain: not a known token there.
        assert!(list.get(8453, usdc_eth).is_none());
    }

    #[test]
    fn rejects_bad_checksums_and_duplicates() {
        let bad = r#"{"tokens":[{"chain_id":1,"address":"0xa0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48","symbol":"U","name":"U","decimals":6}]}"#;
        assert!(parse(bad).is_err());
        let dup = r#"{"tokens":[
            {"chain_id":1,"address":"0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48","symbol":"U","name":"U","decimals":6},
            {"chain_id":1,"address":"0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48","symbol":"V","name":"V","decimals":6}]}"#;
        assert!(parse(dup).is_err());
    }
}
