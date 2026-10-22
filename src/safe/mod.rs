//! Safe transactions and their EIP-712 hashes.
//!
//! - [`SafeVersion`]: which contract version, which selects the domain format;
//! - [`SafeTx`], [`Operation`], [`SafeAccount`]: the transaction and the Safe
//!   that executes it;
//! - [`compute_hashes`]: domain hash, message hash and safeTxHash.

mod eip712;
mod hash;
mod tx;
mod version;

#[cfg(test)]
mod proptests;

pub use hash::{
    DOMAIN_TYPE_WITH_CHAIN_ID, DOMAIN_TYPE_WITHOUT_CHAIN_ID, DOMAIN_TYPEHASH_WITH_CHAIN_ID,
    DOMAIN_TYPEHASH_WITHOUT_CHAIN_ID, HashMismatch, SAFE_TX_TYPE, SAFE_TX_TYPEHASH, SafeTxHashes,
    compute_hashes,
};
pub use tx::{InvalidOperation, Operation, SafeAccount, SafeTx};
pub use version::{SafeVersion, UnsupportedVersion};
