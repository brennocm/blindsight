//! The same hashes as `hash.rs`, computed with alloy's EIP-712 support.
//!
//! `sol!` turns the Solidity struct below into a Rust struct that implements
//! `SolStruct`, which knows how to encode and hash itself per EIP-712. If the
//! hand-written encoding and this one ever disagree, one of them is wrong.

use alloy_primitives::U256;
use alloy_sol_types::{Eip712Domain, SolStruct};

use super::{SafeAccount, SafeTx, SafeTxHashes};

mod abi {
    alloy_sol_types::sol! {
        /// The EIP-712 `SafeTx` type, field for field as in `Safe.sol`.
        struct SafeTx {
            address to;
            uint256 value;
            bytes data;
            uint8 operation;
            uint256 safeTxGas;
            uint256 baseGas;
            uint256 gasPrice;
            address gasToken;
            address refundReceiver;
            uint256 nonce;
        }
    }
}

/// Builds the Safe's EIP-712 domain. Safe domains never have `name`,
/// `version` or `salt`; `chainId` only from 1.3.0 on.
pub(crate) fn domain(account: &SafeAccount) -> Eip712Domain {
    Eip712Domain {
        name: None,
        version: None,
        chain_id: if account.version.domain_has_chain_id() {
            Some(U256::from(account.chain_id))
        } else {
            None
        },
        verifying_contract: Some(account.address),
        salt: None,
    }
}

/// alloy computation of the three hashes.
pub(crate) fn compute_alloy(account: &SafeAccount, tx: &SafeTx) -> SafeTxHashes {
    let domain = domain(account);
    let typed = abi::SafeTx {
        to: tx.to,
        value: tx.value,
        // `Bytes` is reference-counted: this clone does not copy the calldata.
        data: tx.data.clone(),
        operation: tx.operation.as_u8(),
        safeTxGas: tx.safe_tx_gas,
        baseGas: tx.base_gas,
        gasPrice: tx.gas_price,
        gasToken: tx.gas_token,
        refundReceiver: tx.refund_receiver,
        nonce: tx.nonce,
    };
    SafeTxHashes {
        domain_hash: domain.separator(),
        message_hash: typed.eip712_hash_struct(),
        safe_tx_hash: typed.eip712_signing_hash(&domain),
    }
}

#[cfg(test)]
mod tests {
    use alloy_primitives::Address;

    use super::super::SafeVersion;
    use super::super::hash::{
        DOMAIN_TYPE_WITH_CHAIN_ID, DOMAIN_TYPE_WITHOUT_CHAIN_ID, SAFE_TX_TYPE,
    };
    use super::*;

    #[test]
    fn alloy_derives_the_same_type_strings() {
        assert_eq!(abi::SafeTx::eip712_encode_type(), SAFE_TX_TYPE);
        for version in SafeVersion::ALL {
            let account = SafeAccount {
                address: Address::ZERO,
                chain_id: 1,
                version,
            };
            let expected = if version.domain_has_chain_id() {
                DOMAIN_TYPE_WITH_CHAIN_ID
            } else {
                DOMAIN_TYPE_WITHOUT_CHAIN_ID
            };
            assert_eq!(domain(&account).encode_type(), expected);
        }
    }
}
