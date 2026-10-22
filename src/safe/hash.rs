//! EIP-712 hashing of Safe transactions, written out by hand.
//!
//! This is the encoding exactly as the Safe contracts compute it
//! (`getTransactionHash` / `encodeTransactionData`): every field becomes one
//! 32-byte word, `bytes` fields are hashed first, and the final hash is
//! `keccak256(0x19 0x01 ‖ domainSeparator ‖ structHash)`.
//! `eip712.rs` computes the same thing with alloy; [`compute_hashes`] runs
//! both and refuses to answer if they disagree.

use alloy_primitives::{Address, B256, U256, b256, keccak256};
use thiserror::Error;

use super::eip712;
use super::{SafeAccount, SafeTx};

/// EIP-712 type of a Safe transaction, identical in every supported version
/// (1.0.0 to 1.5.0).
pub const SAFE_TX_TYPE: &str = "SafeTx(address to,uint256 value,bytes data,uint8 operation,uint256 safeTxGas,uint256 baseGas,uint256 gasPrice,address gasToken,address refundReceiver,uint256 nonce)";

/// `keccak256(SAFE_TX_TYPE)`, the `SAFE_TX_TYPEHASH` constant of the
/// contracts. A test recomputes it.
pub const SAFE_TX_TYPEHASH: B256 =
    b256!("bb8310d486368db6bd6f849402fdd73ad53d316b5a4b2644ad6efe0f941286d8");

/// EIP-712 domain type before 1.3.0: no chain id.
pub const DOMAIN_TYPE_WITHOUT_CHAIN_ID: &str = "EIP712Domain(address verifyingContract)";

/// `keccak256(DOMAIN_TYPE_WITHOUT_CHAIN_ID)`. A test recomputes it.
pub const DOMAIN_TYPEHASH_WITHOUT_CHAIN_ID: B256 =
    b256!("035aff83d86937d35b32e04f0ddc6ff469290eef2f1b692d8a815c89404d4749");

/// EIP-712 domain type from 1.3.0 on.
pub const DOMAIN_TYPE_WITH_CHAIN_ID: &str =
    "EIP712Domain(uint256 chainId,address verifyingContract)";

/// `keccak256(DOMAIN_TYPE_WITH_CHAIN_ID)`. A test recomputes it.
pub const DOMAIN_TYPEHASH_WITH_CHAIN_ID: B256 =
    b256!("47e79534a245952e8b16893a336b85a3d9ea9fa8c573f3d803afb92a79469218");

/// The three hashes a signer compares.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SafeTxHashes {
    /// EIP-712 domain separator ("Domain hash" on a Ledger).
    pub domain_hash: B256,
    /// EIP-712 struct hash of the `SafeTx` ("Message hash" on a Ledger).
    pub message_hash: B256,
    /// The hash the owners sign (`getTransactionHash`).
    pub safe_tx_hash: B256,
}

/// The two independent hash implementations disagreed. This is a bug in
/// blindsight, never a property of the input.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
#[error(
    "internal error: the two hash implementations disagree; do not trust any hash from this run and please report it"
)]
pub struct HashMismatch;

/// Computes the domain hash, message hash and safeTxHash of `tx` for the
/// Safe `account`.
///
/// Both implementations (hand-written and alloy) run on every call; if they
/// ever disagree, no hash is returned.
///
/// # Errors
///
/// [`HashMismatch`] if the two implementations disagree.
pub fn compute_hashes(account: &SafeAccount, tx: &SafeTx) -> Result<SafeTxHashes, HashMismatch> {
    let manual = compute_manual(account, tx);
    let alloy = eip712::compute_alloy(account, tx);
    if manual == alloy {
        Ok(manual)
    } else {
        Err(HashMismatch)
    }
}

/// Hand-written computation of the three hashes.
pub(crate) fn compute_manual(account: &SafeAccount, tx: &SafeTx) -> SafeTxHashes {
    let domain_hash = domain_separator(account);
    let message_hash = message_hash(tx);
    SafeTxHashes {
        domain_hash,
        message_hash,
        safe_tx_hash: signing_hash(domain_hash, message_hash),
    }
}

/// `keccak256(abi.encode(DOMAIN_TYPEHASH, [chainId,] verifyingContract))`.
fn domain_separator(account: &SafeAccount) -> B256 {
    let mut words: Vec<B256> = Vec::with_capacity(3);
    if account.version.domain_has_chain_id() {
        words.push(DOMAIN_TYPEHASH_WITH_CHAIN_ID);
        words.push(uint_word(U256::from(account.chain_id)));
    } else {
        words.push(DOMAIN_TYPEHASH_WITHOUT_CHAIN_ID);
    }
    words.push(address_word(account.address));
    keccak256(concat_words(&words))
}

/// `keccak256(abi.encode(SAFE_TX_TYPEHASH, to, value, keccak256(data), ...))`.
fn message_hash(tx: &SafeTx) -> B256 {
    let words = [
        SAFE_TX_TYPEHASH,
        address_word(tx.to),
        uint_word(tx.value),
        keccak256(&tx.data),
        uint_word(U256::from(tx.operation.as_u8())),
        uint_word(tx.safe_tx_gas),
        uint_word(tx.base_gas),
        uint_word(tx.gas_price),
        address_word(tx.gas_token),
        address_word(tx.refund_receiver),
        uint_word(tx.nonce),
    ];
    keccak256(concat_words(&words))
}

/// `keccak256(0x19 ‖ 0x01 ‖ domainSeparator ‖ structHash)`, as specified for
/// `eth_signTypedData` in EIP-712.
fn signing_hash(domain_hash: B256, message_hash: B256) -> B256 {
    let mut buf = Vec::with_capacity(2 + 32 + 32);
    buf.extend_from_slice(&[0x19, 0x01]);
    buf.extend_from_slice(domain_hash.as_slice());
    buf.extend_from_slice(message_hash.as_slice());
    keccak256(buf)
}

/// An address as an ABI word: 12 zero bytes, then the 20 address bytes.
fn address_word(address: Address) -> B256 {
    address.into_word()
}

/// A uint256 as an ABI word: 32 bytes, big-endian.
fn uint_word(value: U256) -> B256 {
    B256::from(value.to_be_bytes::<32>())
}

fn concat_words(words: &[B256]) -> Vec<u8> {
    words.iter().flat_map(|w| w.0).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn typehashes_are_keccak_of_their_type_strings() {
        assert_eq!(keccak256(SAFE_TX_TYPE), SAFE_TX_TYPEHASH);
        assert_eq!(
            keccak256(DOMAIN_TYPE_WITHOUT_CHAIN_ID),
            DOMAIN_TYPEHASH_WITHOUT_CHAIN_ID
        );
        assert_eq!(
            keccak256(DOMAIN_TYPE_WITH_CHAIN_ID),
            DOMAIN_TYPEHASH_WITH_CHAIN_ID
        );
    }

    #[test]
    fn words_are_left_padded_big_endian() {
        let addr = Address::repeat_byte(0xab);
        let word = address_word(addr);
        assert_eq!(&word[..12], &[0u8; 12]);
        assert_eq!(&word[12..], addr.as_slice());

        let word = uint_word(U256::from(0x0102u64));
        assert_eq!(&word[..30], &[0u8; 30]);
        assert_eq!(&word[30..], &[0x01, 0x02]);
    }
}
