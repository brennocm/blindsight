//! Property tests of the hashing core.

use alloy_primitives::{Address, Bytes, U256};
use proptest::prelude::*;

use super::eip712::compute_alloy;
use super::hash::compute_manual;
use super::{Operation, SafeAccount, SafeTx, SafeVersion, compute_hashes};

fn address() -> impl Strategy<Value = Address> {
    any::<[u8; 20]>().prop_map(Address::from)
}

fn uint() -> impl Strategy<Value = U256> {
    prop_oneof![
        any::<u64>().prop_map(U256::from),
        any::<[u8; 32]>().prop_map(U256::from_be_bytes),
        Just(U256::ZERO),
        Just(U256::MAX),
    ]
}

fn operation() -> impl Strategy<Value = Operation> {
    prop_oneof![Just(Operation::Call), Just(Operation::DelegateCall)]
}

fn version() -> impl Strategy<Value = SafeVersion> {
    proptest::sample::select(SafeVersion::ALL.to_vec())
}

prop_compose! {
    fn safe_tx()(
        to in address(),
        value in uint(),
        data in proptest::collection::vec(any::<u8>(), 0..300),
        operation in operation(),
        safe_tx_gas in uint(),
        base_gas in uint(),
        gas_price in uint(),
        gas_token in address(),
        refund_receiver in address(),
        nonce in uint(),
    ) -> SafeTx {
        SafeTx {
            to, value, data: Bytes::from(data), operation, safe_tx_gas, base_gas,
            gas_price, gas_token, refund_receiver, nonce,
        }
    }
}

prop_compose! {
    fn account()(address in address(), chain_id in any::<u64>(), version in version()) -> SafeAccount {
        SafeAccount { address, chain_id, version }
    }
}

/// Returns `tx` with exactly one field changed to a different value.
fn mutate(tx: &SafeTx, field: usize) -> SafeTx {
    let mut out = tx.clone();
    let flip_addr = |a: Address| {
        let mut b = a.0.0;
        b[19] ^= 1;
        Address::from(b)
    };
    let flip_uint = |v: U256| v ^ U256::from(1u8);
    match field {
        0 => out.to = flip_addr(tx.to),
        1 => out.value = flip_uint(tx.value),
        2 => {
            let mut d = tx.data.to_vec();
            d.push(0);
            out.data = Bytes::from(d);
        }
        3 => {
            out.operation = match tx.operation {
                Operation::Call => Operation::DelegateCall,
                Operation::DelegateCall => Operation::Call,
            }
        }
        4 => out.safe_tx_gas = flip_uint(tx.safe_tx_gas),
        5 => out.base_gas = flip_uint(tx.base_gas),
        6 => out.gas_price = flip_uint(tx.gas_price),
        7 => out.gas_token = flip_addr(tx.gas_token),
        8 => out.refund_receiver = flip_addr(tx.refund_receiver),
        _ => out.nonce = flip_uint(tx.nonce),
    }
    out
}

proptest! {
    #[test]
    fn manual_and_alloy_always_agree(account in account(), tx in safe_tx()) {
        prop_assert_eq!(compute_manual(&account, &tx), compute_alloy(&account, &tx));
        prop_assert!(compute_hashes(&account, &tx).is_ok());
    }

    #[test]
    fn hashing_is_deterministic(account in account(), tx in safe_tx()) {
        prop_assert_eq!(compute_manual(&account, &tx), compute_manual(&account, &tx));
    }

    #[test]
    fn changing_any_field_changes_message_and_safe_tx_hash(
        account in account(), tx in safe_tx(), field in 0usize..10
    ) {
        let changed = mutate(&tx, field);
        prop_assert_ne!(&changed, &tx);
        let a = compute_manual(&account, &tx);
        let b = compute_manual(&account, &changed);
        prop_assert_eq!(a.domain_hash, b.domain_hash);
        prop_assert_ne!(a.message_hash, b.message_hash);
        prop_assert_ne!(a.safe_tx_hash, b.safe_tx_hash);
    }

    #[test]
    fn changing_the_safe_address_changes_the_domain(account in account(), tx in safe_tx()) {
        let mut other = account;
        let mut b = other.address.0.0;
        b[0] ^= 0x80;
        other.address = Address::from(b);
        let a = compute_manual(&account, &tx);
        let b = compute_manual(&other, &tx);
        prop_assert_ne!(a.domain_hash, b.domain_hash);
        prop_assert_ne!(a.safe_tx_hash, b.safe_tx_hash);
        prop_assert_eq!(a.message_hash, b.message_hash);
    }

    /// From 1.3.0 the chain id is part of the domain; before, it is not, so
    /// the same signature is valid on every chain (cross-chain replay).
    #[test]
    fn chain_id_matters_only_from_1_3_0(account in account(), tx in safe_tx()) {
        let mut other = account;
        other.chain_id = account.chain_id.wrapping_add(1);
        let a = compute_manual(&account, &tx);
        let b = compute_manual(&other, &tx);
        if account.version.domain_has_chain_id() {
            prop_assert_ne!(a.domain_hash, b.domain_hash);
            prop_assert_ne!(a.safe_tx_hash, b.safe_tx_hash);
        } else {
            prop_assert_eq!(a, b);
        }
    }

    #[test]
    fn domain_formats_differ_and_versions_sharing_one_hash_alike(
        address in address(), chain_id in any::<u64>(), tx in safe_tx(),
        v1 in version(), v2 in version(),
    ) {
        let a = compute_manual(&SafeAccount { address, chain_id, version: v1 }, &tx);
        let b = compute_manual(&SafeAccount { address, chain_id, version: v2 }, &tx);
        prop_assert_eq!(a.message_hash, b.message_hash);
        if v1.domain_has_chain_id() == v2.domain_has_chain_id() {
            prop_assert_eq!(a, b);
        } else {
            prop_assert_ne!(a.domain_hash, b.domain_hash);
            prop_assert_ne!(a.safe_tx_hash, b.safe_tx_hash);
        }
    }
}
