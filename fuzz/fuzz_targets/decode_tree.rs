//! The whole decoder on arbitrary calldata: no panic, depth never exceeds
//! the limit + 1. The first byte picks the mode (bit 0: target is the
//! official MultiSend, so batches are verified; bit 1: delegatecall), the
//! rest is the calldata. Seed with real calldata prefixed by 0x03.
#![no_main]

use alloy_primitives::{Address, Bytes, U256};
use blindsight::decode::{MAX_DEPTH, UserAbis, decode_tree};
use blindsight::safe::{Operation, SafeAccount, SafeTx, SafeVersion};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|input: &[u8]| {
    let Some((mode, data)) = input.split_first() else {
        return;
    };
    let official = mode & 1 == 1;
    let delegate = mode & 2 == 2;
    let to: Address = if official {
        // MultiSend 1.4.1, canonical deployment.
        "0x38869bf66a61cF6bDB996A6aE40D5853Fd43B526".parse().unwrap()
    } else {
        Address::repeat_byte(0x99)
    };
    let account = SafeAccount {
        address: Address::repeat_byte(0x5a),
        chain_id: 1,
        version: SafeVersion::V1_4_1,
    };
    let tx = SafeTx {
        to,
        value: U256::ZERO,
        data: Bytes::copy_from_slice(data),
        operation: if delegate { Operation::DelegateCall } else { Operation::Call },
        safe_tx_gas: U256::ZERO,
        base_gas: U256::ZERO,
        gas_price: U256::ZERO,
        gas_token: Address::ZERO,
        refund_receiver: Address::ZERO,
        nonce: U256::ZERO,
    };
    let root = decode_tree(&account, &tx, &UserAbis::default()).unwrap();
    for node in root.nodes() {
        assert!(node.path.depth() <= MAX_DEPTH + 1);
    }
});
