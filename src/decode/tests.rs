//! Tests of the call tree: recursion, executors, depth limit, malformed data.

use alloy_primitives::{Address, Bytes, U256};
use alloy_sol_types::SolCall;

use super::functions::{IHelpers, ISafe};
use super::multisend::{BatchEntry, pack};
use super::*;
use crate::safe::SafeVersion;

const MULTISEND_141: &str = "0x38869bf66a61cF6bDB996A6aE40D5853Fd43B526";
const CALL_ONLY_141: &str = "0x9641d764fc13c8B624c04430C7356C1C7C8102e2";

fn safe() -> Address {
    Address::repeat_byte(0x5a)
}

fn account() -> SafeAccount {
    SafeAccount {
        address: safe(),
        chain_id: 1,
        version: SafeVersion::V1_4_1,
    }
}

fn tx(to: Address, operation: Operation, data: Vec<u8>) -> SafeTx {
    SafeTx {
        to,
        value: U256::ZERO,
        data: Bytes::from(data),
        operation,
        safe_tx_gas: U256::ZERO,
        base_gas: U256::ZERO,
        gas_price: U256::ZERO,
        gas_token: Address::ZERO,
        refund_receiver: Address::ZERO,
        nonce: U256::ZERO,
    }
}

fn multisend(entries: &[BatchEntry]) -> Vec<u8> {
    IHelpers::multiSendCall {
        transactions: Bytes::from(pack(entries)),
    }
    .abi_encode()
}

fn exec(to: Address, operation: u8, data: Vec<u8>) -> Vec<u8> {
    ISafe::execTransactionCall {
        to,
        value: U256::ZERO,
        data: Bytes::from(data),
        operation,
        safeTxGas: U256::ZERO,
        baseGas: U256::ZERO,
        gasPrice: U256::ZERO,
        gasToken: Address::ZERO,
        refundReceiver: Address::ZERO,
        signatures: Bytes::new(),
    }
    .abi_encode()
}

fn entry(operation: Operation, to: Address, data: Vec<u8>) -> BatchEntry {
    BatchEntry {
        operation,
        to,
        value: U256::ZERO,
        data: Bytes::from(data),
    }
}

fn change_threshold() -> Vec<u8> {
    ISafe::changeThresholdCall {
        _threshold: U256::from(1u64),
    }
    .abi_encode()
}

#[test]
fn empty_data_and_unknown_selectors() {
    let root = decode_tree(&account(), &tx(Address::ZERO, Operation::Call, vec![])).unwrap();
    assert_eq!(root.decoded, DecodedCall::Empty);
    let root = decode_tree(
        &account(),
        &tx(Address::ZERO, Operation::Call, vec![1, 2, 3, 4, 5]),
    )
    .unwrap();
    assert_eq!(
        root.decoded,
        DecodedCall::Unknown {
            selector: Some([1, 2, 3, 4])
        }
    );
    let root = decode_tree(&account(), &tx(Address::ZERO, Operation::Call, vec![1, 2])).unwrap();
    assert_eq!(root.decoded, DecodedCall::Unknown { selector: None });
}

#[test]
fn batch_items_run_as_the_safe_when_delegatecalled() {
    let data = multisend(&[
        entry(Operation::Call, safe(), change_threshold()),
        entry(Operation::Call, Address::repeat_byte(9), vec![]),
    ]);
    let ms = MULTISEND_141.parse().unwrap();
    let root = decode_tree(&account(), &tx(ms, Operation::DelegateCall, data)).unwrap();
    let DecodedCall::Batch {
        semantics,
        call_only,
        items,
    } = &root.decoded
    else {
        panic!("not a batch: {:?}", root.decoded);
    };
    assert!(semantics.is_verified());
    assert!(!call_only);
    assert_eq!(items.len(), 2);
    assert_eq!(items[0].path.to_string(), "batch[0]");
    assert_eq!(items[0].executor, safe());
    // changeThreshold on the Safe itself, inside the batch: verified.
    assert!(matches!(
        &items[0].decoded,
        DecodedCall::Known { semantics, .. } if semantics.is_verified()
    ));
    assert_eq!(root.nodes().len(), 3);
}

#[test]
fn call_only_batches_are_recognised() {
    let target = CALL_ONLY_141.parse().unwrap();
    let data = multisend(&[entry(Operation::Call, Address::ZERO, vec![])]);
    let root = decode_tree(&account(), &tx(target, Operation::DelegateCall, data)).unwrap();
    assert!(matches!(
        root.decoded,
        DecodedCall::Batch {
            call_only: true,
            ..
        }
    ));
}

#[test]
fn batch_called_without_delegatecall_runs_as_the_batch_contract() {
    let target = CALL_ONLY_141.parse().unwrap();
    let data = multisend(&[entry(Operation::Call, safe(), change_threshold())]);
    let root = decode_tree(&account(), &tx(target, Operation::Call, data)).unwrap();
    let DecodedCall::Batch {
        semantics, items, ..
    } = &root.decoded
    else {
        panic!("not a batch");
    };
    assert!(!semantics.is_verified());
    assert_eq!(items[0].executor, target);
    // changeThreshold sent to the Safe by another contract: not verified.
    assert!(matches!(
        &items[0].decoded,
        DecodedCall::Known { semantics, .. } if !semantics.is_verified()
    ));
}

#[test]
fn unofficial_batch_targets_are_still_decoded() {
    let fake = Address::repeat_byte(0xee);
    let data = multisend(&[entry(
        Operation::DelegateCall,
        Address::repeat_byte(1),
        vec![],
    )]);
    let root = decode_tree(&account(), &tx(fake, Operation::DelegateCall, data)).unwrap();
    let DecodedCall::Batch {
        semantics, items, ..
    } = &root.decoded
    else {
        panic!("not a batch");
    };
    assert_eq!(*semantics, Semantics::SelectorOnly);
    assert_eq!(items[0].operation, Operation::DelegateCall);
}

#[test]
fn nested_safe_transactions_run_as_the_inner_safe() {
    let inner_safe = Address::repeat_byte(0x77);
    let data = exec(inner_safe, 0, change_threshold());
    let root = decode_tree(&account(), &tx(inner_safe, Operation::Call, data)).unwrap();
    let DecodedCall::Nested {
        semantics, inner, ..
    } = &root.decoded
    else {
        panic!("not nested");
    };
    assert_eq!(*semantics, Semantics::SelectorOnly);
    assert_eq!(inner.path.to_string(), "nested");
    assert_eq!(inner.executor, inner_safe);
    assert_eq!(inner.to, inner_safe);
    // The inner Safe changing its own threshold is a verified admin call.
    assert!(matches!(
        &inner.decoded,
        DecodedCall::Known { semantics, .. } if semantics.is_verified()
    ));
}

#[test]
fn nested_with_invalid_inner_operation_is_malformed() {
    let data = exec(Address::ZERO, 2, vec![]);
    let root = decode_tree(&account(), &tx(Address::ZERO, Operation::Call, data)).unwrap();
    assert!(matches!(
        root.decoded,
        DecodedCall::Malformed {
            function: Some("execTransaction"),
            ..
        }
    ));
}

#[test]
fn malformed_batches_and_arguments() {
    let mut bad = pack(&[entry(Operation::Call, Address::ZERO, vec![1])]);
    bad.pop();
    let data = IHelpers::multiSendCall {
        transactions: Bytes::from(bad),
    }
    .abi_encode();
    let root = decode_tree(
        &account(),
        &tx(Address::ZERO, Operation::DelegateCall, data),
    )
    .unwrap();
    assert!(matches!(
        root.decoded,
        DecodedCall::Malformed {
            function: Some("multiSend"),
            ..
        }
    ));

    let root = decode_tree(
        &account(),
        &tx(
            Address::ZERO,
            Operation::Call,
            vec![0xa9, 0x05, 0x9c, 0xbb, 0],
        ),
    )
    .unwrap();
    assert!(matches!(root.decoded, DecodedCall::Malformed { .. }));
}

/// Wraps `data` in `levels` alternating batch / nested layers.
fn wrap(levels: usize, mut data: Vec<u8>) -> Vec<u8> {
    for level in 0..levels {
        data = if level % 2 == 0 {
            multisend(&[entry(Operation::Call, Address::repeat_byte(1), data)])
        } else {
            exec(Address::repeat_byte(2), 0, data)
        };
    }
    data
}

#[test]
fn depth_limit() {
    // MAX_DEPTH levels of wrapping: the innermost call is still decoded.
    let root = decode_tree(
        &account(),
        &tx(
            Address::repeat_byte(3),
            Operation::Call,
            wrap(MAX_DEPTH, change_threshold()),
        ),
    )
    .unwrap();
    let deepest = root.nodes().into_iter().last().unwrap();
    assert_eq!(deepest.path.depth(), MAX_DEPTH);
    assert!(matches!(deepest.decoded, DecodedCall::Known { .. }));

    // One more level: the innermost call is not analysed.
    let root = decode_tree(
        &account(),
        &tx(
            Address::repeat_byte(3),
            Operation::Call,
            wrap(MAX_DEPTH + 1, change_threshold()),
        ),
    )
    .unwrap();
    let deepest = root.nodes().into_iter().last().unwrap();
    assert_eq!(deepest.path.depth(), MAX_DEPTH + 1);
    assert_eq!(deepest.decoded, DecodedCall::TooDeep);
}

#[test]
fn paths_display() {
    let p = CallPath::default()
        .child(Step::Batch(2))
        .child(Step::Nested)
        .child(Step::Batch(0));
    assert_eq!(p.to_string(), "batch[2] > nested > batch[0]");
    assert_eq!(CallPath::default().to_string(), "root");
}
