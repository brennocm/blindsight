//! Report tests: exit-code rules, hash checks and both renderers.

use alloy_primitives::{Address, B256, Bytes, U256};

use super::*;
use crate::input::TxInput;
use crate::safe::{Operation, SafeAccount, SafeTx, SafeVersion};

fn input(to: Address, operation: Operation, data: Vec<u8>) -> TxInput {
    TxInput {
        account: SafeAccount {
            address: Address::repeat_byte(0x5a),
            chain_id: 1,
            version: SafeVersion::V1_4_1,
        },
        tx: SafeTx {
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
        },
        claimed_safe_tx_hash: None,
        signatures: None,
        warnings: Vec::new(),
    }
}

fn critical_input() -> TxInput {
    input(
        Address::repeat_byte(0xee),
        Operation::DelegateCall,
        vec![1, 2, 3, 4],
    )
}

#[test]
fn exit_codes_follow_fail_on_and_mismatch_wins() {
    let report = analyse(Command::Verify, critical_input(), Options::default()).unwrap();
    assert_eq!(report.verdict(), Some(Severity::Critical));
    assert_eq!(report.exit_code(), EXIT_FINDINGS);

    // Nothing reaches the threshold for a harmless transfer.
    let plain = input(Address::repeat_byte(1), Operation::Call, vec![]);
    let report = analyse(Command::Verify, plain, Options::default()).unwrap();
    assert_eq!(report.exit_code(), EXIT_OK);

    // A mismatch is exit 3 even with critical findings.
    let options = Options {
        expect_safe_tx_hash: Some(B256::repeat_byte(1)),
        ..Options::default()
    };
    let report = analyse(Command::Verify, critical_input(), options).unwrap();
    assert!(report.hash_mismatch());
    assert_eq!(report.exit_code(), EXIT_HASH_MISMATCH);
}

#[test]
fn hash_command_has_no_findings_and_never_exits_1() {
    let report = analyse(Command::Hash, critical_input(), Options::default()).unwrap();
    assert!(report.findings.is_none() && report.tree.is_none());
    assert_eq!(report.exit_code(), EXIT_OK);
}

#[test]
fn claimed_hash_from_the_file_is_checked() {
    let mut tx_input = input(Address::repeat_byte(1), Operation::Call, vec![]);
    let correct = crate::safe::compute_hashes(&tx_input.account, &tx_input.tx)
        .unwrap()
        .safe_tx_hash;
    tx_input.claimed_safe_tx_hash = Some(correct);
    let report = analyse(Command::Hash, tx_input.clone(), Options::default()).unwrap();
    assert_eq!(report.checks.len(), 1);
    assert!(report.checks[0].matches());
    assert_eq!(report.checks[0].source, CheckSource::InputFile);

    tx_input.claimed_safe_tx_hash = Some(B256::ZERO);
    let report = analyse(Command::Hash, tx_input, Options::default()).unwrap();
    assert_eq!(report.exit_code(), EXIT_HASH_MISMATCH);
}

#[test]
fn every_check_compares_the_right_hash() {
    let tx_input = input(Address::repeat_byte(1), Operation::Call, vec![]);
    let h = crate::safe::compute_hashes(&tx_input.account, &tx_input.tx).unwrap();
    let options = Options {
        expect_domain_hash: Some(h.domain_hash),
        expect_message_hash: Some(h.message_hash),
        expect_safe_tx_hash: Some(h.safe_tx_hash),
        ..Options::default()
    };
    let report = analyse(Command::Hash, tx_input, options).unwrap();
    assert_eq!(report.checks.len(), 3);
    assert!(report.checks.iter().all(HashCheck::matches));
}

#[test]
fn renderers_mark_unverified_names_and_produce_valid_json() {
    let data = crate::decode::functions::IERC20::transferCall {
        to: Address::repeat_byte(1),
        amount: U256::from(5u64),
    };
    let data = alloy_sol_types::SolCall::abi_encode(&data);
    let tx_input = input(Address::repeat_byte(0xee), Operation::DelegateCall, data);
    let report = analyse(Command::Verify, tx_input, Options::default()).unwrap();
    let text = text::render(&report);
    assert!(text.contains("CRITICAL: DO NOT SIGN"));
    assert!(text.contains("UNVERIFIED: name inferred from the selector only"));
    let json: serde_json::Value = serde_json::from_str(&json::render(&report)).unwrap();
    assert_eq!(json["schema_version"], SCHEMA_VERSION);
    assert_eq!(json["calls"]["decoded"]["kind"], "known");
    assert_eq!(json["calls"]["decoded"]["function"], "transfer");
    assert_eq!(json["exit_code"], 1);
}

#[test]
fn malformed_reasons_are_sanitised() {
    // A Malformed node's reason comes from the decoder; make sure the renderer
    // would neutralise control characters if one ever contained them.
    let mut report = analyse(
        Command::Decode,
        input(Address::repeat_byte(1), Operation::Call, vec![1, 2, 3, 4]),
        Options::default(),
    )
    .unwrap();
    if let Some(root) = report.tree.as_mut() {
        root.decoded = crate::decode::DecodedCall::Malformed {
            function: None,
            reason: "bad\u{1b}[2Jreason".to_string(),
        };
    }
    let text = text::render(&report);
    assert!(!text.contains("\u{1b}[2J") && text.contains("\\u{1b}[2J"));
    let json = json::render(&report);
    assert!(json.contains("bad\\\\u{1b}[2Jreason"));
}
