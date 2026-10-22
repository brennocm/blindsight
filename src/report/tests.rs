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

#[test]
fn json_covers_every_node_kind() {
    use alloy_sol_types::SolCall;

    use crate::decode::functions::{IHelpers, ISafe};
    use crate::decode::multisend::{BatchEntry, pack};

    let entry = |data: Vec<u8>| BatchEntry {
        operation: Operation::Call,
        to: Address::repeat_byte(3),
        value: U256::from(1u8),
        data: Bytes::from(data),
    };
    // A nested Safe transaction whose inner call is a batch with an empty,
    // an unknown, a short and a malformed entry, and one to a user ABI.
    let mut malformed = vec![0xa9, 0x05, 0x9c, 0xbb];
    malformed.push(0);
    let batch = IHelpers::multiSendCall {
        transactions: Bytes::from(pack(&[
            entry(vec![]),
            entry(vec![1, 2, 3, 4]),
            entry(vec![1]),
            entry(malformed),
            BatchEntry {
                to: Address::repeat_byte(9),
                ..entry(vec![0x12, 0x34, 0x56, 0x78])
            },
        ])),
    }
    .abi_encode();
    let nested = ISafe::execTransactionCall {
        to: "0x38869bf66a61cF6bDB996A6aE40D5853Fd43B526"
            .parse()
            .unwrap(),
        value: U256::ZERO,
        data: Bytes::from(batch),
        operation: 1,
        safeTxGas: U256::ZERO,
        baseGas: U256::ZERO,
        gasPrice: U256::ZERO,
        gasToken: Address::ZERO,
        refundReceiver: Address::ZERO,
        signatures: Bytes::new(),
    }
    .abi_encode();
    let mut tx_input = input(Address::repeat_byte(0x77), Operation::Call, nested);
    // One signature of each kind.
    let mut sigs = Vec::new();
    for v in [0u8, 1, 27, 31, 9] {
        let mut s = vec![0u8; 65];
        s[32..64].copy_from_slice(&U256::from(1000u64).to_be_bytes::<32>());
        s[64] = v;
        sigs.extend(s);
    }
    tx_input.signatures = Some(Bytes::from(sigs));
    let mut abis = crate::decode::UserAbis::default();
    abis.add(
        Address::repeat_byte(9),
        r#"[{"type":"function","name":"poke","stateMutability":"nonpayable","inputs":[],"outputs":[]}]"#,
    )
    .unwrap();
    // The ABI bound to 0x0909… has no function with selector 0x12345678, so
    // that entry stays unknown (a matching call is tested below).
    let options = Options {
        user_abis: abis,
        ..Options::default()
    };
    let report = analyse(Command::Verify, tx_input, options).unwrap();
    let json: serde_json::Value = serde_json::from_str(&json::render(&report)).unwrap();
    let nested = &json["calls"]["decoded"];
    assert_eq!(nested["kind"], "nested");
    let items = nested["inner"]["decoded"]["items"].as_array().unwrap();
    let kinds: Vec<&str> = items
        .iter()
        .map(|i| i["decoded"]["kind"].as_str().unwrap())
        .collect();
    assert_eq!(
        kinds,
        ["empty", "unknown", "unknown", "malformed", "unknown"]
    );
    let sig_kinds: Vec<&str> = json["signatures"]
        .as_array()
        .unwrap()
        .iter()
        .map(|s| s.get("kind").and_then(|k| k.as_str()).unwrap())
        .collect();
    assert_eq!(
        sig_kinds,
        [
            "contract",
            "approved_hash",
            "typed_data",
            "eth_sign",
            "invalid"
        ]
    );
    let text = text::render(&report);
    assert!(text.contains("nested Safe transaction") && text.contains("MALFORMED"));
}

#[test]
fn json_user_abi_and_too_deep_nodes() {
    use alloy_sol_types::SolCall;

    use crate::decode::functions::IHelpers;
    use crate::decode::multisend::{BatchEntry, pack};

    let target = Address::repeat_byte(9);
    let mut abis = crate::decode::UserAbis::default();
    abis.add(
        target,
        r#"[{"type":"function","name":"poke","stateMutability":"nonpayable","inputs":[{"name":"n","type":"uint8"}],"outputs":[]}]"#,
    )
    .unwrap();
    let mut data = alloy_primitives::keccak256("poke(uint8)")[..4].to_vec();
    data.extend_from_slice(&U256::from(7u8).to_be_bytes::<32>());
    let report = analyse(
        Command::Decode,
        input(target, Operation::Call, data),
        Options {
            user_abis: abis,
            ..Options::default()
        },
    )
    .unwrap();
    let json: serde_json::Value = serde_json::from_str(&json::render(&report)).unwrap();
    assert_eq!(json["calls"]["decoded"]["kind"], "user");
    assert_eq!(json["calls"]["decoded"]["args"][0]["value"], "7");
    assert!(json.get("hashes").is_none());

    let mut payload = vec![1, 2, 3, 4];
    for _ in 0..=crate::decode::MAX_DEPTH {
        payload = IHelpers::multiSendCall {
            transactions: Bytes::from(pack(&[BatchEntry {
                operation: Operation::Call,
                to: Address::repeat_byte(1),
                value: U256::ZERO,
                data: Bytes::from(payload),
            }])),
        }
        .abi_encode();
    }
    let report = analyse(
        Command::Verify,
        input(Address::repeat_byte(1), Operation::Call, payload),
        Options::default(),
    )
    .unwrap();
    let rendered = json::render(&report);
    assert!(rendered.contains("\"kind\": \"too_deep\""));
    assert!(text::render(&report).contains("NOT ANALYSED"));
}

#[test]
fn token_decimals_only_for_calls_to_listed_tokens() {
    let usdc: Address = "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48"
        .parse()
        .unwrap();
    let data =
        alloy_sol_types::SolCall::abi_encode(&crate::decode::functions::IERC20::transferCall {
            to: Address::repeat_byte(1),
            amount: U256::from(1_500_000u64),
        });
    let call = analyse(
        Command::Decode,
        input(usdc, Operation::Call, data.clone()),
        Options::default(),
    )
    .unwrap();
    assert!(text::render(&call).contains("1.5 USDC"));
    // Delegatecalled, the same calldata moves no tokens.
    let delegate = analyse(
        Command::Decode,
        input(usdc, Operation::DelegateCall, data),
        Options::default(),
    )
    .unwrap();
    let text = text::render(&delegate);
    assert!(
        !text.contains("1.5 USDC") && text.contains("1500000"),
        "{text}"
    );
}
