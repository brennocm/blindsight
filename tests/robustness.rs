//! Robustness: hostile or extreme input must produce an answer or a clean
//! error, never a panic, a hang or unbounded memory.

// Test code: a panic is how a test reports failure (see clippy.toml and ADR 0004).
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

use std::fs;
use std::path::Path;
use std::time::{Duration, Instant};

use alloy_primitives::{Address, Bytes, U256};
use assert_cmd::Command;
use blindsight::decode::multisend::{BatchEntry, pack};
use blindsight::decode::{DecodedCall, MAX_DEPTH, UserAbis, decode_tree};
use blindsight::input::exec::parse_exec_calldata;
use blindsight::input::json::parse_json;
use blindsight::input::{InputError, MAX_CALLDATA_BYTES, MAX_JSON_BYTES, TxFlags};
use blindsight::report::{self, Command as ReportCommand, Options};
use blindsight::safe::{Operation, SafeAccount, SafeTx, SafeVersion};
use serde_json::Value;

const SAFE: &str = "0x1Db92e2EeBC8E0c075a02BeA49a2935BcD2dFCF4";
const MULTISEND_141: &str = "0x38869bf66a61cF6bDB996A6aE40D5853Fd43B526";

fn blindsight() -> Command {
    let mut cmd = Command::cargo_bin("blindsight").unwrap();
    cmd.env("NO_COLOR", "1");
    cmd
}

fn account() -> SafeAccount {
    SafeAccount {
        address: SAFE.parse().unwrap(),
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
    use alloy_sol_types::SolCall;
    blindsight::decode::functions::IHelpers::multiSendCall {
        transactions: Bytes::from(pack(entries)),
    }
    .abi_encode()
}

#[test]
fn calldata_at_and_over_the_limit() {
    // The exact limit through the library, an oversized stdin input through
    // the binary.
    let at_limit = format!("0x{}", "ab".repeat(MAX_CALLDATA_BYTES));
    let partial = TxFlags {
        chain_id: Some("1".into()),
        safe: Some(SAFE.into()),
        safe_version: Some("1.4.1".into()),
        to: Some(SAFE.into()),
        nonce: Some("0".into()),
        data: Some(at_limit.clone()),
        ..TxFlags::default()
    }
    .parse()
    .unwrap();
    assert_eq!(partial.data.as_ref().unwrap().len(), MAX_CALLDATA_BYTES);
    let over = TxFlags {
        data: Some(format!("{at_limit}ab")),
        ..TxFlags::default()
    }
    .parse();
    assert!(matches!(over, Err(InputError::TooLarge { .. })));

    // A JSON input over 4 MiB on stdin is refused before parsing.
    let huge = format!("{{\"data\": \"0x{}\"}}", "0".repeat(MAX_JSON_BYTES));
    blindsight()
        .args([
            "hash",
            "--tx",
            "-",
            "--chain-id",
            "1",
            "--safe-version",
            "1.4.1",
        ])
        .write_stdin(huge)
        .assert()
        .code(2);
}

#[test]
fn a_one_mebibyte_transaction_is_analysed_quickly() {
    let data = vec![0x5a; MAX_CALLDATA_BYTES];
    let start = Instant::now();
    let input = TxFlags {
        chain_id: Some("1".into()),
        safe: Some(SAFE.into()),
        safe_version: Some("1.4.1".into()),
        to: Some("0x00000000000000000000000000000000000000aa".into()),
        nonce: Some("0".into()),
        data: Some(format!("0x{}", alloy_primitives::hex::encode(&data))),
        ..TxFlags::default()
    }
    .parse()
    .unwrap()
    .finish(false)
    .unwrap();
    let report = report::analyse(ReportCommand::Verify, input, Options::default()).unwrap();
    let _ = report::text::render(&report);
    let _ = report::json::render(&report);
    assert!(start.elapsed() < Duration::from_secs(10));
}

#[test]
fn a_batch_of_thousands_of_entries() {
    let entries: Vec<BatchEntry> = (0..5000u32)
        .map(|i| BatchEntry {
            operation: Operation::Call,
            to: Address::from_word(U256::from(i).into()),
            value: U256::from(i),
            data: Bytes::from(vec![0xab; 4]),
        })
        .collect();
    let start = Instant::now();
    let root = decode_tree(
        &account(),
        &tx(
            MULTISEND_141.parse().unwrap(),
            Operation::DelegateCall,
            multisend(&entries),
        ),
        &UserAbis::default(),
    )
    .unwrap();
    let DecodedCall::Batch { items, .. } = &root.decoded else {
        panic!("not a batch");
    };
    assert_eq!(items.len(), 5000);
    assert_eq!(root.nodes().len(), 5001);
    assert!(start.elapsed() < Duration::from_secs(10));
}

#[test]
fn nesting_exactly_at_and_beyond_the_limit() {
    for (levels, deepest_decoded) in [(MAX_DEPTH, true), (MAX_DEPTH + 1, false)] {
        let mut data = vec![0xde, 0xad, 0xbe, 0xef];
        for _ in 0..levels {
            data = multisend(&[BatchEntry {
                operation: Operation::Call,
                to: Address::repeat_byte(1),
                value: U256::ZERO,
                data: Bytes::from(data),
            }]);
        }
        let root = decode_tree(
            &account(),
            &tx(
                MULTISEND_141.parse().unwrap(),
                Operation::DelegateCall,
                data,
            ),
            &UserAbis::default(),
        )
        .unwrap();
        let deepest = root.nodes().into_iter().last().unwrap();
        assert_eq!(
            !matches!(deepest.decoded, DecodedCall::TooDeep),
            deepest_decoded,
            "{levels} levels"
        );
    }
}

#[test]
fn malformed_and_strange_json_is_rejected_cleanly() {
    let cases = [
        "",
        "{",
        "null",
        "[1,2,3]",
        "{\"to\": \"0x\u{202e}0000000000000000000000000000000000000001\"}",
        "{\"nonce\": \"\u{0661}\u{0662}\"}",
        "{\"value\": \"1\u{200b}0\"}",
        "{\"to\": \"\u{ff10}x0000000000000000000000000000000000000001\"}",
        &format!("{}1{}", "[".repeat(200), "]".repeat(200)),
        "{\"data\": \"0x\u{0000}\"}",
    ];
    for case in cases {
        assert!(parse_json(case).is_err(), "{case:?}");
    }
}

#[test]
fn garbage_exec_calldata_is_rejected_cleanly() {
    let mut data = vec![0x6a, 0x76, 0x12, 0x02];
    for len in [0, 1, 31, 32, 64, 320, 1000] {
        data.resize(4 + len, 0xff);
        assert!(parse_exec_calldata(&data).is_err());
    }
}

/// Every real transaction renders as valid JSON and as text, through the
/// binary, with the exit code the report states.
#[test]
fn every_fixture_through_both_renderers() {
    let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/real");
    for entry in fs::read_dir(dir).unwrap() {
        let path = entry.unwrap().path();
        if path.extension().is_none_or(|e| e != "json") {
            continue;
        }
        let f: Value = serde_json::from_str(&fs::read_to_string(&path).unwrap()).unwrap();
        let args = [
            "--chain-id".to_string(),
            f["chain_id"].to_string(),
            "--safe".into(),
            f["safe"].as_str().unwrap().into(),
            "--safe-version".into(),
            f["safe_version"].as_str().unwrap().into(),
            "--nonce".into(),
            f["tx"]["nonce"].as_str().unwrap().into(),
            "--exec-calldata".into(),
            f["exec_calldata"].as_str().unwrap().into(),
        ];
        let out = blindsight()
            .arg("verify")
            .args(&args)
            .args(["--format", "json"])
            .output()
            .unwrap();
        let json: Value = serde_json::from_slice(&out.stdout).unwrap();
        assert_eq!(
            out.status.code(),
            json["exit_code"]
                .as_i64()
                .map(|c| i32::try_from(c).unwrap()),
            "{}",
            path.display()
        );
        assert_eq!(
            json["hashes"]["safe_tx_hash"],
            f["expected"]["safe_tx_hash"]
        );
        let text = blindsight().arg("verify").args(&args).output().unwrap();
        assert!(!text.stdout.is_empty());
        assert!(
            !text.stdout.contains(&0x1b),
            "escape code without a terminal"
        );
    }
}
