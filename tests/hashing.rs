//! Hashes of real and synthetic Safe transactions must match exactly.
//!
//! Real vectors (`tests/fixtures/real`) are confirmed three ways; see
//! `tests/fixtures/README.md`. Synthetic edge cases
//! (`tests/fixtures/synthetic/hashing-edge-cases.json`) come from the
//! independent Python reference `scripts/fixtures/safehash.py`.

// Test code: a panic is how a test reports failure (see clippy.toml and ADR 0004).
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

use std::fs;
use std::path::Path;

use alloy_primitives::{Address, B256, Bytes, U256};
use blindsight::safe::{Operation, SafeAccount, SafeTx, SafeVersion, compute_hashes};
use serde_json::Value;

fn text<'a>(v: &'a Value, key: &str) -> &'a str {
    v[key]
        .as_str()
        .unwrap_or_else(|| panic!("{key} missing or not a string"))
}

fn uint(v: &Value, key: &str) -> U256 {
    text(v, key).parse().unwrap()
}

fn address(v: &Value, key: &str) -> Address {
    text(v, key).parse().unwrap()
}

fn hash(v: &Value, key: &str) -> B256 {
    text(v, key).parse().unwrap()
}

/// Parses a fixture into what blindsight hashes, and checks the three hashes.
fn check(fixture: &Value) {
    let name = text(fixture, "name");
    let account = SafeAccount {
        address: address(fixture, "safe"),
        chain_id: fixture["chain_id"].as_u64().unwrap(),
        version: text(fixture, "safe_version").parse().unwrap(),
    };
    let t = &fixture["tx"];
    let tx = SafeTx {
        to: address(t, "to"),
        value: uint(t, "value"),
        data: t["data"].as_str().unwrap_or("0x").parse::<Bytes>().unwrap(),
        operation: Operation::try_from(u8::try_from(t["operation"].as_u64().unwrap()).unwrap())
            .unwrap(),
        safe_tx_gas: uint(t, "safeTxGas"),
        base_gas: uint(t, "baseGas"),
        gas_price: uint(t, "gasPrice"),
        gas_token: address(t, "gasToken"),
        refund_receiver: address(t, "refundReceiver"),
        nonce: uint(t, "nonce"),
    };
    let expected = &fixture["expected"];
    let got = compute_hashes(&account, &tx).unwrap();
    assert_eq!(
        got.domain_hash,
        hash(expected, "domain_hash"),
        "{name}: domain hash"
    );
    assert_eq!(
        got.message_hash,
        hash(expected, "message_hash"),
        "{name}: message hash"
    );
    assert_eq!(
        got.safe_tx_hash,
        hash(expected, "safe_tx_hash"),
        "{name}: safeTxHash"
    );
}

#[test]
fn real_vectors_match() {
    let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/real");
    let mut versions = Vec::new();
    let mut count = 0;
    for entry in fs::read_dir(dir).unwrap() {
        let path = entry.unwrap().path();
        if path.extension().is_some_and(|e| e == "json") {
            let fixture: Value = serde_json::from_str(&fs::read_to_string(&path).unwrap()).unwrap();
            check(&fixture);
            versions.push(
                text(&fixture, "safe_version")
                    .parse::<SafeVersion>()
                    .unwrap(),
            );
            count += 1;
        }
    }
    // Guard against a vacuous pass if the directory moves or empties.
    assert_eq!(count, 30);
    // Every version with a real executed transaction is exercised.
    for v in [
        SafeVersion::V1_0_0,
        SafeVersion::V1_1_1,
        SafeVersion::V1_3_0,
        SafeVersion::V1_4_1,
        SafeVersion::V1_5_0,
    ] {
        assert!(versions.contains(&v), "no real vector for {v}");
    }
}

#[test]
fn synthetic_edge_cases_match() {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/synthetic/hashing-edge-cases.json");
    let cases: Vec<Value> = serde_json::from_str(&fs::read_to_string(path).unwrap()).unwrap();
    assert_eq!(cases.len(), 24);
    for case in &cases {
        check(case);
    }
}

/// The Bybit attack transaction, spelled out: this is the hash the three
/// signers' wallets signed.
#[test]
fn bybit_attack_transaction() {
    let account = SafeAccount {
        address: "0x1Db92e2EeBC8E0c075a02BeA49a2935BcD2dFCF4"
            .parse()
            .unwrap(),
        chain_id: 1,
        version: SafeVersion::V1_1_1,
    };
    let tx = SafeTx {
        to: "0x96221423681A6d52E184D440a8eFCEbB105C7242".parse().unwrap(),
        value: U256::ZERO,
        data: "0xa9059cbb000000000000000000000000bdd077f651ebe7f7b3ce16fe5f2b025be29695160000000000000000000000000000000000000000000000000000000000000000".parse().unwrap(),
        operation: Operation::DelegateCall,
        safe_tx_gas: U256::from(45746u64),
        base_gas: U256::ZERO,
        gas_price: U256::ZERO,
        gas_token: Address::ZERO,
        refund_receiver: Address::ZERO,
        nonce: U256::from(71u64),
    };
    let got = compute_hashes(&account, &tx).unwrap();
    assert_eq!(
        got.safe_tx_hash,
        "0xb3476d061aeb8fc1d605a873c483a2402d88a68a9cdd1a8b47655dd55ba004f8"
            .parse::<B256>()
            .unwrap()
    );
}

/// 1 MiB of calldata: both implementations still agree (no expected value;
/// `compute_hashes` fails if they differ).
#[test]
fn one_mebibyte_of_calldata() {
    let account = SafeAccount {
        address: Address::repeat_byte(0x11),
        chain_id: 1,
        version: SafeVersion::V1_5_0,
    };
    let data: Vec<u8> = (0..1u32 << 20)
        .map(|i| u8::try_from(i % 251).unwrap())
        .collect();
    let tx = SafeTx {
        to: Address::repeat_byte(0x22),
        value: U256::ZERO,
        data: Bytes::from(data),
        operation: Operation::Call,
        safe_tx_gas: U256::ZERO,
        base_gas: U256::ZERO,
        gas_price: U256::ZERO,
        gas_token: Address::ZERO,
        refund_receiver: Address::ZERO,
        nonce: U256::ZERO,
    };
    assert!(compute_hashes(&account, &tx).is_ok());
}
