//! Every input path reproduces the real vectors: raw `execTransaction`
//! calldata (plus nonce and context flags) and the JSON format.

// Test code: a panic is how a test reports failure (see clippy.toml and ADR 0004).
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

use std::fs;
use std::path::Path;

use alloy_primitives::{B256, Bytes};
use blindsight::input::exec::parse_exec_calldata;
use blindsight::input::json::parse_json;
use blindsight::input::{InputError, TxFlags, TxInput};
use blindsight::safe::compute_hashes;
use serde_json::{Value, json};

fn fixtures() -> Vec<Value> {
    let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/real");
    let mut out: Vec<Value> = fs::read_dir(dir)
        .unwrap()
        .map(|e| e.unwrap().path())
        .filter(|p| p.extension().is_some_and(|e| e == "json"))
        .map(|p| serde_json::from_str(&fs::read_to_string(p).unwrap()).unwrap())
        .collect();
    out.sort_by_key(|f| f["name"].as_str().unwrap().to_string());
    assert_eq!(out.len(), 30);
    out
}

fn context_flags(fixture: &Value) -> TxFlags {
    TxFlags {
        chain_id: Some(fixture["chain_id"].to_string()),
        safe: Some(fixture["safe"].as_str().unwrap().to_string()),
        safe_version: Some(fixture["safe_version"].as_str().unwrap().to_string()),
        nonce: Some(fixture["tx"]["nonce"].as_str().unwrap().to_string()),
        ..TxFlags::default()
    }
}

fn assert_expected(fixture: &Value, input: &TxInput) {
    let name = fixture["name"].as_str().unwrap();
    let hashes = compute_hashes(&input.account, &input.tx).unwrap();
    let expected: B256 = fixture["expected"]["safe_tx_hash"]
        .as_str()
        .unwrap()
        .parse()
        .unwrap();
    assert_eq!(hashes.safe_tx_hash, expected, "{name}");
    assert!(input.warnings.is_empty(), "{name}: {:?}", input.warnings);
}

#[test]
fn exec_calldata_with_context_flags_reproduces_every_vector() {
    for fixture in fixtures() {
        let calldata: Bytes = fixture["exec_calldata"].as_str().unwrap().parse().unwrap();
        let from_calldata = parse_exec_calldata(&calldata).unwrap();
        let input = context_flags(&fixture)
            .parse()
            .unwrap()
            .merge("flags", from_calldata, "execTransaction calldata")
            .unwrap()
            .finish(false)
            .unwrap();
        assert!(input.signatures.as_ref().is_some_and(|s| !s.is_empty()));
        assert_expected(&fixture, &input);
    }
}

#[test]
fn json_in_transaction_service_shape_reproduces_every_vector() {
    for fixture in fixtures() {
        let mut object = fixture["tx"].clone();
        object["safe"] = fixture["safe"].clone();
        object["chainId"] = fixture["chain_id"].clone();
        object["safeVersion"] = fixture["safe_version"].clone();
        object["safeTxHash"] = fixture["expected"]["safe_tx_hash"].clone();
        let input = parse_json(&object.to_string())
            .unwrap()
            .finish(false)
            .unwrap();
        assert_eq!(
            input.claimed_safe_tx_hash.unwrap().to_string(),
            fixture["expected"]["safe_tx_hash"].as_str().unwrap()
        );
        assert_expected(&fixture, &input);
    }
}

#[test]
fn json_plus_flags_for_missing_context() {
    let fixture = fixtures()
        .into_iter()
        .find(|f| f["name"] == "bybit")
        .unwrap();
    let mut object = fixture["tx"].clone();
    object["safe"] = fixture["safe"].clone();
    let flags = TxFlags {
        chain_id: Some("1".into()),
        safe_version: Some("1.1.1".into()),
        ..TxFlags::default()
    };
    let input = flags
        .parse()
        .unwrap()
        .merge(
            "flags",
            parse_json(&object.to_string()).unwrap(),
            "JSON file",
        )
        .unwrap()
        .finish(false)
        .unwrap();
    assert_expected(&fixture, &input);
}

#[test]
fn a_flag_that_contradicts_the_file_is_rejected() {
    let file = json!({
        "safe": "0x1Db92e2EeBC8E0c075a02BeA49a2935BcD2dFCF4",
        "to": "0x96221423681A6d52E184D440a8eFCEbB105C7242",
        "operation": 1,
        "nonce": "71",
    });
    let flags = TxFlags {
        chain_id: Some("1".into()),
        safe_version: Some("1.1.1".into()),
        operation: Some("0".into()),
        ..TxFlags::default()
    };
    let err = flags
        .parse()
        .unwrap()
        .merge("flags", parse_json(&file.to_string()).unwrap(), "JSON file")
        .unwrap_err();
    assert!(matches!(err, InputError::Conflict { .. }), "{err}");
}
