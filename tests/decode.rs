//! The decoder on the 30 real transactions.
//!
//! Where the Safe Transaction Service decoded a transaction (`tx_service_decoded`
//! in the fixtures), blindsight must find the same function names wherever it
//! knows the selector, and the same number of batch entries. The service's
//! decoding is used only here, as an independent cross-check.

// Test code: a panic is how a test reports failure (see clippy.toml and ADR 0004).
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

use std::fs;
use std::path::Path;

use alloy_primitives::Bytes;
use blindsight::decode::{CallNode, DecodedCall, KnownCall, Semantics, decode_tree};
use blindsight::input::TxFlags;
use blindsight::input::exec::parse_exec_calldata;
use blindsight::safe::Operation;
use serde_json::Value;

fn load(name: &str) -> Value {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/real")
        .join(format!("{name}.json"));
    serde_json::from_str(&fs::read_to_string(path).unwrap()).unwrap()
}

fn all_names() -> Vec<String> {
    let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/real");
    let mut names: Vec<String> = fs::read_dir(dir)
        .unwrap()
        .map(|e| e.unwrap().path())
        .filter(|p| p.extension().is_some_and(|e| e == "json"))
        .map(|p| p.file_stem().unwrap().to_string_lossy().into_owned())
        .collect();
    names.sort();
    names
}

fn tree(fixture: &Value) -> CallNode {
    let flags = TxFlags {
        chain_id: Some(fixture["chain_id"].to_string()),
        safe: Some(fixture["safe"].as_str().unwrap().into()),
        safe_version: Some(fixture["safe_version"].as_str().unwrap().into()),
        nonce: Some(fixture["tx"]["nonce"].as_str().unwrap().into()),
        ..TxFlags::default()
    };
    let calldata: Bytes = fixture["exec_calldata"].as_str().unwrap().parse().unwrap();
    let input = flags
        .parse()
        .unwrap()
        .merge("flags", parse_exec_calldata(&calldata).unwrap(), "calldata")
        .unwrap()
        .finish(false)
        .unwrap();
    decode_tree(&input.account, &input.tx).unwrap()
}

/// The function name blindsight decoded for a node, if it knows one.
fn name(node: &CallNode) -> Option<&'static str> {
    match &node.decoded {
        DecodedCall::Known { call, .. } | DecodedCall::Nested { call, .. } => Some(call.name()),
        DecodedCall::Batch { .. } => Some("multiSend"),
        _ => None,
    }
}

#[test]
fn agrees_with_the_transaction_service_wherever_both_decode() {
    let mut compared = 0;
    for fixture_name in all_names() {
        let fixture = load(&fixture_name);
        let root = tree(&fixture);
        // No real transaction is malformed or too deep.
        for node in root.nodes() {
            assert!(
                !matches!(
                    node.decoded,
                    DecodedCall::Malformed { .. } | DecodedCall::TooDeep
                ),
                "{fixture_name}: {} {:?}",
                node.path,
                node.decoded
            );
        }
        let service = &fixture["tx_service_decoded"];
        let Some(method) = service["method"].as_str() else {
            continue;
        };
        if let Some(ours) = name(&root) {
            assert_eq!(ours, method, "{fixture_name}");
            compared += 1;
        }
        if let DecodedCall::Batch { items, .. } = &root.decoded {
            let entries = service["parameters"][0]["valueDecoded"].as_array().unwrap();
            assert_eq!(items.len(), entries.len(), "{fixture_name}");
            for (item, entry) in items.iter().zip(entries) {
                let op = entry["operation"].as_u64().unwrap();
                assert_eq!(u64::from(item.operation.as_u8()), op, "{fixture_name}");
                if let (Some(ours), Some(theirs)) =
                    (name(item), entry["dataDecoded"]["method"].as_str())
                {
                    assert_eq!(ours, theirs, "{fixture_name} {}", item.path);
                    compared += 1;
                }
            }
        }
    }
    // Guard against a vacuous pass.
    assert!(compared >= 20, "only {compared} comparisons");
}

#[test]
fn bybit_is_a_transfer_shaped_delegatecall_with_unverified_semantics() {
    let root = tree(&load("bybit"));
    assert_eq!(root.operation, Operation::DelegateCall);
    let DecodedCall::Known { call, semantics } = &root.decoded else {
        panic!("{:?}", root.decoded);
    };
    assert!(matches!(call, KnownCall::Transfer { .. }));
    assert_eq!(*semantics, Semantics::SelectorOnly);
}

#[test]
fn wazirx_payload_is_unknown() {
    let root = tree(&load("wazirx"));
    assert_eq!(root.operation, Operation::DelegateCall);
    assert_eq!(
        root.decoded,
        DecodedCall::Unknown {
            selector: Some([0x80, 0x4e, 0x1f, 0x0a])
        }
    );
}

#[test]
fn legitimate_operations_have_verified_semantics() {
    for name in [
        "add-owner-130",
        "change-threshold",
        "remove-owner",
        "swap-owner",
        "disable-module",
        "erc20-transfer-eth-141",
        "sign-message-lib",
    ] {
        let root = tree(&load(name));
        let semantics = match &root.decoded {
            DecodedCall::Known { semantics, .. } => semantics,
            other => panic!("{name}: {other:?}"),
        };
        assert!(semantics.is_verified(), "{name}");
    }
}

#[test]
fn official_batches_from_any_version_are_verified() {
    for name in [
        "multisend-141-l2",
        "arb-multisend-141",
        "op-multisend-141",
        "bsc-multisend-130-from-safe-141",
        "v100-delegatecall-token-refund",
        "multisend-enable-module",
        "multisend-set-guard",
        "gas-refund",
    ] {
        let root = tree(&load(name));
        match &root.decoded {
            DecodedCall::Batch { semantics, .. } => assert!(semantics.is_verified(), "{name}"),
            other => panic!("{name}: {other:?}"),
        }
    }
}

/// A token outside the curated list: the `approve` name is only inferred.
#[test]
fn approve_on_an_unlisted_token_is_selector_only() {
    let root = tree(&load("erc20-approve-base"));
    assert!(matches!(
        &root.decoded,
        DecodedCall::Known {
            call: KnownCall::Approve { .. },
            semantics: Semantics::SelectorOnly
        }
    ));
}
