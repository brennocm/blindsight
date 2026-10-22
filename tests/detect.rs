//! Detectors on the 30 real transactions.
//!
//! The Bybit and `WazirX` attack transactions must produce critical findings;
//! a snapshot records every finding (detector, severity, path) for all
//! fixtures so any change in behaviour shows up in review.

// Test code: a panic is how a test reports failure (see clippy.toml and ADR 0004).
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

use std::fmt::Write;
use std::fs;
use std::path::Path;

use alloy_primitives::Bytes;
use blindsight::decode::{UserAbis, decode_tree};
use blindsight::detect::{Context, Finding, Severity, run, verdict};
use blindsight::input::TxFlags;
use blindsight::input::exec::parse_exec_calldata;
use blindsight::registry::Registry;
use serde_json::Value;

fn names() -> Vec<String> {
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

fn findings(name: &str) -> Vec<Finding> {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/real")
        .join(format!("{name}.json"));
    let fixture: Value = serde_json::from_str(&fs::read_to_string(path).unwrap()).unwrap();
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
    let root = decode_tree(&input.account, &input.tx, &UserAbis::default()).unwrap();
    let ctx = Context {
        account: &input.account,
        tx: &input.tx,
        registry: Registry::load().unwrap(),
        address_book: None,
        current_nonce: None,
    };
    run(&ctx, &root)
}

fn has(findings: &[Finding], id: &str, severity: Severity) -> bool {
    findings
        .iter()
        .any(|f| f.id == id && f.severity == severity)
}

/// The central regression test: the Bybit attack transaction, exactly as the
/// signers' wallets received it, is reported as critical.
#[test]
fn bybit_attack_is_critical() {
    let f = findings("bybit");
    assert_eq!(verdict(&f), Some(Severity::Critical));
    assert!(has(&f, "BS-DELEGATE-001", Severity::Critical));
    assert!(has(&f, "BS-SEMANTICS-001", Severity::Critical));
    let delegate = f.iter().find(|f| f.id == "BS-DELEGATE-001").unwrap();
    assert!(
        delegate
            .detail
            .contains("0x96221423681A6d52E184D440a8eFCEbB105C7242")
    );
}

#[test]
fn wazirx_attack_is_critical() {
    let f = findings("wazirx");
    assert_eq!(verdict(&f), Some(Severity::Critical));
    assert!(has(&f, "BS-DELEGATE-001", Severity::Critical));
    assert!(has(&f, "BS-DECODE-001", Severity::Medium));
}

/// The routine transfers that preceded the Bybit attack raise nothing above
/// low: the signal is specific to the attack.
#[test]
fn bybit_legitimate_transactions_are_not_alarming() {
    for name in ["bybit-legit-nonce70", "bybit-legit-nonce67-token"] {
        let f = findings(name);
        assert!(
            verdict(&f) <= Some(Severity::Low),
            "{name}: {:?}",
            f.iter().map(|f| (f.id, f.severity)).collect::<Vec<_>>()
        );
    }
}

#[test]
fn findings_on_every_real_transaction() {
    let mut out = String::new();
    for name in names() {
        let f = findings(&name);
        let verdict = verdict(&f).map_or("none", Severity::as_str);
        writeln!(out, "{name}: {verdict}").unwrap();
        for finding in &f {
            writeln!(
                out,
                "  {:<8} {:<16} {}",
                finding.severity.as_str(),
                finding.id,
                finding.path
            )
            .unwrap();
        }
    }
    insta::assert_snapshot!(out);
}
