//! End-to-end tests of the `blindsight` binary: every command, both formats,
//! every exit code, stdin input, and output sanitisation.

// Test code: a panic is how a test reports failure (see clippy.toml and ADR 0004).
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

use std::fs;
use std::path::{Path, PathBuf};

use assert_cmd::Command;
use predicates::prelude::*;
use serde_json::Value;

const BYBIT_SAFE: &str = "0x1Db92e2EeBC8E0c075a02BeA49a2935BcD2dFCF4";
const BYBIT_HASH: &str = "0xb3476d061aeb8fc1d605a873c483a2402d88a68a9cdd1a8b47655dd55ba004f8";

fn blindsight() -> Command {
    let mut cmd = Command::cargo_bin("blindsight").unwrap();
    // Deterministic, uncoloured output regardless of the environment.
    cmd.env("NO_COLOR", "1");
    cmd
}

fn fixture(name: &str) -> Value {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/real")
        .join(format!("{name}.json"));
    serde_json::from_str(&fs::read_to_string(path).unwrap()).unwrap()
}

/// `--chain-id … --nonce … --exec-calldata …` for a fixture.
fn exec_args(name: &str) -> Vec<String> {
    let f = fixture(name);
    vec![
        "--chain-id".into(),
        f["chain_id"].to_string(),
        "--safe".into(),
        f["safe"].as_str().unwrap().into(),
        "--safe-version".into(),
        f["safe_version"].as_str().unwrap().into(),
        "--nonce".into(),
        f["tx"]["nonce"].as_str().unwrap().into(),
        "--exec-calldata".into(),
        f["exec_calldata"].as_str().unwrap().into(),
    ]
}

fn stdout_of(cmd: &mut Command) -> String {
    String::from_utf8(cmd.output().unwrap().stdout).unwrap()
}

fn temp_file(name: &str, content: &str) -> PathBuf {
    let path = Path::new(env!("CARGO_TARGET_TMPDIR")).join(name);
    fs::write(&path, content).unwrap();
    path
}

// ------------------------------------------------------------- commands

#[test]
fn version_names_the_embedded_data_and_no_network() {
    blindsight()
        .arg("version")
        .assert()
        .success()
        .stdout(predicate::str::starts_with(format!(
            "blindsight {}\n",
            env!("CARGO_PKG_VERSION")
        )))
        .stdout(predicate::str::contains("network access: none"))
        .stdout(predicate::str::contains(
            "e9cc9798ab834e7fe515d361566eb4a28c65387f",
        ));
}

#[test]
fn verify_bybit_text() {
    let out = stdout_of(blindsight().arg("verify").args(exec_args("bybit")));
    insta::assert_snapshot!(out);
}

#[test]
fn verify_bybit_json() {
    let out = stdout_of(
        blindsight()
            .arg("verify")
            .args(exec_args("bybit"))
            .args(["--format", "json"]),
    );
    let json: Value = serde_json::from_str(&out).unwrap();
    assert_eq!(json["schema_version"], 1);
    assert_eq!(json["hashes"]["safe_tx_hash"], BYBIT_HASH);
    assert_eq!(json["verdict"]["highest_severity"], "critical");
    assert_eq!(json["findings"][0]["id"], "BS-DELEGATE-001");
    assert_eq!(json["calls"]["decoded"]["semantics"]["verified"], false);
    assert_eq!(json["signatures"][0]["kind"], "eth_sign");
    assert_eq!(json["exit_code"], 1);
    insta::assert_snapshot!(out);
}

#[test]
fn hash_command_text_and_json() {
    let out = stdout_of(blindsight().arg("hash").args(exec_args("wazirx")));
    insta::assert_snapshot!(out);
    let json: Value = serde_json::from_str(&stdout_of(
        blindsight()
            .arg("hash")
            .args(exec_args("wazirx"))
            .args(["--format", "json"]),
    ))
    .unwrap();
    assert!(json.get("findings").is_none());
    assert_eq!(
        json["hashes"]["safe_tx_hash"],
        fixture("wazirx")["expected"]["safe_tx_hash"]
    );
}

#[test]
fn decode_command_shows_the_batch() {
    let out = stdout_of(
        blindsight()
            .arg("decode")
            .args(exec_args("multisend-set-guard")),
    );
    insta::assert_snapshot!(out);
}

#[test]
fn detectors_list_and_explain() {
    let list = stdout_of(blindsight().args(["detectors", "list"]));
    insta::assert_snapshot!(list);
    let json: Value = serde_json::from_str(&stdout_of(blindsight().args([
        "detectors",
        "list",
        "--format",
        "json",
    ])))
    .unwrap();
    assert_eq!(json.as_array().unwrap().len(), 20);
    blindsight()
        .args(["detectors", "explain", "bs-delegate-001"])
        .assert()
        .success()
        .stdout(predicate::str::starts_with("# BS-DELEGATE-001:"));
    blindsight()
        .args(["detectors", "explain", "BS-NOPE-001"])
        .assert()
        .code(2);
}

// ------------------------------------------------------------- exit codes

#[test]
fn exit_0_when_nothing_reaches_fail_on() {
    blindsight()
        .arg("verify")
        .args(exec_args("erc20-transfer-eth-141"))
        .assert()
        .code(0);
    // A high finding with --fail-on critical.
    blindsight()
        .arg("verify")
        .args(exec_args("change-threshold"))
        .args(["--fail-on", "critical"])
        .assert()
        .code(0);
}

#[test]
fn exit_1_on_findings_at_or_above_fail_on() {
    blindsight()
        .arg("verify")
        .args(exec_args("bybit"))
        .assert()
        .code(1);
    blindsight()
        .arg("verify")
        .args(exec_args("change-threshold"))
        .assert()
        .code(1);
    blindsight()
        .arg("verify")
        .args(exec_args("bybit-legit-nonce70"))
        .args(["--fail-on", "low"])
        .assert()
        .code(1);
}

#[test]
fn exit_2_on_input_and_usage_errors() {
    let cases: Vec<Vec<&str>> = vec![
        vec!["verify"],
        vec!["verify", "--chain-id", "1"],
        vec![
            "hash",
            "--chain-id",
            "1",
            "--safe",
            "0x1",
            "--safe-version",
            "1.1.1",
            "--to",
            BYBIT_SAFE,
            "--nonce",
            "1",
        ],
        vec![
            "hash",
            "--chain-id",
            "1",
            "--safe",
            BYBIT_SAFE,
            "--safe-version",
            "0.1.0",
            "--to",
            BYBIT_SAFE,
            "--nonce",
            "1",
        ],
        vec![
            "hash",
            "--chain-id",
            "424242424242",
            "--safe",
            BYBIT_SAFE,
            "--safe-version",
            "1.4.1",
            "--to",
            BYBIT_SAFE,
            "--nonce",
            "1",
        ],
        vec!["verify", "--fail-on", "severe"],
        vec!["no-such-command"],
    ];
    for args in cases {
        blindsight().args(&args).assert().code(2);
    }
}

#[test]
fn exit_3_on_hash_mismatch_even_with_findings() {
    let wrong = format!("{}0", &BYBIT_HASH[..65]);
    blindsight()
        .arg("verify")
        .args(exec_args("bybit"))
        .args(["--expect-safe-tx-hash", &wrong])
        .assert()
        .code(3)
        .stdout(predicate::str::contains("HASH MISMATCH"));
    // Matching hashes, the domain hash in Ledger's upper-case form: no mismatch.
    let f = fixture("bybit");
    let domain = format!(
        "0x{}",
        f["expected"]["domain_hash"].as_str().unwrap()[2..].to_uppercase()
    );
    blindsight()
        .arg("hash")
        .args(exec_args("bybit"))
        .args(["--expect-safe-tx-hash", BYBIT_HASH])
        .args(["--expect-domain-hash", &domain])
        .assert()
        .code(0)
        .stdout(predicate::str::contains("MATCH"));
}

// ------------------------------------------------------------- input forms

#[test]
fn json_from_stdin_with_context_flags() {
    let f = fixture("bybit");
    let mut tx = f["tx"].clone();
    tx["safe"] = f["safe"].clone();
    tx["safeTxHash"] = f["expected"]["safe_tx_hash"].clone();
    let args = [
        "hash",
        "--tx",
        "-",
        "--chain-id",
        "1",
        "--safe-version",
        "1.1.1",
    ];
    blindsight()
        .args(args)
        .write_stdin(tx.to_string())
        .assert()
        .code(0)
        .stdout(predicate::str::contains("safeTxHash in the input file"));
    // A file whose safeTxHash does not match its own fields: mismatch.
    tx["safeTxHash"] = Value::String(format!("{}0", &BYBIT_HASH[..65]));
    blindsight()
        .args(args)
        .write_stdin(tx.to_string())
        .assert()
        .code(3);
}

#[test]
fn flags_that_contradict_the_calldata_are_rejected() {
    blindsight()
        .arg("hash")
        .args(exec_args("bybit"))
        .args(["--operation", "0"])
        .assert()
        .code(2)
        .stderr(predicate::str::contains("conflicting values for operation"));
}

#[test]
fn plain_flags() {
    blindsight()
        .args(["hash", "--chain-id", "1", "--safe", BYBIT_SAFE])
        .args(["--safe-version", "1.1.1", "--operation", "delegatecall"])
        .args(["--to", "0x96221423681A6d52E184D440a8eFCEbB105C7242"])
        .args(["--data", fixture("bybit")["tx"]["data"].as_str().unwrap()])
        .args(["--safe-tx-gas", "45746", "--nonce", "71"])
        .args(["--expect-safe-tx-hash", BYBIT_HASH])
        .assert()
        .code(0);
}

// ------------------------------------------------------------- sanitisation

#[test]
fn input_cannot_inject_terminal_escapes() {
    // An address-book name with a "clear screen" sequence and a right-to-left
    // override, for an address the transaction uses.
    let book = temp_file(
        "evil-book.json",
        // JSON escapes, so the file itself holds the raw characters.
        &format!("{{\"\\u001b[2J\\u001b[HTreasury\\u202e\": \"{BYBIT_SAFE}\"}}"),
    );
    let out = blindsight()
        .args(["verify", "--color", "always"])
        .args(exec_args("bybit"))
        .arg("--address-book")
        .arg(&book)
        .output()
        .unwrap();
    let stdout = String::from_utf8(out.stdout).unwrap();
    assert!(
        !stdout.contains("\u{1b}[2J"),
        "raw escape reached the output"
    );
    assert!(
        !stdout.contains('\u{202e}'),
        "bidi override reached the output"
    );
    assert!(stdout.contains("\\u{1b}[2J"), "escape not shown visibly");

    // The same through JSON.
    let json = stdout_of(
        blindsight()
            .args(["verify", "--format", "json"])
            .args(exec_args("bybit"))
            .arg("--address-book")
            .arg(&book),
    );
    assert!(!json.contains('\u{1b}') && !json.contains("\\u001b[2J"));
    assert!(json.contains("\\\\u{1b}[2J"));
}

#[test]
fn decoded_strings_cannot_inject_terminal_escapes() {
    let abi = temp_file(
        "note-abi.json",
        r#"[{"type":"function","name":"note","stateMutability":"nonpayable","outputs":[],
            "inputs":[{"name":"text","type":"string"}]}]"#,
    );
    // note(string) with "\x1b[31mOK\x1b[0m", ABI-encoded by hand.
    let text = b"\x1b[31mOK\x1b[0m";
    let mut data = alloy_primitives::keccak256("note(string)")[..4].to_vec();
    data.extend_from_slice(&alloy_primitives::U256::from(32u8).to_be_bytes::<32>());
    data.extend_from_slice(&alloy_primitives::U256::from(text.len()).to_be_bytes::<32>());
    let mut padded = text.to_vec();
    padded.resize(32, 0);
    data.extend_from_slice(&padded);
    let target = "0x00000000000000000000000000000000000000aa";
    let out = blindsight()
        .args(["decode", "--chain-id", "1", "--safe", BYBIT_SAFE])
        .args(["--safe-version", "1.4.1", "--to", target, "--nonce", "0"])
        .arg("--data")
        .arg(format!("0x{}", alloy_primitives::hex::encode(&data)))
        .arg("--abi")
        .arg(format!("{target}={}", abi.display()))
        .output()
        .unwrap();
    let stdout = String::from_utf8(out.stdout).unwrap();
    assert!(stdout.contains("note(string)"), "{stdout}");
    assert!(!stdout.contains('\u{1b}'), "{stdout}");
    assert!(stdout.contains("\\u{1b}[31mOK"), "{stdout}");
}

#[test]
fn errors_quoting_input_are_sanitised() {
    blindsight()
        .args(["hash", "--chain-id", "1\u{1b}[2J"])
        .assert()
        .code(2)
        .stderr(predicate::str::contains("\\u{1b}[2J"))
        .stderr(predicate::str::contains("\u{1b}").not());
}

#[test]
fn addresses_and_hashes_are_never_truncated() {
    let out = stdout_of(blindsight().arg("verify").args(exec_args("bybit")));
    assert!(!out.contains('…'), "ellipsis in output");
    for full in [
        BYBIT_SAFE,
        "0x96221423681A6d52E184D440a8eFCEbB105C7242",
        "0xbDd077f651EBe7f7b3cE16fe5F2b025BE2969516",
        BYBIT_HASH,
    ] {
        assert!(out.contains(full), "{full} missing");
    }
}

#[test]
fn argument_parser_errors_are_sanitised() {
    // clap strips ANSI sequences itself but, before blindsight sanitised its
    // errors, passed a right-to-left override and a carriage return through.
    blindsight()
        .args(["verify", "--format", "a\u{202e}b\rc"])
        .assert()
        .code(2)
        .stderr(predicate::str::contains("\\u{202e}"))
        .stderr(predicate::str::contains("\u{202e}").not())
        .stderr(predicate::str::contains("\r").not());
    // Help still works and exits 0.
    blindsight()
        .arg("--help")
        .assert()
        .code(0)
        .stdout(predicate::str::contains("Usage"));
}
