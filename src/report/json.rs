//! Machine-readable report (`--format json`).
//!
//! The structs below are the schema; `schema_version` changes when a field is
//! removed or changes meaning (adding fields is compatible). Numbers that can
//! exceed 2^53 (values, gas, nonces) are decimal strings; addresses are
//! checksummed; hashes and byte strings are `0x`-prefixed lower-case hex,
//! never shortened. Free-text fields derived from the input are sanitised
//! like the text output.

use serde::Serialize;

use super::{Command, Report, SCHEMA_VERSION, SignatureKind};
use crate::decode::{ArgValue, CallNode, DecodedCall, Semantics, Verification};
use crate::detect::{Context, Detector, Severity};
use crate::sanitize::sanitize;

#[derive(Serialize)]
struct JsonReport {
    schema_version: u32,
    tool: Tool,
    command: &'static str,
    safe: Safe,
    transaction: Transaction,
    #[serde(skip_serializing_if = "Option::is_none")]
    hashes: Option<Hashes>,
    hash_checks: Vec<HashCheck>,
    hash_mismatch: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    verdict: Option<Verdict>,
    #[serde(skip_serializing_if = "Option::is_none")]
    findings: Option<Vec<Finding>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    calls: Option<Call>,
    warnings: Vec<String>,
    signatures: Vec<Signature>,
    exit_code: u8,
}

#[derive(Serialize)]
struct Tool {
    name: &'static str,
    version: &'static str,
}

#[derive(Serialize)]
struct Safe {
    address: String,
    chain_id: u64,
    chain_name: Option<String>,
    version: &'static str,
    domain_has_chain_id: bool,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct Transaction {
    to: String,
    value: String,
    data: String,
    operation: u8,
    safe_tx_gas: String,
    base_gas: String,
    gas_price: String,
    gas_token: String,
    refund_receiver: String,
    nonce: String,
}

#[derive(Serialize)]
struct Hashes {
    domain_hash: String,
    message_hash: String,
    safe_tx_hash: String,
}

#[derive(Serialize)]
struct HashCheck {
    hash: &'static str,
    source: &'static str,
    expected: String,
    computed: String,
    matches: bool,
}

#[derive(Serialize)]
struct Verdict {
    highest_severity: Option<&'static str>,
    fail_on: &'static str,
}

#[derive(Serialize)]
struct Finding {
    id: &'static str,
    severity: &'static str,
    title: String,
    detail: String,
    path: String,
}

#[derive(Serialize)]
struct Call {
    path: String,
    executor: String,
    to: String,
    to_label: String,
    value: String,
    operation: u8,
    data: String,
    decoded: Decoded,
}

#[derive(Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
enum Decoded {
    Empty,
    Known {
        function: &'static str,
        signature: &'static str,
        semantics: SemanticsJson,
        args: Vec<Arg>,
    },
    User {
        signature: String,
        args: Vec<Arg>,
    },
    Batch {
        semantics: SemanticsJson,
        call_only: bool,
        items: Vec<Call>,
    },
    Nested {
        signature: &'static str,
        semantics: SemanticsJson,
        args: Vec<Arg>,
        inner: Box<Call>,
    },
    Unknown {
        selector: Option<String>,
    },
    Malformed {
        function: Option<&'static str>,
        reason: String,
    },
    TooDeep,
}

#[derive(Serialize)]
struct SemanticsJson {
    verified: bool,
    reason: String,
}

#[derive(Serialize)]
struct Arg {
    name: String,
    value: String,
}

#[derive(Serialize)]
struct Signature {
    index: usize,
    v: u8,
    kind: &'static str,
    signer: Option<String>,
}

fn semantics(s: &Semantics) -> SemanticsJson {
    let (verified, reason) = match s {
        Semantics::Verified(Verification::KnownToken(t)) => {
            (true, format!("listed token {}", sanitize(&t.symbol)))
        }
        Semantics::Verified(Verification::ExecutingSafe) => {
            (true, "Safe function on the executing Safe".to_string())
        }
        Semantics::Verified(Verification::Official(c)) => {
            (true, format!("official {} {}", c.name, c.version))
        }
        Semantics::Verified(Verification::Permit2) => (true, "Permit2".to_string()),
        Semantics::SelectorOnly => (false, "name inferred from the selector only".to_string()),
    };
    SemanticsJson { verified, reason }
}

fn arg_value(value: &ArgValue) -> String {
    match value {
        ArgValue::Address(a) => a.to_checksum(None),
        ArgValue::Uint(u) => u.to_string(),
        ArgValue::Bool(b) => b.to_string(),
        ArgValue::Bytes32(h) => h.to_string(),
        ArgValue::Bytes(b) => b.to_string(),
        ArgValue::Uints(list) => format!(
            "[{}]",
            list.iter()
                .map(ToString::to_string)
                .collect::<Vec<_>>()
                .join(",")
        ),
    }
}

fn call(ctx: &Context<'_>, node: &CallNode) -> Call {
    let args = |call: &crate::decode::KnownCall| -> Vec<Arg> {
        call.args()
            .into_iter()
            .map(|(name, value)| Arg {
                name: name.to_string(),
                value: arg_value(&value),
            })
            .collect()
    };
    let decoded = match &node.decoded {
        DecodedCall::Empty => Decoded::Empty,
        DecodedCall::Known {
            call: known,
            semantics: s,
        } => Decoded::Known {
            function: known.name(),
            signature: known.signature(),
            semantics: semantics(s),
            args: args(known),
        },
        DecodedCall::User { call: user } => Decoded::User {
            signature: sanitize(&user.signature),
            args: user
                .args
                .iter()
                .map(|(name, value)| Arg {
                    name: sanitize(name),
                    value: sanitize(value),
                })
                .collect(),
        },
        DecodedCall::Batch {
            semantics: s,
            call_only,
            items,
        } => Decoded::Batch {
            semantics: semantics(s),
            call_only: *call_only,
            items: items.iter().map(|i| call(ctx, i)).collect(),
        },
        DecodedCall::Nested {
            call: outer,
            semantics: s,
            inner,
        } => Decoded::Nested {
            signature: outer.signature(),
            semantics: semantics(s),
            args: args(outer)
                .into_iter()
                .filter(|a| a.name != "data")
                .collect(),
            inner: Box::new(call(ctx, inner)),
        },
        DecodedCall::Unknown { selector } => Decoded::Unknown {
            selector: selector.map(|s| format!("0x{}", alloy_primitives::hex::encode(s))),
        },
        DecodedCall::Malformed { function, reason } => Decoded::Malformed {
            function: *function,
            reason: sanitize(reason),
        },
        DecodedCall::TooDeep => Decoded::TooDeep,
    };
    Call {
        path: node.path.to_string(),
        executor: node.executor.to_checksum(None),
        to: node.to.to_checksum(None),
        to_label: sanitize(&ctx.describe(node.to)),
        value: node.value.to_string(),
        operation: node.operation.as_u8(),
        data: node.data.to_string(),
        decoded,
    }
}

/// Renders `report` as pretty-printed JSON.
pub fn render(report: &Report) -> String {
    let ctx = report.context();
    let account = &report.input.account;
    let tx = &report.input.tx;
    let doc = JsonReport {
        schema_version: SCHEMA_VERSION,
        tool: Tool {
            name: "blindsight",
            version: crate::VERSION,
        },
        command: report.command.as_str(),
        safe: Safe {
            address: account.address.to_checksum(None),
            chain_id: account.chain_id,
            chain_name: ctx
                .registry
                .chains
                .get(account.chain_id)
                .and_then(|c| c.name.as_deref().map(sanitize)),
            version: account.version.as_str(),
            domain_has_chain_id: account.version.domain_has_chain_id(),
        },
        transaction: Transaction {
            to: tx.to.to_checksum(None),
            value: tx.value.to_string(),
            data: tx.data.to_string(),
            operation: tx.operation.as_u8(),
            safe_tx_gas: tx.safe_tx_gas.to_string(),
            base_gas: tx.base_gas.to_string(),
            gas_price: tx.gas_price.to_string(),
            gas_token: tx.gas_token.to_checksum(None),
            refund_receiver: tx.refund_receiver.to_checksum(None),
            nonce: tx.nonce.to_string(),
        },
        hashes: (report.command != Command::Decode).then(|| Hashes {
            domain_hash: report.hashes.domain_hash.to_string(),
            message_hash: report.hashes.message_hash.to_string(),
            safe_tx_hash: report.hashes.safe_tx_hash.to_string(),
        }),
        hash_checks: report
            .checks
            .iter()
            .map(|c| HashCheck {
                hash: c.kind.key(),
                source: c.source.describe(c.kind),
                expected: c.expected.to_string(),
                computed: c.computed.to_string(),
                matches: c.matches(),
            })
            .collect(),
        hash_mismatch: report.hash_mismatch(),
        verdict: report.findings.as_ref().map(|_| Verdict {
            highest_severity: report.verdict().map(Severity::as_str),
            fail_on: report.options.fail_on.as_str(),
        }),
        findings: report.findings.as_ref().map(|list| {
            list.iter()
                .map(|f| Finding {
                    id: f.id,
                    severity: f.severity.as_str(),
                    title: sanitize(&f.title),
                    detail: sanitize(&f.detail),
                    path: f.path.to_string(),
                })
                .collect()
        }),
        calls: report.tree.as_ref().map(|root| call(&ctx, root)),
        warnings: report
            .input
            .warnings
            .iter()
            .map(|w| sanitize(&w.to_string()))
            .collect(),
        signatures: report
            .signatures
            .iter()
            .map(|s| {
                let (kind, signer) = match s.kind {
                    SignatureKind::Contract(a) => ("contract", Some(a.to_checksum(None))),
                    SignatureKind::ApprovedHash(a) => ("approved_hash", Some(a.to_checksum(None))),
                    SignatureKind::TypedData => ("typed_data", None),
                    SignatureKind::EthSign => ("eth_sign", None),
                    SignatureKind::Invalid => ("invalid", None),
                };
                Signature {
                    index: s.index,
                    v: s.v,
                    kind,
                    signer,
                }
            })
            .collect(),
        exit_code: report.exit_code(),
    };
    // Serialising these plain structs cannot fail; fall back to an error
    // object rather than panicking.
    serde_json::to_string_pretty(&doc)
        .unwrap_or_else(|e| format!("{{\"error\": \"{}\"}}", sanitize(&e.to_string())))
}

/// `blindsight detectors list --format json`.
pub fn detectors_list() -> String {
    #[derive(Serialize)]
    struct Entry {
        id: &'static str,
        title: &'static str,
        severities: &'static str,
        experimental: bool,
    }
    let entries: Vec<Entry> = Detector::ALL
        .iter()
        .map(|d| Entry {
            id: d.id(),
            title: d.title(),
            severities: d.severities(),
            experimental: d.is_experimental(),
        })
        .collect();
    serde_json::to_string_pretty(&entries).unwrap_or_default()
}
