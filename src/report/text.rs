//! Human-readable report.
//!
//! Order: verdict, hash checks, findings, hashes (with the labels and case
//! hardware wallets use), input warnings, decoded calls, signatures, raw
//! parameters. Styles are ANSI escape codes produced here; the binary strips
//! them when the output is not a terminal or `NO_COLOR` is set. Every string
//! derived from the input goes through [`sanitize`] first, so the input
//! cannot inject its own escape codes.

use std::fmt::Write;

use alloy_primitives::{Address, B256, U256};
use anstyle::{AnsiColor, Style};

use super::{Command, Report, SignatureKind};
use crate::decode::{ArgValue, CallNode, DecodedCall, KnownCall, Semantics, Verification};
use crate::detect::{Context, Detector, Severity};
use crate::safe::Operation;
use crate::sanitize::sanitize;

/// Text width for wrapped paragraphs. Addresses and hashes are never split.
const WIDTH: usize = 80;

fn bold() -> Style {
    Style::new().bold()
}

fn severity_style(severity: Severity) -> Style {
    let color = match severity {
        Severity::Critical | Severity::High => AnsiColor::Red,
        Severity::Medium => AnsiColor::Yellow,
        Severity::Low => AnsiColor::Cyan,
        Severity::Info => AnsiColor::BrightBlack,
    };
    Style::new().fg_color(Some(color.into())).bold()
}

fn paint(style: Style, text: &str) -> String {
    format!("{style}{text}{style:#}")
}

/// Wraps `text` at word boundaries to [`WIDTH`], prefixing every line with
/// `indent`. Words longer than a line (addresses, calldata) are kept whole.
fn wrap(text: &str, indent: &str) -> String {
    let mut out = String::new();
    let mut line = String::new();
    for word in text.split(' ').filter(|w| !w.is_empty()) {
        if !line.is_empty() && indent.len() + line.len() + 1 + word.len() > WIDTH {
            out.push_str(indent);
            out.push_str(&line);
            out.push('\n');
            line.clear();
        }
        if !line.is_empty() {
            line.push(' ');
        }
        line.push_str(word);
    }
    if !line.is_empty() {
        out.push_str(indent);
        out.push_str(&line);
        out.push('\n');
    }
    out
}

fn heading(out: &mut String, title: &str) {
    let _ = writeln!(out, "\n{}", paint(bold(), title));
}

fn hex_upper(hash: B256) -> String {
    format!("0x{}", alloy_primitives::hex::encode_upper(hash))
}

/// Renders `report` as text with ANSI styles.
pub fn render(report: &Report) -> String {
    let mut out = String::new();
    let _ = writeln!(
        out,
        "blindsight {}: offline verification of a Safe transaction ({})",
        crate::VERSION,
        report.command.as_str()
    );
    verdict(&mut out, report);
    hash_checks(&mut out, report);
    findings(&mut out, report);
    if report.command != Command::Decode {
        hashes(&mut out, report);
    }
    warnings(&mut out, report);
    if let Some(root) = &report.tree {
        heading(&mut out, "CALLS");
        let ctx = report.context();
        call(&mut out, &ctx, root);
    }
    signatures(&mut out, report);
    raw(&mut out, report);
    out
}

fn verdict(out: &mut String, report: &Report) {
    if report.hash_mismatch() || report.findings.is_some() {
        out.push('\n');
    }
    if report.hash_mismatch() {
        let _ = writeln!(
            out,
            "{}",
            paint(
                severity_style(Severity::Critical),
                "HASH MISMATCH: DO NOT SIGN. The hash you expected is not the hash of these parameters."
            )
        );
    }
    let Some(findings) = &report.findings else {
        return;
    };
    let line = match report.verdict() {
        Some(Severity::Critical) => paint(
            severity_style(Severity::Critical),
            "CRITICAL: DO NOT SIGN without independent review",
        ),
        Some(Severity::High) => paint(
            severity_style(Severity::High),
            "HIGH RISK: review every finding before signing",
        ),
        Some(Severity::Medium) => paint(
            severity_style(Severity::Medium),
            "MEDIUM: some calls need a second look before signing",
        ),
        Some(lower) => format!("No high-risk patterns detected (highest finding: {lower})"),
        None => "No findings".to_string(),
    };
    let _ = writeln!(out, "{line}");
    let counts: Vec<String> = Severity::ALL
        .iter()
        .rev()
        .filter_map(|s| {
            let n = findings.iter().filter(|f| f.severity == *s).count();
            (n > 0).then(|| format!("{n} {s}"))
        })
        .collect();
    if !counts.is_empty() {
        let _ = writeln!(out, "Findings: {}", counts.join(", "));
    }
    // Only worth saying when nothing alarming was found.
    if report.verdict() < Some(Severity::Medium) {
        out.push_str(&wrap(
            "A clean result does not make a transaction safe: blindsight does not simulate it. Compare the hashes below with your wallet.",
            "",
        ));
    }
}

fn hash_checks(out: &mut String, report: &Report) {
    if report.checks.is_empty() {
        return;
    }
    heading(out, "HASH CHECK");
    for check in &report.checks {
        let source = check.source.describe(check.kind);
        if check.matches() {
            let _ = writeln!(
                out,
                "  {}  {} ({source})\n            {}",
                paint(
                    Style::new().fg_color(Some(AnsiColor::Green.into())).bold(),
                    "MATCH   "
                ),
                check.kind.label(),
                check.computed
            );
        } else {
            let _ = writeln!(
                out,
                "  {}  {} ({source})\n            expected {}\n            computed {}",
                paint(severity_style(Severity::Critical), "MISMATCH"),
                check.kind.label(),
                check.expected,
                check.computed
            );
        }
    }
}

fn findings(out: &mut String, report: &Report) {
    let Some(findings) = &report.findings else {
        return;
    };
    heading(out, &format!("FINDINGS ({})", findings.len()));
    if findings.is_empty() {
        let _ = writeln!(out, "  none");
    }
    for f in findings {
        // Pad before painting: escape codes would count towards the width.
        let label = format!("{:<8}", f.severity.as_str().to_uppercase());
        let _ = writeln!(
            out,
            "  {}  {:<16}  {}",
            paint(severity_style(f.severity), &label),
            f.id,
            f.path
        );
        out.push_str(&wrap(&sanitize(&f.title), "            "));
        out.push_str(&wrap(&sanitize(&f.detail), "            "));
    }
}

fn hashes(out: &mut String, report: &Report) {
    let account = &report.input.account;
    let ctx = report.context();
    let h = &report.hashes;
    heading(out, "HASHES: compare with your hardware wallet");
    let chain = ctx
        .registry
        .chains
        .get(account.chain_id)
        .and_then(|c| c.name.clone())
        .map_or_else(|| "unknown chain".to_string(), |n| sanitize(&n));
    let domain_note = if account.version.domain_has_chain_id() {
        ""
    } else {
        " (no chain id in the domain)"
    };
    let _ = writeln!(
        out,
        "  Safe            {}",
        sanitize(&ctx.describe(account.address))
    );
    let _ = writeln!(out, "  Chain           {} ({chain})", account.chain_id);
    let _ = writeln!(out, "  Safe version    {}{domain_note}", account.version);
    let _ = writeln!(out, "  Domain hash     {}", h.domain_hash);
    let _ = writeln!(out, "    as on Ledger  {}", hex_upper(h.domain_hash));
    let _ = writeln!(out, "  Message hash    {}", h.message_hash);
    let _ = writeln!(out, "    as on Ledger  {}", hex_upper(h.message_hash));
    let _ = writeln!(
        out,
        "  safeTxHash      {}",
        paint(bold(), &h.safe_tx_hash.to_string())
    );
    out.push_str(&wrap(
        "Ledger shows \"Domain hash\" and \"Message hash\" in upper case. Trezor shows the Safe address and chain id under \"Confirm domain\", the fields, and optionally \"Confirm message hash\". If your device shows a single hash (eth_sign), it is the safeTxHash. Every character must match; see docs/hardware-wallets.md.",
        "  ",
    ));
}

fn warnings(out: &mut String, report: &Report) {
    if report.input.warnings.is_empty() {
        return;
    }
    heading(out, "INPUT WARNINGS");
    for w in &report.input.warnings {
        out.push_str(&wrap(&format!("! {}", sanitize(&w.to_string())), "  "));
    }
}

fn operation(op: Operation) -> &'static str {
    match op {
        Operation::Call => "CALL",
        Operation::DelegateCall => "DELEGATECALL",
    }
}

fn semantics_label(semantics: &Semantics) -> String {
    match semantics {
        Semantics::Verified(Verification::KnownToken(t)) => {
            format!("verified: listed token {}", sanitize(&t.symbol))
        }
        Semantics::Verified(Verification::ExecutingSafe) => {
            "verified: Safe function on the executing Safe".to_string()
        }
        Semantics::Verified(Verification::Official(c)) => {
            format!("verified: official {} {}", c.name, c.version)
        }
        Semantics::Verified(Verification::Permit2) => "verified: Permit2".to_string(),
        Semantics::SelectorOnly => "UNVERIFIED: name inferred from the selector only".to_string(),
    }
}

/// An argument value; amounts of a listed token get their decimals.
fn arg_value(
    ctx: &Context<'_>,
    node: &CallNode,
    call: &KnownCall,
    name: &str,
    value: &ArgValue,
) -> String {
    match value {
        ArgValue::Address(a) => sanitize(&ctx.describe(*a)),
        ArgValue::Uint(u) => {
            let token_amount = matches!(
                call,
                KnownCall::Transfer { .. }
                    | KnownCall::TransferFrom { .. }
                    | KnownCall::Approve { .. }
                    | KnownCall::IncreaseAllowance { .. }
            ) && (name == "amount" || name == "addedValue");
            // Only a CALL to a listed token moves tokens; delegatecalled,
            // the same number means nothing in token units.
            if token_amount
                && node.operation == Operation::Call
                && ctx
                    .registry
                    .tokens
                    .get(ctx.account.chain_id, node.to)
                    .is_some()
            {
                ctx.token_amount(node.to, *u)
            } else {
                u.to_string()
            }
        }
        ArgValue::Bool(b) => b.to_string(),
        ArgValue::Bytes32(h) => h.to_string(),
        ArgValue::Bytes(b) => {
            if b.is_empty() {
                "0x (empty)".to_string()
            } else {
                format!("{b} ({} bytes)", b.len())
            }
        }
        ArgValue::Uints(list) => format!(
            "[{}]",
            list.iter()
                .map(U256::to_string)
                .collect::<Vec<_>>()
                .join(", ")
        ),
    }
}

fn call(out: &mut String, ctx: &Context<'_>, node: &CallNode) {
    let depth = node.path.depth();
    let indent = "  ".repeat(depth + 1);
    let inner = format!("{indent}    ");
    let _ = writeln!(
        out,
        "{indent}{}  {} {}",
        paint(bold(), &node.path.to_string()),
        operation(node.operation),
        sanitize(&ctx.describe(node.to))
    );
    if node.executor != ctx.account.address {
        let _ = writeln!(
            out,
            "{inner}executed by {}",
            sanitize(&ctx.describe(node.executor))
        );
    }
    if !node.value.is_zero() {
        let _ = writeln!(out, "{inner}value {}", ctx.native_amount(node.value));
    }
    match &node.decoded {
        DecodedCall::Empty => {
            let _ = writeln!(out, "{inner}no calldata");
        }
        DecodedCall::Known { call, semantics } => {
            let _ = writeln!(
                out,
                "{inner}{}  [{}]",
                call.signature(),
                semantics_label(semantics)
            );
            for (name, value) in call.args() {
                let _ = writeln!(
                    out,
                    "{inner}  {name:<16} {}",
                    arg_value(ctx, node, call, name, &value)
                );
            }
        }
        DecodedCall::User { call } => {
            let _ = writeln!(
                out,
                "{inner}{}  [decoded with your ABI for this address]",
                sanitize(&call.signature)
            );
            for (name, value) in &call.args {
                let _ = writeln!(out, "{inner}  {:<16} {}", sanitize(name), sanitize(value));
            }
        }
        DecodedCall::Batch {
            semantics, items, ..
        } => {
            let _ = writeln!(
                out,
                "{inner}multiSend: batch of {}  [{}]",
                items.len(),
                semantics_label(semantics)
            );
            for item in items {
                call(out, ctx, item);
            }
        }
        DecodedCall::Nested {
            call: outer,
            semantics,
            inner: inner_node,
        } => {
            let _ = writeln!(
                out,
                "{inner}{}  [{}; nested Safe transaction]",
                outer.signature(),
                semantics_label(semantics)
            );
            for (name, value) in outer.args() {
                // The inner transaction is shown as its own node below.
                if !matches!(name, "to" | "value" | "data" | "operation") {
                    let _ = writeln!(
                        out,
                        "{inner}  {name:<16} {}",
                        arg_value(ctx, node, outer, name, &value)
                    );
                }
            }
            call(out, ctx, inner_node);
        }
        DecodedCall::Unknown { selector } => {
            let what = selector.map_or_else(
                || format!("{} bytes, shorter than a selector", node.data.len()),
                |s| format!("selector 0x{}", alloy_primitives::hex::encode(s)),
            );
            let _ = writeln!(out, "{inner}UNKNOWN function ({what})");
        }
        DecodedCall::Malformed { function, reason } => {
            let _ = writeln!(
                out,
                "{inner}MALFORMED{}: {}",
                function.map_or_else(String::new, |f| format!(" {f}")),
                sanitize(reason)
            );
        }
        DecodedCall::TooDeep => {
            let _ = writeln!(out, "{inner}NOT ANALYSED: nested too deeply");
        }
    }
    if !matches!(node.decoded, DecodedCall::Empty) && !node.path.is_root() {
        let _ = writeln!(out, "{inner}calldata {}", node.data);
    }
}

fn signatures(out: &mut String, report: &Report) {
    if report.signatures.is_empty() {
        return;
    }
    heading(out, "SIGNATURES (from the execTransaction calldata)");
    let ctx = report.context();
    for s in &report.signatures {
        let text = match s.kind {
            SignatureKind::Contract(a) => format!("contract signature (EIP-1271) by {}", sanitize(&ctx.describe(a))),
            SignatureKind::ApprovedHash(a) => format!("hash approved on chain by {}", sanitize(&ctx.describe(a))),
            SignatureKind::TypedData => "ECDSA over the EIP-712 hash (typed-data signing)".to_string(),
            SignatureKind::EthSign => "eth_sign: the hash was signed as a raw message; the device could only show a 32-byte hash, not the transaction".to_string(),
            SignatureKind::Invalid => "invalid v value: the Safe rejects this signature".to_string(),
        };
        out.push_str(&wrap(&format!("#{} (v={}) {text}", s.index, s.v), "  "));
    }
}

fn raw(out: &mut String, report: &Report) {
    let tx = &report.input.tx;
    heading(out, "RAW PARAMETERS");
    let address = |a: Address| a.to_checksum(None);
    let rows = [
        ("to", address(tx.to)),
        ("value", tx.value.to_string()),
        (
            "data",
            if tx.data.is_empty() {
                "0x".to_string()
            } else {
                format!("{} ({} bytes)", tx.data, tx.data.len())
            },
        ),
        ("operation", tx.operation.to_string()),
        ("safeTxGas", tx.safe_tx_gas.to_string()),
        ("baseGas", tx.base_gas.to_string()),
        ("gasPrice", tx.gas_price.to_string()),
        ("gasToken", address(tx.gas_token)),
        ("refundReceiver", address(tx.refund_receiver)),
        ("nonce", tx.nonce.to_string()),
    ];
    for (name, value) in rows {
        let _ = writeln!(out, "  {name:<15} {value}");
    }
}

/// `blindsight detectors list`.
pub fn detectors_list() -> String {
    let mut out = String::new();
    let _ = writeln!(out, "{:<17} {:<52} SEVERITY", "ID", "TITLE");
    for d in Detector::ALL {
        let _ = writeln!(out, "{:<17} {:<52} {}", d.id(), d.title(), d.severities());
    }
    out.push_str("\nRun `blindsight detectors explain <ID>` for details.\n");
    out
}
