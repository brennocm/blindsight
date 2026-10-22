//! Risk detectors.
//!
//! Each detector is a pure function of the decoded call tree and the
//! [`Context`]; none does I/O. [`run`] applies every detector to every node of
//! the tree, so wrapping a payload in a batch or a nested Safe transaction
//! does not hide it. Detectors are an `enum` ([`Detector`]) rather than trait
//! objects: the set is closed and a `match` makes every case explicit.
//! Documentation for each one lives in `docs/detectors/<ID>.md` and is
//! compiled in for `blindsight detectors explain`.

mod approval_001;
mod approval_002;
mod decode_001;
mod delegate_001;
mod delegate_002;
mod fallback_001;
mod guard_001;
mod impl_001;
mod module_001;
mod owners_001;
mod poison_001;
mod refund_001;
mod semantics_001;
mod target_001;
mod threshold_001;
mod value_001;

#[cfg(test)]
mod testutil;

use std::fmt;
use std::str::FromStr;

use alloy_primitives::{Address, U256};

use crate::addressbook::AddressBook;
use crate::decode::{CallNode, CallPath};
use crate::registry::{Registry, Role};
use crate::safe::{SafeAccount, SafeTx};
use crate::units::format_units;

/// How serious a finding is. Ordered: `Info < Low < Medium < High < Critical`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Severity {
    /// Context worth knowing.
    Info,
    /// Unusual, low risk.
    Low,
    /// Needs a second look.
    Medium,
    /// Can cause loss or takeover if not intended.
    High,
    /// Can hand over the Safe or its funds.
    Critical,
}

impl Severity {
    /// Every severity, lowest first.
    pub const ALL: [Severity; 5] = [
        Severity::Info,
        Severity::Low,
        Severity::Medium,
        Severity::High,
        Severity::Critical,
    ];

    /// Lower-case name, e.g. `"high"`.
    pub fn as_str(self) -> &'static str {
        match self {
            Severity::Info => "info",
            Severity::Low => "low",
            Severity::Medium => "medium",
            Severity::High => "high",
            Severity::Critical => "critical",
        }
    }
}

impl fmt::Display for Severity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for Severity {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Severity::ALL
            .into_iter()
            .find(|sev| sev.as_str().eq_ignore_ascii_case(s.trim()))
            .ok_or_else(|| "expected one of: info, low, medium, high, critical".to_string())
    }
}

/// One thing a detector found.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Finding {
    /// Detector ID, e.g. `BS-DELEGATE-001`.
    pub id: &'static str,
    /// Severity.
    pub severity: Severity,
    /// One-line summary.
    pub title: String,
    /// Explanation and what to check. May contain address-book names:
    /// sanitise before printing.
    pub detail: String,
    /// Where in the call tree.
    pub path: CallPath,
}

/// What detectors know besides the call tree.
#[derive(Debug, Clone, Copy)]
pub struct Context<'a> {
    /// The Safe executing the root transaction.
    pub account: &'a SafeAccount,
    /// The root transaction.
    pub tx: &'a SafeTx,
    /// Embedded data.
    pub registry: Registry,
    /// The user's address book, if given.
    pub address_book: Option<&'a AddressBook>,
    /// The Safe's current nonce, if given.
    pub current_nonce: Option<U256>,
}

impl Context<'_> {
    /// Whether a delegatecall to `address` is a normal operation: an official
    /// helper (`MultiSend`, `SignMessageLib`, `CreateCall`, migrations, L2 setup)
    /// on this chain, of any Safe version.
    pub fn is_trusted_helper(&self, address: Address) -> bool {
        self.registry
            .contracts
            .at(self.account.chain_id, address)
            .iter()
            .any(|c| c.role.is_trusted_delegatecall_target())
    }

    /// Whether `address` is an official contract with role `role` here.
    pub fn is_official(&self, address: Address, role: Role) -> bool {
        self.registry
            .contracts
            .at(self.account.chain_id, address)
            .iter()
            .any(|c| c.role == role)
    }

    /// The full checksummed address followed by what blindsight knows about
    /// it, e.g. `0xA0b8…eB48 (token USDC)`, written out in full.
    pub fn describe(&self, address: Address) -> String {
        let mut labels = Vec::new();
        if address == self.account.address {
            labels.push("this Safe".to_string());
        }
        if let Some(entry) = self.address_book.and_then(|b| b.get(address)) {
            labels.push(format!("address book: \"{}\"", entry.name));
        }
        for c in self.registry.contracts.at(self.account.chain_id, address) {
            labels.push(format!("official {} {}", c.name, c.version));
        }
        if let Some(t) = self.registry.tokens.get(self.account.chain_id, address) {
            labels.push(format!("token {}", t.symbol));
        }
        if self.registry.permit2.is_at(self.account.chain_id, address) {
            labels.push("Permit2".to_string());
        }
        if address == Address::ZERO {
            labels.push("zero address".to_string());
        }
        let checksummed = address.to_checksum(None);
        if labels.is_empty() {
            checksummed
        } else {
            format!("{checksummed} ({})", labels.join(", "))
        }
    }

    /// Whether blindsight knows anything about `address`.
    pub fn is_known(&self, address: Address) -> bool {
        let chain = self.account.chain_id;
        address == self.account.address
            || self.address_book.is_some_and(|b| b.get(address).is_some())
            || !self.registry.contracts.at(chain, address).is_empty()
            || self.registry.tokens.get(chain, address).is_some()
            || self.registry.permit2.is_at(chain, address)
    }

    /// A native amount with the chain's symbol and decimals when known,
    /// e.g. `1.5 ETH (1500000000000000000 wei)`.
    pub fn native_amount(&self, wei: U256) -> String {
        let chain = self.registry.chains.get(self.account.chain_id);
        let symbol = chain.and_then(|c| c.native_symbol.clone());
        let decimals = chain.and_then(|c| c.native_decimals);
        match (symbol, decimals.and_then(|d| format_units(wei, d))) {
            (Some(symbol), Some(amount)) => format!("{amount} {symbol} ({wei} base units)"),
            _ => format!("{wei} base units of the native currency"),
        }
    }

    /// A token amount, with decimals when the token is known.
    pub fn token_amount(&self, token: Address, amount: U256) -> String {
        match self.registry.tokens.get(self.account.chain_id, token) {
            Some(t) => match format_units(amount, t.decimals) {
                Some(formatted) => format!("{formatted} {} ({amount} base units)", t.symbol),
                None => format!("{amount} base units of {}", t.symbol),
            },
            None => format!("{amount} base units (token decimals unknown)"),
        }
    }
}

/// Every detector.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(missing_docs)] // Each variant is documented by its `docs/detectors/<ID>.md`.
pub enum Detector {
    Delegate001,
    Delegate002,
    Semantics001,
    Owners001,
    Threshold001,
    Module001,
    Guard001,
    Fallback001,
    Impl001,
    Refund001,
    Approval001,
    Approval002,
    Value001,
    Poison001,
    Target001,
    Decode001,
}

impl Detector {
    /// Every detector, in catalog order.
    pub const ALL: [Detector; 16] = [
        Detector::Delegate001,
        Detector::Delegate002,
        Detector::Semantics001,
        Detector::Owners001,
        Detector::Threshold001,
        Detector::Module001,
        Detector::Guard001,
        Detector::Fallback001,
        Detector::Impl001,
        Detector::Refund001,
        Detector::Approval001,
        Detector::Approval002,
        Detector::Value001,
        Detector::Poison001,
        Detector::Target001,
        Detector::Decode001,
    ];

    /// Stable ID, e.g. `BS-DELEGATE-001`.
    pub fn id(self) -> &'static str {
        self.meta().0
    }

    /// Short title.
    pub fn title(self) -> &'static str {
        self.meta().1
    }

    /// Severities it can report, as text, e.g. `high; critical if ...`.
    pub fn severities(self) -> &'static str {
        self.meta().2
    }

    /// Whether the detector is experimental.
    pub fn is_experimental(self) -> bool {
        matches!(self, Detector::Approval002)
    }

    /// The detector's documentation (`docs/detectors/<ID>.md`).
    pub fn documentation(self) -> &'static str {
        match self {
            Detector::Delegate001 => include_str!("../../docs/detectors/BS-DELEGATE-001.md"),
            Detector::Delegate002 => include_str!("../../docs/detectors/BS-DELEGATE-002.md"),
            Detector::Semantics001 => include_str!("../../docs/detectors/BS-SEMANTICS-001.md"),
            Detector::Owners001 => include_str!("../../docs/detectors/BS-OWNERS-001.md"),
            Detector::Threshold001 => include_str!("../../docs/detectors/BS-THRESHOLD-001.md"),
            Detector::Module001 => include_str!("../../docs/detectors/BS-MODULE-001.md"),
            Detector::Guard001 => include_str!("../../docs/detectors/BS-GUARD-001.md"),
            Detector::Fallback001 => include_str!("../../docs/detectors/BS-FALLBACK-001.md"),
            Detector::Impl001 => include_str!("../../docs/detectors/BS-IMPL-001.md"),
            Detector::Refund001 => include_str!("../../docs/detectors/BS-REFUND-001.md"),
            Detector::Approval001 => include_str!("../../docs/detectors/BS-APPROVAL-001.md"),
            Detector::Approval002 => include_str!("../../docs/detectors/BS-APPROVAL-002.md"),
            Detector::Value001 => include_str!("../../docs/detectors/BS-VALUE-001.md"),
            Detector::Poison001 => include_str!("../../docs/detectors/BS-POISON-001.md"),
            Detector::Target001 => include_str!("../../docs/detectors/BS-TARGET-001.md"),
            Detector::Decode001 => include_str!("../../docs/detectors/BS-DECODE-001.md"),
        }
    }

    /// The detector with this ID (case-insensitive).
    pub fn from_id(id: &str) -> Option<Detector> {
        Detector::ALL
            .into_iter()
            .find(|d| d.id().eq_ignore_ascii_case(id.trim()))
    }

    fn meta(self) -> (&'static str, &'static str, &'static str) {
        match self {
            Detector::Delegate001 => (
                delegate_001::ID,
                "Delegatecall to an untrusted contract",
                "critical",
            ),
            Detector::Delegate002 => (
                delegate_002::ID,
                "Delegatecall inside a batch",
                "critical (untrusted target), medium (official helper), info (MultiSendCallOnly)",
            ),
            Detector::Semantics001 => (
                semantics_001::ID,
                "Function name is a guess",
                "low; critical under delegatecall",
            ),
            Detector::Owners001 => (
                owners_001::ID,
                "Owner set change",
                "high; critical if the new threshold is 1",
            ),
            Detector::Threshold001 => (
                threshold_001::ID,
                "Threshold change",
                "high; critical if the new threshold is 1",
            ),
            Detector::Module001 => (
                module_001::ID,
                "Module enabled or disabled",
                "critical (enable), medium (disable)",
            ),
            Detector::Guard001 => (guard_001::ID, "Transaction or module guard change", "high"),
            Detector::Fallback001 => (
                fallback_001::ID,
                "Fallback handler change",
                "high; low if the handler is official",
            ),
            Detector::Impl001 => (
                impl_001::ID,
                "Implementation (singleton) change",
                "critical; info for official singletons and migrations",
            ),
            Detector::Refund001 => (
                refund_001::ID,
                "Gas refund paid by the Safe",
                "high (token or uncapped native refund), medium (capped native), low (inert fields)",
            ),
            Detector::Approval001 => (
                approval_001::ID,
                "Unlimited or operator approval",
                "high (unlimited or operator), info (bounded or revoked)",
            ),
            Detector::Approval002 => (
                approval_002::ID,
                "Permit2 allowance (experimental)",
                "high (unlimited), info (bounded)",
            ),
            Detector::Value001 => (
                value_001::ID,
                "Native value transfer",
                "info; high with delegatecall",
            ),
            Detector::Poison001 => (
                poison_001::ID,
                "Address looks like an address-book entry",
                "high",
            ),
            Detector::Target001 => (target_001::ID, "Unknown target", "info"),
            Detector::Decode001 => (
                decode_001::ID,
                "Undecodable or malformed calldata",
                "medium; high for a malformed batch",
            ),
        }
    }

    /// Runs the detector on one node.
    pub fn check(self, ctx: &Context<'_>, node: &CallNode) -> Vec<Finding> {
        match self {
            Detector::Delegate001 => delegate_001::check(ctx, node),
            Detector::Delegate002 => delegate_002::check(ctx, node),
            Detector::Semantics001 => semantics_001::check(ctx, node),
            Detector::Owners001 => owners_001::check(ctx, node),
            Detector::Threshold001 => threshold_001::check(ctx, node),
            Detector::Module001 => module_001::check(ctx, node),
            Detector::Guard001 => guard_001::check(ctx, node),
            Detector::Fallback001 => fallback_001::check(ctx, node),
            Detector::Impl001 => impl_001::check(ctx, node),
            Detector::Refund001 => refund_001::check(ctx, node),
            Detector::Approval001 => approval_001::check(ctx, node),
            Detector::Approval002 => approval_002::check(ctx, node),
            Detector::Value001 => value_001::check(ctx, node),
            Detector::Poison001 => poison_001::check(ctx, node),
            Detector::Target001 => target_001::check(ctx, node),
            Detector::Decode001 => decode_001::check(ctx, node),
        }
    }
}

/// Runs every detector on every node. Findings are sorted by severity
/// (highest first), then by position in the tree, then by detector order.
pub fn run(ctx: &Context<'_>, root: &CallNode) -> Vec<Finding> {
    let mut findings = Vec::new();
    for node in root.nodes() {
        for detector in Detector::ALL {
            findings.extend(detector.check(ctx, node));
        }
    }
    // The sort is stable: equal severities keep tree and detector order.
    findings.sort_by_key(|f| std::cmp::Reverse(f.severity));
    findings
}

/// The highest severity among `findings`, if any.
pub fn verdict(findings: &[Finding]) -> Option<Severity> {
    findings.iter().map(|f| f.severity).max()
}

/// Builds a finding for `node`.
fn finding(
    id: &'static str,
    severity: Severity,
    node: &CallNode,
    title: impl Into<String>,
    detail: impl Into<String>,
) -> Finding {
    Finding {
        id,
        severity,
        title: title.into(),
        detail: detail.into(),
        path: node.path.clone(),
    }
}

#[cfg(test)]
mod tests {
    use super::testutil::*;
    use super::{Detector, verdict};

    #[test]
    fn detector_table_is_consistent() {
        let mut ids: Vec<&str> = Detector::ALL.iter().map(|d| d.id()).collect();
        for d in Detector::ALL {
            assert!(d.id().starts_with("BS-"));
            assert!(
                d.documentation().starts_with(&format!("# {}:", d.id())),
                "{}",
                d.id()
            );
            assert_eq!(Detector::from_id(&d.id().to_lowercase()), Some(d));
        }
        ids.sort_unstable();
        ids.dedup();
        assert_eq!(ids.len(), Detector::ALL.len());
    }

    #[test]
    fn findings_are_sorted_by_severity() {
        let evil = Address::repeat_byte(0xee);
        let f = findings(&tx(evil, Operation::DelegateCall, transfer()));
        assert!(f.windows(2).all(|w| w[0].severity >= w[1].severity));
        assert_eq!(verdict(&f), Some(Severity::Critical));
        assert_eq!(verdict(&[]), None);
    }

    #[test]
    fn severities_parse() {
        assert_eq!("HIGH".parse::<Severity>(), Ok(Severity::High));
        assert!("severe".parse::<Severity>().is_err());
    }
}
