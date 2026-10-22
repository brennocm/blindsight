//! Risk detectors.
//!
//! Each detector is a pure function of the decoded call tree and the
//! [`Context`]; none does I/O. [`run`] applies every detector to every node of
//! the tree, so wrapping a payload in a batch or a nested Safe transaction
//! does not hide it. Detectors are an `enum` ([`Detector`]) rather than trait
//! objects: the set is closed and a `match` makes every case explicit.
//! Documentation for each one lives in `docs/detectors/<ID>.md` and is
//! compiled in for `blindsight detectors explain`.

mod delegate_001;

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
}

impl Detector {
    /// Every detector, in catalog order.
    pub const ALL: [Detector; 1] = [Detector::Delegate001];

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
        false
    }

    /// The detector's documentation (`docs/detectors/<ID>.md`).
    pub fn documentation(self) -> &'static str {
        match self {
            Detector::Delegate001 => include_str!("../../docs/detectors/BS-DELEGATE-001.md"),
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
        }
    }

    /// Runs the detector on one node.
    pub fn check(self, ctx: &Context<'_>, node: &CallNode) -> Vec<Finding> {
        match self {
            Detector::Delegate001 => delegate_001::check(ctx, node),
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
