//! The result of an analysis, and how it is rendered.
//!
//! [`analyse`] runs everything a command needs (hashes, decoding, detectors,
//! expected-hash checks) and returns a [`Report`]; [`text`] and [`json`]
//! render it. Rendering never truncates an address or a hash and sanitises
//! every string that comes from the input.

pub mod json;
pub mod signatures;
pub mod text;

use alloy_primitives::{B256, U256};
use thiserror::Error;

use crate::addressbook::AddressBook;
use crate::decode::{CallNode, UserAbis, decode_tree};
use crate::detect::{self, Context, Finding, Severity};
use crate::input::TxInput;
use crate::registry::{Registry, RegistryError};
use crate::safe::{HashMismatch, SafeTxHashes, compute_hashes};

pub use signatures::{SignatureInfo, SignatureKind, parse_signatures};

/// Exit code: nothing at or above `--fail-on`, hashes match.
pub const EXIT_OK: u8 = 0;
/// Exit code: at least one finding at or above `--fail-on`.
pub const EXIT_FINDINGS: u8 = 1;
/// Exit code: input, usage or internal error; no verdict was produced.
pub const EXIT_ERROR: u8 = 2;
/// Exit code: an expected hash does not match. Takes precedence over 1.
pub const EXIT_HASH_MISMATCH: u8 = 3;

/// Version of the JSON output schema. Incremented on incompatible changes.
pub const SCHEMA_VERSION: u32 = 1;

/// Which command produced the report, and so which sections it has.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Command {
    /// Hashes, decoding and detectors.
    Verify,
    /// Hashes only.
    Hash,
    /// Decoding only.
    Decode,
}

impl Command {
    /// Lower-case name.
    pub fn as_str(self) -> &'static str {
        match self {
            Command::Verify => "verify",
            Command::Hash => "hash",
            Command::Decode => "decode",
        }
    }
}

/// Which of the three hashes a check concerns.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HashKind {
    /// EIP-712 domain separator.
    Domain,
    /// EIP-712 struct hash.
    Message,
    /// Final safeTxHash.
    SafeTx,
}

impl HashKind {
    /// Label as hardware wallets and the Safe interface use it.
    pub fn label(self) -> &'static str {
        match self {
            HashKind::Domain => "Domain hash",
            HashKind::Message => "Message hash",
            HashKind::SafeTx => "safeTxHash",
        }
    }

    /// Machine name used in JSON.
    pub fn key(self) -> &'static str {
        match self {
            HashKind::Domain => "domain_hash",
            HashKind::Message => "message_hash",
            HashKind::SafeTx => "safe_tx_hash",
        }
    }
}

/// Where an expected hash came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CheckSource {
    /// An `--expect-*` flag: what the user read on their screen.
    Flag,
    /// The `safeTxHash` key of the JSON input file.
    InputFile,
}

impl CheckSource {
    /// Human description.
    pub fn describe(self, kind: HashKind) -> &'static str {
        match (self, kind) {
            (CheckSource::Flag, HashKind::Domain) => "--expect-domain-hash",
            (CheckSource::Flag, HashKind::Message) => "--expect-message-hash",
            (CheckSource::Flag, HashKind::SafeTx) => "--expect-safe-tx-hash",
            (CheckSource::InputFile, _) => "safeTxHash in the input file",
        }
    }
}

/// One expected hash compared with the computed one.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HashCheck {
    /// Which hash.
    pub kind: HashKind,
    /// Where the expectation came from.
    pub source: CheckSource,
    /// The expected value.
    pub expected: B256,
    /// The computed value.
    pub computed: B256,
}

impl HashCheck {
    /// Whether the expected and computed hashes are equal.
    pub fn matches(&self) -> bool {
        self.expected == self.computed
    }
}

/// Everything besides the transaction that an analysis can use.
#[derive(Debug, Clone)]
pub struct Options {
    /// `--expect-domain-hash`.
    pub expect_domain_hash: Option<B256>,
    /// `--expect-message-hash`.
    pub expect_message_hash: Option<B256>,
    /// `--expect-safe-tx-hash`.
    pub expect_safe_tx_hash: Option<B256>,
    /// `--address-book`.
    pub address_book: Option<AddressBook>,
    /// `--abi` bindings.
    pub user_abis: UserAbis,
    /// `--current-nonce`.
    pub current_nonce: Option<U256>,
    /// `--fail-on`: lowest severity that makes the exit code 1.
    pub fail_on: Severity,
}

impl Default for Options {
    fn default() -> Self {
        Options {
            expect_domain_hash: None,
            expect_message_hash: None,
            expect_safe_tx_hash: None,
            address_book: None,
            user_abis: UserAbis::default(),
            current_nonce: None,
            fail_on: Severity::High,
        }
    }
}

/// The analysis could not be completed. Never caused by the transaction
/// itself: malformed calldata becomes findings, not errors.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum AnalysisError {
    /// Embedded data is corrupt.
    #[error(transparent)]
    Registry(#[from] RegistryError),
    /// The two hash implementations disagree.
    #[error(transparent)]
    Hash(#[from] HashMismatch),
}

/// The result of one command.
#[derive(Debug, Clone)]
pub struct Report {
    /// Which command.
    pub command: Command,
    /// The validated input.
    pub input: TxInput,
    /// The three hashes.
    pub hashes: SafeTxHashes,
    /// Comparisons with expected hashes.
    pub checks: Vec<HashCheck>,
    /// The decoded call tree (`verify`, `decode`).
    pub tree: Option<CallNode>,
    /// Findings, highest severity first (`verify`).
    pub findings: Option<Vec<Finding>>,
    /// Signatures found in `execTransaction` calldata.
    pub signatures: Vec<SignatureInfo>,
    /// The options used.
    pub options: Options,
    /// Embedded data.
    pub registry: Registry,
}

/// Runs `command` on `input`.
///
/// # Errors
///
/// [`AnalysisError`] if embedded data is corrupt or the hash implementations
/// disagree.
pub fn analyse(
    command: Command,
    input: TxInput,
    options: Options,
) -> Result<Report, AnalysisError> {
    let registry = Registry::load()?;
    let hashes = compute_hashes(&input.account, &input.tx)?;

    let mut checks = Vec::new();
    let expectations = [
        (
            HashKind::Domain,
            CheckSource::Flag,
            options.expect_domain_hash,
        ),
        (
            HashKind::Message,
            CheckSource::Flag,
            options.expect_message_hash,
        ),
        (
            HashKind::SafeTx,
            CheckSource::Flag,
            options.expect_safe_tx_hash,
        ),
        (
            HashKind::SafeTx,
            CheckSource::InputFile,
            input.claimed_safe_tx_hash,
        ),
    ];
    for (kind, source, expected) in expectations {
        if let Some(expected) = expected {
            let computed = match kind {
                HashKind::Domain => hashes.domain_hash,
                HashKind::Message => hashes.message_hash,
                HashKind::SafeTx => hashes.safe_tx_hash,
            };
            checks.push(HashCheck {
                kind,
                source,
                expected,
                computed,
            });
        }
    }

    let tree = match command {
        Command::Verify | Command::Decode => {
            Some(decode_tree(&input.account, &input.tx, &options.user_abis)?)
        }
        Command::Hash => None,
    };
    let findings = match (&tree, command) {
        (Some(root), Command::Verify) => {
            let ctx = Context {
                account: &input.account,
                tx: &input.tx,
                registry,
                address_book: options.address_book.as_ref(),
                current_nonce: options.current_nonce,
            };
            Some(detect::run(&ctx, root))
        }
        _ => None,
    };
    let signatures = input
        .signatures
        .as_ref()
        .map(|s| parse_signatures(s))
        .unwrap_or_default();

    Ok(Report {
        command,
        input,
        hashes,
        checks,
        tree,
        findings,
        signatures,
        options,
        registry,
    })
}

impl Report {
    /// The highest finding severity, if any findings were produced.
    pub fn verdict(&self) -> Option<Severity> {
        self.findings.as_deref().and_then(detect::verdict)
    }

    /// Whether any expected hash differs from the computed one.
    pub fn hash_mismatch(&self) -> bool {
        self.checks.iter().any(|c| !c.matches())
    }

    /// The process exit code: 3 on a hash mismatch, else 1 if a finding is
    /// at or above `--fail-on`, else 0.
    pub fn exit_code(&self) -> u8 {
        if self.hash_mismatch() {
            EXIT_HASH_MISMATCH
        } else if self.verdict().is_some_and(|v| v >= self.options.fail_on) {
            EXIT_FINDINGS
        } else {
            EXIT_OK
        }
    }

    /// A detector context for labelling addresses while rendering.
    pub fn context(&self) -> Context<'_> {
        Context {
            account: &self.input.account,
            tx: &self.input.tx,
            registry: self.registry,
            address_book: self.options.address_book.as_ref(),
            current_nonce: self.options.current_nonce,
        }
    }
}

#[cfg(test)]
mod tests;
