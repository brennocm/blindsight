//! Turning user input into a [`TxInput`]: the Safe, the transaction, and
//! anything worth warning about.
//!
//! Three sources, each parsed into a [`PartialTx`] (every field optional):
//!
//! - command-line flags ([`TxFlags`]);
//! - a JSON file in the Safe Transaction Service format ([`json`]);
//! - raw `execTransaction` calldata ([`exec`]), which lacks the nonce.
//!
//! Sources are merged field by field. A field given by two sources must have
//! the same value in both, otherwise the input is rejected: silently
//! preferring one would let a tampered file override what the user typed.
//! [`PartialTx::finish`] then checks required fields, applies the defaults the
//! official interface uses, and validates the chain.

pub mod exec;
pub mod fields;
pub mod json;

use std::fmt;
use std::io::Read;

use alloy_primitives::{Address, B256, Bytes, U256};
use thiserror::Error;

use crate::registry::{self, RegistryError};
use crate::safe::{Operation, SafeAccount, SafeTx, SafeVersion};

/// Largest calldata accepted, in bytes (`data`, or `execTransaction`
/// calldata). Real Safe transactions, including large `MultiSend` batches, are
/// far smaller; the limit bounds memory and decoding time.
pub const MAX_CALLDATA_BYTES: usize = 1024 * 1024;

/// Largest JSON input accepted, in bytes (hex doubles the calldata size).
pub const MAX_JSON_BYTES: usize = 4 * 1024 * 1024;

/// An input field, for error messages.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(missing_docs)] // The variants are the field names.
pub enum Field {
    ChainId,
    Safe,
    SafeVersion,
    To,
    Value,
    Data,
    Operation,
    SafeTxGas,
    BaseGas,
    GasPrice,
    GasToken,
    RefundReceiver,
    Nonce,
    SafeTxHash,
    ExecCalldata,
    ExpectDomainHash,
    ExpectMessageHash,
    ExpectSafeTxHash,
}

impl Field {
    /// Lower-case name used in messages, e.g. `"safeTxGas"`.
    pub fn name(self) -> &'static str {
        match self {
            Field::ChainId => "chainId",
            Field::Safe => "safe",
            Field::SafeVersion => "safeVersion",
            Field::To => "to",
            Field::Value => "value",
            Field::Data => "data",
            Field::Operation => "operation",
            Field::SafeTxGas => "safeTxGas",
            Field::BaseGas => "baseGas",
            Field::GasPrice => "gasPrice",
            Field::GasToken => "gasToken",
            Field::RefundReceiver => "refundReceiver",
            Field::Nonce => "nonce",
            Field::SafeTxHash => "safeTxHash",
            Field::ExecCalldata => "execTransaction calldata",
            Field::ExpectDomainHash => "expected domain hash",
            Field::ExpectMessageHash => "expected message hash",
            Field::ExpectSafeTxHash => "expected safeTxHash",
        }
    }

    /// The command-line flag that sets this field.
    pub fn flag(self) -> &'static str {
        match self {
            Field::ChainId => "--chain-id",
            Field::Safe => "--safe",
            Field::SafeVersion => "--safe-version",
            Field::To => "--to",
            Field::Value => "--value",
            Field::Data => "--data",
            Field::Operation => "--operation",
            Field::SafeTxGas => "--safe-tx-gas",
            Field::BaseGas => "--base-gas",
            Field::GasPrice => "--gas-price",
            Field::GasToken => "--gas-token",
            Field::RefundReceiver => "--refund-receiver",
            Field::Nonce => "--nonce",
            Field::SafeTxHash => "--tx (safeTxHash key)",
            Field::ExecCalldata => "--exec-calldata",
            Field::ExpectDomainHash => "--expect-domain-hash",
            Field::ExpectMessageHash => "--expect-message-hash",
            Field::ExpectSafeTxHash => "--expect-safe-tx-hash",
        }
    }
}

impl fmt::Display for Field {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} ({})", self.name(), self.flag())
    }
}

/// Why the input was rejected. Every message names the field; quoted values
/// are sanitised excerpts.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum InputError {
    /// A value could not be parsed.
    #[error("invalid {field}: {reason}; got \"{value}\"")]
    Invalid {
        /// The field.
        field: Field,
        /// Sanitised excerpt of the value given.
        value: String,
        /// What was expected.
        reason: String,
    },
    /// A required field was not given by any source.
    #[error("missing {field}")]
    Missing {
        /// The field.
        field: Field,
    },
    /// Two sources gave different values for the same field.
    #[error(
        "conflicting values for {field}: {first} from {first_source}, {second} from {second_source}"
    )]
    Conflict {
        /// The field.
        field: Field,
        /// First value, formatted.
        first: String,
        /// Where the first value came from.
        first_source: &'static str,
        /// Second value, formatted.
        second: String,
        /// Where the second value came from.
        second_source: &'static str,
    },
    /// The chain id is not one with an official Safe deployment.
    #[error(
        "unknown chain id {0}: no official Safe deployment is known on it; pass --allow-unknown-chain to continue (official helper contracts will not be recognised)"
    )]
    UnknownChain(u64),
    /// Input larger than the limits.
    #[error("{what} is larger than the limit of {limit} bytes")]
    TooLarge {
        /// What was too large.
        what: &'static str,
        /// The limit in bytes.
        limit: usize,
    },
    /// The JSON input is malformed or has the wrong shape.
    #[error("invalid JSON input: {0}")]
    Json(String),
    /// Reading the input failed.
    #[error("cannot read {what}: {reason}")]
    Read {
        /// What was being read.
        what: String,
        /// The I/O error.
        reason: String,
    },
    /// The embedded data could not be loaded.
    #[error(transparent)]
    Registry(#[from] RegistryError),
}

/// Something about the input that does not stop the analysis but must be
/// shown to the user.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InputWarning {
    /// A mixed-case address whose EIP-55 checksum is wrong.
    BadChecksum {
        /// The field.
        field: Field,
        /// The address as given (valid hex, safe to print).
        given: String,
        /// The correctly checksummed address.
        expected: String,
    },
    /// The chain id is not known but `--allow-unknown-chain` was given.
    UnknownChainAllowed(u64),
    /// An address-book entry whose mixed-case checksum is wrong.
    BookChecksum {
        /// Sanitised name of the entry.
        name: String,
        /// The address as given (valid hex, safe to print).
        given: String,
        /// The correctly checksummed address.
        expected: String,
    },
}

impl fmt::Display for InputWarning {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            InputWarning::BadChecksum {
                field,
                given,
                expected,
            } => write!(
                f,
                "{field}: {given} has an invalid EIP-55 checksum; the correctly checksummed form is {expected}. A corrupted checksum can mean the address was altered: check where it came from"
            ),
            InputWarning::BookChecksum {
                name,
                given,
                expected,
            } => write!(
                f,
                "address book entry \"{name}\": {given} has an invalid EIP-55 checksum; the correctly checksummed form is {expected}. Check the entry against its source"
            ),
            InputWarning::UnknownChainAllowed(id) => write!(
                f,
                "chain id {id} is not a chain with an official Safe deployment; official helper contracts (MultiSend, migrations) cannot be recognised on it"
            ),
        }
    }
}

/// A transaction with every field optional, as one input source gives it.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
#[allow(missing_docs)] // Same fields as `SafeAccount` and `SafeTx`.
pub struct PartialTx {
    pub chain_id: Option<u64>,
    pub safe: Option<Address>,
    pub version: Option<SafeVersion>,
    pub to: Option<Address>,
    pub value: Option<U256>,
    pub data: Option<Bytes>,
    pub operation: Option<Operation>,
    pub safe_tx_gas: Option<U256>,
    pub base_gas: Option<U256>,
    pub gas_price: Option<U256>,
    pub gas_token: Option<Address>,
    pub refund_receiver: Option<Address>,
    pub nonce: Option<U256>,
    /// The safeTxHash a JSON file claims (Transaction Service `safeTxHash`).
    pub claimed_safe_tx_hash: Option<B256>,
    /// Signatures from `execTransaction` calldata.
    pub signatures: Option<Bytes>,
    /// Warnings raised while parsing this source.
    pub warnings: Vec<InputWarning>,
}

/// The input, validated and complete.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TxInput {
    /// The Safe that executes the transaction.
    pub account: SafeAccount,
    /// The transaction.
    pub tx: SafeTx,
    /// safeTxHash claimed by the input file, to compare with the computed one.
    pub claimed_safe_tx_hash: Option<B256>,
    /// Signatures, when the input was `execTransaction` calldata.
    pub signatures: Option<Bytes>,
    /// Warnings to show to the user.
    pub warnings: Vec<InputWarning>,
}

/// Formats a conflicting value for an error message. Long values (calldata)
/// are summarised by length rather than cut, so nothing partial is shown.
fn conflict_value(value: &impl fmt::Debug) -> String {
    let text = format!("{value:?}");
    if text.chars().count() > 132 {
        format!("<a value of {} characters>", text.chars().count())
    } else {
        text
    }
}

/// Picks the value of one field from two sources; they must agree.
fn merge_field<T: PartialEq + fmt::Debug>(
    field: Field,
    first: Option<T>,
    first_source: &'static str,
    second: Option<T>,
    second_source: &'static str,
) -> Result<Option<T>, InputError> {
    match (first, second) {
        (Some(a), Some(b)) if a != b => Err(InputError::Conflict {
            field,
            first: conflict_value(&a),
            first_source,
            second: conflict_value(&b),
            second_source,
        }),
        (Some(a), _) => Ok(Some(a)),
        (None, b) => Ok(b),
    }
}

impl PartialTx {
    /// Combines two sources. A field set in both must have the same value.
    ///
    /// # Errors
    ///
    /// [`InputError::Conflict`] naming the first field that differs.
    pub fn merge(
        self,
        self_source: &'static str,
        other: PartialTx,
        other_source: &'static str,
    ) -> Result<PartialTx, InputError> {
        let (a, b) = (self_source, other_source);
        let mut warnings = self.warnings;
        warnings.extend(other.warnings);
        Ok(PartialTx {
            chain_id: merge_field(Field::ChainId, self.chain_id, a, other.chain_id, b)?,
            safe: merge_field(Field::Safe, self.safe, a, other.safe, b)?,
            version: merge_field(Field::SafeVersion, self.version, a, other.version, b)?,
            to: merge_field(Field::To, self.to, a, other.to, b)?,
            value: merge_field(Field::Value, self.value, a, other.value, b)?,
            data: merge_field(Field::Data, self.data, a, other.data, b)?,
            operation: merge_field(Field::Operation, self.operation, a, other.operation, b)?,
            safe_tx_gas: merge_field(Field::SafeTxGas, self.safe_tx_gas, a, other.safe_tx_gas, b)?,
            base_gas: merge_field(Field::BaseGas, self.base_gas, a, other.base_gas, b)?,
            gas_price: merge_field(Field::GasPrice, self.gas_price, a, other.gas_price, b)?,
            gas_token: merge_field(Field::GasToken, self.gas_token, a, other.gas_token, b)?,
            refund_receiver: merge_field(
                Field::RefundReceiver,
                self.refund_receiver,
                a,
                other.refund_receiver,
                b,
            )?,
            nonce: merge_field(Field::Nonce, self.nonce, a, other.nonce, b)?,
            claimed_safe_tx_hash: merge_field(
                Field::SafeTxHash,
                self.claimed_safe_tx_hash,
                a,
                other.claimed_safe_tx_hash,
                b,
            )?,
            signatures: merge_field(Field::ExecCalldata, self.signatures, a, other.signatures, b)?,
            warnings,
        })
    }

    /// Checks required fields, applies defaults and validates the chain.
    ///
    /// Required: chain id, Safe address, Safe version, `to`, nonce. Defaults,
    /// as in the official Safe interface: `value` 0, empty `data`, `CALL`,
    /// all gas fields 0, `gasToken` and `refundReceiver` the zero address.
    ///
    /// # Errors
    ///
    /// [`InputError::Missing`] for a missing required field,
    /// [`InputError::UnknownChain`] for a chain without an official Safe
    /// deployment unless `allow_unknown_chain`.
    pub fn finish(self, allow_unknown_chain: bool) -> Result<TxInput, InputError> {
        // Closures build the error only when the field is missing.
        let missing = |field| move || InputError::Missing { field };
        let chain_id = self.chain_id.ok_or_else(missing(Field::ChainId))?;
        let mut warnings = self.warnings;
        if registry::chains()?.get(chain_id).is_none() {
            if allow_unknown_chain {
                warnings.push(InputWarning::UnknownChainAllowed(chain_id));
            } else {
                return Err(InputError::UnknownChain(chain_id));
            }
        }
        let account = SafeAccount {
            address: self.safe.ok_or_else(missing(Field::Safe))?,
            chain_id,
            version: self.version.ok_or_else(missing(Field::SafeVersion))?,
        };
        let tx = SafeTx {
            to: self.to.ok_or_else(missing(Field::To))?,
            value: self.value.unwrap_or_default(),
            data: self.data.unwrap_or_default(),
            operation: self.operation.unwrap_or(Operation::Call),
            safe_tx_gas: self.safe_tx_gas.unwrap_or_default(),
            base_gas: self.base_gas.unwrap_or_default(),
            gas_price: self.gas_price.unwrap_or_default(),
            gas_token: self.gas_token.unwrap_or_default(),
            refund_receiver: self.refund_receiver.unwrap_or_default(),
            nonce: self.nonce.ok_or_else(missing(Field::Nonce))?,
        };
        Ok(TxInput {
            account,
            tx,
            claimed_safe_tx_hash: self.claimed_safe_tx_hash,
            signatures: self.signatures,
            warnings,
        })
    }
}

/// Raw flag values, as typed on the command line.
#[derive(Debug, Clone, Default)]
#[allow(missing_docs)] // One field per flag, named after it.
pub struct TxFlags {
    pub chain_id: Option<String>,
    pub safe: Option<String>,
    pub safe_version: Option<String>,
    pub to: Option<String>,
    pub value: Option<String>,
    pub data: Option<String>,
    pub operation: Option<String>,
    pub safe_tx_gas: Option<String>,
    pub base_gas: Option<String>,
    pub gas_price: Option<String>,
    pub gas_token: Option<String>,
    pub refund_receiver: Option<String>,
    pub nonce: Option<String>,
}

impl TxFlags {
    /// Parses every flag that was given.
    ///
    /// # Errors
    ///
    /// The first [`InputError::Invalid`] found.
    pub fn parse(&self) -> Result<PartialTx, InputError> {
        use fields::{
            parse_address, parse_bytes, parse_operation, parse_u64, parse_uint, parse_version,
        };

        let mut warnings = Vec::new();
        let mut address = |field, value: &Option<String>| -> Result<Option<Address>, InputError> {
            match value {
                Some(s) => {
                    let (a, warning) = parse_address(field, s)?;
                    warnings.extend(warning);
                    Ok(Some(a))
                }
                None => Ok(None),
            }
        };
        let safe = address(Field::Safe, &self.safe)?;
        let to = address(Field::To, &self.to)?;
        let gas_token = address(Field::GasToken, &self.gas_token)?;
        let refund_receiver = address(Field::RefundReceiver, &self.refund_receiver)?;

        let uint = |field, value: &Option<String>| {
            value.as_deref().map(|s| parse_uint(field, s)).transpose()
        };
        Ok(PartialTx {
            chain_id: self
                .chain_id
                .as_deref()
                .map(|s| parse_u64(Field::ChainId, s))
                .transpose()?,
            safe,
            version: self
                .safe_version
                .as_deref()
                .map(|s| parse_version(Field::SafeVersion, s))
                .transpose()?,
            to,
            value: uint(Field::Value, &self.value)?,
            data: self
                .data
                .as_deref()
                .map(|s| parse_bytes(Field::Data, s))
                .transpose()?,
            operation: self
                .operation
                .as_deref()
                .map(|s| parse_operation(Field::Operation, s))
                .transpose()?,
            safe_tx_gas: uint(Field::SafeTxGas, &self.safe_tx_gas)?,
            base_gas: uint(Field::BaseGas, &self.base_gas)?,
            gas_price: uint(Field::GasPrice, &self.gas_price)?,
            gas_token,
            refund_receiver,
            nonce: uint(Field::Nonce, &self.nonce)?,
            claimed_safe_tx_hash: None,
            signatures: None,
            warnings,
        })
    }
}

/// Reads at most `limit` bytes of UTF-8 text from `reader`.
///
/// # Errors
///
/// [`InputError::TooLarge`] past the limit, [`InputError::Read`] on I/O
/// errors or invalid UTF-8.
pub fn read_limited(
    reader: impl Read,
    limit: usize,
    what: &'static str,
) -> Result<String, InputError> {
    let mut buf = Vec::new();
    // Read one byte past the limit to tell "exactly at the limit" from "over".
    let cap = u64::try_from(limit).unwrap_or(u64::MAX).saturating_add(1);
    reader
        .take(cap)
        .read_to_end(&mut buf)
        .map_err(|e| InputError::Read {
            what: what.to_string(),
            reason: e.to_string(),
        })?;
    if buf.len() > limit {
        return Err(InputError::TooLarge { what, limit });
    }
    String::from_utf8(buf).map_err(|_| InputError::Read {
        what: what.to_string(),
        reason: "not valid UTF-8".to_string(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn flags() -> TxFlags {
        TxFlags {
            chain_id: Some("1".into()),
            safe: Some("0x1Db92e2EeBC8E0c075a02BeA49a2935BcD2dFCF4".into()),
            safe_version: Some("1.1.1".into()),
            to: Some("0x96221423681A6d52E184D440a8eFCEbB105C7242".into()),
            nonce: Some("71".into()),
            ..TxFlags::default()
        }
    }

    #[test]
    fn minimal_flags_get_official_defaults() {
        let input = flags().parse().unwrap().finish(false).unwrap();
        assert_eq!(input.account.chain_id, 1);
        assert_eq!(input.tx.value, U256::ZERO);
        assert!(input.tx.data.is_empty());
        assert_eq!(input.tx.operation, Operation::Call);
        assert_eq!(input.tx.safe_tx_gas, U256::ZERO);
        assert_eq!(input.tx.base_gas, U256::ZERO);
        assert_eq!(input.tx.gas_price, U256::ZERO);
        assert_eq!(input.tx.gas_token, Address::ZERO);
        assert_eq!(input.tx.refund_receiver, Address::ZERO);
        assert_eq!(input.tx.nonce, U256::from(71u64));
        assert!(input.warnings.is_empty());
    }

    #[test]
    fn each_required_field_is_reported_when_missing() {
        type Clear = fn(&mut TxFlags);
        let cases: [(Field, Clear); 5] = [
            (Field::ChainId, |f| f.chain_id = None),
            (Field::Safe, |f| f.safe = None),
            (Field::SafeVersion, |f| f.safe_version = None),
            (Field::To, |f| f.to = None),
            (Field::Nonce, |f| f.nonce = None),
        ];
        for (field, clear) in cases {
            let mut f = flags();
            clear(&mut f);
            assert_eq!(
                f.parse().unwrap().finish(false),
                Err(InputError::Missing { field })
            );
        }
    }

    #[test]
    fn unknown_chain_needs_explicit_permission() {
        let mut f = flags();
        f.chain_id = Some("987654321987".into());
        let partial = f.parse().unwrap();
        assert_eq!(
            partial.clone().finish(false),
            Err(InputError::UnknownChain(987_654_321_987))
        );
        let input = partial.finish(true).unwrap();
        assert_eq!(
            input.warnings,
            [InputWarning::UnknownChainAllowed(987_654_321_987)]
        );
    }

    #[test]
    fn checksum_warnings_are_collected() {
        let mut f = flags();
        f.to = Some("0x96221423681a6D52E184D440a8eFCEbB105C7242".into());
        let input = f.parse().unwrap().finish(false).unwrap();
        assert!(matches!(
            input.warnings.as_slice(),
            [InputWarning::BadChecksum {
                field: Field::To,
                ..
            }]
        ));
    }

    #[test]
    fn merge_accepts_agreeing_sources_and_rejects_conflicts() {
        let a = PartialTx {
            nonce: Some(U256::from(5u64)),
            to: Some(Address::ZERO),
            ..PartialTx::default()
        };
        let same = PartialTx {
            nonce: Some(U256::from(5u64)),
            chain_id: Some(1),
            ..PartialTx::default()
        };
        let merged = a.clone().merge("flags", same, "JSON file").unwrap();
        assert_eq!(merged.nonce, Some(U256::from(5u64)));
        assert_eq!(merged.chain_id, Some(1));
        assert_eq!(merged.to, Some(Address::ZERO));

        let other = PartialTx {
            nonce: Some(U256::from(6u64)),
            ..PartialTx::default()
        };
        let err = a.merge("flags", other, "JSON file").unwrap_err();
        assert!(matches!(
            err,
            InputError::Conflict {
                field: Field::Nonce,
                ..
            }
        ));
        assert!(err.to_string().contains("JSON file"));
    }

    #[test]
    fn read_limited_enforces_the_limit() {
        assert_eq!(read_limited(&b"abc"[..], 3, "x").unwrap(), "abc");
        assert_eq!(
            read_limited(&b"abcd"[..], 3, "x"),
            Err(InputError::TooLarge {
                what: "x",
                limit: 3
            })
        );
        assert!(matches!(
            read_limited(&[0xff, 0xfe][..], 10, "x"),
            Err(InputError::Read { .. })
        ));
    }

    #[test]
    fn messages_name_fields_and_flags() {
        assert_eq!(Field::SafeTxGas.to_string(), "safeTxGas (--safe-tx-gas)");
        for field in [
            Field::ChainId,
            Field::Safe,
            Field::SafeVersion,
            Field::To,
            Field::Value,
            Field::Data,
            Field::Operation,
            Field::SafeTxGas,
            Field::BaseGas,
            Field::GasPrice,
            Field::GasToken,
            Field::RefundReceiver,
            Field::Nonce,
            Field::SafeTxHash,
            Field::ExecCalldata,
            Field::ExpectDomainHash,
            Field::ExpectMessageHash,
            Field::ExpectSafeTxHash,
        ] {
            assert!(!field.name().is_empty() && field.flag().starts_with("--"));
        }
        let warnings = [
            InputWarning::BadChecksum {
                field: Field::To,
                given: "0xab".into(),
                expected: "0xAB".into(),
            },
            InputWarning::UnknownChainAllowed(5),
            InputWarning::BookChecksum {
                name: "Ops".into(),
                given: "0xab".into(),
                expected: "0xAB".into(),
            },
        ];
        for w in warnings {
            assert!(w.to_string().len() > 40);
        }
        let errors = [
            InputError::Missing { field: Field::To },
            InputError::UnknownChain(5),
            InputError::TooLarge {
                what: "x",
                limit: 1,
            },
            InputError::Json("bad".into()),
        ];
        for e in errors {
            assert!(!e.to_string().is_empty());
        }
    }

    #[test]
    fn long_conflicting_values_are_summarised() {
        let a = PartialTx {
            data: Some(Bytes::from(vec![1; 200])),
            ..PartialTx::default()
        };
        let b = PartialTx {
            data: Some(Bytes::from(vec![2; 200])),
            ..PartialTx::default()
        };
        let err = a.merge("flags", b, "file").unwrap_err().to_string();
        assert!(err.contains("<a value of"), "{err}");
    }
}
