//! Decoding calls to the user's own contracts with ABIs they provide
//! (`--abi ADDRESS=FILE`).
//!
//! An ABI is bound to one address: blindsight only uses it for calls to that
//! address, so a function name from it describes code the user vouches for.
//! It never makes a delegatecall target trusted.
//!
//! The decoded values must re-encode to exactly the original arguments. This
//! rejects dirty high bytes and other non-canonical encodings, matching the
//! strictness of the built-in decoder.

use std::collections::BTreeMap;
use std::fmt::Write;

use alloy_dyn_abi::{DynSolValue, JsonAbiExt};
use alloy_json_abi::JsonAbi;
use alloy_primitives::Address;
use thiserror::Error;

/// Largest ABI file accepted, in bytes.
pub const MAX_ABI_BYTES: usize = 4 * 1024 * 1024;

/// ABIs supplied by the user, each bound to one address.
#[derive(Debug, Clone, Default)]
pub struct UserAbis {
    by_address: BTreeMap<Address, JsonAbi>,
}

/// Why an ABI file was rejected.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum UserAbiError {
    /// Not a valid JSON ABI.
    #[error("invalid ABI for {address}: {reason}")]
    Invalid {
        /// The address it was given for.
        address: String,
        /// The parser's message.
        reason: String,
    },
    /// Two ABIs for the same address.
    #[error("two ABIs given for {0}")]
    Duplicate(String),
    /// Larger than [`MAX_ABI_BYTES`].
    #[error("ABI file for {0} is larger than {MAX_ABI_BYTES} bytes")]
    TooLarge(String),
}

/// A call decoded with a user ABI.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UserCall {
    /// Full signature, e.g. `"rebalance(address,uint256)"`.
    pub signature: String,
    /// `(parameter name, formatted value)` pairs. Both come from input
    /// (the ABI file and the calldata): sanitise before printing.
    pub args: Vec<(String, String)>,
}

impl UserAbis {
    /// Adds the ABI in `json` (a JSON ABI array) for `address`.
    ///
    /// # Errors
    ///
    /// [`UserAbiError`] for invalid JSON, a second ABI for the same address,
    /// or an oversized file.
    pub fn add(&mut self, address: Address, json: &str) -> Result<(), UserAbiError> {
        let label = address.to_checksum(None);
        if json.len() > MAX_ABI_BYTES {
            return Err(UserAbiError::TooLarge(label));
        }
        let abi: JsonAbi = serde_json::from_str(json).map_err(|e| UserAbiError::Invalid {
            address: label.clone(),
            reason: e.to_string(),
        })?;
        if self.by_address.insert(address, abi).is_some() {
            return Err(UserAbiError::Duplicate(label));
        }
        Ok(())
    }

    /// Whether no ABI was given.
    pub fn is_empty(&self) -> bool {
        self.by_address.is_empty()
    }

    /// Decodes `data` sent to `to` with the ABI bound to `to`.
    ///
    /// `None` if there is no ABI for `to` or no function with this selector
    /// in it; `Some(Err(reason))` if the selector matches but the arguments
    /// do not decode canonically.
    pub fn decode(&self, to: Address, data: &[u8]) -> Option<Result<UserCall, String>> {
        let abi = self.by_address.get(&to)?;
        let selector = data.get(..4)?;
        let function = abi
            .functions()
            .find(|f| f.selector().as_slice() == selector)?;
        let signature = function.signature();
        let args_data = data.get(4..).unwrap_or_default();
        let result = function
            .abi_decode_input(args_data)
            .map_err(|e| format!("does not decode as {signature} from your ABI: {e}"))
            .and_then(|values| {
                let reencoded = DynSolValue::Tuple(values.clone()).abi_encode_params();
                if reencoded == args_data {
                    Ok(values)
                } else {
                    Err(format!(
                        "arguments are not a canonical encoding of {signature} (dirty bits, gaps or trailing bytes)"
                    ))
                }
            })
            .map(|values| UserCall {
                args: function
                    .inputs
                    .iter()
                    .zip(&values)
                    .enumerate()
                    .map(|(i, (param, value))| {
                        let name = if param.name.is_empty() {
                            format!("arg{i}")
                        } else {
                            param.name.clone()
                        };
                        (name, format_value(value))
                    })
                    .collect(),
                signature,
            });
        Some(result)
    }
}

/// Formats a decoded value. Addresses are checksummed and never shortened.
fn format_value(value: &DynSolValue) -> String {
    let list = |items: &[DynSolValue], open: char, close: char| {
        let mut out = String::new();
        out.push(open);
        for (i, item) in items.iter().enumerate() {
            if i > 0 {
                out.push_str(", ");
            }
            out.push_str(&format_value(item));
        }
        out.push(close);
        out
    };
    match value {
        DynSolValue::Bool(b) => b.to_string(),
        DynSolValue::Int(i, _) => i.to_string(),
        DynSolValue::Uint(u, _) => u.to_string(),
        DynSolValue::FixedBytes(word, size) => {
            let bytes = word.get(..*size).unwrap_or_default();
            format!("0x{}", alloy_primitives::hex::encode(bytes))
        }
        DynSolValue::Address(a) => a.to_checksum(None),
        DynSolValue::Function(f) => format!("0x{}", alloy_primitives::hex::encode(f.as_slice())),
        DynSolValue::Bytes(b) => format!("0x{}", alloy_primitives::hex::encode(b)),
        DynSolValue::String(s) => {
            let mut out = String::new();
            // Writing to a String cannot fail.
            let _ = write!(out, "{s:?}");
            out
        }
        DynSolValue::Array(items) | DynSolValue::FixedArray(items) => list(items, '[', ']'),
        DynSolValue::Tuple(items) => list(items, '(', ')'),
    }
}

#[cfg(test)]
mod tests {
    use alloy_primitives::U256;

    use super::*;

    const ABI: &str = r#"[
        {"type":"function","name":"rebalance","stateMutability":"nonpayable","outputs":[],
         "inputs":[{"name":"pool","type":"address"},{"name":"amount","type":"uint256"},
                   {"name":"","type":"string"},{"name":"ids","type":"uint8[]"}]}
    ]"#;

    fn encoded() -> Vec<u8> {
        let abi: JsonAbi = serde_json::from_str(ABI).unwrap();
        let f = abi.functions().next().unwrap();
        f.abi_encode_input(&[
            DynSolValue::Address(Address::repeat_byte(0xab)),
            DynSolValue::Uint(U256::from(5u64), 256),
            DynSolValue::String("hi\u{1b}[2J".into()),
            DynSolValue::Array(vec![DynSolValue::Uint(U256::from(1u8), 8)]),
        ])
        .unwrap()
    }

    #[test]
    fn decodes_only_for_the_bound_address() {
        let mut abis = UserAbis::default();
        let target = Address::repeat_byte(0x11);
        abis.add(target, ABI).unwrap();
        let call = abis.decode(target, &encoded()).unwrap().unwrap();
        assert_eq!(call.signature, "rebalance(address,uint256,string,uint8[])");
        assert_eq!(
            call.args[0],
            ("pool".into(), Address::repeat_byte(0xab).to_checksum(None))
        );
        assert_eq!(call.args[1], ("amount".into(), "5".into()));
        assert_eq!(call.args[2].0, "arg2");
        assert_eq!(call.args[2].1, "\"hi\\u{1b}[2J\"");
        assert_eq!(call.args[3].1, "[1]");
        assert!(
            abis.decode(Address::repeat_byte(0x22), &encoded())
                .is_none()
        );
        assert!(abis.decode(target, &[1, 2, 3, 4]).is_none());
    }

    #[test]
    fn rejects_non_canonical_arguments() {
        let mut abis = UserAbis::default();
        let target = Address::repeat_byte(0x11);
        abis.add(target, ABI).unwrap();
        let mut dirty = encoded();
        dirty[4] = 1; // high byte of the address word
        assert!(matches!(abis.decode(target, &dirty), Some(Err(_))));
        let mut trailing = encoded();
        trailing.extend_from_slice(&[0; 32]);
        assert!(matches!(abis.decode(target, &trailing), Some(Err(_))));
    }

    #[test]
    fn rejects_bad_files_and_duplicates() {
        let mut abis = UserAbis::default();
        assert!(abis.add(Address::ZERO, "{}").is_err());
        assert!(abis.add(Address::ZERO, "nope").is_err());
        abis.add(Address::ZERO, ABI).unwrap();
        assert!(matches!(
            abis.add(Address::ZERO, ABI),
            Err(UserAbiError::Duplicate(_))
        ));
    }
}
