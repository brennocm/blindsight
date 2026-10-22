//! JSON input: the Safe Transaction Service format.
//!
//! The object returned by `GET /api/v1/multisig-transactions/{safeTxHash}/`
//! can be passed as is. Its hash-relevant keys are `safe`, `to`, `value`,
//! `data`, `operation`, `safeTxGas`, `baseGas`, `gasPrice`, `gasToken`,
//! `refundReceiver`, `nonce` and `safeTxHash`. The service does not return
//! the chain id or the Safe version, so blindsight also reads `chainId` and
//! `safeVersion` keys, or takes them from flags.
//!
//! Numbers may be JSON strings or JSON integers (the service mixes both).
//! `"data": null` means empty calldata. Every other key, including the
//! service's own `dataDecoded`, is ignored: decoding is done locally.
//!
//! An object with a repeated key is rejected. Parsers disagree on which copy
//! wins, so a file with two `"to"` keys could show one transaction in another
//! tool and a different one here.

use std::collections::BTreeMap;
use std::fmt;

use serde::Deserialize;
use serde::de::{self, MapAccess, Visitor};
use serde_json::Value;

use super::fields::{
    parse_address, parse_bytes, parse_hash, parse_operation, parse_u64, parse_uint, parse_version,
};
use super::{Field, InputError, MAX_JSON_BYTES, PartialTx};

/// A JSON object whose top-level keys are unique.
struct UniqueKeys(BTreeMap<String, Value>);

impl<'de> Deserialize<'de> for UniqueKeys {
    fn deserialize<D: de::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct ObjectVisitor;

        impl<'de> Visitor<'de> for ObjectVisitor {
            type Value = UniqueKeys;

            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("a JSON object describing one Safe transaction")
            }

            fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<UniqueKeys, A::Error> {
                let mut out = BTreeMap::new();
                while let Some((key, value)) = map.next_entry::<String, Value>()? {
                    if out.contains_key(&key) {
                        return Err(de::Error::custom(format!(
                            "key \"{}\" appears more than once",
                            crate::sanitize::excerpt(&key)
                        )));
                    }
                    out.insert(key, value);
                }
                Ok(UniqueKeys(out))
            }
        }

        deserializer.deserialize_map(ObjectVisitor)
    }
}

/// The JSON keys blindsight reads, with the field each one sets.
const KEYS: [(&str, Field); 14] = [
    ("chainId", Field::ChainId),
    ("safe", Field::Safe),
    ("safeVersion", Field::SafeVersion),
    ("to", Field::To),
    ("value", Field::Value),
    ("data", Field::Data),
    ("operation", Field::Operation),
    ("safeTxGas", Field::SafeTxGas),
    ("baseGas", Field::BaseGas),
    ("gasPrice", Field::GasPrice),
    ("gasToken", Field::GasToken),
    ("refundReceiver", Field::RefundReceiver),
    ("nonce", Field::Nonce),
    ("safeTxHash", Field::SafeTxHash),
];

/// A JSON value as the text a field parser takes: strings as they are,
/// integers in decimal. `None` for `null`.
fn as_text(field: Field, value: &Value) -> Result<Option<String>, InputError> {
    match value {
        Value::Null => Ok(None),
        Value::String(s) => Ok(Some(s.clone())),
        Value::Number(n) => match n.as_u64() {
            Some(u) => Ok(Some(u.to_string())),
            // Floats and huge integers lose precision in JSON parsers.
            None => Err(InputError::Json(format!(
                "{}: {n} is not a non-negative integer that fits in 64 bits; write large numbers as strings",
                field.name()
            ))),
        },
        Value::Bool(_) | Value::Array(_) | Value::Object(_) => Err(InputError::Json(format!(
            "{}: expected a string or an integer",
            field.name()
        ))),
    }
}

/// Parses one transaction object.
///
/// # Errors
///
/// [`InputError::TooLarge`], [`InputError::Json`] for malformed JSON,
/// duplicate keys or wrong value types, and the field parsers' errors.
pub fn parse_json(text: &str) -> Result<PartialTx, InputError> {
    if text.len() > MAX_JSON_BYTES {
        return Err(InputError::TooLarge {
            what: "JSON input",
            limit: MAX_JSON_BYTES,
        });
    }
    let UniqueKeys(object) =
        serde_json::from_str(text).map_err(|e| InputError::Json(e.to_string()))?;
    if object.contains_key("results") && !object.contains_key("to") {
        return Err(InputError::Json(
            "this looks like a list response; pass a single transaction object".to_string(),
        ));
    }

    let mut partial = PartialTx::default();
    for (key, field) in KEYS {
        let Some(value) = object.get(key) else {
            continue;
        };
        let text = as_text(field, value)?;
        let Some(s) = text else {
            if field == Field::Data {
                // The service writes empty calldata as null.
                partial.data = Some(alloy_primitives::Bytes::new());
            }
            continue;
        };
        let s = s.as_str();
        match field {
            Field::ChainId => partial.chain_id = Some(parse_u64(field, s)?),
            Field::SafeVersion => partial.version = Some(parse_version(field, s)?),
            Field::Value => partial.value = Some(parse_uint(field, s)?),
            Field::Data => partial.data = Some(parse_bytes(field, s)?),
            Field::Operation => partial.operation = Some(parse_operation(field, s)?),
            Field::SafeTxGas => partial.safe_tx_gas = Some(parse_uint(field, s)?),
            Field::BaseGas => partial.base_gas = Some(parse_uint(field, s)?),
            Field::GasPrice => partial.gas_price = Some(parse_uint(field, s)?),
            Field::Nonce => partial.nonce = Some(parse_uint(field, s)?),
            Field::SafeTxHash => partial.claimed_safe_tx_hash = Some(parse_hash(field, s)?),
            Field::Safe | Field::To | Field::GasToken | Field::RefundReceiver => {
                let (address, warning) = parse_address(field, s)?;
                partial.warnings.extend(warning);
                match field {
                    Field::Safe => partial.safe = Some(address),
                    Field::To => partial.to = Some(address),
                    Field::GasToken => partial.gas_token = Some(address),
                    _ => partial.refund_receiver = Some(address),
                }
            }
            // Not JSON keys (see KEYS).
            Field::ExecCalldata
            | Field::ExpectDomainHash
            | Field::ExpectMessageHash
            | Field::ExpectSafeTxHash => {}
        }
    }
    Ok(partial)
}

#[cfg(test)]
mod tests {
    use alloy_primitives::{Address, U256};

    use super::*;
    use crate::safe::{Operation, SafeVersion};

    /// Shape of a real Transaction Service response (Bybit nonce 70, trimmed),
    /// with mixed number types and `data: null`.
    const SERVICE: &str = r#"{
        "safe": "0x1Db92e2EeBC8E0c075a02BeA49a2935BcD2dFCF4",
        "to": "0xf89d7b9c864f589bbF53a82105107622B35EaA40",
        "value": "60000000000000000000000",
        "data": null,
        "operation": 0,
        "gasToken": "0x0000000000000000000000000000000000000000",
        "safeTxGas": 0,
        "baseGas": 0,
        "gasPrice": "0",
        "refundReceiver": "0x0000000000000000000000000000000000000000",
        "nonce": 70,
        "executionDate": "2025-02-21T13:52:47Z",
        "safeTxHash": "0x0000000000000000000000000000000000000000000000000000000000000001",
        "dataDecoded": {"method": "transfer", "parameters": [], "method": "dup inside is ignored"},
        "confirmations": []
    }"#;

    #[test]
    fn reads_the_transaction_service_format() {
        let p = parse_json(SERVICE).unwrap();
        assert_eq!(
            p.safe,
            Some(
                "0x1Db92e2EeBC8E0c075a02BeA49a2935BcD2dFCF4"
                    .parse::<Address>()
                    .unwrap()
            )
        );
        assert_eq!(
            p.value,
            Some(U256::from(60_000u64) * U256::from(10u64).pow(U256::from(18u64)))
        );
        assert_eq!(p.data, Some(alloy_primitives::Bytes::new()));
        assert_eq!(p.operation, Some(Operation::Call));
        assert_eq!(p.nonce, Some(U256::from(70u64)));
        assert!(p.claimed_safe_tx_hash.is_some());
        assert_eq!(p.chain_id, None);
        assert_eq!(p.version, None);
    }

    #[test]
    fn reads_chain_id_and_version_keys() {
        let p = parse_json(r#"{"chainId": 8453, "safeVersion": "1.4.1+L2"}"#).unwrap();
        assert_eq!(p.chain_id, Some(8453));
        assert_eq!(p.version, Some(SafeVersion::V1_4_1));
    }

    #[test]
    fn rejects_duplicate_keys() {
        let err = parse_json(r#"{"to": "0x0000000000000000000000000000000000000001", "to": "0x0000000000000000000000000000000000000002"}"#)
            .unwrap_err();
        assert!(err.to_string().contains("more than once"), "{err}");
    }

    #[test]
    fn rejects_wrong_types_and_lossy_numbers() {
        for bad in [
            r#"{"nonce": 1.5}"#,
            r#"{"nonce": -1}"#,
            r#"{"value": 100000000000000000000000}"#,
            r#"{"nonce": true}"#,
            r#"{"to": ["0x00"]}"#,
            r#"{"operation": 2}"#,
            r#"[]"#,
            r#""tx""#,
            r#"{"nonce": 1"#,
            "",
        ] {
            assert!(parse_json(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn rejects_list_responses() {
        let err = parse_json(r#"{"count": 1, "results": []}"#).unwrap_err();
        assert!(err.to_string().contains("single transaction"));
    }

    #[test]
    fn rejects_oversized_input() {
        let big = format!("{{\"data\": \"0x{}\"}}", "0".repeat(MAX_JSON_BYTES));
        assert!(matches!(parse_json(&big), Err(InputError::TooLarge { .. })));
    }
}
