//! Strict parsers for individual field values.
//!
//! Every parser takes the [`Field`] it is parsing so errors can name it.
//! Accepted syntax is deliberately narrow: numbers are decimal digits or
//! `0x` hex, addresses are `0x` plus 40 hex digits, byte strings are `0x`
//! plus an even number of hex digits.

use alloy_primitives::{Address, B256, Bytes, U256};

use super::{Field, InputError, InputWarning, MAX_CALLDATA_BYTES};
use crate::safe::{Operation, SafeVersion};
use crate::sanitize::excerpt;

fn invalid(field: Field, value: &str, reason: &str) -> InputError {
    InputError::Invalid {
        field,
        value: excerpt(value),
        reason: reason.to_string(),
    }
}

/// Strips a `0x` (or `0X`) prefix.
fn strip_hex_prefix(s: &str) -> Option<&str> {
    s.strip_prefix("0x").or_else(|| s.strip_prefix("0X"))
}

/// An unsigned 256-bit integer, written in decimal (`"1000"`) or hex
/// (`"0x3e8"`). No sign, no separators, no whitespace inside.
///
/// # Errors
///
/// [`InputError::Invalid`] for anything else, or a value above 2^256 − 1.
pub fn parse_uint(field: Field, s: &str) -> Result<U256, InputError> {
    let t = s.trim();
    let (digits, radix) = match strip_hex_prefix(t) {
        Some(hex) => (hex, 16),
        None => (t, 10),
    };
    if digits.is_empty() {
        return Err(invalid(field, s, "expected a number"));
    }
    if !digits.chars().all(|c| c.is_digit(radix)) {
        let reason = if radix == 16 {
            "expected hex digits after 0x"
        } else {
            "expected decimal digits (or 0x followed by hex digits)"
        };
        return Err(invalid(field, s, reason));
    }
    U256::from_str_radix(digits, u64::from(radix))
        .map_err(|_| invalid(field, s, "number does not fit in 256 bits"))
}

/// A `u64` (chain ids), decimal or `0x` hex.
///
/// # Errors
///
/// [`InputError::Invalid`] if it is not a number or does not fit in 64 bits.
pub fn parse_u64(field: Field, s: &str) -> Result<u64, InputError> {
    let value = parse_uint(field, s)?;
    u64::try_from(value).map_err(|_| invalid(field, s, "number does not fit in 64 bits"))
}

/// An address: `0x` followed by 40 hex digits.
///
/// All-lowercase and all-uppercase addresses carry no checksum and are
/// accepted as is. A mixed-case address claims an EIP-55 checksum; if the
/// checksum is wrong, the address is still used but a warning is returned,
/// because a corrupted checksum can be a sign of tampering or a typo.
///
/// # Errors
///
/// [`InputError::Invalid`] if it is not `0x` plus 40 hex digits.
pub fn parse_address(field: Field, s: &str) -> Result<(Address, Option<InputWarning>), InputError> {
    let t = s.trim();
    let Some(hex) = strip_hex_prefix(t) else {
        return Err(invalid(field, s, "expected 0x followed by 40 hex digits"));
    };
    if hex.len() != 40 || !hex.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(invalid(field, s, "expected 0x followed by 40 hex digits"));
    }
    let address: Address = hex
        .parse()
        .map_err(|_| invalid(field, s, "expected 0x followed by 40 hex digits"))?;
    let has_lower = hex.chars().any(|c| c.is_ascii_lowercase());
    let has_upper = hex.chars().any(|c| c.is_ascii_uppercase());
    let warning = if has_lower && has_upper {
        let expected = address.to_checksum(None);
        // Compare the 40 digits only: the prefix case is irrelevant.
        if expected.get(2..) == Some(hex) {
            None
        } else {
            Some(InputWarning::BadChecksum {
                field,
                given: t.to_string(),
                expected,
            })
        }
    } else {
        None
    };
    Ok((address, warning))
}

/// A byte string: `0x` followed by an even number of hex digits. `""` and
/// `"0x"` are empty. At most [`MAX_CALLDATA_BYTES`] bytes.
///
/// # Errors
///
/// [`InputError::Invalid`] for bad hex or an odd number of digits,
/// [`InputError::TooLarge`] past the limit.
pub fn parse_bytes(field: Field, s: &str) -> Result<Bytes, InputError> {
    let t = s.trim();
    if t.is_empty() {
        return Ok(Bytes::new());
    }
    let Some(hex) = strip_hex_prefix(t) else {
        return Err(invalid(field, s, "expected 0x followed by hex digits"));
    };
    if hex.len() / 2 > MAX_CALLDATA_BYTES {
        return Err(InputError::TooLarge {
            what: field.name(),
            limit: MAX_CALLDATA_BYTES,
        });
    }
    if !hex.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(invalid(field, s, "expected hex digits after 0x"));
    }
    if hex.len() % 2 != 0 {
        return Err(invalid(
            field,
            s,
            "odd number of hex digits (each byte is two digits)",
        ));
    }
    hex.parse::<Bytes>()
        .map_err(|_| invalid(field, s, "expected hex digits after 0x"))
}

/// A 32-byte hash: `0x` followed by 64 hex digits.
///
/// # Errors
///
/// [`InputError::Invalid`] for anything else.
pub fn parse_hash(field: Field, s: &str) -> Result<B256, InputError> {
    let t = s.trim();
    let Some(hex) = strip_hex_prefix(t)
        .filter(|hex| hex.len() == 64 && hex.chars().all(|c| c.is_ascii_hexdigit()))
    else {
        return Err(invalid(field, s, "expected 0x followed by 64 hex digits"));
    };
    hex.parse()
        .map_err(|_| invalid(field, s, "expected 0x followed by 64 hex digits"))
}

/// The operation: `0`/`call` or `1`/`delegatecall` (case-insensitive).
///
/// # Errors
///
/// [`InputError::Invalid`] for any other value.
pub fn parse_operation(field: Field, s: &str) -> Result<Operation, InputError> {
    match s.trim().to_ascii_lowercase().as_str() {
        "0" | "call" => Ok(Operation::Call),
        "1" | "delegatecall" => Ok(Operation::DelegateCall),
        _ => Err(invalid(
            field,
            s,
            "expected 0 (call) or 1 (delegatecall); the Safe rejects any other value",
        )),
    }
}

/// A Safe version such as `1.4.1`.
///
/// # Errors
///
/// [`InputError::Invalid`] for a version blindsight does not support.
pub fn parse_version(field: Field, s: &str) -> Result<SafeVersion, InputError> {
    s.parse().map_err(|_| {
        invalid(
            field,
            s,
            "supported versions are 1.0.0, 1.1.1, 1.2.0, 1.3.0, 1.4.1, 1.5.0",
        )
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const F: Field = Field::Value;

    #[test]
    fn uints() {
        let cases: &[(&str, Option<U256>)] = &[
            ("0", Some(U256::ZERO)),
            ("1000", Some(U256::from(1000u64))),
            ("0x3e8", Some(U256::from(1000u64))),
            ("0X3E8", Some(U256::from(1000u64))),
            (" 42 ", Some(U256::from(42u64))),
            (
                "115792089237316195423570985008687907853269984665640564039457584007913129639935",
                Some(U256::MAX),
            ),
            (
                "115792089237316195423570985008687907853269984665640564039457584007913129639936",
                None,
            ),
            (&format!("0x{}", "f".repeat(64)), Some(U256::MAX)),
            (&format!("0x1{}", "0".repeat(64)), None),
            ("", None),
            ("0x", None),
            ("-1", None),
            ("+1", None),
            ("1_000", None),
            ("1e18", None),
            ("1.5", None),
            ("0b101", None),
            ("0xg", None),
            ("1 000", None),
            ("١٢", None), // non-ASCII digits
        ];
        for (input, expected) in cases {
            assert_eq!(parse_uint(F, input).ok(), *expected, "input {input:?}");
        }
    }

    #[test]
    fn u64s() {
        assert_eq!(parse_u64(Field::ChainId, "8453").unwrap(), 8453);
        assert_eq!(
            parse_u64(Field::ChainId, "18446744073709551615").unwrap(),
            u64::MAX
        );
        assert!(parse_u64(Field::ChainId, "18446744073709551616").is_err());
    }

    #[test]
    fn addresses_and_checksums() {
        let good = "0x1Db92e2EeBC8E0c075a02BeA49a2935BcD2dFCF4";
        let (addr, warning) = parse_address(Field::Safe, good).unwrap();
        assert_eq!(addr.to_checksum(None), good);
        assert!(warning.is_none());

        // No checksum claimed: fine.
        assert!(
            parse_address(Field::Safe, &good.to_lowercase())
                .unwrap()
                .1
                .is_none()
        );
        let upper = format!("0x{}", good[2..].to_uppercase());
        assert!(parse_address(Field::Safe, &upper).unwrap().1.is_none());

        // Wrong checksum: same address, with a warning.
        let bad = "0x1db92e2EeBC8E0c075a02BeA49a2935BcD2dFCF4";
        let (bad_addr, warning) = parse_address(Field::Safe, bad).unwrap();
        assert_eq!(bad_addr, addr);
        assert_eq!(
            warning,
            Some(InputWarning::BadChecksum {
                field: Field::Safe,
                given: bad.to_string(),
                expected: good.to_string(),
            })
        );

        for invalid in [
            "",
            "0x",
            "1Db92e2EeBC8E0c075a02BeA49a2935BcD2dFCF4",
            "0x1Db92e2EeBC8E0c075a02BeA49a2935BcD2dFCF",
            "0x1Db92e2EeBC8E0c075a02BeA49a2935BcD2dFCF4a",
            "0x1Db92e2EeBC8E0c075a02BeA49a2935BcD2dFCFg",
            "vitalik.eth",
        ] {
            assert!(parse_address(Field::To, invalid).is_err(), "{invalid:?}");
        }
    }

    #[test]
    fn bytes() {
        assert_eq!(parse_bytes(Field::Data, "").unwrap(), Bytes::new());
        assert_eq!(parse_bytes(Field::Data, "0x").unwrap(), Bytes::new());
        assert_eq!(
            parse_bytes(Field::Data, "0xA9059cbb").unwrap().to_vec(),
            vec![0xa9, 0x05, 0x9c, 0xbb]
        );
        for invalid in ["a9059cbb", "0xa9059cb", "0xzz", "0x 00"] {
            assert!(parse_bytes(Field::Data, invalid).is_err(), "{invalid:?}");
        }
        let too_big = format!("0x{}", "00".repeat(MAX_CALLDATA_BYTES + 1));
        assert!(matches!(
            parse_bytes(Field::Data, &too_big),
            Err(InputError::TooLarge { .. })
        ));
        let at_limit = format!("0x{}", "00".repeat(MAX_CALLDATA_BYTES));
        assert_eq!(
            parse_bytes(Field::Data, &at_limit).unwrap().len(),
            MAX_CALLDATA_BYTES
        );
    }

    #[test]
    fn hashes() {
        let h = "0xb3476d061aeb8fc1d605a873c483a2402d88a68a9cdd1a8b47655dd55ba004f8";
        assert!(parse_hash(Field::ExpectSafeTxHash, h).is_ok());
        assert!(
            parse_hash(
                Field::ExpectSafeTxHash,
                &h.to_uppercase().replace("0X", "0x")
            )
            .is_ok()
        );
        assert!(parse_hash(Field::ExpectSafeTxHash, &h[..65]).is_err());
        assert!(parse_hash(Field::ExpectSafeTxHash, &h[2..]).is_err());
    }

    #[test]
    fn operations() {
        assert_eq!(parse_operation(F, "0").unwrap(), Operation::Call);
        assert_eq!(parse_operation(F, "CALL").unwrap(), Operation::Call);
        assert_eq!(parse_operation(F, "1").unwrap(), Operation::DelegateCall);
        assert_eq!(
            parse_operation(F, "DelegateCall").unwrap(),
            Operation::DelegateCall
        );
        for invalid in ["2", "-1", "", "01", "staticcall"] {
            assert!(parse_operation(F, invalid).is_err(), "{invalid:?}");
        }
    }

    #[test]
    fn error_messages_name_the_field_and_sanitise_the_value() {
        let err = parse_uint(Field::Nonce, "1\u{1b}[31m").unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("nonce"), "{msg}");
        assert!(!msg.contains('\u{1b}'), "{msg}");
    }
}
