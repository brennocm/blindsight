//! The user's address book: names for addresses they trust, and detection of
//! addresses that imitate them.
//!
//! Format: a JSON object mapping names to addresses,
//!
//! ```json
//! { "Treasury": "0x1Db92e2EeBC8E0c075a02BeA49a2935BcD2dFCF4", "Ops multisig": "0x..." }
//! ```
//!
//! Names label addresses in the report. They come from a file, so they are
//! sanitised before printing like any other input. Repeated names (duplicate
//! keys) and two names for one address are rejected: either would make a
//! label ambiguous.
//!
//! **Address poisoning** relies on people and interfaces checking only the
//! start and end of an address. [`AddressBook::lookalikes`] finds book entries
//! that share the first four and last four hex digits with an address that is
//! not itself in the book.

use std::collections::BTreeMap;

use alloy_primitives::Address;
use serde_json::Value;
use thiserror::Error;

use crate::input::fields::parse_address;
use crate::input::json::parse_object_unique_keys;
use crate::input::{Field, InputWarning};
use crate::sanitize::excerpt;

/// Largest address book file accepted, in bytes.
pub const MAX_BOOK_BYTES: usize = 1024 * 1024;

/// Most entries accepted.
pub const MAX_ENTRIES: usize = 10_000;

/// Longest name accepted, in characters.
pub const MAX_NAME_CHARS: usize = 100;

/// Hex digits compared at each end by [`AddressBook::lookalikes`].
pub const LOOKALIKE_HEX_DIGITS: usize = 4;

/// One named address.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Entry {
    /// The name, as written in the file (sanitise before printing).
    pub name: String,
    /// The address.
    pub address: Address,
}

/// The user's named addresses.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct AddressBook {
    by_address: BTreeMap<Address, Entry>,
}

/// Why an address book was rejected.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum AddressBookError {
    /// Not a JSON object, malformed, or a repeated name.
    #[error("invalid address book: {0}")]
    Json(String),
    /// An entry is invalid.
    #[error("invalid address book entry \"{name}\": {reason}")]
    Entry {
        /// Sanitised excerpt of the name.
        name: String,
        /// What is wrong.
        reason: String,
    },
    /// Two names for the same address.
    #[error("address book gives two names to {address}: \"{first}\" and \"{second}\"")]
    DuplicateAddress {
        /// The address.
        address: String,
        /// Sanitised first name.
        first: String,
        /// Sanitised second name.
        second: String,
    },
    /// More than [`MAX_ENTRIES`] entries.
    #[error("address book has more than {MAX_ENTRIES} entries")]
    TooManyEntries,
    /// Larger than [`MAX_BOOK_BYTES`].
    #[error("address book is larger than {MAX_BOOK_BYTES} bytes")]
    TooLarge,
}

impl AddressBook {
    /// Parses an address book. Returns it with checksum warnings for
    /// mixed-case addresses whose checksum is wrong.
    ///
    /// # Errors
    ///
    /// [`AddressBookError`] for malformed JSON, invalid names or addresses,
    /// repeated names or addresses, and size limits.
    pub fn parse(text: &str) -> Result<(AddressBook, Vec<InputWarning>), AddressBookError> {
        if text.len() > MAX_BOOK_BYTES {
            return Err(AddressBookError::TooLarge);
        }
        let object = parse_object_unique_keys(text).map_err(AddressBookError::Json)?;
        if object.len() > MAX_ENTRIES {
            return Err(AddressBookError::TooManyEntries);
        }
        let mut book = AddressBook::default();
        let mut names = std::collections::BTreeSet::new();
        let mut warnings = Vec::new();
        for (name, value) in object {
            let entry_error = |reason: &str| AddressBookError::Entry {
                name: excerpt(&name),
                reason: reason.to_string(),
            };
            let trimmed = name.trim();
            if trimmed.is_empty() {
                return Err(entry_error("the name is empty"));
            }
            if trimmed.chars().count() > MAX_NAME_CHARS {
                return Err(entry_error("the name is longer than 100 characters"));
            }
            let Value::String(text) = value else {
                return Err(entry_error("the value must be an address string"));
            };
            let (address, warning) = parse_address(Field::To, &text)
                .map_err(|_| entry_error("the value is not 0x followed by 40 hex digits"))?;
            // The checksum warning should name the book entry, not a tx field.
            warnings.extend(warning.map(|w| match w {
                InputWarning::BadChecksum {
                    given, expected, ..
                } => InputWarning::BookChecksum {
                    name: excerpt(trimmed),
                    given,
                    expected,
                },
                other => other,
            }));
            // Names that differ only by surrounding spaces or letter case
            // would be the same label for two addresses.
            if !names.insert(trimmed.to_lowercase()) {
                return Err(entry_error(
                    "another entry has the same name (ignoring case and surrounding spaces)",
                ));
            }
            let entry = Entry {
                name: trimmed.to_string(),
                address,
            };
            if let Some(previous) = book.by_address.insert(address, entry) {
                return Err(AddressBookError::DuplicateAddress {
                    address: address.to_checksum(None),
                    first: excerpt(&previous.name),
                    second: excerpt(trimmed),
                });
            }
        }
        Ok((book, warnings))
    }

    /// The entry for `address`, if the book names it.
    pub fn get(&self, address: Address) -> Option<&Entry> {
        self.by_address.get(&address)
    }

    /// Number of entries.
    pub fn len(&self) -> usize {
        self.by_address.len()
    }

    /// Whether the book is empty.
    pub fn is_empty(&self) -> bool {
        self.by_address.is_empty()
    }

    /// Entries that look like `address` without being it: same first and
    /// last [`LOOKALIKE_HEX_DIGITS`] hex digits (case-insensitive). Empty if
    /// `address` itself is in the book.
    pub fn lookalikes(&self, address: Address) -> Vec<&Entry> {
        if self.by_address.contains_key(&address) {
            return Vec::new();
        }
        // 4 hex digits are 2 bytes at each end.
        let ends = |a: &Address| {
            let b = a.as_slice();
            (
                b.get(..2).map(<[u8]>::to_vec),
                b.get(18..).map(<[u8]>::to_vec),
            )
        };
        let target = ends(&address);
        self.by_address
            .values()
            .filter(|e| ends(&e.address) == target)
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const TREASURY: &str = "0x1Db92e2EeBC8E0c075a02BeA49a2935BcD2dFCF4";

    fn addr(s: &str) -> Address {
        s.parse().unwrap()
    }

    #[test]
    fn parses_names_and_finds_entries() {
        let (book, warnings) = AddressBook::parse(&format!(
            r#"{{"Treasury": "{TREASURY}", " Ops ": "0x0000000000000000000000000000000000000001"}}"#
        ))
        .unwrap();
        assert!(warnings.is_empty());
        assert_eq!(book.len(), 2);
        assert_eq!(book.get(addr(TREASURY)).unwrap().name, "Treasury");
        assert_eq!(
            book.get(addr("0x0000000000000000000000000000000000000001"))
                .unwrap()
                .name,
            "Ops"
        );
    }

    #[test]
    fn rejects_ambiguous_or_invalid_books() {
        let cases = [
            r#"{"A": "0x0000000000000000000000000000000000000001", "A": "0x0000000000000000000000000000000000000002"}"#,
            r#"{"A": "0x0000000000000000000000000000000000000001", "B": "0x0000000000000000000000000000000000000001"}"#,
            r#"{"": "0x0000000000000000000000000000000000000001"}"#,
            r#"{"Ops": "0x0000000000000000000000000000000000000001", " ops ": "0x0000000000000000000000000000000000000002"}"#,
            r#"{"A": "0x01"}"#,
            r#"{"A": 1}"#,
            r#"["0x0000000000000000000000000000000000000001"]"#,
            "not json",
        ];
        for case in cases {
            assert!(AddressBook::parse(case).is_err(), "{case}");
        }
        let long = format!(r#"{{"{}": "{TREASURY}"}}"#, "n".repeat(101));
        assert!(AddressBook::parse(&long).is_err());
    }

    #[test]
    fn errors_sanitise_names() {
        let err = AddressBook::parse("{\"\\u001b[31mX\": 1}").unwrap_err();
        assert!(!err.to_string().contains('\u{1b}'), "{err}");
    }

    #[test]
    fn warns_on_bad_checksums() {
        let bad = "0x1db92e2EeBC8E0c075a02BeA49a2935BcD2dFCF4";
        let (_, warnings) = AddressBook::parse(&format!(r#"{{"Treasury": "{bad}"}}"#)).unwrap();
        assert!(matches!(
            warnings.as_slice(),
            [InputWarning::BookChecksum { name, .. }] if name == "Treasury"
        ));
    }

    #[test]
    fn finds_lookalikes_by_first_and_last_four_hex_digits() {
        let (book, _) = AddressBook::parse(&format!(r#"{{"Treasury": "{TREASURY}"}}"#)).unwrap();
        // Same 1db9…fcf4 ends, different middle: a poisoning candidate.
        let fake = addr("0x1db9000000000000000000000000000000dafcf4");
        let found = book.lookalikes(fake);
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].name, "Treasury");
        // The real address is not its own lookalike.
        assert!(book.lookalikes(addr(TREASURY)).is_empty());
        // Only one end matching is not enough.
        assert!(
            book.lookalikes(addr("0x1db9000000000000000000000000000000000000"))
                .is_empty()
        );
        assert!(
            book.lookalikes(addr("0x000000000000000000000000000000000000fcf4"))
                .is_empty()
        );
    }
}
