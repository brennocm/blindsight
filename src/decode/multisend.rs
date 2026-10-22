//! The packed transaction format of `MultiSend` / `MultiSendCallOnly`.
//!
//! `multiSend(bytes transactions)` takes a concatenation, without padding,
//! of entries:
//!
//! | bytes        | field                                  |
//! |--------------|----------------------------------------|
//! | 1            | operation (0 call, 1 delegatecall)     |
//! | 20           | to                                     |
//! | 32           | value                                  |
//! | 32           | data length                            |
//! | data length  | data                                   |
//!
//! The contract reads this with unchecked `mload`s: a truncated last entry
//! reads past the buffer instead of failing. blindsight is stricter than the
//! contract: any truncation, impossible length or operation byte other than
//! 0/1 is an error, because the batch could not be shown faithfully.

use alloy_primitives::{Address, Bytes, U256};
use thiserror::Error;

use crate::safe::Operation;

/// Size of an entry without its data (tests use it to build cases).
#[cfg(test)]
const HEADER: usize = 1 + 20 + 32 + 32;

/// One transaction of a batch.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BatchEntry {
    /// Call or delegatecall.
    pub operation: Operation,
    /// Target.
    pub to: Address,
    /// Native value.
    pub value: U256,
    /// Calldata.
    pub data: Bytes,
}

/// Why a `MultiSend` payload could not be unpacked.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum MultiSendError {
    /// Fewer than 85 bytes left for the next entry's header.
    #[error("entry {index} is truncated: {remaining} bytes left, a header needs 85")]
    TruncatedHeader {
        /// Entry index.
        index: usize,
        /// Bytes left.
        remaining: usize,
    },
    /// The operation byte is not 0 or 1.
    #[error("entry {index} has operation byte {byte}; only 0 and 1 are valid")]
    BadOperation {
        /// Entry index.
        index: usize,
        /// The byte found.
        byte: u8,
    },
    /// The data length points past the end of the payload.
    #[error("entry {index} declares {declared} bytes of data but only {remaining} remain")]
    TruncatedData {
        /// Entry index.
        index: usize,
        /// Declared length (may be huge).
        declared: U256,
        /// Bytes left after the header.
        remaining: usize,
    },
}

/// Unpacks a `multiSend` payload into its entries.
///
/// An empty payload is a valid, empty batch.
///
/// # Errors
///
/// [`MultiSendError`] at the first malformed entry.
pub fn unpack(transactions: &[u8]) -> Result<Vec<BatchEntry>, MultiSendError> {
    let mut entries = Vec::new();
    let mut rest = transactions;
    while !rest.is_empty() {
        let index = entries.len();
        let truncated = MultiSendError::TruncatedHeader {
            index,
            remaining: rest.len(),
        };
        // Each step returns `None` instead of panicking if bytes run out;
        // fixed-size arrays make the field widths part of the types.
        let (&byte, after) = rest.split_first().ok_or(truncated.clone())?;
        let (to_bytes, after) = after.split_first_chunk::<20>().ok_or(truncated.clone())?;
        let (value_bytes, after) = after.split_first_chunk::<32>().ok_or(truncated.clone())?;
        let (len_bytes, after) = after.split_first_chunk::<32>().ok_or(truncated)?;

        let operation =
            Operation::try_from(byte).map_err(|_| MultiSendError::BadOperation { index, byte })?;
        let to = Address::from(*to_bytes);
        let value = U256::from_be_bytes(*value_bytes);
        let declared = U256::from_be_bytes(*len_bytes);

        let remaining = after.len();
        let too_long = || MultiSendError::TruncatedData {
            index,
            declared,
            remaining,
        };
        let data_len = usize::try_from(declared).map_err(|_| too_long())?;
        let (data, next) = after.split_at_checked(data_len).ok_or_else(too_long)?;
        entries.push(BatchEntry {
            operation,
            to,
            value,
            data: Bytes::copy_from_slice(data),
        });
        rest = next;
    }
    Ok(entries)
}

/// Packs entries into the `multiSend` format (the inverse of [`unpack`]).
pub fn pack(entries: &[BatchEntry]) -> Vec<u8> {
    let mut out = Vec::new();
    for e in entries {
        out.push(e.operation.as_u8());
        out.extend_from_slice(e.to.as_slice());
        out.extend_from_slice(&e.value.to_be_bytes::<32>());
        out.extend_from_slice(&U256::from(e.data.len()).to_be_bytes::<32>());
        out.extend_from_slice(&e.data);
    }
    out
}

#[cfg(test)]
mod tests {
    use proptest::prelude::*;

    use super::*;

    fn entry(op: Operation, data: &[u8]) -> BatchEntry {
        BatchEntry {
            operation: op,
            to: Address::repeat_byte(0x33),
            value: U256::from(9u64),
            data: Bytes::copy_from_slice(data),
        }
    }

    #[test]
    fn empty_payload_is_an_empty_batch() {
        assert_eq!(unpack(&[]), Ok(vec![]));
    }

    #[test]
    fn unpacks_entries_with_and_without_data() {
        let entries = vec![
            entry(Operation::Call, &[]),
            entry(Operation::DelegateCall, &[1, 2, 3]),
        ];
        assert_eq!(unpack(&pack(&entries)), Ok(entries));
    }

    #[test]
    fn rejects_truncated_header() {
        let packed = pack(&[entry(Operation::Call, &[])]);
        for cut in 1..HEADER {
            assert_eq!(
                unpack(&packed[..cut]),
                Err(MultiSendError::TruncatedHeader {
                    index: 0,
                    remaining: cut
                })
            );
        }
    }

    #[test]
    fn rejects_truncated_data_and_huge_lengths() {
        let packed = pack(&[entry(Operation::Call, &[1, 2, 3])]);
        assert!(matches!(
            unpack(&packed[..packed.len() - 1]),
            Err(MultiSendError::TruncatedData { .. })
        ));
        let mut huge = pack(&[entry(Operation::Call, &[])]);
        huge[1 + 20 + 32..HEADER].fill(0xff);
        assert!(matches!(
            unpack(&huge),
            Err(MultiSendError::TruncatedData { .. })
        ));
    }

    #[test]
    fn rejects_operation_bytes_other_than_0_and_1() {
        let mut packed = pack(&[entry(Operation::Call, &[]), entry(Operation::Call, &[])]);
        packed[HEADER] = 2;
        assert_eq!(
            unpack(&packed),
            Err(MultiSendError::BadOperation { index: 1, byte: 2 })
        );
    }

    #[test]
    fn trailing_garbage_is_an_error() {
        let mut packed = pack(&[entry(Operation::Call, &[])]);
        packed.push(0);
        assert!(matches!(
            unpack(&packed),
            Err(MultiSendError::TruncatedHeader { index: 1, .. })
        ));
    }

    fn arb_entry() -> impl Strategy<Value = BatchEntry> {
        (
            prop_oneof![Just(Operation::Call), Just(Operation::DelegateCall)],
            any::<[u8; 20]>(),
            any::<[u8; 32]>(),
            proptest::collection::vec(any::<u8>(), 0..200),
        )
            .prop_map(|(operation, to, value, data)| BatchEntry {
                operation,
                to: Address::from(to),
                value: U256::from_be_bytes(value),
                data: Bytes::from(data),
            })
    }

    proptest! {
        #[test]
        fn pack_then_unpack_is_identity(entries in proptest::collection::vec(arb_entry(), 0..20)) {
            prop_assert_eq!(unpack(&pack(&entries)), Ok(entries));
        }

        #[test]
        fn unpack_never_panics(bytes in proptest::collection::vec(any::<u8>(), 0..600)) {
            let _ = unpack(&bytes);
        }
    }
}
