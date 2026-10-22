//! The Safe transaction (`SafeTx`) and the account it belongs to.

use std::fmt;

use alloy_primitives::{Address, Bytes, U256};
use thiserror::Error;

use super::SafeVersion;

/// How the Safe calls `to`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Operation {
    /// `CALL`: `to` runs with its own storage.
    Call,
    /// `DELEGATECALL`: `to`'s code runs with the **Safe's** storage and can
    /// rewrite owners, modules and the implementation pointer.
    DelegateCall,
}

impl Operation {
    /// The value used in the `SafeTx` struct (`uint8 operation`).
    pub fn as_u8(self) -> u8 {
        match self {
            Operation::Call => 0,
            Operation::DelegateCall => 1,
        }
    }
}

impl fmt::Display for Operation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Operation::Call => f.write_str("0 (CALL)"),
            Operation::DelegateCall => f.write_str("1 (DELEGATECALL)"),
        }
    }
}

/// An operation value other than 0 or 1.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
#[error("invalid operation {0}: must be 0 (call) or 1 (delegatecall)")]
pub struct InvalidOperation(pub u8);

impl TryFrom<u8> for Operation {
    type Error = InvalidOperation;

    /// Only 0 and 1 are valid. The contract would revert on anything else
    /// (`Executor.sol`), so accepting it would hash a transaction that can
    /// never execute.
    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(Operation::Call),
            1 => Ok(Operation::DelegateCall),
            other => Err(InvalidOperation(other)),
        }
    }
}

/// The ten fields of a Safe transaction, in the order of the EIP-712
/// `SafeTx` type.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SafeTx {
    /// Destination of the call.
    pub to: Address,
    /// Native value in wei.
    pub value: U256,
    /// Calldata.
    pub data: Bytes,
    /// Call or delegatecall.
    pub operation: Operation,
    /// Gas reserved for the inner call (0 = all available).
    pub safe_tx_gas: U256,
    /// Gas paid for regardless of the inner call (refund base).
    pub base_gas: U256,
    /// Refund price per gas; 0 means no refund.
    pub gas_price: U256,
    /// Token used for the refund; zero address means the native token.
    pub gas_token: Address,
    /// Refund receiver; zero address means whoever submits the transaction.
    pub refund_receiver: Address,
    /// Safe nonce this transaction is valid for.
    pub nonce: U256,
}

/// The Safe that would execute a transaction: what goes into the EIP-712
/// domain.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SafeAccount {
    /// Address of the Safe proxy (`verifyingContract`).
    pub address: Address,
    /// Chain id. Part of the domain from 1.3.0 on.
    pub chain_id: u64,
    /// Contract version, which selects the domain format.
    pub version: SafeVersion,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn operation_accepts_only_0_and_1() {
        for byte in 0..=u8::MAX {
            let parsed = Operation::try_from(byte);
            match byte {
                0 => assert_eq!(parsed, Ok(Operation::Call)),
                1 => assert_eq!(parsed, Ok(Operation::DelegateCall)),
                _ => assert_eq!(parsed, Err(InvalidOperation(byte))),
            }
        }
    }

    #[test]
    fn operation_round_trips_through_u8() {
        for op in [Operation::Call, Operation::DelegateCall] {
            assert_eq!(Operation::try_from(op.as_u8()), Ok(op));
        }
    }
}
