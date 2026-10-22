//! Input from raw `execTransaction` calldata, as shown by a block explorer
//! for an executed (or submitted) Safe transaction.
//!
//! `execTransaction` carries nine of the ten `SafeTx` fields plus the
//! signatures. The nonce is not a parameter (the contract reads its own
//! storage), so it must be given separately, as must the Safe address (the
//! address the calldata was sent to), the chain and the version.

use alloy_sol_types::{SolCall, sol};

use super::{Field, InputError, MAX_CALLDATA_BYTES, PartialTx};
use crate::safe::Operation;

sol! {
    /// `execTransaction` of every Safe version from 1.0.0 to 1.5.0.
    function execTransaction(
        address to,
        uint256 value,
        bytes data,
        uint8 operation,
        uint256 safeTxGas,
        uint256 baseGas,
        uint256 gasPrice,
        address gasToken,
        address refundReceiver,
        bytes signatures
    ) external payable returns (bool success);
}

/// The `execTransaction` selector, `0x6a761202`.
pub const EXEC_TRANSACTION_SELECTOR: [u8; 4] = execTransactionCall::SELECTOR;

/// Decodes `execTransaction` calldata into every field it carries.
///
/// Decoding validates the encoding the way Solidity's decoder does: an
/// address or `uint8` with non-zero high bytes is rejected, since the
/// contract would revert on it.
///
/// # Errors
///
/// [`InputError::Invalid`] for another function, a malformed encoding or an
/// operation other than 0/1; [`InputError::TooLarge`] past the size limit.
pub fn parse_exec_calldata(calldata: &[u8]) -> Result<PartialTx, InputError> {
    if calldata.len() > MAX_CALLDATA_BYTES {
        return Err(InputError::TooLarge {
            what: "execTransaction calldata",
            limit: MAX_CALLDATA_BYTES,
        });
    }
    let invalid = |reason: String| InputError::Invalid {
        field: Field::ExecCalldata,
        value: format!("{} bytes", calldata.len()),
        reason,
    };
    match calldata.get(..4) {
        Some(selector) if selector == EXEC_TRANSACTION_SELECTOR => {}
        Some(selector) => {
            return Err(invalid(format!(
                "selector 0x{} is not execTransaction (0x6a761202)",
                alloy_primitives::hex::encode(selector)
            )));
        }
        None => return Err(invalid("shorter than a function selector".to_string())),
    }
    let call = execTransactionCall::abi_decode_validate(calldata)
        .map_err(|e| invalid(format!("not a valid execTransaction encoding: {e}")))?;
    let operation = Operation::try_from(call.operation).map_err(|e| invalid(e.to_string()))?;
    Ok(PartialTx {
        to: Some(call.to),
        value: Some(call.value),
        data: Some(call.data),
        operation: Some(operation),
        safe_tx_gas: Some(call.safeTxGas),
        base_gas: Some(call.baseGas),
        gas_price: Some(call.gasPrice),
        gas_token: Some(call.gasToken),
        refund_receiver: Some(call.refundReceiver),
        signatures: Some(call.signatures),
        ..PartialTx::default()
    })
}

#[cfg(test)]
mod tests {
    use alloy_primitives::{Address, Bytes, U256};

    use super::*;

    fn encode(operation: u8) -> Vec<u8> {
        execTransactionCall {
            to: Address::repeat_byte(1),
            value: U256::from(5u64),
            data: Bytes::from(vec![0xab; 3]),
            operation,
            safeTxGas: U256::ZERO,
            baseGas: U256::ZERO,
            gasPrice: U256::ZERO,
            gasToken: Address::ZERO,
            refundReceiver: Address::ZERO,
            signatures: Bytes::from(vec![0; 65]),
        }
        .abi_encode()
    }

    #[test]
    fn selector_is_the_documented_one() {
        assert_eq!(EXEC_TRANSACTION_SELECTOR, [0x6a, 0x76, 0x12, 0x02]);
        assert_eq!(
            execTransactionCall::SIGNATURE,
            "execTransaction(address,uint256,bytes,uint8,uint256,uint256,uint256,address,address,bytes)"
        );
    }

    #[test]
    fn round_trips() {
        let p = parse_exec_calldata(&encode(1)).unwrap();
        assert_eq!(p.to, Some(Address::repeat_byte(1)));
        assert_eq!(p.operation, Some(Operation::DelegateCall));
        assert_eq!(p.data.unwrap().len(), 3);
        assert_eq!(p.signatures.unwrap().len(), 65);
        assert_eq!(p.nonce, None);
    }

    #[test]
    fn rejects_bad_operation_other_selectors_and_truncation() {
        assert!(parse_exec_calldata(&encode(2)).is_err());
        let mut other = encode(0);
        other[0] = 0;
        assert!(parse_exec_calldata(&other).is_err());
        let full = encode(0);
        // The last 31 bytes are padding after the 65 signature bytes; like
        // Solidity's decoder, blindsight accepts calldata without them.
        assert!(parse_exec_calldata(&full[..full.len() - 31]).is_ok());
        for len in [0, 3, 4, 36, full.len() - 32] {
            assert!(parse_exec_calldata(&full[..len]).is_err(), "len {len}");
        }
    }

    #[test]
    fn rejects_dirty_high_bytes() {
        // Word 3 (after the selector) holds `operation`: set a high byte.
        let mut dirty = encode(0);
        dirty[4 + 3 * 32] = 1;
        assert!(parse_exec_calldata(&dirty).is_err());
        // Word 0 holds `to`: set a byte in the 12-byte padding.
        let mut dirty = encode(0);
        dirty[4] = 1;
        assert!(parse_exec_calldata(&dirty).is_err());
    }
}
