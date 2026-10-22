//! `BS-REFUND-001`: the Safe pays a gas refund (`handlePayment`).
//!
//! Applies to the root transaction and to every nested Safe transaction,
//! whose inner gas fields make the inner Safe pay.

use alloy_primitives::{Address, U256};

use super::{Context, Finding, Severity, finding};
use crate::decode::{CallNode, DecodedCall, KnownCall};
use crate::safe::SafeVersion;

/// Detector ID.
pub const ID: &str = "BS-REFUND-001";

/// The refund-related fields of a Safe transaction.
struct GasFields {
    safe_tx_gas: U256,
    base_gas: U256,
    gas_price: U256,
    gas_token: Address,
    refund_receiver: Address,
    /// `None` when the paying Safe's version is unknown (nested Safes).
    version: Option<SafeVersion>,
}

pub fn check(ctx: &Context<'_>, node: &CallNode) -> Vec<Finding> {
    let mut findings = Vec::new();
    // The root transaction's own refund, paid by this Safe.
    if node.path.is_root() {
        let fields = GasFields {
            safe_tx_gas: ctx.tx.safe_tx_gas,
            base_gas: ctx.tx.base_gas,
            gas_price: ctx.tx.gas_price,
            gas_token: ctx.tx.gas_token,
            refund_receiver: ctx.tx.refund_receiver,
            version: Some(ctx.account.version),
        };
        findings.extend(analyse(ctx, node, &fields, ctx.account.address));
    }
    // A nested transaction's refund, paid by the Safe it is addressed to.
    // Checked independently: wrapping must not hide a refund.
    if let DecodedCall::Nested {
        call:
            KnownCall::ExecTransaction {
                safe_tx_gas,
                base_gas,
                gas_price,
                gas_token,
                refund_receiver,
                ..
            },
        ..
    } = &node.decoded
    {
        let fields = GasFields {
            safe_tx_gas: *safe_tx_gas,
            base_gas: *base_gas,
            gas_price: *gas_price,
            gas_token: *gas_token,
            refund_receiver: *refund_receiver,
            version: None,
        };
        findings.extend(analyse(ctx, node, &fields, node.to));
    }
    findings
}

fn analyse(ctx: &Context<'_>, node: &CallNode, f: &GasFields, payer: Address) -> Vec<Finding> {
    let payer = ctx.describe(payer);
    if f.gas_price.is_zero() {
        if f.gas_token != Address::ZERO
            || f.refund_receiver != Address::ZERO
            || !f.base_gas.is_zero()
        {
            return vec![finding(
                ID,
                Severity::Low,
                node,
                "Refund fields set while gasPrice is 0",
                format!(
                    "gasPrice is 0, so {payer} pays no refund, but gasToken, refundReceiver or baseGas is non-zero (gasToken {}, refundReceiver {}, baseGas {}). Interfaces leave these at zero; check who built this transaction.",
                    ctx.describe(f.gas_token),
                    ctx.describe(f.refund_receiver),
                    f.base_gas
                ),
            )];
        }
        return Vec::new();
    }

    let receiver = if f.refund_receiver == Address::ZERO {
        "whoever submits the transaction (tx.origin): anyone holding the signatures".to_string()
    } else {
        ctx.describe(f.refund_receiver)
    };
    let minimum = f.base_gas.checked_mul(f.gas_price);
    let (severity, currency, minimum_text) = if f.gas_token == Address::ZERO {
        let capped = f.version.map(|v| v >= SafeVersion::V1_3_0);
        let severity = match capped {
            Some(true) => Severity::Medium,
            Some(false) | None => Severity::High,
        };
        let cap = match capped {
            Some(true) => {
                " The price per gas is capped by the submitter's own gas price (1.3.0 and later)."
            }
            Some(false) => {
                " Before 1.3.0 the price per gas is not capped by the network gas price."
            }
            None => {
                " Whether the price is capped depends on the paying Safe's version, which is unknown here."
            }
        };
        let min = minimum.map_or_else(
            || "more than 2^256 (the transaction would revert)".to_string(),
            |m| ctx.native_amount(m),
        );
        (severity, format!("the native currency.{cap}"), min)
    } else {
        let min = minimum.map_or_else(
            || "more than 2^256 (the transaction would revert)".to_string(),
            |m| ctx.token_amount(f.gas_token, m),
        );
        (
            Severity::High,
            format!(
                "token {}. Token refunds are never capped: gasPrice is an arbitrary number of token units per gas.",
                ctx.describe(f.gas_token)
            ),
            min,
        )
    };
    let gs013 = if f.safe_tx_gas.is_zero() {
        ""
    } else {
        " Because safeTxGas is not 0, the inner call may fail while the transaction still succeeds: the nonce is used up and the refund paid anyway."
    };
    vec![finding(
        ID,
        severity,
        node,
        "The Safe pays a gas refund",
        format!(
            "{payer} pays (gasUsed + baseGas) x gasPrice = (gasUsed + {}) x {} in {currency} At least {minimum_text} is paid regardless of gas used, to {receiver}. The submitter chooses the gas limit and therefore gasUsed.{gs013}",
            f.base_gas, f.gas_price
        ),
    )]
}

#[cfg(test)]
mod tests {
    use crate::detect::testutil::*;

    #[test]
    fn gas_refunds() {
        let mut t = tx(Address::repeat_byte(1), Operation::Call, vec![]);
        assert!(with_id(&findings(&t), "BS-REFUND-001").is_empty());

        t.gas_price = U256::from(1u64);
        assert_eq!(
            with_id(&findings(&t), "BS-REFUND-001"),
            [(Severity::Medium, "root".into())]
        );
        let old = Run {
            version: SafeVersion::V1_2_0,
            ..Run::default()
        };
        assert_eq!(
            with_id(&old.findings(&t), "BS-REFUND-001"),
            [(Severity::High, "root".into())]
        );
        t.gas_token = addr(USDC);
        assert_eq!(
            with_id(&findings(&t), "BS-REFUND-001"),
            [(Severity::High, "root".into())]
        );

        let mut inert = tx(Address::repeat_byte(1), Operation::Call, vec![]);
        inert.refund_receiver = Address::repeat_byte(2);
        assert_eq!(
            with_id(&findings(&inert), "BS-REFUND-001"),
            [(Severity::Low, "root".into())]
        );

        // Overflowing baseGas * gasPrice does not panic.
        let mut huge = tx(Address::repeat_byte(1), Operation::Call, vec![]);
        huge.gas_price = U256::MAX;
        huge.base_gas = U256::MAX;
        let f = findings(&huge);
        assert!(
            f.iter()
                .any(|f| f.id == "BS-REFUND-001" && f.detail.contains("2^256"))
        );
    }

    #[test]
    fn refunds_in_nested_transactions() {
        let data = ISafe::execTransactionCall {
            to: Address::repeat_byte(1),
            value: U256::ZERO,
            data: Bytes::new(),
            operation: 0,
            safeTxGas: U256::ZERO,
            baseGas: U256::from(100_000u64),
            gasPrice: U256::from(10u64).pow(U256::from(9u64)),
            gasToken: Address::ZERO,
            refundReceiver: Address::repeat_byte(0xbb),
            signatures: Bytes::new(),
        }
        .abi_encode();
        let f = findings(&tx(Address::repeat_byte(0x77), Operation::Call, data));
        // The inner Safe's version is unknown, so the native refund is high.
        assert_eq!(
            with_id(&f, "BS-REFUND-001"),
            [(Severity::High, "root".into())]
        );
    }
}
