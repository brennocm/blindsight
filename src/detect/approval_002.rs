//! `BS-APPROVAL-002` (experimental): Permit2 allowances.

use alloy_primitives::U256;

use super::{Context, Finding, Severity, finding};
use crate::decode::{CallNode, KnownCall};

/// Detector ID.
pub const ID: &str = "BS-APPROVAL-002";

pub fn check(ctx: &Context<'_>, node: &CallNode) -> Vec<Finding> {
    let Some(KnownCall::Permit2Approve {
        token,
        spender,
        amount,
        expiration,
    }) = node.known_call()
    else {
        return Vec::new();
    };
    // `type(uint160).max` means unlimited in Permit2 (IAllowanceTransfer.sol).
    let max = (U256::from(1u8) << 160) - U256::from(1u8);
    let (severity, title, size) = if *amount == max {
        (
            Severity::High,
            "Unlimited Permit2 allowance",
            "an unlimited amount".to_string(),
        )
    } else {
        (
            Severity::Info,
            "Permit2 allowance",
            ctx.token_amount(*token, *amount),
        )
    };
    vec![finding(
        ID,
        severity,
        node,
        title,
        format!(
            "Through Permit2 at {}, allows {} to transfer {size} of {} from {}, until timestamp {expiration}. Permit2 allowances are separate from the token's own approvals and easy to forget.",
            ctx.describe(node.to),
            ctx.describe(*spender),
            ctx.describe(*token),
            ctx.describe(node.executor)
        ),
    )]
}

#[cfg(test)]
mod tests {
    use crate::detect::testutil::*;

    #[test]
    fn permit2_approvals() {
        let approve = |amount: U256| {
            tx(
                addr(PERMIT2),
                Operation::Call,
                IPermit2::approveCall {
                    token: addr(USDC),
                    spender: Address::repeat_byte(1),
                    amount: amount.to(),
                    expiration: alloy_primitives::aliases::U48::from(1_900_000_000u64),
                }
                .abi_encode(),
            )
        };
        let max160 = (U256::from(1u8) << 160) - U256::from(1u8);
        assert_eq!(
            with_id(&findings(&approve(max160)), "BS-APPROVAL-002"),
            [(Severity::High, "root".into())]
        );
        let bounded = findings(&approve(U256::from(5u64)));
        assert_eq!(
            with_id(&bounded, "BS-APPROVAL-002"),
            [(Severity::Info, "root".into())]
        );
        // Sent to Permit2 by CALL: the name is verified.
        assert!(with_id(&bounded, "BS-SEMANTICS-001").is_empty());
    }
}
