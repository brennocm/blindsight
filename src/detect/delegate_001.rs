//! `BS-DELEGATE-001`: delegatecall to a contract that is not an official
//! Safe helper: the Bybit and `WazirX` takeovers.

use super::{Context, Finding, Severity, finding};
use crate::decode::CallNode;
use crate::safe::Operation;

/// Detector ID.
pub const ID: &str = "BS-DELEGATE-001";

pub fn check(ctx: &Context<'_>, node: &CallNode) -> Vec<Finding> {
    if node.operation != Operation::DelegateCall || ctx.is_trusted_helper(node.to) {
        return Vec::new();
    }
    vec![finding(
        ID,
        Severity::Critical,
        node,
        "Delegatecall to a contract that is not an official Safe helper",
        format!(
            "This call runs the code at {} with the storage of {}. That code can replace the owners, threshold, modules, guard, fallback handler and the implementation pointer in storage slot 0, after which the attacker no longer needs any signature. This is how the Bybit (2025) and WazirX (2024) Safes were taken over. Do not sign unless you have reviewed the target's source and know why it needs delegatecall.",
            ctx.describe(node.to),
            ctx.describe(node.executor),
        ),
    )]
}

#[cfg(test)]
mod tests {
    use crate::detect::testutil::*;

    #[test]
    fn delegatecall_to_unknown_is_critical_anywhere_in_the_tree() {
        let evil = Address::repeat_byte(0xee);
        let root = tx(evil, Operation::DelegateCall, transfer());
        assert_eq!(
            with_id(&findings(&root), "BS-DELEGATE-001"),
            [(Severity::Critical, "root".into())]
        );

        let batch = tx(
            addr(MULTISEND_141),
            Operation::DelegateCall,
            multisend(&[
                entry(Operation::Call, Address::repeat_byte(1), vec![]),
                entry(Operation::DelegateCall, evil, transfer()),
            ]),
        );
        let f = findings(&batch);
        assert_eq!(
            with_id(&f, "BS-DELEGATE-001"),
            [(Severity::Critical, "batch[1]".into())]
        );

        // Hidden in a nested Safe transaction.
        let inner_safe = Address::repeat_byte(0x77);
        let nested = tx(inner_safe, Operation::Call, exec(evil, 1, transfer()));
        assert_eq!(
            with_id(&findings(&nested), "BS-DELEGATE-001"),
            [(Severity::Critical, "nested".into())]
        );
    }

    #[test]
    fn delegatecall_to_official_helpers_is_not_flagged() {
        let batch = tx(
            addr(MULTISEND_141),
            Operation::DelegateCall,
            multisend(&[entry(Operation::Call, Address::repeat_byte(1), vec![])]),
        );
        assert!(with_id(&findings(&batch), "BS-DELEGATE-001").is_empty());
        let sign = tx(
            addr(SIGN_MESSAGE_LIB_141),
            Operation::DelegateCall,
            IHelpers::signMessageCall {
                _data: Bytes::from(vec![1]),
            }
            .abi_encode(),
        );
        assert!(with_id(&findings(&sign), "BS-DELEGATE-001").is_empty());
    }
}
