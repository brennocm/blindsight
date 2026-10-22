//! `BS-SELF-001`: a call from a Safe to itself.

use super::{Context, Finding, Severity, finding};
use crate::decode::{CallNode, DecodedCall, FunctionKind};
use crate::safe::Operation;

/// Detector ID.
pub const ID: &str = "BS-SELF-001";

pub fn check(ctx: &Context<'_>, node: &CallNode) -> Vec<Finding> {
    if node.to != node.executor || node.operation != Operation::Call {
        return Vec::new();
    }
    let safe = ctx.describe(node.to);
    let is_safe_function = match &node.decoded {
        DecodedCall::Empty => true,
        DecodedCall::Known { call, .. } => call.kind() == FunctionKind::SafeAdmin,
        _ => false,
    };
    let found = if is_safe_function {
        finding(
            ID,
            Severity::Info,
            node,
            "Administrative call to the Safe itself",
            format!(
                "{safe} calls itself: this changes its own configuration (see the other findings for what changes)."
            ),
        )
    } else {
        finding(
            ID,
            Severity::Medium,
            node,
            "Call to the Safe itself with a non-Safe function",
            format!(
                "{safe} calls itself with a function that is not one of its own. The call is routed to the Safe's fallback handler, whose behaviour depends on which handler is installed."
            ),
        )
    };
    vec![found]
}

#[cfg(test)]
mod tests {
    use crate::detect::testutil::*;

    #[test]
    fn calls_to_self() {
        let threshold = ISafe::changeThresholdCall {
            _threshold: U256::from(2u64),
        }
        .abi_encode();
        assert_eq!(
            with_id(&findings(&admin(threshold)), "BS-SELF-001"),
            [(Severity::Info, "root".into())]
        );
        assert_eq!(
            with_id(&findings(&admin(vec![1, 2, 3, 4])), "BS-SELF-001"),
            [(Severity::Medium, "root".into())]
        );
    }
}
