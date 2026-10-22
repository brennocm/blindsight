//! `BS-THRESHOLD-001`: the number of required signatures changes.

use alloy_primitives::U256;

use super::{Context, Finding, Severity, finding};
use crate::decode::{CallNode, DecodedCall, KnownCall, Semantics, Verification};

/// Detector ID.
pub const ID: &str = "BS-THRESHOLD-001";

pub fn check(ctx: &Context<'_>, node: &CallNode) -> Vec<Finding> {
    let DecodedCall::Known {
        call: KnownCall::ChangeThreshold { threshold },
        semantics: Semantics::Verified(Verification::ExecutingSafe),
    } = &node.decoded
    else {
        return Vec::new();
    };
    let one = *threshold == U256::from(1u8);
    let severity = if one {
        Severity::Critical
    } else {
        Severity::High
    };
    let extra = if one {
        " A threshold of 1 lets any single owner, or a single stolen key, control the Safe."
    } else if threshold.is_zero() {
        " A threshold of 0 is rejected by the contract, so this transaction would revert."
    } else {
        ""
    };
    vec![finding(
        ID,
        severity,
        node,
        format!("Changes the threshold to {threshold}"),
        format!(
            "Sets the number of owner signatures {} requires to {threshold}. The current number of owners is not known offline; the contract reverts if the threshold exceeds it.{extra}",
            ctx.describe(node.executor)
        ),
    )]
}

#[cfg(test)]
mod tests {
    use crate::detect::testutil::*;

    #[test]
    fn threshold_changes() {
        let change = |n: u64| {
            ISafe::changeThresholdCall {
                _threshold: U256::from(n),
            }
            .abi_encode()
        };
        assert_eq!(
            with_id(&findings(&admin(change(3))), "BS-THRESHOLD-001"),
            [(Severity::High, "root".into())]
        );
        assert_eq!(
            with_id(&findings(&admin(change(1))), "BS-THRESHOLD-001"),
            [(Severity::Critical, "root".into())]
        );
    }
}
