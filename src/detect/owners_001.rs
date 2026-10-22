//! `BS-OWNERS-001`: owners added, removed or replaced.

use alloy_primitives::U256;

use super::{Context, Finding, Severity, finding};
use crate::decode::{CallNode, DecodedCall, KnownCall, Semantics, Verification};

/// Detector ID.
pub const ID: &str = "BS-OWNERS-001";

fn severity_for(threshold: U256) -> Severity {
    if threshold == U256::from(1u8) {
        Severity::Critical
    } else {
        Severity::High
    }
}

pub fn check(ctx: &Context<'_>, node: &CallNode) -> Vec<Finding> {
    let DecodedCall::Known {
        call,
        semantics: Semantics::Verified(Verification::ExecutingSafe),
    } = &node.decoded
    else {
        return Vec::new();
    };
    let safe = ctx.describe(node.executor);
    let one_note =
        "A threshold of 1 lets any single owner, or a single stolen key, control the Safe.";
    let (severity, title, detail) = match call {
        KnownCall::AddOwnerWithThreshold { owner, threshold } => (
            severity_for(*threshold),
            "Adds an owner".to_string(),
            format!(
                "Adds {} as an owner of {safe} and sets the threshold to {threshold}.{}",
                ctx.describe(*owner),
                if *threshold == U256::from(1u8) {
                    format!(" {one_note}")
                } else {
                    String::new()
                }
            ),
        ),
        KnownCall::RemoveOwner {
            prev_owner,
            owner,
            threshold,
        } => (
            severity_for(*threshold),
            "Removes an owner".to_string(),
            format!(
                "Removes {} from the owners of {safe} and sets the threshold to {threshold} (linked-list pointer prevOwner: {}).{}",
                ctx.describe(*owner),
                ctx.describe(*prev_owner),
                if *threshold == U256::from(1u8) {
                    format!(" {one_note}")
                } else {
                    String::new()
                }
            ),
        ),
        KnownCall::SwapOwner {
            prev_owner,
            old_owner,
            new_owner,
        } => (
            Severity::High,
            "Replaces an owner".to_string(),
            format!(
                "Replaces owner {} with {} on {safe} (linked-list pointer prevOwner: {}). Confirm the new owner's address out of band.",
                ctx.describe(*old_owner),
                ctx.describe(*new_owner),
                ctx.describe(*prev_owner),
            ),
        ),
        _ => return Vec::new(),
    };
    vec![finding(ID, severity, node, title, detail)]
}

#[cfg(test)]
mod tests {
    use crate::detect::testutil::*;

    #[test]
    fn owner_changes() {
        let add = |threshold: u64| {
            ISafe::addOwnerWithThresholdCall {
                owner: Address::repeat_byte(1),
                _threshold: U256::from(threshold),
            }
            .abi_encode()
        };
        assert_eq!(
            with_id(&findings(&admin(add(2))), "BS-OWNERS-001"),
            [(Severity::High, "root".into())]
        );
        assert_eq!(
            with_id(&findings(&admin(add(1))), "BS-OWNERS-001"),
            [(Severity::Critical, "root".into())]
        );
        let swap = ISafe::swapOwnerCall {
            prevOwner: Address::repeat_byte(1),
            oldOwner: Address::repeat_byte(2),
            newOwner: Address::repeat_byte(3),
        }
        .abi_encode();
        assert_eq!(
            with_id(&findings(&admin(swap.clone())), "BS-OWNERS-001"),
            [(Severity::High, "root".into())]
        );
        // Sent to another address: not an owner change of this Safe.
        assert!(
            with_id(
                &findings(&tx(Address::repeat_byte(9), Operation::Call, swap)),
                "BS-OWNERS-001"
            )
            .is_empty()
        );
        // Inside a batch, still found.
        let batch = tx(
            addr(MULTISEND_141),
            Operation::DelegateCall,
            multisend(&[entry(Operation::Call, safe(), add(1))]),
        );
        assert_eq!(
            with_id(&findings(&batch), "BS-OWNERS-001"),
            [(Severity::Critical, "batch[0]".into())]
        );
    }
}
