//! `BS-DELEGATE-002`: delegatecall entries inside a `multiSend` batch.

use super::{Context, Finding, Severity, finding};
use crate::decode::{CallNode, DecodedCall};
use crate::safe::Operation;

/// Detector ID.
pub const ID: &str = "BS-DELEGATE-002";

pub fn check(ctx: &Context<'_>, node: &CallNode) -> Vec<Finding> {
    let DecodedCall::Batch {
        call_only, items, ..
    } = &node.decoded
    else {
        return Vec::new();
    };
    items
        .iter()
        .filter(|item| item.operation == Operation::DelegateCall)
        .map(|item| {
            let target = ctx.describe(item.to);
            if *call_only {
                finding(
                    ID,
                    Severity::Info,
                    item,
                    "Delegatecall entry in a MultiSendCallOnly batch",
                    format!(
                        "Entry {} delegatecalls {target}, but MultiSendCallOnly rejects delegatecall entries: the whole batch will revert if executed.",
                        item.path
                    ),
                )
            } else if ctx.is_trusted_helper(item.to) {
                finding(
                    ID,
                    Severity::Medium,
                    item,
                    "Batch entry delegatecalls an official helper",
                    format!(
                        "Entry {} delegatecalls {target}. The target is an official Safe helper, but delegatecalls inside a batch are unusual; check the entry's purpose.",
                        item.path
                    ),
                )
            } else {
                finding(
                    ID,
                    Severity::Critical,
                    item,
                    "Delegatecall hidden inside a batch",
                    format!(
                        "Entry {} of the batch delegatecalls {target}, which is not an official Safe helper. A delegatecall buried among routine entries is easy to miss in an interface; it gives the target full control of the Safe's storage.",
                        item.path
                    ),
                )
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use crate::detect::testutil::*;

    #[test]
    fn untrusted_delegatecall_entry_is_critical() {
        let batch = tx(
            addr(MULTISEND_141),
            Operation::DelegateCall,
            multisend(&[
                entry(Operation::Call, Address::repeat_byte(1), vec![]),
                entry(
                    Operation::DelegateCall,
                    Address::repeat_byte(0xee),
                    transfer(),
                ),
            ]),
        );
        assert_eq!(
            with_id(&findings(&batch), "BS-DELEGATE-002"),
            [(Severity::Critical, "batch[1]".into())]
        );
    }

    #[test]
    fn delegatecall_entries_in_batches() {
        // An official helper delegatecalled from a MultiSend batch: medium.
        let ms = tx(
            addr(MULTISEND_141),
            Operation::DelegateCall,
            multisend(&[entry(
                Operation::DelegateCall,
                addr(SIGN_MESSAGE_LIB_141),
                vec![],
            )]),
        );
        assert_eq!(
            with_id(&findings(&ms), "BS-DELEGATE-002"),
            [(Severity::Medium, "batch[0]".into())]
        );
        // Any delegatecall entry in MultiSendCallOnly: info (the batch reverts).
        let co = tx(
            addr(CALL_ONLY_141),
            Operation::DelegateCall,
            multisend(&[entry(
                Operation::DelegateCall,
                Address::repeat_byte(3),
                vec![],
            )]),
        );
        assert_eq!(
            with_id(&findings(&co), "BS-DELEGATE-002"),
            [(Severity::Info, "batch[0]".into())]
        );
    }
}
