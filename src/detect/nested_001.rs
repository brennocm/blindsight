//! `BS-NESTED-001`: transactions for another Safe, opaque hash approvals,
//! and nesting too deep to analyse.

use super::{Context, Finding, Severity, finding};
use crate::decode::{CallNode, DecodedCall, KnownCall, MAX_DEPTH};

/// Detector ID.
pub const ID: &str = "BS-NESTED-001";

pub fn check(ctx: &Context<'_>, node: &CallNode) -> Vec<Finding> {
    let target = ctx.describe(node.to);
    let (severity, title, detail) = match &node.decoded {
        DecodedCall::Nested { .. } => (
            Severity::Info,
            "Executes a transaction of another Safe",
            format!(
                "Calls execTransaction on {target}. The inner transaction is decoded and analysed below (path \"{} > nested\"). Its own owners must have signed it; blindsight cannot compute its hash without that Safe's nonce and version.",
                node.path
            ),
        ),
        DecodedCall::Known {
            call: KnownCall::ApproveHash { hash },
            ..
        } => (
            Severity::High,
            "Approves an opaque hash",
            format!(
                "Calls approveHash({hash}) on {target}: this Safe, as an owner of that Safe, approves whatever transaction has this hash. The hash reveals nothing about the transaction. Compute it yourself from the inner transaction (blindsight hash, with that Safe's address, chain, version and nonce) before signing."
            ),
        ),
        DecodedCall::TooDeep => (
            Severity::High,
            "Nesting too deep to analyse",
            format!(
                "This call is more than {MAX_DEPTH} batch or nested levels deep, so blindsight did not decode or check it. Legitimate transactions are rarely nested this deeply."
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
    fn nested_hash_approvals_and_depth() {
        let approve = ISafe::approveHashCall {
            hashToApprove: B256::repeat_byte(1),
        }
        .abi_encode();
        assert_eq!(
            with_id(
                &findings(&tx(Address::repeat_byte(7), Operation::Call, approve)),
                "BS-NESTED-001"
            ),
            [(Severity::High, "root".into())]
        );
        let nested = tx(
            Address::repeat_byte(7),
            Operation::Call,
            exec(Address::repeat_byte(1), 0, vec![]),
        );
        assert_eq!(
            with_id(&findings(&nested), "BS-NESTED-001"),
            [(Severity::Info, "root".into())]
        );

        // Five levels of batches: the innermost is not analysed.
        let mut data = transfer();
        for _ in 0..=MAX_DEPTH {
            data = multisend(&[entry(Operation::Call, Address::repeat_byte(1), data)]);
        }
        let deep = findings(&tx(addr(MULTISEND_141), Operation::DelegateCall, data));
        assert!(
            with_id(&deep, "BS-NESTED-001")
                .iter()
                .any(|(s, _)| *s == Severity::High)
        );
    }
}
