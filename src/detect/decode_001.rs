//! `BS-DECODE-001`: calldata blindsight cannot decode.

use super::{Context, Finding, Severity, finding};
use crate::decode::{CallNode, DecodedCall};

/// Detector ID.
pub const ID: &str = "BS-DECODE-001";

pub fn check(ctx: &Context<'_>, node: &CallNode) -> Vec<Finding> {
    let target = ctx.describe(node.to);
    let (severity, title, detail) = match &node.decoded {
        DecodedCall::Unknown {
            selector: Some(selector),
        } => (
            Severity::Medium,
            "Unknown function",
            format!(
                "The calldata to {target} starts with selector 0x{}, which is not a function blindsight knows. Signing calldata you cannot read is blind signing: obtain the target's ABI (and pass it with --abi) or verify the call another way.",
                alloy_primitives::hex::encode(selector)
            ),
        ),
        DecodedCall::Unknown { selector: None } => (
            Severity::Medium,
            "Calldata shorter than a function selector",
            format!(
                "The calldata to {target} has {} bytes, fewer than the 4 of a function selector. No interface produces this.",
                node.data.len()
            ),
        ),
        DecodedCall::Malformed {
            function: Some("multiSend"),
            reason,
        } => (
            Severity::High,
            "Malformed batch",
            format!(
                "The multiSend payload sent to {target} cannot be unpacked: {reason}. The contract reads it without bounds checks, so it may execute something other than any display of it shows."
            ),
        ),
        DecodedCall::Malformed { function, reason } => (
            Severity::Medium,
            "Malformed calldata",
            format!(
                "The calldata to {target}{} does not decode: {reason}.",
                function.map_or_else(String::new, |f| format!(" (function {f})"))
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
    fn undecodable_data() {
        let f = findings(&tx(
            Address::repeat_byte(9),
            Operation::Call,
            vec![1, 2, 3, 4],
        ));
        assert_eq!(
            with_id(&f, "BS-DECODE-001"),
            [(Severity::Medium, "root".into())]
        );

        let short = findings(&tx(Address::repeat_byte(9), Operation::Call, vec![1]));
        assert_eq!(
            with_id(&short, "BS-DECODE-001"),
            [(Severity::Medium, "root".into())]
        );

        let mut bad = pack(&[entry(Operation::Call, Address::ZERO, vec![1])]);
        bad.pop();
        let malformed = tx(
            addr(MULTISEND_141),
            Operation::DelegateCall,
            IHelpers::multiSendCall {
                transactions: Bytes::from(bad),
            }
            .abi_encode(),
        );
        assert_eq!(
            with_id(&findings(&malformed), "BS-DECODE-001"),
            [(Severity::High, "root".into())]
        );
    }
}
