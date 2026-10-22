//! `BS-SEMANTICS-001`: a decoded function name that is only a selector
//! match. The Bybit payload was "transfer" by selector.

use super::{Context, Finding, Severity, finding};
use crate::decode::{CallNode, DecodedCall, FunctionKind, KnownCall, Semantics};
use crate::safe::Operation;

/// Detector ID.
pub const ID: &str = "BS-SEMANTICS-001";

/// Why a call of this kind, sent this way, could not be verified.
fn reason(ctx: &Context<'_>, kind: FunctionKind, node: &CallNode) -> String {
    let delegate = node.operation == Operation::DelegateCall;
    match kind {
        FunctionKind::Erc20 if delegate => "under delegatecall a token function moves no tokens: the target's code runs on the Safe's own storage".to_string(),
        FunctionKind::Erc20 => "the target is not in blindsight's token list for this chain".to_string(),
        FunctionKind::Nft => "NFT contracts are not in blindsight's registry".to_string(),
        FunctionKind::Permit2 => "the target is not the Permit2 contract on this chain (or the call is a delegatecall)".to_string(),
        FunctionKind::SafeAdmin if node.to != node.executor => format!(
            "Safe administrative functions only mean that when called on the Safe itself, and this call goes to another address than {}",
            ctx.describe(node.executor)
        ),
        FunctionKind::SafeAdmin => "Safe administrative functions are called, not delegatecalled".to_string(),
        FunctionKind::MultiSend
        | FunctionKind::SignMessage
        | FunctionKind::CreateCall
        | FunctionKind::Migration
            if delegate =>
        {
            "the target is not the official Safe contract that implements it on this chain".to_string()
        }
        FunctionKind::MultiSend
        | FunctionKind::SignMessage
        | FunctionKind::CreateCall
        | FunctionKind::Migration => "Safe helper libraries only act on the Safe when delegatecalled; this is a plain call".to_string(),
        FunctionKind::NestedSafe => "whether the target is a Safe cannot be known offline".to_string(),
    }
}

pub fn check(ctx: &Context<'_>, node: &CallNode) -> Vec<Finding> {
    let (name, signature, kind) = match &node.decoded {
        DecodedCall::Known {
            call,
            semantics: Semantics::SelectorOnly,
        } => (call.name(), call.signature(), call.kind()),
        DecodedCall::Batch {
            semantics: Semantics::SelectorOnly,
            ..
        } => {
            let call = KnownCall::MultiSend {
                transactions: Default::default(),
            };
            (call.name(), call.signature(), call.kind())
        }
        _ => return Vec::new(),
    };
    // Nested Safe transactions are covered by BS-NESTED-001.
    if kind == FunctionKind::NestedSafe {
        return Vec::new();
    }
    let severity = match node.operation {
        Operation::DelegateCall => Severity::Critical,
        Operation::Call => Severity::Low,
    };
    vec![finding(
        ID,
        severity,
        node,
        format!("\"{name}\" is a guess from the selector, not a verified function"),
        format!(
            "The calldata matches {signature}, but {} is not known to implement it: {}. Any contract can give a function this signature and do something else; the Bybit attack used transfer(address,uint256), executed by delegatecall, to replace the Safe's implementation. Treat the decoded name and arguments as a layout, not as a description.",
            ctx.describe(node.to),
            reason(ctx, kind, node),
        ),
    )]
}

#[cfg(test)]
mod tests {
    use crate::detect::testutil::*;

    #[test]
    fn guessed_names_are_low_by_call_and_critical_by_delegatecall() {
        let unknown = Address::repeat_byte(0x99);
        assert_eq!(
            with_id(
                &findings(&tx(unknown, Operation::Call, transfer())),
                "BS-SEMANTICS-001"
            ),
            [(Severity::Low, "root".into())]
        );
        assert_eq!(
            with_id(
                &findings(&tx(unknown, Operation::DelegateCall, transfer())),
                "BS-SEMANTICS-001"
            ),
            [(Severity::Critical, "root".into())]
        );
        // A listed token by CALL: verified, no finding.
        assert!(
            with_id(
                &findings(&tx(addr(USDC), Operation::Call, transfer())),
                "BS-SEMANTICS-001"
            )
            .is_empty()
        );
        // An unofficial "MultiSend": the batch name is a guess too.
        let fake = tx(
            unknown,
            Operation::Call,
            multisend(&[entry(Operation::Call, Address::repeat_byte(1), vec![])]),
        );
        assert_eq!(
            with_id(&findings(&fake), "BS-SEMANTICS-001"),
            [(Severity::Low, "root".into())]
        );
    }
}
