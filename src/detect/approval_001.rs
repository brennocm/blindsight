//! `BS-APPROVAL-001`: token approvals, unlimited or to an operator.

use alloy_primitives::U256;

use super::{Context, Finding, Severity, finding};
use crate::decode::{CallNode, KnownCall};

/// Detector ID.
pub const ID: &str = "BS-APPROVAL-001";

/// Amounts at or above 2^255 are treated as unlimited: `type(uint256).max`
/// and the "max-ish" values some interfaces use.
fn unlimited_threshold() -> U256 {
    U256::from(1u8) << 255
}

pub fn check(ctx: &Context<'_>, node: &CallNode) -> Vec<Finding> {
    let Some(call) = node.known_call() else {
        return Vec::new();
    };
    let token = ctx.describe(node.to);
    let (severity, title, detail) = match call {
        KnownCall::Approve { spender, amount }
        | KnownCall::IncreaseAllowance {
            spender,
            added: amount,
        } => {
            let verb = if matches!(call, KnownCall::Approve { .. }) {
                "approves"
            } else {
                "increases the allowance of"
            };
            if *amount >= unlimited_threshold() {
                (
                    Severity::High,
                    "Unlimited token approval",
                    format!(
                        "{verb} {} to spend an unlimited amount ({amount}) of {token} held by {}. The spender can take the whole balance, now and later, until the approval is revoked.",
                        ctx.describe(*spender),
                        ctx.describe(node.executor)
                    ),
                )
            } else {
                (
                    Severity::Info,
                    "Token approval",
                    format!(
                        "{verb} {} to spend {} of {token}.",
                        ctx.describe(*spender),
                        ctx.token_amount(node.to, *amount)
                    ),
                )
            }
        }
        KnownCall::SetApprovalForAll { operator, approved } => {
            if *approved {
                (
                    Severity::High,
                    "Operator approval for all tokens",
                    format!(
                        "Lets {} transfer every token of collection {token} held by {}.",
                        ctx.describe(*operator),
                        ctx.describe(node.executor)
                    ),
                )
            } else {
                (
                    Severity::Info,
                    "Operator approval revoked",
                    format!(
                        "Revokes {} as operator of collection {token}.",
                        ctx.describe(*operator)
                    ),
                )
            }
        }
        _ => return Vec::new(),
    };
    // The verb starts the sentence.
    let detail = capitalise(&detail);
    vec![finding(ID, severity, node, title, detail)]
}

fn capitalise(s: &str) -> String {
    let mut chars = s.chars();
    match chars.next() {
        Some(first) => first.to_uppercase().chain(chars).collect(),
        None => String::new(),
    }
}

#[cfg(test)]
mod tests {
    use crate::detect::testutil::*;

    #[test]
    fn approval_edges() {
        let approve = |amount: U256| {
            tx(
                addr(USDC),
                Operation::Call,
                IERC20::approveCall {
                    spender: Address::repeat_byte(1),
                    amount,
                }
                .abi_encode(),
            )
        };
        let half = U256::from(1u8) << 255;
        for (amount, expected) in [
            (U256::MAX, Severity::High),
            (U256::MAX - U256::from(1u8), Severity::High),
            (half, Severity::High),
            (half - U256::from(1u8), Severity::Info),
            (U256::from(1_000_000u64), Severity::Info),
        ] {
            assert_eq!(
                with_id(&findings(&approve(amount)), "BS-APPROVAL-001"),
                [(expected, "root".into())],
                "amount {amount}"
            );
        }
        let bounded = findings(&approve(U256::from(1_500_000u64)));
        let detail = &bounded
            .iter()
            .find(|f| f.id == "BS-APPROVAL-001")
            .unwrap()
            .detail;
        assert!(detail.contains("1.5 USDC"), "{detail}");

        let operator = |approved: bool| {
            tx(
                Address::repeat_byte(8),
                Operation::Call,
                IERC721::setApprovalForAllCall {
                    operator: Address::repeat_byte(1),
                    approved,
                }
                .abi_encode(),
            )
        };
        assert_eq!(
            with_id(&findings(&operator(true)), "BS-APPROVAL-001"),
            [(Severity::High, "root".into())]
        );
        assert_eq!(
            with_id(&findings(&operator(false)), "BS-APPROVAL-001"),
            [(Severity::Info, "root".into())]
        );
    }
}
