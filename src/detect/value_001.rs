//! `BS-VALUE-001`: native value sent with a call.

use super::{Context, Finding, Severity, finding};
use crate::decode::CallNode;
use crate::safe::Operation;

/// Detector ID.
pub const ID: &str = "BS-VALUE-001";

pub fn check(ctx: &Context<'_>, node: &CallNode) -> Vec<Finding> {
    if node.value.is_zero() {
        return Vec::new();
    }
    let amount = ctx.native_amount(node.value);
    let found = match node.operation {
        Operation::Call => finding(
            ID,
            Severity::Info,
            node,
            "Sends native currency",
            format!(
                "Sends {amount} from {} to {}.",
                ctx.describe(node.executor),
                ctx.describe(node.to)
            ),
        ),
        Operation::DelegateCall => finding(
            ID,
            Severity::High,
            node,
            "Value attached to a delegatecall",
            format!(
                "The call carries {amount}, but a delegatecall transfers no value (Safe Executor.sol ignores it). No normal interface builds this; the transaction was likely crafted by hand. Find out who built it and why."
            ),
        ),
    };
    vec![found]
}

#[cfg(test)]
mod tests {
    use crate::detect::testutil::*;

    #[test]
    fn native_value() {
        let mut t = tx(Address::repeat_byte(1), Operation::Call, vec![]);
        t.value = U256::from(10u64).pow(U256::from(18u64)) * U256::from(3u64) / U256::from(2u64);
        let f = findings(&t);
        assert_eq!(
            with_id(&f, "BS-VALUE-001"),
            [(Severity::Info, "root".into())]
        );
        assert!(f.iter().any(|f| f.detail.contains("1.5 ETH")));
        t.operation = Operation::DelegateCall;
        assert_eq!(
            with_id(&findings(&t), "BS-VALUE-001"),
            [(Severity::High, "root".into())]
        );
    }
}
