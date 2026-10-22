//! `BS-NONCE-001`: a nonce that is already used or far in the future.

use alloy_primitives::U256;

use super::{Context, Finding, Severity, finding};
use crate::decode::CallNode;

/// Detector ID.
pub const ID: &str = "BS-NONCE-001";

/// How far ahead of the current nonce a transaction counts as queued.
pub const QUEUE_WINDOW: u64 = 3;

pub fn check(ctx: &Context<'_>, node: &CallNode) -> Vec<Finding> {
    let Some(current) = ctx.current_nonce else {
        return Vec::new();
    };
    if !node.path.is_root() {
        return Vec::new();
    }
    let nonce = ctx.tx.nonce;
    let (severity, title, detail) = if nonce < current {
        (
            Severity::Medium,
            "Nonce already used",
            format!(
                "Nonce {nonce} is below the Safe's current nonce {current}: this transaction can never execute. There is no reason to sign it; ask why it was requested."
            ),
        )
    } else if nonce == current {
        return Vec::new();
    } else if nonce - current <= U256::from(QUEUE_WINDOW) {
        (
            Severity::Info,
            "Queued transaction",
            format!(
                "Nonce {nonce} is ahead of the current nonce {current}: it executes only after the transactions before it."
            ),
        )
    } else {
        (
            Severity::Medium,
            "Nonce far in the future",
            format!(
                "Nonce {nonce} is more than {QUEUE_WINDOW} ahead of the current nonce {current}. A pre-signed future transaction stays valid until a transaction with that nonce executes; ask why it is needed now."
            ),
        )
    };
    vec![finding(ID, severity, node, title, detail)]
}

#[cfg(test)]
mod tests {
    use crate::detect::testutil::*;

    #[test]
    fn nonces() {
        let t = tx(Address::repeat_byte(1), Operation::Call, vec![]); // nonce 10
        let at = |current: u64| {
            with_id(
                &Run {
                    current_nonce: Some(U256::from(current)),
                    ..Run::default()
                }
                .findings(&t),
                "BS-NONCE-001",
            )
        };
        assert_eq!(at(11), [(Severity::Medium, "root".into())]);
        assert!(at(10).is_empty());
        assert_eq!(at(7), [(Severity::Info, "root".into())]);
        assert_eq!(at(6), [(Severity::Medium, "root".into())]);
        assert!(with_id(&findings(&t), "BS-NONCE-001").is_empty());
    }
}
