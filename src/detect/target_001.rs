//! `BS-TARGET-001`: a call to an address blindsight knows nothing about.

use super::{Context, Finding, Severity, finding};
use crate::decode::CallNode;

/// Detector ID.
pub const ID: &str = "BS-TARGET-001";

pub fn check(ctx: &Context<'_>, node: &CallNode) -> Vec<Finding> {
    if ctx.is_known(node.to) || node.to == node.executor {
        return Vec::new();
    }
    vec![finding(
        ID,
        Severity::Info,
        node,
        "Unknown target",
        format!(
            "{} is not an official Safe contract, a listed token or an address-book entry. Check it against a source you trust (add it to your address book to label it).",
            node.to.to_checksum(None)
        ),
    )]
}

#[cfg(test)]
mod tests {
    use crate::detect::testutil::*;

    #[test]
    fn unknown_targets() {
        let f = findings(&tx(
            Address::repeat_byte(9),
            Operation::Call,
            vec![1, 2, 3, 4],
        ));
        assert_eq!(
            with_id(&f, "BS-TARGET-001"),
            [(Severity::Info, "root".into())]
        );
        assert!(
            with_id(
                &findings(&tx(addr(USDC), Operation::Call, vec![])),
                "BS-TARGET-001"
            )
            .is_empty()
        );
        // A Safe calling itself is not an unknown target.
        assert!(with_id(&findings(&admin(vec![])), "BS-TARGET-001").is_empty());
    }
}
