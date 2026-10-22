//! `BS-REPLAY-001`: Safes before 1.3.0 sign without a chain id.

use super::{Context, Finding, Severity, finding};
use crate::decode::CallNode;

/// Detector ID.
pub const ID: &str = "BS-REPLAY-001";

pub fn check(ctx: &Context<'_>, node: &CallNode) -> Vec<Finding> {
    if !node.path.is_root() || ctx.account.version.domain_has_chain_id() {
        return Vec::new();
    }
    vec![finding(
        ID,
        Severity::Low,
        node,
        "Signature valid on every chain",
        format!(
            "Safe {} has no chain id in its signing domain, so this signature is also valid on any other chain where a Safe exists at {} with the same nonce. Make sure no such Safe exists, or that it is under the same control.",
            ctx.account.version,
            ctx.account.address.to_checksum(None)
        ),
    )]
}

#[cfg(test)]
mod tests {
    use crate::detect::testutil::*;

    #[test]
    fn replay_before_1_3_0() {
        let t = tx(Address::repeat_byte(1), Operation::Call, vec![]);
        for version in SafeVersion::ALL {
            let f = Run {
                version,
                ..Run::default()
            }
            .findings(&t);
            let expected = if version.domain_has_chain_id() {
                vec![]
            } else {
                vec![(Severity::Low, "root".to_string())]
            };
            assert_eq!(with_id(&f, "BS-REPLAY-001"), expected, "{version}");
        }
    }
}
