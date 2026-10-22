//! `BS-MODULE-001`: a module is enabled or disabled.

use super::{Context, Finding, Severity, finding};
use crate::decode::{CallNode, DecodedCall, KnownCall, Semantics, Verification};

/// Detector ID.
pub const ID: &str = "BS-MODULE-001";

pub fn check(ctx: &Context<'_>, node: &CallNode) -> Vec<Finding> {
    let DecodedCall::Known {
        call,
        semantics: Semantics::Verified(Verification::ExecutingSafe),
    } = &node.decoded
    else {
        return Vec::new();
    };
    let safe = ctx.describe(node.executor);
    match call {
        KnownCall::EnableModule { module } => vec![finding(
            ID,
            Severity::Critical,
            node,
            "Enables a module",
            format!(
                "Enables {} as a module of {safe}. A module can execute any transaction from the Safe, including delegatecalls, without owner signatures: its power equals full control of the Safe. Enable only audited modules you expect.",
                ctx.describe(*module)
            ),
        )],
        KnownCall::DisableModule {
            prev_module,
            module,
        } => vec![finding(
            ID,
            Severity::Medium,
            node,
            "Disables a module",
            format!(
                "Disables module {} on {safe} (linked-list pointer prevModule: {}). Check it is not a recovery or security module you rely on.",
                ctx.describe(*module),
                ctx.describe(*prev_module)
            ),
        )],
        _ => Vec::new(),
    }
}

#[cfg(test)]
mod tests {
    use crate::detect::testutil::*;

    #[test]
    fn module_changes() {
        let enable = ISafe::enableModuleCall {
            module: Address::repeat_byte(4),
        }
        .abi_encode();
        assert_eq!(
            with_id(&findings(&admin(enable)), "BS-MODULE-001"),
            [(Severity::Critical, "root".into())]
        );
        let disable = ISafe::disableModuleCall {
            prevModule: Address::repeat_byte(1),
            module: Address::repeat_byte(4),
        }
        .abi_encode();
        assert_eq!(
            with_id(&findings(&admin(disable)), "BS-MODULE-001"),
            [(Severity::Medium, "root".into())]
        );
    }
}
