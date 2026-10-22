//! `BS-GUARD-001`: the transaction guard or module guard changes.

use alloy_primitives::Address;

use super::{Context, Finding, Severity, finding};
use crate::decode::{CallNode, DecodedCall, KnownCall, Semantics, Verification};
use crate::safe::SafeVersion;

/// Detector ID.
pub const ID: &str = "BS-GUARD-001";

pub fn check(ctx: &Context<'_>, node: &CallNode) -> Vec<Finding> {
    let DecodedCall::Known {
        call,
        semantics: Semantics::Verified(Verification::ExecutingSafe),
    } = &node.decoded
    else {
        return Vec::new();
    };
    let (guard, kind, since) = match call {
        KnownCall::SetGuard { guard } => (*guard, "transaction guard", SafeVersion::V1_3_0),
        KnownCall::SetModuleGuard { guard } => (*guard, "module guard", SafeVersion::V1_5_0),
        _ => return Vec::new(),
    };
    let safe = ctx.describe(node.executor);
    let action = if guard == Address::ZERO {
        format!(
            "Removes the {kind} of {safe}. Any protection the current guard enforces stops applying."
        )
    } else {
        format!(
            "Sets the {kind} of {safe} to {}. A guard runs before and after every transaction and can block all of them, bricking the Safe if it is faulty or malicious.",
            ctx.describe(guard)
        )
    };
    // The root Safe's version is known; for nested Safes it is not.
    let version_note = if node.executor == ctx.account.address && ctx.account.version < since {
        format!(
            " This Safe is version {}, which has no such function before {since}: the call would reach the fallback handler instead.",
            ctx.account.version
        )
    } else {
        String::new()
    };
    vec![finding(
        ID,
        Severity::High,
        node,
        format!("Changes the {kind}"),
        format!("{action}{version_note}"),
    )]
}

#[cfg(test)]
mod tests {
    use crate::detect::testutil::*;

    #[test]
    fn guard_changes() {
        let guard = ISafe::setGuardCall {
            guard: Address::repeat_byte(4),
        }
        .abi_encode();
        let f = findings(&admin(guard.clone()));
        assert_eq!(
            with_id(&f, "BS-GUARD-001"),
            [(Severity::High, "root".into())]
        );
        // On a 1.1.1 Safe, setGuard does not exist.
        let old = Run {
            version: SafeVersion::V1_1_1,
            ..Run::default()
        }
        .findings(&admin(guard));
        let detail = &old.iter().find(|f| f.id == "BS-GUARD-001").unwrap().detail;
        assert!(detail.contains("fallback handler"), "{detail}");
    }
}
