//! `BS-FALLBACK-001`: the fallback handler changes.

use alloy_primitives::Address;

use super::{Context, Finding, Severity, finding};
use crate::decode::{CallNode, DecodedCall, KnownCall, Semantics, Verification};
use crate::registry::Role;

/// Detector ID.
pub const ID: &str = "BS-FALLBACK-001";

pub fn check(ctx: &Context<'_>, node: &CallNode) -> Vec<Finding> {
    let DecodedCall::Known {
        call: KnownCall::SetFallbackHandler { handler },
        semantics: Semantics::Verified(Verification::ExecutingSafe),
    } = &node.decoded
    else {
        return Vec::new();
    };
    let safe = ctx.describe(node.executor);
    let (severity, detail) = if ctx.is_official(*handler, Role::FallbackHandler) {
        (
            Severity::Low,
            format!(
                "Sets the fallback handler of {safe} to {}, an official Safe fallback handler on this chain.",
                ctx.describe(*handler)
            ),
        )
    } else if *handler == Address::ZERO {
        (
            Severity::High,
            format!(
                "Removes the fallback handler of {safe}. Contract signatures (EIP-1271) and token callbacks handled by it stop working."
            ),
        )
    } else {
        (
            Severity::High,
            format!(
                "Sets the fallback handler of {safe} to {}, which is not an official handler. The handler receives every call to the Safe that matches no Safe function, including EIP-1271 isValidSignature: a malicious handler can make the Safe appear to sign arbitrary messages.",
                ctx.describe(*handler)
            ),
        )
    };
    vec![finding(
        ID,
        severity,
        node,
        "Changes the fallback handler",
        detail,
    )]
}

#[cfg(test)]
mod tests {
    use crate::detect::testutil::*;

    #[test]
    fn fallback_handler_changes() {
        let handler = |h: Address| ISafe::setFallbackHandlerCall { handler: h }.abi_encode();
        assert_eq!(
            with_id(
                &findings(&admin(handler(addr(FALLBACK_141)))),
                "BS-FALLBACK-001"
            ),
            [(Severity::Low, "root".into())]
        );
        assert_eq!(
            with_id(
                &findings(&admin(handler(Address::repeat_byte(6)))),
                "BS-FALLBACK-001"
            ),
            [(Severity::High, "root".into())]
        );
    }
}
