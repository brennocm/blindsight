//! `BS-IMPL-001`: the Safe's implementation (singleton) changes.

use super::{Context, Finding, Severity, finding};
use crate::decode::{CallNode, DecodedCall, KnownCall, Semantics, Verification};
use crate::registry::Role;
use crate::safe::SafeVersion;

/// Detector ID.
pub const ID: &str = "BS-IMPL-001";

pub fn check(ctx: &Context<'_>, node: &CallNode) -> Vec<Finding> {
    let DecodedCall::Known { call, semantics } = &node.decoded else {
        return Vec::new();
    };
    match (call, semantics) {
        (
            KnownCall::ChangeMasterCopy { master_copy },
            Semantics::Verified(Verification::ExecutingSafe),
        ) => {
            let official = ctx.is_official(*master_copy, Role::Singleton)
                || ctx.is_official(*master_copy, Role::SingletonL2);
            let version_note = if node.executor == ctx.account.address
                && ctx.account.version > SafeVersion::V1_2_0
            {
                format!(
                    " This Safe is version {}, which has no changeMasterCopy: the call would reach the fallback handler instead.",
                    ctx.account.version
                )
            } else {
                String::new()
            };
            let (severity, detail) = if official {
                (
                    Severity::Info,
                    format!(
                        "Replaces the implementation of {} with {}, an official Safe singleton. Make sure the upgrade is planned; the new version may hash transactions differently.{version_note}",
                        ctx.describe(node.executor),
                        ctx.describe(*master_copy)
                    ),
                )
            } else {
                (
                    Severity::Critical,
                    format!(
                        "Replaces the implementation of {} with {}, which is not an official Safe singleton. Whoever controls that code controls the Safe and its funds.{version_note}",
                        ctx.describe(node.executor),
                        ctx.describe(*master_copy)
                    ),
                )
            };
            vec![finding(
                ID,
                severity,
                node,
                "Changes the Safe's implementation",
                detail,
            )]
        }
        (
            KnownCall::MigrateSingleton
            | KnownCall::MigrateWithFallbackHandler
            | KnownCall::MigrateL2Singleton
            | KnownCall::MigrateL2WithFallbackHandler
            | KnownCall::MigrateToL2 { .. }
            | KnownCall::MigrateFromV111 { .. }
            | KnownCall::SetupToL2 { .. },
            Semantics::Verified(Verification::Official(contract)),
        ) => {
            let nonce_note =
                if contract.name == "SafeToL2Setup" || contract.name == "SafeToL2Migration" {
                    " This contract only works while the Safe's nonce is 0."
                } else {
                    ""
                };
            vec![finding(
                ID,
                Severity::Info,
                node,
                "Migrates the Safe to another implementation",
                format!(
                    "Delegatecalls {} ({}): this official migration replaces the implementation of {} in storage slot 0. Make sure the migration is planned.{nonce_note}",
                    ctx.describe(node.to),
                    call.name(),
                    ctx.describe(node.executor),
                ),
            )]
        }
        _ => Vec::new(),
    }
}

#[cfg(test)]
mod tests {
    use crate::detect::testutil::*;

    #[test]
    fn implementation_changes() {
        let change = |to: Address| ISafe::changeMasterCopyCall { _masterCopy: to }.abi_encode();
        let old = Run {
            version: SafeVersion::V1_1_1,
            ..Run::default()
        };
        assert_eq!(
            with_id(
                &old.findings(&admin(change(addr(SINGLETON_130)))),
                "BS-IMPL-001"
            ),
            [(Severity::Info, "root".into())]
        );
        assert_eq!(
            with_id(
                &old.findings(&admin(change(Address::repeat_byte(6)))),
                "BS-IMPL-001"
            ),
            [(Severity::Critical, "root".into())]
        );
    }

    #[test]
    fn official_migrations_are_info() {
        // SafeMigration 1.4.1 and SafeToL2Setup 1.4.1, canonical addresses
        // (docs/research.md §3).
        let migration = tx(
            addr("0x526643F69b81B008F46d95CD5ced5eC0edFFDaC6"),
            Operation::DelegateCall,
            IHelpers::migrateSingletonCall {}.abi_encode(),
        );
        let f = findings(&migration);
        assert_eq!(
            with_id(&f, "BS-IMPL-001"),
            [(Severity::Info, "root".into())]
        );
        assert!(with_id(&f, "BS-DELEGATE-001").is_empty());

        let setup = tx(
            addr("0xBD89A1CE4DDe368FFAB0eC35506eEcE0b1fFdc54"),
            Operation::DelegateCall,
            IHelpers::setupToL2Call {
                l2Singleton: Address::repeat_byte(1),
            }
            .abi_encode(),
        );
        let f = findings(&setup);
        let detail = &f.iter().find(|f| f.id == "BS-IMPL-001").unwrap().detail;
        assert!(detail.contains("nonce is 0"), "{detail}");

        // The same function on an unofficial contract is not a migration.
        let fake = tx(
            Address::repeat_byte(0xee),
            Operation::DelegateCall,
            IHelpers::migrateSingletonCall {}.abi_encode(),
        );
        assert!(with_id(&findings(&fake), "BS-IMPL-001").is_empty());
    }

    #[test]
    fn change_master_copy_on_a_recent_safe_is_noted() {
        let call = ISafe::changeMasterCopyCall {
            _masterCopy: Address::repeat_byte(6),
        }
        .abi_encode();
        let f = findings(&admin(call));
        let detail = &f.iter().find(|f| f.id == "BS-IMPL-001").unwrap().detail;
        assert!(detail.contains("no changeMasterCopy"), "{detail}");
    }
}
