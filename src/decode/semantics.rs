//! Is the decoded function name a fact or a guess?
//!
//! A selector only describes how arguments are laid out. Any contract can
//! implement `transfer(address,uint256)` to do anything: the Bybit payload was
//! exactly that, executed by delegatecall. blindsight calls a decoded function
//! **verified** only when the target is known to implement it and the
//! operation is the one that function is meant for; otherwise the name is
//! labelled as inferred from the selector.

use alloy_primitives::Address;

use super::functions::{FunctionKind, KnownCall};
use crate::registry::{OfficialContract, Registry, Token};
use crate::safe::Operation;

/// Whether a decoded call's meaning is established.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Semantics {
    /// The target is known to implement this function.
    Verified(Verification),
    /// Only the selector matched; the target's code is unknown.
    SelectorOnly,
}

impl Semantics {
    /// Whether the meaning is verified.
    pub fn is_verified(&self) -> bool {
        matches!(self, Semantics::Verified(_))
    }
}

/// Why a call's meaning is considered verified.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Verification {
    /// An ERC-20 function, called on a token of the embedded list.
    KnownToken(Token),
    /// A Safe administrative function, called on the Safe that executes it.
    ExecutingSafe,
    /// A function of an official Safe helper, delegatecalled as intended.
    Official(OfficialContract),
    /// A Permit2 function, called on the Permit2 contract.
    Permit2,
}

/// Official contract names that implement each helper function.
fn official_names(call: &KnownCall) -> &'static [&'static str] {
    use KnownCall as K;
    match call {
        K::MultiSend { .. } => &["MultiSend", "MultiSendCallOnly"],
        K::SignMessage { .. } => &["SignMessageLib"],
        K::PerformCreate { .. } | K::PerformCreate2 { .. } => &["CreateCall"],
        K::MigrateSingleton
        | K::MigrateWithFallbackHandler
        | K::MigrateL2Singleton
        | K::MigrateL2WithFallbackHandler => &["SafeMigration"],
        K::MigrateToL2 { .. } | K::MigrateFromV111 { .. } => &["SafeToL2Migration"],
        K::SetupToL2 { .. } => &["SafeToL2Setup"],
        _ => &[],
    }
}

/// Decides the semantics of `call`, sent to `to` with `operation` by the Safe
/// `executor` on `chain_id`.
pub fn semantics(
    call: &KnownCall,
    to: Address,
    operation: Operation,
    executor: Address,
    chain_id: u64,
    registry: &Registry,
) -> Semantics {
    let verified = match (call.kind(), operation) {
        // A token function only means a token operation when it is a CALL:
        // delegatecalled, the token's code would run on the Safe's storage.
        (FunctionKind::Erc20, Operation::Call) => registry
            .tokens
            .get(chain_id, to)
            .map(|t| Verification::KnownToken(t.clone())),
        (FunctionKind::Permit2, Operation::Call) if registry.permit2.is_at(chain_id, to) => {
            Some(Verification::Permit2)
        }
        (FunctionKind::SafeAdmin, Operation::Call) if to == executor => {
            Some(Verification::ExecutingSafe)
        }
        // Helpers are libraries: they act on the Safe only when delegatecalled.
        (
            FunctionKind::MultiSend
            | FunctionKind::SignMessage
            | FunctionKind::CreateCall
            | FunctionKind::Migration,
            Operation::DelegateCall,
        ) => registry
            .contracts
            .at(chain_id, to)
            .iter()
            .find(|c| official_names(call).contains(&c.name.as_str()))
            .map(|c| Verification::Official(c.clone())),
        // NFT standards have no registry, and whether an address is another
        // Safe cannot be known offline.
        _ => None,
    };
    verified.map_or(Semantics::SelectorOnly, Semantics::Verified)
}

#[cfg(test)]
mod tests {
    use alloy_primitives::U256;

    use super::*;
    use crate::registry::Registry;

    fn addr(s: &str) -> Address {
        s.parse().unwrap()
    }

    fn sem(
        call: &KnownCall,
        to: Address,
        op: Operation,
        executor: Address,
        chain: u64,
    ) -> Semantics {
        semantics(call, to, op, executor, chain, &Registry::load().unwrap())
    }

    const USDC: &str = "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48";
    const MULTISEND_130: &str = "0xA238CBeb142c10Ef7Ad8442C6D1f9E89e07e7761";
    const CALL_ONLY_130: &str = "0x40A2aCCbd92BCA938b02010E17A5b8929b49130D";

    #[test]
    fn token_transfer_is_verified_only_on_a_known_token_by_call() {
        let transfer = KnownCall::Transfer {
            to: Address::ZERO,
            amount: U256::from(1u64),
        };
        let safe = Address::repeat_byte(5);
        assert!(sem(&transfer, addr(USDC), Operation::Call, safe, 1).is_verified());
        // Same address on another chain is not the same token.
        assert!(!sem(&transfer, addr(USDC), Operation::Call, safe, 8453).is_verified());
        // Delegatecalled, even a real token is not a transfer.
        assert!(!sem(&transfer, addr(USDC), Operation::DelegateCall, safe, 1).is_verified());
        // The Bybit target.
        let bybit = addr("0x96221423681A6d52E184D440a8eFCEbB105C7242");
        assert_eq!(
            sem(&transfer, bybit, Operation::DelegateCall, safe, 1),
            Semantics::SelectorOnly
        );
    }

    #[test]
    fn admin_functions_are_verified_only_on_the_executing_safe() {
        let call = KnownCall::ChangeThreshold {
            threshold: U256::from(2u64),
        };
        let safe = Address::repeat_byte(5);
        assert_eq!(
            sem(&call, safe, Operation::Call, safe, 1),
            Semantics::Verified(Verification::ExecutingSafe)
        );
        assert!(!sem(&call, Address::repeat_byte(6), Operation::Call, safe, 1).is_verified());
        assert!(!sem(&call, safe, Operation::DelegateCall, safe, 1).is_verified());
    }

    #[test]
    fn helpers_are_verified_when_delegatecalled_on_an_official_address() {
        let call = KnownCall::MultiSend {
            transactions: Default::default(),
        };
        let safe = Address::repeat_byte(5);
        for target in [MULTISEND_130, CALL_ONLY_130] {
            assert!(sem(&call, addr(target), Operation::DelegateCall, safe, 1).is_verified());
            assert!(!sem(&call, addr(target), Operation::Call, safe, 1).is_verified());
        }
        assert!(
            !sem(
                &call,
                Address::repeat_byte(7),
                Operation::DelegateCall,
                safe,
                1
            )
            .is_verified()
        );
        // An official contract of another kind does not verify the function.
        let sign = KnownCall::SignMessage {
            message: Default::default(),
        };
        assert!(!sem(&sign, addr(MULTISEND_130), Operation::DelegateCall, safe, 1).is_verified());
    }
}
