//! The functions blindsight understands, decoded statically with `sol!`.
//!
//! Signatures are written as Solidity; `sol!` computes each selector from
//! its signature at compile time, and a test checks them against the table
//! in `docs/research.md` (read from the contract sources). A selector only
//! says how the arguments are laid out: whether the target really implements
//! that function is decided separately (see `semantics.rs`).

use alloy_primitives::{Address, B256, Bytes, U256};
use alloy_sol_types::{SolCall, sol};

sol! {
    /// ERC-20 (and the ERC-721 functions with identical signatures).
    interface IERC20 {
        function transfer(address to, uint256 amount);
        function transferFrom(address from, address to, uint256 amount);
        function approve(address spender, uint256 amount);
        function increaseAllowance(address spender, uint256 addedValue);
    }

    /// ERC-721 functions that differ from ERC-20.
    interface IERC721 {
        function safeTransferFrom(address from, address to, uint256 tokenId);
        function safeTransferFrom(address from, address to, uint256 tokenId, bytes data);
        function setApprovalForAll(address operator, bool approved);
    }

    /// ERC-1155 transfers (`setApprovalForAll` is shared with ERC-721).
    interface IERC1155 {
        function safeTransferFrom(address from, address to, uint256 id, uint256 amount, bytes data);
        function safeBatchTransferFrom(address from, address to, uint256[] ids, uint256[] amounts, bytes data);
    }

    /// Functions of the Safe itself (`OwnerManager`, `ModuleManager`,
    /// `GuardManager`, `FallbackManager`, `Safe`), 1.0.0 to 1.5.0.
    interface ISafe {
        function addOwnerWithThreshold(address owner, uint256 _threshold);
        function removeOwner(address prevOwner, address owner, uint256 _threshold);
        function swapOwner(address prevOwner, address oldOwner, address newOwner);
        function changeThreshold(uint256 _threshold);
        function enableModule(address module);
        function disableModule(address prevModule, address module);
        function setGuard(address guard);
        function setModuleGuard(address moduleGuard);
        function setFallbackHandler(address handler);
        function changeMasterCopy(address _masterCopy);
        function approveHash(bytes32 hashToApprove);
        function execTransaction(
            address to,
            uint256 value,
            bytes data,
            uint8 operation,
            uint256 safeTxGas,
            uint256 baseGas,
            uint256 gasPrice,
            address gasToken,
            address refundReceiver,
            bytes signatures
        );
    }

    /// Official helper libraries.
    interface IHelpers {
        function multiSend(bytes transactions);
        function signMessage(bytes _data);
        function performCreate(uint256 value, bytes deploymentData);
        function performCreate2(uint256 value, bytes deploymentData, bytes32 salt);
        function migrateSingleton();
        function migrateWithFallbackHandler();
        function migrateL2Singleton();
        function migrateL2WithFallbackHandler();
        function migrateToL2(address l2Singleton);
        function migrateFromV111(address l2Singleton, address fallbackHandler);
        function setupToL2(address l2Singleton);
    }
}

/// A decoded call to a known function, with typed arguments.
#[derive(Debug, Clone, PartialEq, Eq)]
#[allow(missing_docs)] // Variants and fields mirror the Solidity signatures above.
pub enum KnownCall {
    // Tokens
    Transfer {
        to: Address,
        amount: U256,
    },
    TransferFrom {
        from: Address,
        to: Address,
        amount: U256,
    },
    Approve {
        spender: Address,
        amount: U256,
    },
    IncreaseAllowance {
        spender: Address,
        added: U256,
    },
    SafeTransferFrom721 {
        from: Address,
        to: Address,
        token_id: U256,
    },
    SafeTransferFrom721WithData {
        from: Address,
        to: Address,
        token_id: U256,
        data: Bytes,
    },
    SetApprovalForAll {
        operator: Address,
        approved: bool,
    },
    SafeTransferFrom1155 {
        from: Address,
        to: Address,
        id: U256,
        amount: U256,
        data: Bytes,
    },
    SafeBatchTransferFrom1155 {
        from: Address,
        to: Address,
        ids: Vec<U256>,
        amounts: Vec<U256>,
        data: Bytes,
    },
    // Safe administration
    AddOwnerWithThreshold {
        owner: Address,
        threshold: U256,
    },
    RemoveOwner {
        prev_owner: Address,
        owner: Address,
        threshold: U256,
    },
    SwapOwner {
        prev_owner: Address,
        old_owner: Address,
        new_owner: Address,
    },
    ChangeThreshold {
        threshold: U256,
    },
    EnableModule {
        module: Address,
    },
    DisableModule {
        prev_module: Address,
        module: Address,
    },
    SetGuard {
        guard: Address,
    },
    SetModuleGuard {
        guard: Address,
    },
    SetFallbackHandler {
        handler: Address,
    },
    ChangeMasterCopy {
        master_copy: Address,
    },
    ApproveHash {
        hash: B256,
    },
    ExecTransaction {
        to: Address,
        value: U256,
        data: Bytes,
        operation: u8,
        safe_tx_gas: U256,
        base_gas: U256,
        gas_price: U256,
        gas_token: Address,
        refund_receiver: Address,
        signatures: Bytes,
    },
    // Helpers
    MultiSend {
        transactions: Bytes,
    },
    SignMessage {
        message: Bytes,
    },
    PerformCreate {
        value: U256,
        deployment_data: Bytes,
    },
    PerformCreate2 {
        value: U256,
        deployment_data: Bytes,
        salt: B256,
    },
    MigrateSingleton,
    MigrateWithFallbackHandler,
    MigrateL2Singleton,
    MigrateL2WithFallbackHandler,
    MigrateToL2 {
        l2_singleton: Address,
    },
    MigrateFromV111 {
        l2_singleton: Address,
        fallback_handler: Address,
    },
    SetupToL2 {
        l2_singleton: Address,
    },
}

/// A decoded argument value, for display.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ArgValue {
    /// An address.
    Address(Address),
    /// An unsigned integer.
    Uint(U256),
    /// A boolean.
    Bool(bool),
    /// A 32-byte value.
    Bytes32(B256),
    /// A byte string.
    Bytes(Bytes),
    /// A list of unsigned integers.
    Uints(Vec<U256>),
}

/// What a function is, for deciding whether its target is plausible.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FunctionKind {
    /// ERC-20 function (also ERC-721 for `transferFrom` / `approve`).
    Erc20,
    /// ERC-721 or ERC-1155 function.
    Nft,
    /// Administrative function of the executing Safe itself.
    SafeAdmin,
    /// A transaction or hash approval addressed to another Safe.
    NestedSafe,
    /// `multiSend` of `MultiSend` / `MultiSendCallOnly`.
    MultiSend,
    /// `signMessage` of `SignMessageLib`.
    SignMessage,
    /// `performCreate*` of `CreateCall`.
    CreateCall,
    /// A function of an official migration or L2 setup contract.
    Migration,
}

impl KnownCall {
    /// Function name, e.g. `"transfer"`.
    pub fn name(&self) -> &'static str {
        self.info().0
    }

    /// Canonical signature, e.g. `"transfer(address,uint256)"`.
    pub fn signature(&self) -> &'static str {
        self.info().1
    }

    /// What kind of function this is.
    pub fn kind(&self) -> FunctionKind {
        self.info().2
    }

    fn info(&self) -> (&'static str, &'static str, FunctionKind) {
        use FunctionKind as K;
        use KnownCall as C;
        match self {
            C::Transfer { .. } => ("transfer", IERC20::transferCall::SIGNATURE, K::Erc20),
            C::TransferFrom { .. } => (
                "transferFrom",
                IERC20::transferFromCall::SIGNATURE,
                K::Erc20,
            ),
            C::Approve { .. } => ("approve", IERC20::approveCall::SIGNATURE, K::Erc20),
            C::IncreaseAllowance { .. } => (
                "increaseAllowance",
                IERC20::increaseAllowanceCall::SIGNATURE,
                K::Erc20,
            ),
            C::SafeTransferFrom721 { .. } => (
                "safeTransferFrom",
                IERC721::safeTransferFrom_0Call::SIGNATURE,
                K::Nft,
            ),
            C::SafeTransferFrom721WithData { .. } => (
                "safeTransferFrom",
                IERC721::safeTransferFrom_1Call::SIGNATURE,
                K::Nft,
            ),
            C::SetApprovalForAll { .. } => (
                "setApprovalForAll",
                IERC721::setApprovalForAllCall::SIGNATURE,
                K::Nft,
            ),
            C::SafeTransferFrom1155 { .. } => (
                "safeTransferFrom",
                IERC1155::safeTransferFromCall::SIGNATURE,
                K::Nft,
            ),
            C::SafeBatchTransferFrom1155 { .. } => (
                "safeBatchTransferFrom",
                IERC1155::safeBatchTransferFromCall::SIGNATURE,
                K::Nft,
            ),
            C::AddOwnerWithThreshold { .. } => (
                "addOwnerWithThreshold",
                ISafe::addOwnerWithThresholdCall::SIGNATURE,
                K::SafeAdmin,
            ),
            C::RemoveOwner { .. } => (
                "removeOwner",
                ISafe::removeOwnerCall::SIGNATURE,
                K::SafeAdmin,
            ),
            C::SwapOwner { .. } => ("swapOwner", ISafe::swapOwnerCall::SIGNATURE, K::SafeAdmin),
            C::ChangeThreshold { .. } => (
                "changeThreshold",
                ISafe::changeThresholdCall::SIGNATURE,
                K::SafeAdmin,
            ),
            C::EnableModule { .. } => (
                "enableModule",
                ISafe::enableModuleCall::SIGNATURE,
                K::SafeAdmin,
            ),
            C::DisableModule { .. } => (
                "disableModule",
                ISafe::disableModuleCall::SIGNATURE,
                K::SafeAdmin,
            ),
            C::SetGuard { .. } => ("setGuard", ISafe::setGuardCall::SIGNATURE, K::SafeAdmin),
            C::SetModuleGuard { .. } => (
                "setModuleGuard",
                ISafe::setModuleGuardCall::SIGNATURE,
                K::SafeAdmin,
            ),
            C::SetFallbackHandler { .. } => (
                "setFallbackHandler",
                ISafe::setFallbackHandlerCall::SIGNATURE,
                K::SafeAdmin,
            ),
            C::ChangeMasterCopy { .. } => (
                "changeMasterCopy",
                ISafe::changeMasterCopyCall::SIGNATURE,
                K::SafeAdmin,
            ),
            C::ApproveHash { .. } => (
                "approveHash",
                ISafe::approveHashCall::SIGNATURE,
                K::NestedSafe,
            ),
            C::ExecTransaction { .. } => (
                "execTransaction",
                ISafe::execTransactionCall::SIGNATURE,
                K::NestedSafe,
            ),
            C::MultiSend { .. } => (
                "multiSend",
                IHelpers::multiSendCall::SIGNATURE,
                K::MultiSend,
            ),
            C::SignMessage { .. } => (
                "signMessage",
                IHelpers::signMessageCall::SIGNATURE,
                K::SignMessage,
            ),
            C::PerformCreate { .. } => (
                "performCreate",
                IHelpers::performCreateCall::SIGNATURE,
                K::CreateCall,
            ),
            C::PerformCreate2 { .. } => (
                "performCreate2",
                IHelpers::performCreate2Call::SIGNATURE,
                K::CreateCall,
            ),
            C::MigrateSingleton => (
                "migrateSingleton",
                IHelpers::migrateSingletonCall::SIGNATURE,
                K::Migration,
            ),
            C::MigrateWithFallbackHandler => (
                "migrateWithFallbackHandler",
                IHelpers::migrateWithFallbackHandlerCall::SIGNATURE,
                K::Migration,
            ),
            C::MigrateL2Singleton => (
                "migrateL2Singleton",
                IHelpers::migrateL2SingletonCall::SIGNATURE,
                K::Migration,
            ),
            C::MigrateL2WithFallbackHandler => (
                "migrateL2WithFallbackHandler",
                IHelpers::migrateL2WithFallbackHandlerCall::SIGNATURE,
                K::Migration,
            ),
            C::MigrateToL2 { .. } => (
                "migrateToL2",
                IHelpers::migrateToL2Call::SIGNATURE,
                K::Migration,
            ),
            C::MigrateFromV111 { .. } => (
                "migrateFromV111",
                IHelpers::migrateFromV111Call::SIGNATURE,
                K::Migration,
            ),
            C::SetupToL2 { .. } => (
                "setupToL2",
                IHelpers::setupToL2Call::SIGNATURE,
                K::Migration,
            ),
        }
    }

    /// Arguments as `(name, value)` pairs, in signature order.
    pub fn args(&self) -> Vec<(&'static str, ArgValue)> {
        use ArgValue::{Address as A, Bool, Bytes as By, Bytes32, Uint as U, Uints};
        use KnownCall as C;
        match self {
            C::Transfer { to, amount } => vec![("to", A(*to)), ("amount", U(*amount))],
            C::TransferFrom { from, to, amount } => {
                vec![("from", A(*from)), ("to", A(*to)), ("amount", U(*amount))]
            }
            C::Approve { spender, amount } => {
                vec![("spender", A(*spender)), ("amount", U(*amount))]
            }
            C::IncreaseAllowance { spender, added } => {
                vec![("spender", A(*spender)), ("addedValue", U(*added))]
            }
            C::SafeTransferFrom721 { from, to, token_id } => {
                vec![
                    ("from", A(*from)),
                    ("to", A(*to)),
                    ("tokenId", U(*token_id)),
                ]
            }
            C::SafeTransferFrom721WithData {
                from,
                to,
                token_id,
                data,
            } => vec![
                ("from", A(*from)),
                ("to", A(*to)),
                ("tokenId", U(*token_id)),
                ("data", By(data.clone())),
            ],
            C::SetApprovalForAll { operator, approved } => {
                vec![("operator", A(*operator)), ("approved", Bool(*approved))]
            }
            C::SafeTransferFrom1155 {
                from,
                to,
                id,
                amount,
                data,
            } => vec![
                ("from", A(*from)),
                ("to", A(*to)),
                ("id", U(*id)),
                ("amount", U(*amount)),
                ("data", By(data.clone())),
            ],
            C::SafeBatchTransferFrom1155 {
                from,
                to,
                ids,
                amounts,
                data,
            } => vec![
                ("from", A(*from)),
                ("to", A(*to)),
                ("ids", Uints(ids.clone())),
                ("amounts", Uints(amounts.clone())),
                ("data", By(data.clone())),
            ],
            C::AddOwnerWithThreshold { owner, threshold } => {
                vec![("owner", A(*owner)), ("_threshold", U(*threshold))]
            }
            C::RemoveOwner {
                prev_owner,
                owner,
                threshold,
            } => vec![
                ("prevOwner", A(*prev_owner)),
                ("owner", A(*owner)),
                ("_threshold", U(*threshold)),
            ],
            C::SwapOwner {
                prev_owner,
                old_owner,
                new_owner,
            } => vec![
                ("prevOwner", A(*prev_owner)),
                ("oldOwner", A(*old_owner)),
                ("newOwner", A(*new_owner)),
            ],
            C::ChangeThreshold { threshold } => vec![("_threshold", U(*threshold))],
            C::EnableModule { module } => vec![("module", A(*module))],
            C::DisableModule {
                prev_module,
                module,
            } => vec![("prevModule", A(*prev_module)), ("module", A(*module))],
            C::SetGuard { guard } => vec![("guard", A(*guard))],
            C::SetModuleGuard { guard } => vec![("moduleGuard", A(*guard))],
            C::SetFallbackHandler { handler } => vec![("handler", A(*handler))],
            C::ChangeMasterCopy { master_copy } => vec![("_masterCopy", A(*master_copy))],
            C::ApproveHash { hash } => vec![("hashToApprove", Bytes32(*hash))],
            C::ExecTransaction {
                to,
                value,
                data,
                operation,
                safe_tx_gas,
                base_gas,
                gas_price,
                gas_token,
                refund_receiver,
                signatures,
            } => vec![
                ("to", A(*to)),
                ("value", U(*value)),
                ("data", By(data.clone())),
                ("operation", U(U256::from(*operation))),
                ("safeTxGas", U(*safe_tx_gas)),
                ("baseGas", U(*base_gas)),
                ("gasPrice", U(*gas_price)),
                ("gasToken", A(*gas_token)),
                ("refundReceiver", A(*refund_receiver)),
                ("signatures", By(signatures.clone())),
            ],
            C::MultiSend { transactions } => vec![("transactions", By(transactions.clone()))],
            C::SignMessage { message } => vec![("_data", By(message.clone()))],
            C::PerformCreate {
                value,
                deployment_data,
            } => vec![
                ("value", U(*value)),
                ("deploymentData", By(deployment_data.clone())),
            ],
            C::PerformCreate2 {
                value,
                deployment_data,
                salt,
            } => vec![
                ("value", U(*value)),
                ("deploymentData", By(deployment_data.clone())),
                ("salt", Bytes32(*salt)),
            ],
            C::MigrateSingleton
            | C::MigrateWithFallbackHandler
            | C::MigrateL2Singleton
            | C::MigrateL2WithFallbackHandler => vec![],
            C::MigrateToL2 { l2_singleton } | C::SetupToL2 { l2_singleton } => {
                vec![("l2Singleton", A(*l2_singleton))]
            }
            C::MigrateFromV111 {
                l2_singleton,
                fallback_handler,
            } => vec![
                ("l2Singleton", A(*l2_singleton)),
                ("fallbackHandler", A(*fallback_handler)),
            ],
        }
    }
}

/// Decodes `data` as call `C`, validating the encoding as Solidity would
/// (no dirty high bytes in addresses, `bool`s or `uint8`s).
fn decode<C: SolCall>(data: &[u8]) -> Result<C, String> {
    C::abi_decode_validate(data).map_err(|e| e.to_string())
}

/// Decodes calldata whose selector is a known function.
///
/// Returns `None` if the selector is not known (or `data` is shorter than a
/// selector), `Some(Err(reason))` if it is known but the arguments do not
/// decode.
#[allow(clippy::too_many_lines)] // One arm per function; splitting it would hide the table.
pub fn decode_known(data: &[u8]) -> Option<Result<KnownCall, String>> {
    use KnownCall as K;
    let selector: [u8; 4] = data.get(..4)?.try_into().ok()?;
    let s = selector;
    let result = if s == IERC20::transferCall::SELECTOR {
        decode::<IERC20::transferCall>(data).map(|c| K::Transfer {
            to: c.to,
            amount: c.amount,
        })
    } else if s == IERC20::transferFromCall::SELECTOR {
        decode::<IERC20::transferFromCall>(data).map(|c| K::TransferFrom {
            from: c.from,
            to: c.to,
            amount: c.amount,
        })
    } else if s == IERC20::approveCall::SELECTOR {
        decode::<IERC20::approveCall>(data).map(|c| K::Approve {
            spender: c.spender,
            amount: c.amount,
        })
    } else if s == IERC20::increaseAllowanceCall::SELECTOR {
        decode::<IERC20::increaseAllowanceCall>(data).map(|c| K::IncreaseAllowance {
            spender: c.spender,
            added: c.addedValue,
        })
    } else if s == IERC721::safeTransferFrom_0Call::SELECTOR {
        decode::<IERC721::safeTransferFrom_0Call>(data).map(|c| K::SafeTransferFrom721 {
            from: c.from,
            to: c.to,
            token_id: c.tokenId,
        })
    } else if s == IERC721::safeTransferFrom_1Call::SELECTOR {
        decode::<IERC721::safeTransferFrom_1Call>(data).map(|c| K::SafeTransferFrom721WithData {
            from: c.from,
            to: c.to,
            token_id: c.tokenId,
            data: c.data,
        })
    } else if s == IERC721::setApprovalForAllCall::SELECTOR {
        decode::<IERC721::setApprovalForAllCall>(data).map(|c| K::SetApprovalForAll {
            operator: c.operator,
            approved: c.approved,
        })
    } else if s == IERC1155::safeTransferFromCall::SELECTOR {
        decode::<IERC1155::safeTransferFromCall>(data).map(|c| K::SafeTransferFrom1155 {
            from: c.from,
            to: c.to,
            id: c.id,
            amount: c.amount,
            data: c.data,
        })
    } else if s == IERC1155::safeBatchTransferFromCall::SELECTOR {
        decode::<IERC1155::safeBatchTransferFromCall>(data).map(|c| K::SafeBatchTransferFrom1155 {
            from: c.from,
            to: c.to,
            ids: c.ids,
            amounts: c.amounts,
            data: c.data,
        })
    } else if s == ISafe::addOwnerWithThresholdCall::SELECTOR {
        decode::<ISafe::addOwnerWithThresholdCall>(data).map(|c| K::AddOwnerWithThreshold {
            owner: c.owner,
            threshold: c._threshold,
        })
    } else if s == ISafe::removeOwnerCall::SELECTOR {
        decode::<ISafe::removeOwnerCall>(data).map(|c| K::RemoveOwner {
            prev_owner: c.prevOwner,
            owner: c.owner,
            threshold: c._threshold,
        })
    } else if s == ISafe::swapOwnerCall::SELECTOR {
        decode::<ISafe::swapOwnerCall>(data).map(|c| K::SwapOwner {
            prev_owner: c.prevOwner,
            old_owner: c.oldOwner,
            new_owner: c.newOwner,
        })
    } else if s == ISafe::changeThresholdCall::SELECTOR {
        decode::<ISafe::changeThresholdCall>(data).map(|c| K::ChangeThreshold {
            threshold: c._threshold,
        })
    } else if s == ISafe::enableModuleCall::SELECTOR {
        decode::<ISafe::enableModuleCall>(data).map(|c| K::EnableModule { module: c.module })
    } else if s == ISafe::disableModuleCall::SELECTOR {
        decode::<ISafe::disableModuleCall>(data).map(|c| K::DisableModule {
            prev_module: c.prevModule,
            module: c.module,
        })
    } else if s == ISafe::setGuardCall::SELECTOR {
        decode::<ISafe::setGuardCall>(data).map(|c| K::SetGuard { guard: c.guard })
    } else if s == ISafe::setModuleGuardCall::SELECTOR {
        decode::<ISafe::setModuleGuardCall>(data).map(|c| K::SetModuleGuard {
            guard: c.moduleGuard,
        })
    } else if s == ISafe::setFallbackHandlerCall::SELECTOR {
        decode::<ISafe::setFallbackHandlerCall>(data)
            .map(|c| K::SetFallbackHandler { handler: c.handler })
    } else if s == ISafe::changeMasterCopyCall::SELECTOR {
        decode::<ISafe::changeMasterCopyCall>(data).map(|c| K::ChangeMasterCopy {
            master_copy: c._masterCopy,
        })
    } else if s == ISafe::approveHashCall::SELECTOR {
        decode::<ISafe::approveHashCall>(data).map(|c| K::ApproveHash {
            hash: c.hashToApprove,
        })
    } else if s == ISafe::execTransactionCall::SELECTOR {
        decode::<ISafe::execTransactionCall>(data).map(|c| K::ExecTransaction {
            to: c.to,
            value: c.value,
            data: c.data,
            operation: c.operation,
            safe_tx_gas: c.safeTxGas,
            base_gas: c.baseGas,
            gas_price: c.gasPrice,
            gas_token: c.gasToken,
            refund_receiver: c.refundReceiver,
            signatures: c.signatures,
        })
    } else if s == IHelpers::multiSendCall::SELECTOR {
        decode::<IHelpers::multiSendCall>(data).map(|c| K::MultiSend {
            transactions: c.transactions,
        })
    } else if s == IHelpers::signMessageCall::SELECTOR {
        decode::<IHelpers::signMessageCall>(data).map(|c| K::SignMessage { message: c._data })
    } else if s == IHelpers::performCreateCall::SELECTOR {
        decode::<IHelpers::performCreateCall>(data).map(|c| K::PerformCreate {
            value: c.value,
            deployment_data: c.deploymentData,
        })
    } else if s == IHelpers::performCreate2Call::SELECTOR {
        decode::<IHelpers::performCreate2Call>(data).map(|c| K::PerformCreate2 {
            value: c.value,
            deployment_data: c.deploymentData,
            salt: c.salt,
        })
    } else if s == IHelpers::migrateSingletonCall::SELECTOR {
        decode::<IHelpers::migrateSingletonCall>(data).map(|_| K::MigrateSingleton)
    } else if s == IHelpers::migrateWithFallbackHandlerCall::SELECTOR {
        decode::<IHelpers::migrateWithFallbackHandlerCall>(data)
            .map(|_| K::MigrateWithFallbackHandler)
    } else if s == IHelpers::migrateL2SingletonCall::SELECTOR {
        decode::<IHelpers::migrateL2SingletonCall>(data).map(|_| K::MigrateL2Singleton)
    } else if s == IHelpers::migrateL2WithFallbackHandlerCall::SELECTOR {
        decode::<IHelpers::migrateL2WithFallbackHandlerCall>(data)
            .map(|_| K::MigrateL2WithFallbackHandler)
    } else if s == IHelpers::migrateToL2Call::SELECTOR {
        decode::<IHelpers::migrateToL2Call>(data).map(|c| K::MigrateToL2 {
            l2_singleton: c.l2Singleton,
        })
    } else if s == IHelpers::migrateFromV111Call::SELECTOR {
        decode::<IHelpers::migrateFromV111Call>(data).map(|c| K::MigrateFromV111 {
            l2_singleton: c.l2Singleton,
            fallback_handler: c.fallbackHandler,
        })
    } else if s == IHelpers::setupToL2Call::SELECTOR {
        decode::<IHelpers::setupToL2Call>(data).map(|c| K::SetupToL2 {
            l2_singleton: c.l2Singleton,
        })
    } else {
        return None;
    };
    Some(result)
}

#[cfg(test)]
mod tests {
    use alloy_primitives::keccak256;

    use super::*;

    /// Every signature blindsight knows, with its selector. Signatures were
    /// checked against their primary sources (EIP-20, EIP-721, EIP-1155,
    /// `OpenZeppelin` `ERC20.sol` v4.9.6 for `increaseAllowance`, and the Safe
    /// contract sources); selectors were computed with `pycryptodome`'s keccak,
    /// an implementation independent of the one under test, and agree with
    /// `docs/research.md`.
    const TABLE: &[(&str, [u8; 4])] = &[
        ("transfer(address,uint256)", [0xa9, 0x05, 0x9c, 0xbb]),
        (
            "transferFrom(address,address,uint256)",
            [0x23, 0xb8, 0x72, 0xdd],
        ),
        ("approve(address,uint256)", [0x09, 0x5e, 0xa7, 0xb3]),
        (
            "increaseAllowance(address,uint256)",
            [0x39, 0x50, 0x93, 0x51],
        ),
        (
            "safeTransferFrom(address,address,uint256)",
            [0x42, 0x84, 0x2e, 0x0e],
        ),
        (
            "safeTransferFrom(address,address,uint256,bytes)",
            [0xb8, 0x8d, 0x4f, 0xde],
        ),
        ("setApprovalForAll(address,bool)", [0xa2, 0x2c, 0xb4, 0x65]),
        (
            "safeTransferFrom(address,address,uint256,uint256,bytes)",
            [0xf2, 0x42, 0x43, 0x2a],
        ),
        (
            "safeBatchTransferFrom(address,address,uint256[],uint256[],bytes)",
            [0x2e, 0xb2, 0xc2, 0xd6],
        ),
        (
            "addOwnerWithThreshold(address,uint256)",
            [0x0d, 0x58, 0x2f, 0x13],
        ),
        (
            "removeOwner(address,address,uint256)",
            [0xf8, 0xdc, 0x5d, 0xd9],
        ),
        (
            "swapOwner(address,address,address)",
            [0xe3, 0x18, 0xb5, 0x2b],
        ),
        ("changeThreshold(uint256)", [0x69, 0x4e, 0x80, 0xc3]),
        ("enableModule(address)", [0x61, 0x0b, 0x59, 0x25]),
        ("disableModule(address,address)", [0xe0, 0x09, 0xcf, 0xde]),
        ("setGuard(address)", [0xe1, 0x9a, 0x9d, 0xd9]),
        ("setModuleGuard(address)", [0xe0, 0x68, 0xdf, 0x37]),
        ("setFallbackHandler(address)", [0xf0, 0x8a, 0x03, 0x23]),
        ("changeMasterCopy(address)", [0x7d, 0xe7, 0xed, 0xef]),
        ("approveHash(bytes32)", [0xd4, 0xd9, 0xbd, 0xcd]),
        (
            "execTransaction(address,uint256,bytes,uint8,uint256,uint256,uint256,address,address,bytes)",
            [0x6a, 0x76, 0x12, 0x02],
        ),
        ("multiSend(bytes)", [0x8d, 0x80, 0xff, 0x0a]),
        ("signMessage(bytes)", [0x85, 0xa5, 0xaf, 0xfe]),
        ("performCreate(uint256,bytes)", [0x4c, 0x8c, 0x9e, 0xa1]),
        (
            "performCreate2(uint256,bytes,bytes32)",
            [0x48, 0x47, 0xbe, 0x6f],
        ),
        ("migrateSingleton()", [0xf6, 0x68, 0x2a, 0xb0]),
        ("migrateWithFallbackHandler()", [0xed, 0x00, 0x7f, 0xc6]),
        ("migrateL2Singleton()", [0x07, 0xf4, 0x64, 0xa4]),
        ("migrateL2WithFallbackHandler()", [0x68, 0xcb, 0x3d, 0x94]),
        ("migrateToL2(address)", [0xef, 0x26, 0x24, 0xae]),
        ("migrateFromV111(address,address)", [0xd9, 0xa2, 0x08, 0x12]),
        ("setupToL2(address)", [0xfe, 0x51, 0xf6, 0x43]),
    ];

    #[test]
    fn selectors_match_the_research_table() {
        for (signature, selector) in TABLE {
            assert_eq!(&keccak256(signature)[..4], selector, "{signature}");
        }
    }

    #[test]
    fn every_known_function_is_in_the_table_and_selectors_are_unique() {
        let all = all_samples();
        assert_eq!(all.len(), TABLE.len());
        let mut selectors: Vec<[u8; 4]> = Vec::new();
        for call in &all {
            let selector: [u8; 4] = keccak256(call.signature())[..4].try_into().unwrap();
            assert!(
                TABLE
                    .iter()
                    .any(|(sig, sel)| *sig == call.signature() && *sel == selector),
                "{} not in TABLE",
                call.signature()
            );
            assert!(
                !selectors.contains(&selector),
                "duplicate {}",
                call.signature()
            );
            selectors.push(selector);
        }
    }

    /// One instance of every variant, encoded with `sol!` and decoded back.
    fn all_samples() -> Vec<KnownCall> {
        let a = Address::repeat_byte(0xa1);
        let b = Address::repeat_byte(0xb2);
        let c = Address::repeat_byte(0xc3);
        let n = U256::from(7u64);
        let bytes = Bytes::from(vec![1, 2, 3]);
        let h = B256::repeat_byte(0x44);
        use KnownCall as K;
        vec![
            K::Transfer { to: a, amount: n },
            K::TransferFrom {
                from: a,
                to: b,
                amount: n,
            },
            K::Approve {
                spender: a,
                amount: n,
            },
            K::IncreaseAllowance {
                spender: a,
                added: n,
            },
            K::SafeTransferFrom721 {
                from: a,
                to: b,
                token_id: n,
            },
            K::SafeTransferFrom721WithData {
                from: a,
                to: b,
                token_id: n,
                data: bytes.clone(),
            },
            K::SetApprovalForAll {
                operator: a,
                approved: true,
            },
            K::SafeTransferFrom1155 {
                from: a,
                to: b,
                id: n,
                amount: n,
                data: bytes.clone(),
            },
            K::SafeBatchTransferFrom1155 {
                from: a,
                to: b,
                ids: vec![n, n],
                amounts: vec![n, U256::ZERO],
                data: bytes.clone(),
            },
            K::AddOwnerWithThreshold {
                owner: a,
                threshold: n,
            },
            K::RemoveOwner {
                prev_owner: a,
                owner: b,
                threshold: n,
            },
            K::SwapOwner {
                prev_owner: a,
                old_owner: b,
                new_owner: c,
            },
            K::ChangeThreshold { threshold: n },
            K::EnableModule { module: a },
            K::DisableModule {
                prev_module: a,
                module: b,
            },
            K::SetGuard { guard: a },
            K::SetModuleGuard { guard: a },
            K::SetFallbackHandler { handler: a },
            K::ChangeMasterCopy { master_copy: a },
            K::ApproveHash { hash: h },
            K::ExecTransaction {
                to: a,
                value: n,
                data: bytes.clone(),
                operation: 1,
                safe_tx_gas: n,
                base_gas: n,
                gas_price: n,
                gas_token: b,
                refund_receiver: c,
                signatures: bytes.clone(),
            },
            K::MultiSend {
                transactions: bytes.clone(),
            },
            K::SignMessage {
                message: bytes.clone(),
            },
            K::PerformCreate {
                value: n,
                deployment_data: bytes.clone(),
            },
            K::PerformCreate2 {
                value: n,
                deployment_data: bytes.clone(),
                salt: h,
            },
            K::MigrateSingleton,
            K::MigrateWithFallbackHandler,
            K::MigrateL2Singleton,
            K::MigrateL2WithFallbackHandler,
            K::MigrateToL2 { l2_singleton: a },
            K::MigrateFromV111 {
                l2_singleton: a,
                fallback_handler: b,
            },
            K::SetupToL2 { l2_singleton: a },
        ]
    }

    /// ABI-encodes a sample with its own `sol!` type.
    fn encode(call: &KnownCall) -> Vec<u8> {
        use KnownCall as K;
        match call.clone() {
            K::Transfer { to, amount } => IERC20::transferCall { to, amount }.abi_encode(),
            K::TransferFrom { from, to, amount } => {
                IERC20::transferFromCall { from, to, amount }.abi_encode()
            }
            K::Approve { spender, amount } => IERC20::approveCall { spender, amount }.abi_encode(),
            K::IncreaseAllowance { spender, added } => IERC20::increaseAllowanceCall {
                spender,
                addedValue: added,
            }
            .abi_encode(),
            K::SafeTransferFrom721 { from, to, token_id } => IERC721::safeTransferFrom_0Call {
                from,
                to,
                tokenId: token_id,
            }
            .abi_encode(),
            K::SafeTransferFrom721WithData {
                from,
                to,
                token_id,
                data,
            } => IERC721::safeTransferFrom_1Call {
                from,
                to,
                tokenId: token_id,
                data,
            }
            .abi_encode(),
            K::SetApprovalForAll { operator, approved } => {
                IERC721::setApprovalForAllCall { operator, approved }.abi_encode()
            }
            K::SafeTransferFrom1155 {
                from,
                to,
                id,
                amount,
                data,
            } => IERC1155::safeTransferFromCall {
                from,
                to,
                id,
                amount,
                data,
            }
            .abi_encode(),
            K::SafeBatchTransferFrom1155 {
                from,
                to,
                ids,
                amounts,
                data,
            } => IERC1155::safeBatchTransferFromCall {
                from,
                to,
                ids,
                amounts,
                data,
            }
            .abi_encode(),
            K::AddOwnerWithThreshold { owner, threshold } => ISafe::addOwnerWithThresholdCall {
                owner,
                _threshold: threshold,
            }
            .abi_encode(),
            K::RemoveOwner {
                prev_owner,
                owner,
                threshold,
            } => ISafe::removeOwnerCall {
                prevOwner: prev_owner,
                owner,
                _threshold: threshold,
            }
            .abi_encode(),
            K::SwapOwner {
                prev_owner,
                old_owner,
                new_owner,
            } => ISafe::swapOwnerCall {
                prevOwner: prev_owner,
                oldOwner: old_owner,
                newOwner: new_owner,
            }
            .abi_encode(),
            K::ChangeThreshold { threshold } => ISafe::changeThresholdCall {
                _threshold: threshold,
            }
            .abi_encode(),
            K::EnableModule { module } => ISafe::enableModuleCall { module }.abi_encode(),
            K::DisableModule {
                prev_module,
                module,
            } => ISafe::disableModuleCall {
                prevModule: prev_module,
                module,
            }
            .abi_encode(),
            K::SetGuard { guard } => ISafe::setGuardCall { guard }.abi_encode(),
            K::SetModuleGuard { guard } => {
                ISafe::setModuleGuardCall { moduleGuard: guard }.abi_encode()
            }
            K::SetFallbackHandler { handler } => {
                ISafe::setFallbackHandlerCall { handler }.abi_encode()
            }
            K::ChangeMasterCopy { master_copy } => ISafe::changeMasterCopyCall {
                _masterCopy: master_copy,
            }
            .abi_encode(),
            K::ApproveHash { hash } => ISafe::approveHashCall {
                hashToApprove: hash,
            }
            .abi_encode(),
            K::ExecTransaction {
                to,
                value,
                data,
                operation,
                safe_tx_gas,
                base_gas,
                gas_price,
                gas_token,
                refund_receiver,
                signatures,
            } => ISafe::execTransactionCall {
                to,
                value,
                data,
                operation,
                safeTxGas: safe_tx_gas,
                baseGas: base_gas,
                gasPrice: gas_price,
                gasToken: gas_token,
                refundReceiver: refund_receiver,
                signatures,
            }
            .abi_encode(),
            K::MultiSend { transactions } => IHelpers::multiSendCall { transactions }.abi_encode(),
            K::SignMessage { message } => IHelpers::signMessageCall { _data: message }.abi_encode(),
            K::PerformCreate {
                value,
                deployment_data,
            } => IHelpers::performCreateCall {
                value,
                deploymentData: deployment_data,
            }
            .abi_encode(),
            K::PerformCreate2 {
                value,
                deployment_data,
                salt,
            } => IHelpers::performCreate2Call {
                value,
                deploymentData: deployment_data,
                salt,
            }
            .abi_encode(),
            K::MigrateSingleton => IHelpers::migrateSingletonCall {}.abi_encode(),
            K::MigrateWithFallbackHandler => {
                IHelpers::migrateWithFallbackHandlerCall {}.abi_encode()
            }
            K::MigrateL2Singleton => IHelpers::migrateL2SingletonCall {}.abi_encode(),
            K::MigrateL2WithFallbackHandler => {
                IHelpers::migrateL2WithFallbackHandlerCall {}.abi_encode()
            }
            K::MigrateToL2 { l2_singleton } => IHelpers::migrateToL2Call {
                l2Singleton: l2_singleton,
            }
            .abi_encode(),
            K::MigrateFromV111 {
                l2_singleton,
                fallback_handler,
            } => IHelpers::migrateFromV111Call {
                l2Singleton: l2_singleton,
                fallbackHandler: fallback_handler,
            }
            .abi_encode(),
            K::SetupToL2 { l2_singleton } => IHelpers::setupToL2Call {
                l2Singleton: l2_singleton,
            }
            .abi_encode(),
        }
    }

    #[test]
    fn every_variant_round_trips() {
        for call in all_samples() {
            let encoded = encode(&call);
            assert_eq!(
                decode_known(&encoded),
                Some(Ok(call.clone())),
                "{}",
                call.signature()
            );
            // The argument list has one entry per signature parameter.
            let params = call.signature().matches(',').count()
                + usize::from(!call.signature().ends_with("()"));
            assert_eq!(call.args().len(), params, "{}", call.signature());
        }
    }

    #[test]
    fn unknown_and_short_selectors() {
        assert_eq!(decode_known(&[]), None);
        assert_eq!(decode_known(&[0xa9, 0x05, 0x9c]), None);
        assert_eq!(decode_known(&[0x80, 0x4e, 0x1f, 0x0a]), None); // WazirX payload selector
    }

    #[test]
    fn known_selector_with_bad_arguments_is_an_error() {
        // transfer selector with a truncated argument.
        assert!(matches!(
            decode_known(&[0xa9, 0x05, 0x9c, 0xbb, 0, 0]),
            Some(Err(_))
        ));
        // setApprovalForAll with a dirty bool (2).
        let mut data = IERC721::setApprovalForAllCall {
            operator: Address::ZERO,
            approved: true,
        }
        .abi_encode();
        let last = data.len() - 1;
        data[last] = 2;
        assert!(matches!(decode_known(&data), Some(Err(_))));
    }
}
