//! Decoding a Safe transaction into a tree of calls.
//!
//! The root is the Safe transaction itself. A `multiSend` becomes a batch
//! node with one child per entry; an `execTransaction` addressed to another
//! Safe becomes a nested node whose child is the inner transaction. Every
//! node records who executes it and whether its decoded meaning is verified
//! ([`Semantics`]). Detectors and reports walk this tree, so a dangerous
//! call is found at any depth, not only at the top.

pub mod functions;
pub mod multisend;
pub mod semantics;

use std::fmt;

use alloy_primitives::{Address, Bytes, U256};

pub use functions::{ArgValue, FunctionKind, KnownCall, decode_known};
pub use semantics::{Semantics, Verification};

use crate::registry::{self, RegistryError, SafeContracts, TokenList};
use crate::safe::{Operation, SafeAccount, SafeTx};

/// Deepest level decoded. The root is level 0; each batch or nested Safe
/// transaction adds one. Calls below this level are reported as
/// [`DecodedCall::TooDeep`] instead of being analysed.
pub const MAX_DEPTH: usize = 4;

/// One step from a node to a child.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Step {
    /// Entry `n` (0-based) of a `multiSend` batch.
    Batch(usize),
    /// The inner transaction of a nested `execTransaction`.
    Nested,
}

/// Where a node is in the tree, e.g. `batch[2] > nested > batch[0]`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CallPath(pub Vec<Step>);

impl CallPath {
    /// The path of a child reached through `step`.
    pub fn child(&self, step: Step) -> CallPath {
        let mut steps = self.0.clone();
        steps.push(step);
        CallPath(steps)
    }

    /// Nesting level (0 for the root).
    pub fn depth(&self) -> usize {
        self.0.len()
    }

    /// Whether this is the root transaction.
    pub fn is_root(&self) -> bool {
        self.0.is_empty()
    }
}

impl fmt::Display for CallPath {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.0.is_empty() {
            return f.write_str("root");
        }
        for (i, step) in self.0.iter().enumerate() {
            if i > 0 {
                f.write_str(" > ")?;
            }
            match step {
                Step::Batch(n) => write!(f, "batch[{n}]")?,
                Step::Nested => f.write_str("nested")?,
            }
        }
        Ok(())
    }
}

/// One call in the tree.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CallNode {
    /// Position in the tree.
    pub path: CallPath,
    /// Address whose context the call runs from (`msg.sender` for a call):
    /// the Safe, another Safe for nested transactions, or a batch contract
    /// called without delegatecall.
    pub executor: Address,
    /// Target.
    pub to: Address,
    /// Native value.
    pub value: U256,
    /// Call or delegatecall.
    pub operation: Operation,
    /// Raw calldata.
    pub data: Bytes,
    /// What the calldata decodes to.
    pub decoded: DecodedCall,
}

/// The decoded content of a call.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DecodedCall {
    /// No calldata: a plain transfer of native value (or an empty call).
    Empty,
    /// A known function.
    Known {
        /// The function and its arguments.
        call: KnownCall,
        /// Whether the target is known to implement it.
        semantics: Semantics,
    },
    /// A `multiSend` batch.
    Batch {
        /// Whether the target is an official `MultiSend` contract.
        semantics: Semantics,
        /// The target is the official `MultiSendCallOnly`, which reverts on
        /// delegatecall entries.
        call_only: bool,
        /// One node per entry.
        items: Vec<CallNode>,
    },
    /// An `execTransaction` addressed to another Safe.
    Nested {
        /// The outer call (`execTransaction` and its fields).
        call: KnownCall,
        /// Always [`Semantics::SelectorOnly`]: whether the target is a Safe
        /// cannot be known offline.
        semantics: Semantics,
        /// The inner transaction, executed by the target Safe.
        inner: Box<CallNode>,
    },
    /// The selector is not a known function.
    Unknown {
        /// The selector, if the data has at least 4 bytes.
        selector: Option<[u8; 4]>,
    },
    /// A known selector whose arguments (or `multiSend` payload) do not
    /// decode. The transaction cannot be shown faithfully.
    Malformed {
        /// Name of the function the selector belongs to, if known.
        function: Option<&'static str>,
        /// Why decoding failed.
        reason: String,
    },
    /// Below [`MAX_DEPTH`]: not analysed.
    TooDeep,
}

impl CallNode {
    /// Every node of the tree, parents before children.
    pub fn nodes(&self) -> Vec<&CallNode> {
        let mut out = vec![self];
        match &self.decoded {
            DecodedCall::Batch { items, .. } => {
                for item in items {
                    out.extend(item.nodes());
                }
            }
            DecodedCall::Nested { inner, .. } => out.extend(inner.nodes()),
            _ => {}
        }
        out
    }

    /// The decoded known call, for `Known` and `Nested` nodes.
    pub fn known_call(&self) -> Option<&KnownCall> {
        match &self.decoded {
            DecodedCall::Known { call, .. } | DecodedCall::Nested { call, .. } => Some(call),
            _ => None,
        }
    }
}

/// Registry tables the decoder consults.
struct Ctx<'a> {
    chain_id: u64,
    contracts: &'a SafeContracts,
    tokens: &'a TokenList,
}

/// Decodes `tx`, executed by `account`, into a call tree.
///
/// # Errors
///
/// Only [`RegistryError`] (corrupt embedded data). Malformed calldata is not
/// an error: it becomes a [`DecodedCall::Malformed`] node.
pub fn decode_tree(account: &SafeAccount, tx: &SafeTx) -> Result<CallNode, RegistryError> {
    let ctx = Ctx {
        chain_id: account.chain_id,
        contracts: registry::safe_contracts()?,
        tokens: registry::tokens()?,
    };
    Ok(decode_node(
        &ctx,
        CallPath::default(),
        account.address,
        tx.to,
        tx.value,
        tx.operation,
        tx.data.clone(),
    ))
}

fn decode_node(
    ctx: &Ctx<'_>,
    path: CallPath,
    executor: Address,
    to: Address,
    value: U256,
    operation: Operation,
    data: Bytes,
) -> CallNode {
    let decoded = if path.depth() > MAX_DEPTH {
        DecodedCall::TooDeep
    } else {
        decode_content(ctx, &path, executor, to, operation, &data)
    };
    CallNode {
        path,
        executor,
        to,
        value,
        operation,
        data,
        decoded,
    }
}

fn decode_content(
    ctx: &Ctx<'_>,
    path: &CallPath,
    executor: Address,
    to: Address,
    operation: Operation,
    data: &[u8],
) -> DecodedCall {
    if data.is_empty() {
        return DecodedCall::Empty;
    }
    let call = match decode_known(data) {
        None => {
            return DecodedCall::Unknown {
                selector: data.get(..4).and_then(|s| s.try_into().ok()),
            };
        }
        Some(Err(reason)) => {
            return DecodedCall::Malformed {
                function: None,
                reason,
            };
        }
        Some(Ok(call)) => call,
    };
    let semantics = semantics::semantics(
        &call,
        to,
        operation,
        executor,
        ctx.chain_id,
        ctx.contracts,
        ctx.tokens,
    );
    match call {
        KnownCall::MultiSend { transactions } => {
            let entries = match multisend::unpack(&transactions) {
                Ok(entries) => entries,
                Err(e) => {
                    return DecodedCall::Malformed {
                        function: Some("multiSend"),
                        reason: e.to_string(),
                    };
                }
            };
            let call_only = matches!(
                &semantics,
                Semantics::Verified(Verification::Official(c)) if c.name == "MultiSendCallOnly"
            );
            // Delegatecalled, the batch runs as the Safe; called, as the
            // batch contract itself.
            let item_executor = match operation {
                Operation::DelegateCall => executor,
                Operation::Call => to,
            };
            let items = entries
                .into_iter()
                .enumerate()
                .map(|(i, e)| {
                    decode_node(
                        ctx,
                        path.child(Step::Batch(i)),
                        item_executor,
                        e.to,
                        e.value,
                        e.operation,
                        e.data,
                    )
                })
                .collect();
            DecodedCall::Batch {
                semantics,
                call_only,
                items,
            }
        }
        KnownCall::ExecTransaction {
            to: inner_to,
            value: inner_value,
            data: ref inner_data,
            operation: inner_op,
            ..
        } => {
            let Ok(inner_operation) = Operation::try_from(inner_op) else {
                return DecodedCall::Malformed {
                    function: Some("execTransaction"),
                    reason: format!("inner operation {inner_op} is not 0 or 1"),
                };
            };
            // The inner transaction runs in the context of the Safe at `to`.
            let inner = decode_node(
                ctx,
                path.child(Step::Nested),
                to,
                inner_to,
                inner_value,
                inner_operation,
                inner_data.clone(),
            );
            DecodedCall::Nested {
                call,
                semantics,
                inner: Box::new(inner),
            }
        }
        call => DecodedCall::Known { call, semantics },
    }
}

#[cfg(test)]
mod tests;
