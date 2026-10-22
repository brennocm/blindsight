//! Shared helpers for the detector tests: synthetic transactions and a
//! runner that decodes them and applies every detector.

// A shared toolbox: each detector's tests use a subset of it.
#![allow(dead_code, unused_imports)]

pub(super) use alloy_primitives::{Address, B256, Bytes, U256};
pub(super) use alloy_sol_types::SolCall;

pub(super) use super::{Context, Finding, Registry, SafeAccount, SafeTx, Severity, run};
pub(super) use crate::addressbook::AddressBook;
pub(super) use crate::decode::functions::{IERC20, IERC721, IHelpers, IPermit2, ISafe};
pub(super) use crate::decode::multisend::{BatchEntry, pack};
pub(super) use crate::decode::{MAX_DEPTH, UserAbis, decode_tree};
pub(super) use crate::safe::{Operation, SafeVersion};

pub(super) const MULTISEND_141: &str = "0x38869bf66a61cF6bDB996A6aE40D5853Fd43B526";
pub(super) const CALL_ONLY_141: &str = "0x9641d764fc13c8B624c04430C7356C1C7C8102e2";
pub(super) const SIGN_MESSAGE_LIB_141: &str = "0xd53cd0aB83D845Ac265BE939c57F53AD838012c9";
pub(super) const USDC: &str = "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48";
pub(super) const FALLBACK_141: &str = "0xfd0732Dc9E303f09fCEf3a7388Ad10A83459Ec99";
pub(super) const SINGLETON_130: &str = "0xd9Db270c1B5E3Bd161E8c8503c55cEABeE709552";
pub(super) const PERMIT2: &str = "0x000000000022D473030F116dDEE9F6B43aC78BA3";

pub(super) fn addr(s: &str) -> Address {
    s.parse().unwrap()
}

pub(super) fn safe() -> Address {
    Address::repeat_byte(0x5a)
}

pub(super) fn account(version: SafeVersion) -> SafeAccount {
    SafeAccount {
        address: safe(),
        chain_id: 1,
        version,
    }
}

pub(super) fn tx(to: Address, operation: Operation, data: Vec<u8>) -> SafeTx {
    SafeTx {
        to,
        value: U256::ZERO,
        data: Bytes::from(data),
        operation,
        safe_tx_gas: U256::ZERO,
        base_gas: U256::ZERO,
        gas_price: U256::ZERO,
        gas_token: Address::ZERO,
        refund_receiver: Address::ZERO,
        nonce: U256::from(10u64),
    }
}

pub(super) struct Run {
    pub(super) version: SafeVersion,
    pub(super) book: Option<AddressBook>,
    pub(super) current_nonce: Option<U256>,
}

impl Default for Run {
    fn default() -> Self {
        Run {
            version: SafeVersion::V1_4_1,
            book: None,
            current_nonce: None,
        }
    }
}

impl Run {
    pub(super) fn findings(&self, tx: &SafeTx) -> Vec<Finding> {
        let account = account(self.version);
        let root = decode_tree(&account, tx, &UserAbis::default()).unwrap();
        let ctx = Context {
            account: &account,
            tx,
            registry: Registry::load().unwrap(),
            address_book: self.book.as_ref(),
            current_nonce: self.current_nonce,
        };
        run(&ctx, &root)
    }
}

pub(super) fn findings(tx: &SafeTx) -> Vec<Finding> {
    Run::default().findings(tx)
}

/// `(id, severity, path)` of every finding with this id.
pub(super) fn with_id(findings: &[Finding], id: &str) -> Vec<(Severity, String)> {
    findings
        .iter()
        .filter(|f| f.id == id)
        .map(|f| (f.severity, f.path.to_string()))
        .collect()
}

pub(super) fn multisend(entries: &[BatchEntry]) -> Vec<u8> {
    IHelpers::multiSendCall {
        transactions: Bytes::from(pack(entries)),
    }
    .abi_encode()
}

pub(super) fn entry(operation: Operation, to: Address, data: Vec<u8>) -> BatchEntry {
    BatchEntry {
        operation,
        to,
        value: U256::ZERO,
        data: Bytes::from(data),
    }
}

pub(super) fn exec(to: Address, operation: u8, data: Vec<u8>) -> Vec<u8> {
    ISafe::execTransactionCall {
        to,
        value: U256::ZERO,
        data: Bytes::from(data),
        operation,
        safeTxGas: U256::ZERO,
        baseGas: U256::ZERO,
        gasPrice: U256::ZERO,
        gasToken: Address::ZERO,
        refundReceiver: Address::ZERO,
        signatures: Bytes::new(),
    }
    .abi_encode()
}

pub(super) fn transfer() -> Vec<u8> {
    IERC20::transferCall {
        to: Address::repeat_byte(1),
        amount: U256::from(5u64),
    }
    .abi_encode()
}

pub(super) fn admin(data: Vec<u8>) -> SafeTx {
    tx(safe(), Operation::Call, data)
}
