//! `BS-POISON-001`: an address that imitates an address-book entry.

use alloy_primitives::Address;

use super::{Context, Finding, Severity, finding};
use crate::decode::{ArgValue, CallNode, DecodedCall};

/// Detector ID.
pub const ID: &str = "BS-POISON-001";

/// Every address mentioned by a node: target, decoded address arguments,
/// and for the root, the refund fields.
fn addresses(ctx: &Context<'_>, node: &CallNode) -> Vec<Address> {
    let mut out = vec![node.to];
    if let Some(call) = node.known_call() {
        out.extend(call.args().into_iter().filter_map(|(_, v)| match v {
            ArgValue::Address(a) => Some(a),
            _ => None,
        }));
    }
    if let DecodedCall::User { call } = &node.decoded {
        out.extend(
            call.args
                .iter()
                .filter_map(|(_, v)| v.parse::<Address>().ok()),
        );
    }
    if node.path.is_root() {
        out.push(ctx.tx.gas_token);
        out.push(ctx.tx.refund_receiver);
    }
    out.sort();
    out.dedup();
    out
}

pub fn check(ctx: &Context<'_>, node: &CallNode) -> Vec<Finding> {
    let Some(book) = ctx.address_book else {
        return Vec::new();
    };
    let mut findings = Vec::new();
    for address in addresses(ctx, node) {
        for entry in book.lookalikes(address) {
            findings.push(finding(
                ID,
                Severity::High,
                node,
                "Address looks like an address-book entry",
                format!(
                    "{} has the same first and last four hex digits as \"{}\" ({}) but is a different address. Address poisoning relies on people comparing only the start and end. Compare every character.",
                    address.to_checksum(None),
                    entry.name,
                    entry.address.to_checksum(None)
                ),
            ));
        }
    }
    findings
}

#[cfg(test)]
mod tests {
    use crate::detect::testutil::*;

    #[test]
    fn address_poisoning() {
        let (book, _) =
            AddressBook::parse(r#"{"Treasury": "0x1Db92e2EeBC8E0c075a02BeA49a2935BcD2dFCF4"}"#)
                .unwrap();
        let run = Run {
            book: Some(book),
            ..Run::default()
        };
        let fake = addr("0x1db9000000000000000000000000000000dafcf4");
        // As the recipient of a token transfer.
        let t = tx(
            addr(USDC),
            Operation::Call,
            IERC20::transferCall {
                to: fake,
                amount: U256::from(1u64),
            }
            .abi_encode(),
        );
        let f = run.findings(&t);
        assert_eq!(
            with_id(&f, "BS-POISON-001"),
            [(Severity::High, "root".into())]
        );
        // As the refund receiver.
        let mut t = tx(Address::repeat_byte(1), Operation::Call, vec![]);
        t.refund_receiver = fake;
        assert_eq!(
            with_id(&run.findings(&t), "BS-POISON-001"),
            [(Severity::High, "root".into())]
        );
        // The real address: no finding, and no book: no finding.
        let real = tx(
            addr("0x1Db92e2EeBC8E0c075a02BeA49a2935BcD2dFCF4"),
            Operation::Call,
            vec![],
        );
        assert!(with_id(&run.findings(&real), "BS-POISON-001").is_empty());
        assert!(
            with_id(
                &findings(&tx(fake, Operation::Call, vec![])),
                "BS-POISON-001"
            )
            .is_empty()
        );
    }
}
