# BS-REFUND-001: Gas refund paid by the Safe

**Severity:** high / medium / low

## What it detects

For the root transaction and every nested Safe transaction: `gasPrice > 0` with the native currency is **medium** from 1.3.0 (the price is capped by the submitter's gas price) and **high** before (uncapped) or when the paying Safe's version is unknown; `gasPrice > 0` with a token is **high** (never capped); `gasPrice = 0` but `gasToken`, `refundReceiver` or `baseGas` set is **low** (inert but unusual).

## Why it matters

`handlePayment` pays `(gasUsed + baseGas) × gasPrice` to `refundReceiver`, or to `tx.origin` (whoever submits) when it is zero. The submitter chooses the gas limit and so `gasUsed`. With a token, `gasPrice` is an arbitrary number of token units per gas: `baseGas × gasPrice` alone can be the whole balance. With `safeTxGas` or `gasPrice` non-zero, the inner call may fail and the refund is still paid (`GS013` logic).

## Example

`gas-refund` fixture (native refund on 1.3.0); `v100-swapowner-token-refund` (token refund on 1.0.0).

## Related incidents

None recorded; the interface defaults these fields to zero.

## Known false positives and limits

Relayed transactions that legitimately pay a relayer. The finding shows the guaranteed minimum and the receiver so the amount can be checked.
