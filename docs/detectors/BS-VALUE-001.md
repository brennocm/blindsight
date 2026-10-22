# BS-VALUE-001: Native value transfer

**Severity:** info; high with delegatecall

## What it detects

Any call with `value > 0`: info, with the amount in the chain's native currency. With `operation = 1`: high.

## Why it matters

Value transfers are what most transactions do, so they are shown but not flagged. A delegatecall, however, transfers no value: the Safe's `Executor.sol` ignores it. A non-zero value on a delegatecall means the transaction was built by hand.

## Example

`bybit-legit-nonce70` fixture: 60,000 ETH sent to the warm wallet (info).

## Related incidents

None recorded.

## Known false positives and limits

None known for the high case.
