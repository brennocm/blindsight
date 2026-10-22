# BS-REPLAY-001: Domain without chain id (pre-1.3.0)

**Severity:** low

## What it detects

The executing Safe is older than 1.3.0.

## Why it matters

Before 1.3.0 the EIP-712 domain is only `verifyingContract`: the same signature is valid on every chain where a Safe exists at the same address with the same nonce (`docs/research.md` §1.2).

## Example

`bybit` fixture (Safe 1.1.1).

## Related incidents

None recorded for Safes; cross-chain replay is a known risk for any signature without chain id.

## Known false positives and limits

Safes that exist on one chain only.
