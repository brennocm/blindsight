# BS-APPROVAL-002: Permit2 allowance (experimental)

**Severity:** high (unlimited), info (bounded)

## What it detects

`approve(token, spender, amount, expiration)` of Uniswap's Permit2 (`AllowanceTransfer`): high when `amount` is `type(uint160).max` (unlimited per `IAllowanceTransfer.sol`), info otherwise. Permit2's address comes from Uniswap's repository and was checked on seven chains (`data/permit2.json`).

## Why it matters

Permit2 allowances are separate from the token's own approvals and easy to forget; they give the spender the same power over tokens already approved to Permit2.

## Example

`approve(USDC, 0x…, 2^160 − 1, …)` sent to Permit2.

## Related incidents

None recorded.

## Known false positives and limits

Experimental: Permit2 signature-based approvals (`permit`) are not decoded yet.
