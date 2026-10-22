# BS-APPROVAL-001: Unlimited or operator approval

**Severity:** high (unlimited or operator), info (bounded or revoked)

## What it detects

`approve(spender, amount)` or `increaseAllowance(spender, amount)` with `amount ≥ 2^255` (high, covers `type(uint256).max` and other "max-ish" values); smaller amounts are info, with decimals when the token is listed. `setApprovalForAll(operator, true)` is high; `false` is info.

## Why it matters

An unlimited allowance lets the spender take the whole balance, now and later, until revoked. Drainer contracts rely on it.

## Example

`approve(0x…, 2^256 − 1)` on a token.

## Related incidents

Allowance phishing campaigns against individual and multisig wallets.

## Known false positives and limits

Integrations that need standing allowances (DEX routers, vaults). Prefer bounded amounts.
