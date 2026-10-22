# BS-DELEGATE-001: Delegatecall to an untrusted contract

**Severity:** critical

## What it detects

Any call in the tree (root, batch entry or nested transaction) with `operation = 1` whose target is not an official Safe helper on this chain: `MultiSend`, `MultiSendCallOnly`, `SignMessageLib`, `CreateCall`, `SafeMigration`, `SafeToL2Migration` or `SafeToL2Setup`, of any released version, from `data/safe_deployments.json`.

## Why it matters

A delegatecall runs the target's code with the Safe's storage. That code can rewrite owners, threshold, modules, guard, fallback handler and storage slot 0, which holds the address of the implementation. Once slot 0 points to attacker code, no signature is needed any more. There is no safe unknown delegatecall target.

## Example

`to = 0x96221423681A6d52E184D440a8eFCEbB105C7242`, `operation = 1`, data shaped like `transfer(address,uint256)` (the Bybit transaction, `tests/fixtures/real/bybit.json`).

## Related incidents

Bybit (February 2025) and WazirX (July 2024): both Safes delegatecalled an attacker contract that replaced slot 0. See `docs/incidents.md`.

## Known false positives and limits

Libraries meant for delegatecall that are not Safe-official (Zodiac, protocol-specific helpers). There is no override in v1: verify the target's source and deployment, and why it needs delegatecall.
