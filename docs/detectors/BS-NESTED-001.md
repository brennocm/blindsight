# BS-NESTED-001: Nested Safe transaction or opaque hash approval

**Severity:** info (nested), high (approveHash, too deep)

## What it detects

`execTransaction` addressed to another Safe: info, and the inner transaction is decoded and analysed by every detector. `approveHash(h)`: high. Calls deeper than 4 batch or nested levels: high (not analysed).

## Why it matters

When a Safe owns another Safe, its owners approve a hash of the inner transaction. The hash reveals nothing; it must be recomputed from the inner transaction (`blindsight hash` with the inner Safe's address, chain, version and nonce). Deep nesting is a way to push a payload past a tool's analysis.

## Example

`approveHash(0x…)` sent to another Safe.

## Related incidents

None recorded.

## Known false positives and limits

Legitimate Safe-owned-by-Safe setups (high for `approveHash` until the inner transaction is checked).
