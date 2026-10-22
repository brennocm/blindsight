# BS-NESTED-001: Nested Safe transaction or opaque approval

**Severity:** info (nested), medium (signMessage), high (approveHash), critical (too deep)

## What it detects

`execTransaction` addressed to another Safe: info, and the inner transaction is decoded and analysed by every detector. `signMessage(m)` delegatecalled to the official `SignMessageLib`: medium (the Safe will confirm the message as signed, EIP-1271). `approveHash(h)`: high. Calls deeper than 4 batch or nested levels: **critical**, because they were not analysed and could hide a takeover.

## Why it matters

When a Safe owns another Safe, its owners approve a hash of the inner transaction. The hash reveals nothing; it must be recomputed from the inner transaction (`blindsight hash` with the inner Safe's address, chain, version and nonce). A message signed through `SignMessageLib` is honoured by every contract that checks the Safe's signature, so a permit or order hidden in it can move funds; blindsight shows its size and hash but does not interpret it. Deep nesting is a way to push a payload past a tool's analysis, so it is treated as the worst case. These two rules were added after the project's final security review.

## Example

`approveHash(0x…)` sent to another Safe.

## Related incidents

None recorded.

## Known false positives and limits

Legitimate Safe-owned-by-Safe setups (high for `approveHash` until the inner transaction is checked); routine message signing (votes, orders) is medium.
