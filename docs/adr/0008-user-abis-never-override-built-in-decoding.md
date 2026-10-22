# 8. User ABIs never override built-in decoding

Date: 2026-10-22
Status: accepted. Amends [ADR 0006](0006-verified-and-inferred-semantics.md)
on how user ABIs are applied.

## Context

`--abi ADDRESS=FILE` lets users decode calls to their own contracts. As first
implemented, an ABI bound to an address was tried before the built-in
function table. The final security review found the consequence: an ABI file
for a `MultiSend` address (one that arrives "helpfully" with a transaction,
for example) could declare its own `multiSend(bytes)`; the call would then be
shown as an opaque user call, the batch would not be unpacked, and no
detector would see a delegatecall inside it. The same applies to
`execTransaction` and nested Safe transactions.

## Decision

The built-in table always wins. A user ABI is consulted only when the
selector is unknown to blindsight, and only for calls to the address it is
bound to. Its function names never make a target trusted.

## Alternatives

- **User ABI first** (the original behaviour): lets the input that is being
  verified influence how much of it is analysed.
- **Reject ABIs that declare a known selector**: stricter, but punishes
  legitimate ABIs of contracts that also implement `transfer` or `approve`.

## Consequences

- A user contract that implements a function with a built-in signature (say
  `transfer(address,uint256)`) is decoded by the built-in table, labelled
  selector-only unless it is a listed token. Its arguments are identical, so
  nothing is lost except the user's parameter names.
- Tests (`decode::tests`) pin that an ABI cannot hide a batch.
