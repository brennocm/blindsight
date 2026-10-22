# 5. Two hash implementations, and which Safe versions are supported

Date: 2026-10-22
Status: accepted

## Context

The hashes are the one output a signer compares with the hardware wallet. A
wrong hash is worse than no tool: it either makes users ignore a real mismatch
or trust a transaction they should not. Safe's EIP-712 encoding differs between
versions (`docs/research.md` §1): the domain gained `chainId` in 1.3.0, and
before 1.0.0 one field of `SafeTx` had a different name.

## Decision

**Two implementations, compared on every run.** `src/safe/hash.rs` writes the
encoding out by hand, word by word, as the contracts do. `src/safe/eip712.rs`
uses alloy's `sol!` struct and `Eip712Domain`. `compute_hashes` runs both and
returns an error instead of a hash if they differ. Tests check both against:

- 30 real executed transactions, each confirmed by the Safe Transaction
  Service, an on-chain attestation and an independent Python recomputation;
- synthetic edge cases (empty and large calldata, maximum values, zero
  addresses, extreme chain ids) computed by the Python reference;
- property tests: the two implementations agree on random input, any field
  change changes the hash, and versions with the same domain format hash
  alike while different formats do not.

Every typehash constant has a test that recomputes `keccak256` of its type
string, and a test checks that alloy derives the same type strings.

**Supported versions** are those with an official deployment in
`safe-deployments`: 1.0.0, 1.1.1, 1.2.0, 1.3.0, 1.4.1 and 1.5.0 (`+L2`
variants hash identically). In all of them the `SafeTx` typehash is the same;
only the domain differs (no `chainId` before 1.3.0). Any other version string,
including 0.1.0 (different typehash, no real transaction to test against) and
the never-deployed 1.1.0 and 1.4.0 tags, is rejected as an input error. The
version is mandatory: guessing it would silently produce a wrong domain hash.

1.2.0 has no real vector; its domain and typehash constants are identical to
1.1.1 in the source (checked at the `v1.2.0` tag), and 1.1.1 has three.

## Alternatives

- **Only alloy**: less code, but a single implementation can share a
  misunderstanding with the test data generator; and the hand-written version
  documents what EIP-712 does.
- **Only hand-written**: the same single-point-of-failure argument.
- **Compare only in tests**: the runtime cost of the second implementation is
  one extra hash of the calldata, negligible next to the cost of a wrong hash.
- **Support 0.1.0 from source only**: would ship a code path no real
  transaction has ever validated.

## Consequences

- A disagreement between implementations surfaces as an internal error that
  asks the user to report it, never as a hash.
- Adding a Safe version means: confirm its type strings in the source, add a
  real vector confirmed by two other sources, add the variant.
- Before 1.3.0 the chain id does not affect any hash; the report must say so
  (cross-chain replay, detector `BS-REPLAY-001`).
