# 6. Verified versus inferred function semantics

Date: 2026-10-22
Status: accepted

## Context

A function selector is four bytes of `keccak256` of a signature. It tells a
decoder how to lay out the arguments, nothing about what the target's code
does. The Bybit attack transaction decoded as `transfer(address,uint256)`; it
was executed by delegatecall on an attacker contract whose "transfer" wrote
its first argument into storage slot 0 (`docs/incidents.md`). A tool that
prints "transfer 0 tokens to 0xbDd0…" states something false with authority.

## Decision

Every decoded call carries a `Semantics` value:

- **Verified** when the target is known to implement the function *and* the
  operation is the one the function is meant for:
  - an ERC-20 function sent by CALL to a token in the embedded list;
  - a Safe administrative function sent by CALL to the Safe that executes it;
  - a helper function (`multiSend`, `signMessage`, `performCreate*`,
    migrations) sent by DELEGATECALL to an official contract of the matching
    name on this chain.
- **Selector only** otherwise. The report labels such names as inferred, and
  detector `BS-SEMANTICS-001` turns it into a finding (low, critical under
  delegatecall).

Nested `execTransaction` and `approveHash` are always selector-only: whether an
address is a Safe cannot be known offline. They are still decoded and analysed
recursively. A user-supplied ABI (`--abi ADDRESS=FILE`) applies only to its
address and counts as the user's own statement; it never makes a delegatecall
target trusted.

## Alternatives

- **Decode by selector and print names as facts** (what most decoders do):
  simple, and exactly the failure mode exploited at Bybit.
- **Refuse to decode unknown targets**: hides information the signer needs;
  the arguments are still useful once labelled as a guess.
- **Online lookups** (verified source on a block explorer, 4byte): excluded by
  ADR 0002, and a verified source still says nothing about a delegatecall into
  it being safe.

## Consequences

- Legitimate calls to tokens outside the short embedded list are labelled as
  inferred (a low finding). The fix for users is an address book or `--abi`;
  for the project, a careful extension of the token list.
- The label depends on chain id and operation, so the same calldata can be
  verified on one chain and not on another, which is correct.
