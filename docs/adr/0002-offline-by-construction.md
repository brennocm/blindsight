# 2. Offline by construction

Date: 2026-10-22
Status: accepted

## Context

blindsight exists because the interface that prepares a Safe transaction can be
compromised. In the Bybit incident (`docs/incidents.md`) the signers' web
interface showed a routine transfer while their wallets signed a delegatecall
that replaced the Safe's implementation. Any tool that fetches the transaction,
its decoding or contract metadata from a remote service inherits the same trust
problem: whoever controls the service, the network path or the DNS controls what
the tool shows.

Existing tools offer an offline mode (see `docs/research.md`), but their
binaries still contain HTTP clients and async runtimes. "Offline" is then a
property of how the tool is invoked, not of the program, and a user cannot
check it without reading the code paths.

## Decision

blindsight has **no network capability at all**, not even optional or behind a
feature flag. This is enforced, not just promised:

1. `deny.toml` `[bans]` forbids HTTP clients and servers, TLS stacks, async
   runtimes, socket/event-loop crates and the alloy/ethers provider and
   umbrella crates. If any dependency, direct or transitive, starts pulling one
   of them, `cargo deny check` fails in CI. The graph checked includes
   dev-dependencies and all features.
2. Only the alloy sub-crates needed for primitives and ABI/EIP-712 encoding are
   used (`alloy-primitives`, `alloy-sol-types`, and if needed `alloy-dyn-abi` /
   `alloy-json-abi`), never the `alloy` umbrella crate.
3. CI runs the whole test suite on Linux inside a network namespace with no
   interfaces (`unshare --net`). A test that needed the network would fail.
4. Everything the tool knows about the world (official contract addresses,
   function signatures, tokens) is embedded at build time from files in
   `data/`, each recording its upstream source and commit.

Research scripts in `scripts/fixtures/` that collected the test vectors use the
network; they are Python, are not part of the crate and are not packaged.

## Alternatives

- **Optional network mode** (fetch from the Safe Transaction Service when the
  user asks): convenient, but it puts HTTP and TLS code in the binary that
  verifies signatures, and makes the trusted computing base depend on a flag.
- **Feature flag `network`, off by default**: the default build would be
  offline, but users installing pre-built binaries could not tell which build
  they have, and the code would still need review.
- **Rely on documentation only**: not verifiable by users.

## Consequences

- The user must supply the transaction parameters (flags, JSON or the raw
  `execTransaction` calldata). This is deliberate: the point is to verify them
  independently of the interface that produced them.
- Information that needs chain state (current owners, current nonce, balances,
  simulation) is out of scope unless the user provides it.
- The ban list must be reviewed when dependencies change; a new networking
  crate not on the list would not be caught by `[bans]`, though the
  no-network test run would catch any test that tries to use it.
- Updating embedded data is a code change with a reviewable diff.
