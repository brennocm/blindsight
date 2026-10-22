# 7. Embedded registry, matched per chain and not per Safe version

Date: 2026-10-22
Status: accepted

## Context

To tell a routine delegatecall (to the official `MultiSendCallOnly`) from an
attack (to anything else), blindsight must know the official contracts of
every chain. It also needs chain names and, to label token amounts, a few
token addresses and decimals. ADR 0002 rules out fetching any of it.

Real transactions delegatecall helpers from versions other than the Safe's own:
a 1.4.1 Safe used `MultiSend` 1.3.0 (fixture
`bsc-multisend-130-from-safe-141`), a 1.0.0 Safe used `MultiSend` 1.1.1
(`v100-delegatecall-token-refund`).

## Decision

- `data/` holds generated JSON files, each recording its upstream source and
  revision, compiled into the binary with `include_str!` and parsed once
  (`LazyLock`):
  - `safe_deployments.json` from `safe-global/safe-deployments`, all chains
    and all released versions (dropping a chain would turn its official
    `MultiSend` into a critical false positive);
  - `chains.json`: the chains with a Safe deployment, named from
    `ethereum-lists/chains`;
  - `tokens.json`: six major tokens per chain from the Uniswap Labs default
    list, each confirmed by reading `symbol()` and `decimals()` from the
    contract.
- Official contracts are matched by `(chain id, address)` regardless of the
  executing Safe's version. Trusted delegatecall targets are the roles
  `MultiSend`, `MultiSendCallOnly`, `SignMessageLib`, `CreateCall`,
  migrations and L2 setup.
- Embedded addresses must carry a valid EIP-55 checksum; tests check the
  tables against the research and each other.
- If embedded data ever failed to parse, the tool stops with an internal
  error rather than continuing with an empty registry.

## Alternatives

- **Generate Rust code at build time** (`build.rs`): faster start-up, but a
  build script is more machinery to audit than a JSON file and a parser.
- **Allowlist keyed by Safe version**: produces false positives on real
  transactions (above).
- **Large token lists**: more labels, more data to trust; a short list
  verified on chain is easier to defend.

## Consequences

- The registry can become outdated: new chains or helper versions appear as
  unknown until blindsight is updated. Unknown chains require
  `--allow-unknown-chain` and print a warning.
- Updating data is a reviewable diff produced by the scripts in
  `scripts/fixtures/`.
