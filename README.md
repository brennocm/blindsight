# blindsight

[![CI](https://github.com/brennocm/blindsight/actions/workflows/ci.yml/badge.svg)](https://github.com/brennocm/blindsight/actions/workflows/ci.yml)
[![crates.io](https://img.shields.io/crates/v/blindsight.svg)](https://crates.io/crates/blindsight)
[![License: Apache-2.0](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)
[![OpenSSF Scorecard](https://api.scorecard.dev/projects/github.com/brennocm/blindsight/badge)](https://scorecard.dev/viewer/?uri=github.com/brennocm/blindsight)

**Offline verifier for Safe multisig transactions: it computes the hashes your
hardware wallet shows, decodes what you are about to sign, and tells you when
it can take over your Safe.**

![blindsight on the Bybit attack transaction](docs/demo/bybit.gif)

## Why

A Safe multisig is controlled by a few owners, who each sign an EIP-712 hash of
the transaction, usually on a hardware wallet. Many devices can only show that
hash, so owners rely on the web interface that prepared the transaction to tell
them what it does. If that interface is compromised, they sign something else.

That is what happened to Bybit on 21 February 2025: about US$1.5 billion was
stolen ([FBI](https://www.ic3.gov/PSA/2025/PSA250226)). Malicious JavaScript
served to the signers swapped the transaction they were shown for another
([Sygnia](https://www.sygnia.co/blog/sygnia-investigation-bybit-hack/)). The
signed transaction delegatecalled an attacker contract through a function that
*looked like* `transfer(address,uint256)`; its code replaced the Safe's
implementation, and the attacker then emptied the wallet without any further
signature ([NCC Group](https://www.nccgroup.com/research/in-depth-technical-analysis-of-the-bybit-hack/)).
The three owners signed with `eth_sign`, so their devices could show only a
32-byte hash. WazirX lost ~US$230 million the same way in July 2024. The
on-chain details of both are in [docs/incidents.md](docs/incidents.md).

blindsight assumes **the machine and interface that prepared the transaction
may be compromised**. It runs elsewhere, with no network, and recomputes
everything from the raw parameters.

## How it works

```
 flags / Transaction Service JSON / execTransaction calldata
                         │
                 strict input parsing ──────── sanitised errors, size limits
                         │
        ┌────────────────┼──────────────────────────┐
        ▼                ▼                          ▼
  EIP-712 hashes    call tree decoding        embedded registry
  (two independent  (MultiSend, nested Safe,  (official Safe contracts per
  implementations)   user ABIs; verified vs    chain, tokens checked on
        │            inferred names)           chain, Permit2)
        │                │                          │
        │                ▼                          │
        │          20 detectors on every node ◄─────┘
        ▼                ▼
   report: verdict · hash checks · findings · hashes (wallet labels) · calls
           text or JSON · exit code 0/1/2/3
```

1. **Hashes.** The domain hash, message hash and safeTxHash are computed by a
   hand-written EIP-712 encoder and by alloy's, on every run; if they ever
   disagree, no hash is printed. Both are tested against 30 real transactions
   from 8 chains and 5 Safe versions, each confirmed by the Safe Transaction
   Service, an on-chain event or signature recovery, and an independent Python
   implementation ([tests/fixtures](tests/fixtures/README.md)).
2. **Decoding.** Calldata becomes a tree: `multiSend` batches and
   `execTransaction` calls to other Safes are decoded recursively. Each
   function name is labelled **verified** (the target is known to implement
   it, with the right operation) or **inferred from the selector**. The Bybit
   payload decodes as `transfer`, labelled unverified, because a selector says
   nothing about what the code does.
3. **Detectors.** Twenty detectors with stable IDs and severities run on every
   node of the tree, so wrapping a payload in a batch does not hide it.

## Install

Pre-built binaries for Linux, macOS and Windows are attached to each
[release](https://github.com/brennocm/blindsight/releases), with checksums,
an SBOM and GitHub build-provenance attestations. Verify a download before
using it:

```sh
gh attestation verify blindsight-x86_64-unknown-linux-gnu.tar.xz --repo brennocm/blindsight
sha256sum -c blindsight-x86_64-unknown-linux-gnu.tar.xz.sha256
```

Or build from source (Rust 1.90 or later):

```sh
cargo install --locked blindsight
```

## Usage

From the parameters shown in your Safe interface:

```sh
blindsight verify --chain-id 1 --safe 0xYourSafe --safe-version 1.4.1 \
  --to 0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48 \
  --data 0xa9059cbb000000000000000000000000... --nonce 42 \
  --expect-safe-tx-hash 0x...      # the hash your wallet or interface shows
```

From a Safe Transaction Service JSON (the chain id and version are not in it):

```sh
blindsight verify --tx tx.json --chain-id 1 --safe-version 1.4.1
blindsight verify --tx - --chain-id 1 --safe-version 1.4.1 < tx.json   # or from stdin
```

From an already executed transaction (calldata from a block explorer; the
nonce is not part of it):

```sh
blindsight verify --exec-calldata 0x6a761202… --chain-id 1 \
  --safe 0xYourSafe --safe-version 1.1.1 --nonce 71
```

With your address book (labels addresses and catches look-alikes) and the
Safe's current nonce:

```sh
blindsight verify --tx tx.json --chain-id 1 --safe-version 1.4.1 \
  --address-book book.json --current-nonce 42
# book.json: { "Treasury": "0x…", "Ops multisig": "0x…" }
```

Other commands: `blindsight hash` (hashes only), `blindsight decode`,
`blindsight detectors list`, `blindsight detectors explain BS-DELEGATE-001`,
`blindsight version` (shows the source commit of every embedded data file).
`--format json` gives a versioned, machine-readable report; `--abi
ADDRESS=FILE` decodes calls to your own contracts.

Exit codes: `0` nothing at or above `--fail-on` (default `high`), `1`
findings at or above it, `2` input or usage error, `3` an expected hash does
not match. Details: [docs/OUTPUT.md](docs/OUTPUT.md).

## Verifying with your hardware wallet

blindsight prints the hashes with the labels and letter case devices use:

- **Ledger**: compare **Domain hash** and **Message hash** with the
  upper-case lines (`as on Ledger`).
- **Trezor**: check the Safe address and chain id under **Confirm domain**,
  every field of the transaction, and **Confirm message hash** when shown.
- **Only one hash on screen** (`eth_sign`): it is the **safeTxHash**.

Every character must match. A matching hash proves you are signing the
transaction you gave blindsight; the findings tell you what that transaction
does. Firmware details and sources: [docs/hardware-wallets.md](docs/hardware-wallets.md).

## Recommended workflow

1. Get the transaction parameters from the interface, and the hash shown by
   your wallet.
2. Run blindsight **on a different machine** from the one that prepared the
   transaction (ideally an offline one), entering or copying the parameters.
3. Pass the hash from your screen with `--expect-safe-tx-hash` (or
   `--expect-domain-hash` / `--expect-message-hash`). A mismatch is exit code
   3 and a red line at the top.
4. Read the verdict and every finding. Do not sign a critical or high finding
   you cannot explain.
5. Simulate the transaction as well (Tenderly, Foundry): blindsight does not
   execute anything.

## Detectors

| ID | Title | Severity |
|---|---|---|
| `BS-DELEGATE-001` | Delegatecall to an untrusted contract | critical |
| `BS-DELEGATE-002` | Delegatecall inside a batch | critical (untrusted target), medium (official helper), info (MultiSendCallOnly) |
| `BS-SEMANTICS-001` | Function name is a guess | low; critical under delegatecall |
| `BS-OWNERS-001` | Owner set change | high; critical if the new threshold is 1 |
| `BS-THRESHOLD-001` | Threshold change | high; critical if the new threshold is 1 |
| `BS-MODULE-001` | Module enabled or disabled | critical (enable), medium (disable) |
| `BS-GUARD-001` | Transaction or module guard change | high |
| `BS-FALLBACK-001` | Fallback handler change | high; low if the handler is official |
| `BS-IMPL-001` | Implementation (singleton) change | critical; info for official singletons and migrations |
| `BS-REFUND-001` | Gas refund paid by the Safe | high (token or uncapped native refund), medium (capped native), low (inert fields) |
| `BS-APPROVAL-001` | Unlimited or operator approval | high (unlimited or operator), info (bounded or revoked) |
| `BS-APPROVAL-002` | Permit2 allowance (experimental) | high (unlimited), info (bounded) |
| `BS-VALUE-001` | Native value transfer | info; high with delegatecall |
| `BS-POISON-001` | Address looks like an address-book entry | high |
| `BS-TARGET-001` | Unknown target | info |
| `BS-DECODE-001` | Undecodable or malformed calldata | medium; high for a malformed batch |
| `BS-SELF-001` | Call to the Safe itself | info; medium if the function is not a Safe function |
| `BS-NONCE-001` | Suspicious nonce | medium; info if queued |
| `BS-NESTED-001` | Nested Safe transaction or opaque approval | info (nested, decoded), medium (signMessage), high (approveHash), critical (too deep) |
| `BS-REPLAY-001` | Domain without chain id (pre-1.3.0) | low |

Each has a page in [docs/detectors](docs/detectors/) (also `blindsight
detectors explain <ID>`). A test keeps this table in sync with the code.

## Comparison with other tools

blindsight builds on the work of these projects, which exist for the same
reason and are worth using:

| | [safe-tx-hashes-util](https://github.com/pcaversaccio/safe-tx-hashes-util) | [safe-hash](https://github.com/Cyfrin/safe-hash-rs) | [op-txverify](https://github.com/ethereum-optimism/op-txverify) | blindsight |
|---|---|---|---|---|
| Language | Bash (+ Foundry `cast`) | Rust | Go | Rust |
| Hashes (domain, message, safeTxHash) | yes | yes | yes | yes |
| Off-chain messages | yes | yes | — | not yet |
| Works offline | with manual input | `--offline` flag | air-gapped via QR codes | only mode; no network code in the binary |
| Source of transaction data | Safe Transaction Service | Transaction Service or input | Transaction Service | user input only |
| Calldata decoding | from the Transaction Service | from the Transaction Service | local (MultiSend, Multicall3) | local, recursive, verified vs inferred |
| Warnings | delegatecall, owner/threshold changes, gas refunds | delegatecall, gas refunds, owner changes | labels known addresses | 20 detectors with IDs, severities and exit codes |

`safe-tx-hashes-util` is the community reference that Safe's own help center
points to; `safe-hash` brought it to Rust; `op-txverify` pioneered the
air-gapped workflow. "—" means not checked for this comparison.
blindsight's differences are narrower: no network code at
all (enforced by `cargo deny` and a CI job without network), local decoding
that never trusts a service's labels, explicit unverified-name labelling,
address-poisoning checks and output sanitisation. It does not yet handle
off-chain messages, which the others do.

## Security

- **Offline by construction**: networking and async crates are banned from the
  dependency tree ([ADR 0002](docs/adr/0002-offline-by-construction.md)) and
  the test suite runs in CI inside a network namespace with no interfaces.
- **No panics on input**, `unsafe` forbidden, fuzzed parsers and decoders
  ([ADR 0004](docs/adr/0004-no-panics-on-input.md)).
- Threat model: [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md). Report
  vulnerabilities privately: [SECURITY.md](SECURITY.md).

## Limitations

- **No simulation.** blindsight does not execute the transaction or read chain
  state; it cannot see balances, current owners or what unknown code does.
- **Unknown contracts stay unknown.** It flags that a function name is only a
  guess and that a target is unverified; it cannot tell you the code is
  malicious.
- **The embedded registry can go stale**: new chains, helper versions or
  tokens appear as unknown until blindsight is updated. Unknown chains need
  `--allow-unknown-chain`.
- **Only Safe versions 1.0.0 to 1.5.0 that were officially deployed**;
  0.1.0, 1.1.0 and 1.4.0 are refused.
- **ECDSA signers are not recovered** from `execTransaction` signatures; only
  the signature kinds are shown.
- **It only helps if you compare.** A matching hash is meaningless unless you
  check it against your device, character by character.

## Disclaimer

blindsight is an independent project. It is not affiliated with, endorsed by
or sponsored by the Safe Ecosystem Foundation, Safe Labs or Chainlink Labs.
"Safe" refers to the Safe smart account contracts that blindsight analyses.
It is provided as is, without warranty, and is not a guarantee of security:
use it as one layer of review among others.

## License

[Apache-2.0](LICENSE)
