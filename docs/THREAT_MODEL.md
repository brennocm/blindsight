# Threat model

## Central assumption

**The web interface and the machine that prepared the transaction may be
compromised.** This is what happened to Bybit (`docs/incidents.md`): the
signers' interface showed one transaction while their wallets signed another.
blindsight is meant to run somewhere else, without network, and recompute
everything from raw parameters.

## Assets

1. **The Safe's funds and control**: what an attacker wants.
2. **The integrity of the hashes blindsight prints**: a wrong hash makes users
   trust the wrong transaction or ignore a real mismatch.
3. **The integrity of the analysis**: findings, labels and decoded calls must
   not be suppressible or forgeable by the input.
4. **The integrity of blindsight itself**: its code, dependencies, embedded
   data and release binaries.

## Attackers

- Whoever controls the transaction source: a compromised interface, Safe
  Transaction Service response, JSON file or calldata.
- Whoever deploys contracts the transaction calls (selector collisions,
  misleading function names, look-alike addresses).
- Whoever can tamper with blindsight's supply chain (a dependency, a GitHub
  Action, a release artifact).

Out of scope: an attacker who controls the machine running blindsight (they
can change its output), or the signer's hardware wallet.

## Threats and mitigations

| Threat | Mitigation |
|---|---|
| Crafted input crashes or stalls the tool, so it is ignored or bypassed | No `unwrap`/`expect`/`panic`/slice indexing in production code, enforced by Clippy ([ADR 0004](adr/0004-no-panics-on-input.md)); `unsafe` forbidden; size limits (1 MiB calldata, 4 MiB JSON, 1 MiB address book, 4 MiB ABI); nesting limit (4); 5 fuzz targets; robustness tests (5,000-entry batches, 1 MiB calldata). |
| Input that decodes differently here than in the contract | `execTransaction` and known functions are decoded with validation (dirty high bytes rejected, like Solidity's decoder); `MultiSend` is unpacked more strictly than the contract (truncation and bad operation bytes are errors, reported high); user-ABI decoding must re-encode to the same bytes; JSON with duplicate keys is rejected. |
| A function name that lies (selector collision, `transfer` that rewrites storage) | Every decoded name is labelled verified or inferred; inferred names are a finding, critical under delegatecall ([ADR 0006](adr/0006-verified-and-inferred-semantics.md)). |
| Dangerous operations hidden in batches or nested transactions | The call tree is decoded recursively and every detector runs on every node; delegatecalls inside batches have their own detector; nesting beyond the limit is reported high, not skipped silently. |
| Terminal escape injection hiding or rewriting findings | Every input-derived string (address-book names, ABI names, decoded strings, error messages, JSON fields) passes through `sanitize`, which escapes C0/C1 controls, DEL, bidi overrides and zero-width characters; tested end to end, including with colours forced on. |
| Address poisoning | Addresses are never shortened anywhere; `BS-POISON-001` compares every address in the transaction with the address book's first and last four hex digits. |
| Wrong Safe version or chain giving a wrong hash | Version and chain are mandatory; unsupported versions and unknown chains are rejected unless explicitly allowed; the domain format per version is tested against 30 real transactions and 24 synthetic cases; two independent implementations must agree at run time ([ADR 0005](adr/0005-dual-hashing-and-supported-versions.md)). |
| A tampered input file or contradictory sources | A `safeTxHash` in the JSON input is checked against the computed hash (mismatch = exit 3); a field given by two sources must agree; mixed-case addresses with a wrong EIP-55 checksum produce a warning. |
| A user who does not look at the result | The verdict is the first line; a mismatch is a red line at the top and exit code 3; `--fail-on` makes findings fail scripts. |
| Exfiltration or remote influence through the network | No networking or async crate may enter the dependency graph (`cargo deny` bans), and CI runs the test suite in a network namespace without interfaces ([ADR 0002](adr/0002-offline-by-construction.md)). |
| Compromised dependency | Small dependency tree, every addition reviewed; `cargo deny` (advisories, licenses, crates.io only), `cargo audit`, Dependabot; `Cargo.lock` committed and builds use `--locked`. |
| Compromised CI or release | Workflow token read-only by default; actions pinned by commit SHA; release binaries built by CI with checksums, SBOM and build-provenance attestations, and `cargo-auditable` metadata (see the release workflow). |
| Embedded registry wrong or stale | Data generated from recorded upstream revisions by scripts in the repository; addresses checksummed; tokens and Permit2 confirmed on chain; tests cross-check tables; `blindsight version` prints every source. |

## Residual risks (accepted)

- **No execution.** blindsight cannot tell what unknown code does. A call to an
  unknown contract with a plausible verified-looking shape (e.g. a CALL to an
  unlisted token's `transfer`) is only a low finding.
- **Stale registry.** A new official helper is treated as untrusted (false
  positive, critical) until blindsight is updated; a new chain needs
  `--allow-unknown-chain`.
- **Compromised analysis machine.** If the machine running blindsight is
  compromised, its output can be forged. Running it on a separate, ideally
  offline, machine is the mitigation, and verifying release provenance.
- **Human comparison.** The hash check only helps if the user compares the
  values on the device. blindsight cannot see the device.
- **Signers not identified.** ECDSA signatures in `execTransaction` calldata
  are classified but their signers are not recovered.
- **Upstream data trust.** Official addresses come from `safe-deployments`;
  if that repository were compromised at the recorded commit, so would the
  registry be (mitigated by review of the generated diff).
