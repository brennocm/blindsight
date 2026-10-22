# Changelog

All notable changes to this project are documented in this file. The format is
based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this
project follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0] - 2026-10-22

### Added

- Crate scaffold, lint policy and dependency policy (no network or async
  crates, enforced by `cargo deny`).
- Safe EIP-712 hashing (domain hash, message hash, safeTxHash) for Safe
  1.0.0, 1.1.1, 1.2.0, 1.3.0, 1.4.1 and 1.5.0, computed by two independent
  implementations that must agree.
- Input from flags, Safe Transaction Service JSON or raw `execTransaction`
  calldata, with strict validation, conflict detection between sources and
  size limits.
- Sanitisation of every input-derived string before printing.
- Embedded registry: official Safe contracts per chain, a token list
  confirmed on chain, chain names and Permit2.
- Decoding into a call tree (MultiSend batches, nested Safe transactions,
  user ABIs bound to an address), with each function name labelled as
  verified or inferred from the selector.
- Address book with look-alike (address poisoning) detection.
- 20 detectors with stable IDs and severities, documented in
  `docs/detectors/`.
- Commands `verify`, `hash`, `decode`, `detectors list|explain` and
  `version`; text and JSON output (`schema_version` 1); expected-hash checks
  with `--expect-*`; exit codes 0/1/2/3 (`docs/OUTPUT.md`).
- Release configuration: archives for Linux, macOS and Windows (x86_64 and
  aarch64) with checksums, a CycloneDX SBOM, `cargo-auditable` metadata and
  build-provenance attestations.

### Security

Fixed during the final security review, before any release:

- Argument-parser errors could pass a right-to-left override or a carriage
  return from a command-line argument to the terminal; they are now
  sanitised.
- A user ABI bound to a `MultiSend` address could turn the batch into an
  opaque call hidden from the detectors; built-in decoding now always takes
  precedence (ADR 0008).
- A payload nested beyond the analysis depth was reported high; it is now
  critical.
- `signMessage` through `SignMessageLib` and value sent through `CreateCall`
  now produce findings.
- Addresses imitating the Safe itself are flagged even without an address
  book; address-book names that differ only by case or spaces are rejected.
- Characters that render as blank space (Hangul fillers, variation
  selectors, braille blank) are escaped in all output.
- Token amounts are no longer formatted with token decimals when the token
  function is delegatecalled.
- Only one input may be read from standard input.

[0.1.0]: https://github.com/brennocm/blindsight/releases/tag/v0.1.0
