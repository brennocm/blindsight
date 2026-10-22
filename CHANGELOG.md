# Changelog

All notable changes to this project are documented in this file. The format is
based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this
project follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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
