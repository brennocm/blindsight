# 3. Single package with a library and a binary

Date: 2026-10-22
Status: accepted

## Context

blindsight has a CLI, but its core (hashing, decoding, detectors) should be
testable without spawning a process and usable from other Rust programs. Cargo
supports either one package with `src/lib.rs` and `src/main.rs`, or a workspace
of several crates (for example `blindsight-core` and `blindsight-cli`).

## Decision

One package, `blindsight`, with a library (`src/lib.rs`) and a binary
(`src/main.rs`). The binary only parses arguments, calls the library, prints
and sets the exit code. All logic and all tests of logic live in the library.
`thiserror` error types are used in the library and `anyhow` only in the binary.

## Alternatives

- **Workspace with separate core and CLI crates**: cleaner boundaries if the
  library were published and versioned on its own, but more manifests, more
  versioning and more concepts for a first Rust project, with no current user
  of the library alone.

## Consequences

- The library's public API is whatever `lib.rs` exports; it is not promised to
  be stable before 1.0.
- If an independent library user appears, the split into a workspace is
  mechanical because the binary already depends only on the public API.
