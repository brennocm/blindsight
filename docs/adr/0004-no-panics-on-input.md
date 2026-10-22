# 4. No panics in production code

Date: 2026-10-22
Status: accepted

## Context

blindsight parses untrusted input: calldata, JSON and nested batches built by
whoever prepared the transaction, possibly an attacker. In Rust, `unwrap()`,
`expect()`, `panic!` and slice indexing (`data[4..36]`) abort the program when
their assumption fails. For a verifier, a crash on crafted input is a denial of
service at best; at worst a user learns to ignore the tool.

## Decision

In production code these are denied by Clippy (`Cargo.toml` `[lints.clippy]`):
`unwrap_used`, `expect_used`, `panic`, `todo`, `unimplemented`, `dbg_macro` and
`indexing_slicing`. Fallible operations return `Result` and use `?`; byte
ranges are read with `.get(a..b)`, which returns `None` instead of panicking.
`unsafe` is forbidden (`unsafe_code = "forbid"`).

Tests may unwrap, panic and index (`clippy.toml`), because a panic is how a
test reports failure.

A narrowly scoped `#[allow(...)]` is acceptable only with a comment proving the
operation cannot fail (for example, indexing a fixed-size array with a constant
in range).

A selected set of pedantic lints is also enabled, mainly the `cast_*` lints
that flag silent numeric truncation and sign changes, which matter when
converting between `U256`, `u64` and `usize` lengths read from calldata.

## Alternatives

- **Clippy defaults only**: `unwrap` would pass review by habit.
- **All of `clippy::pedantic`**: noisy for a first Rust project; the selected
  lints are those with a security or readability reason.

## Consequences

Some code is more verbose (`.get()` with explicit errors instead of indexing).
Fuzzing checks the property this ADR aims for: no input makes the
decoders panic.
