# Contributing

Thanks for considering a contribution.

## Ground rules

- **No network.** blindsight must never open a connection, not even behind a
  flag. Dependencies that can (HTTP, TLS, async runtimes) are banned in
  `deny.toml`. See [ADR 0002](docs/adr/0002-offline-by-construction.md).
- **No facts from memory.** Typehashes, selectors and contract addresses come
  from primary sources (contract source code, the official deployments
  repository, on-chain data) and each one has a test that recomputes or
  cross-checks it. See [docs/research.md](docs/research.md).
- **Test vectors need two independent confirmations** of the expected hash. See
  [tests/fixtures/README.md](tests/fixtures/README.md).
- **No panics on input.** No `unwrap`, `expect`, `panic!` or slice indexing in
  production code; no `unsafe`. See
  [ADR 0004](docs/adr/0004-no-panics-on-input.md).
- **Never truncate addresses or hashes** in output, and sanitize everything
  that comes from the input before printing it.

## Development

The toolchain is pinned in `rust-toolchain.toml`; `rustup` installs it on first
use. Before sending a change:

```sh
cargo fmt --check
cargo clippy --all-targets -- -D warnings
cargo nextest run        # or: cargo test
cargo deny check
```

Commits follow [Conventional Commits](https://www.conventionalcommits.org/).
Each commit builds and passes the checks above on its own. Decisions that are
not obvious from the code get an ADR in `docs/adr/`.
