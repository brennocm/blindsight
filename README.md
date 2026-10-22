# blindsight

Offline verifier for Safe multisig transactions.

Given the parameters of a Safe transaction, blindsight computes the EIP-712
domain hash, message hash and safeTxHash that your hardware wallet displays,
decodes the calldata (including MultiSend batches and nested Safe transactions)
and reports risky operations with a severity. It has no network capability at
all ([ADR 0002](docs/adr/0002-offline-by-construction.md)).

**Status: under development, not ready for use.**

Research behind the project: [docs/research.md](docs/research.md),
[docs/incidents.md](docs/incidents.md),
[docs/hardware-wallets.md](docs/hardware-wallets.md).

## Disclaimer

blindsight is an independent project. It is not affiliated with, endorsed by or
sponsored by the Safe Ecosystem Foundation, Safe Labs or Chainlink Labs.
"Safe" refers to the Safe smart account contracts that blindsight analyses.

## License

[Apache-2.0](LICENSE)
