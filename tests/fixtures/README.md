# Test fixtures

## `real/` — executed mainnet and testnet transactions

30 real Safe transactions across 8 chains (Ethereum, Arbitrum, Optimism, Base,
Polygon, Gnosis Chain, BNB Chain, Sepolia) and Safe versions 1.0.0, 1.1.1,
1.3.0, 1.4.1 and 1.5.0.

A vector is included only if **three independent sources agree** on the
safeTxHash:

1. **Official service** — the Safe Transaction Service returns the
   transaction and its `safeTxHash` (`sources.official_tx_service`).
2. **On-chain attestation** — either
   - the `ExecutionSuccess(txHash, payment)` event that the Safe itself emitted
     when executing (1.1.1+), or
   - for 1.0.0 (no success event): the signatures in the executed calldata
     recover, over the computed hash, to at least `threshold` addresses
     returned by `getOwners()` at the previous block.
3. **Independent recomputation** — `scripts/fixtures/safehash.py`, written
   from the contract sources (not from any existing tool), with the Safe
   version read on chain via `VERSION()` at the block before execution.

The `expected` domain and message hashes come from source 3; the safeTxHash
derived from them is the one sources 1 and 2 confirm.

Each file has:

| Field | Meaning |
|---|---|
| `chain_id`, `safe`, `safe_version` | hashing context |
| `tx` | the ten `SafeTx` fields; numbers as decimal strings |
| `expected` | `domain_hash`, `message_hash`, `safe_tx_hash` |
| `exec_calldata` | the raw `execTransaction` calldata as executed (input for `--exec-calldata`; the nonce is in `tx.nonce`) |
| `sources` | where each fact came from, with block numbers |
| `tx_service_decoded` | the service's own decoding, kept **only** to cross-check our decoder in tests; never used by the tool |

### Reproducing

The scripts in `scripts/fixtures/` are research tools. They use the network
(public RPCs, the Safe Transaction Service, Blockscout) and are **not** part
of `blindsight`, which never uses the network.

```
python -m venv .venv && .venv/bin/pip install pycryptodome
cd scripts/fixtures
../../.venv/bin/python collect.py validate ethereum 0x46deef0f52e3a983b67abf4714448a41dd7ffd6d32d32da69d62081c68ad7882
../../.venv/bin/python validate_sig.py ethereum 0x6c6063fb6ba786e1098dddd8d2eb756a5d13a62398026e5aa07cd4290ef9d751
```

## Coverage

| Category | Fixtures |
|---|---|
| Incidents | `bybit`, `wazirx` |
| Legitimate counterparts | `bybit-legit-nonce70`, `bybit-legit-nonce67-token` |
| ERC-20 transfer / approve | `erc20-transfer-eth-141`, `erc20-transfer-polygon-130`, `bsc-transfer`, `sepolia-transfer`, `erc20-approve-base`, `erc20-approve-gnosis` |
| MultiSend (delegatecall to official helper) | `multisend-141-l2`, `arb-multisend-141`, `op-multisend-141`, `bsc-multisend-130-from-safe-141`, `v100-delegatecall-token-refund` |
| Admin in batch | `multisend-enable-module`, `multisend-set-guard` |
| Admin direct | `add-owner-130`, `add-owner-150-l2`, `remove-owner`, `swap-owner`, `change-threshold`, `disable-module`, `v100-swapowner-token-refund` |
| Other official delegatecall | `sign-message-lib` |
| Gas refunds | `gas-refund` (native, 1.3.0), `v100-eth-refund-native`, `v100-swapowner-token-refund` and `v100-delegatecall-token-refund` (ERC-20 gas token) |
| Unknown selectors / value | `unknown-selector-call`, `value-with-unknown-call`, `set-pre-signature` |
| Same Safe, different chain (domain differs) | `arb-multisend-141` vs `op-multisend-141` |

Not covered by real vectors: v1.2.0 (same typehash and domain as 1.1.1),
v0.1.0 (not supported).

## `synthetic/` — edge cases

`hashing-edge-cases.json` holds 24 cases no real transaction covers: empty,
one-byte, 33-byte and 16 KiB calldata; all-zero and all-maximum fields for
every supported version; a chain id of 0 and of 2^64 − 1; and the same
pre-1.3.0 transaction on two chains (identical hashes: no chain id in the
domain). Expected hashes come from `scripts/fixtures/safehash.py`
(`gen_synthetic.py` regenerates the file, without network); the Rust tests
check both Rust implementations against them, so each expected value is
confirmed by an implementation written independently of the code under
test.
