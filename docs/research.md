# Research notes

Everything in this document was checked against primary sources: the Safe
contract source code at each release tag, the official `safe-deployments`
repository, on-chain data, and hardware-wallet firmware source. Each claim
links to where it can be re-verified.

Research snapshot: 2026-10-22.

| Source | Revision used |
|---|---|
| [safe-global/safe-smart-account](https://github.com/safe-global/safe-smart-account) | tags `v0.1.0` … `v1.5.0` (HEAD `247b8ce3`) |
| [safe-global/safe-deployments](https://github.com/safe-global/safe-deployments) | `e9cc9798ab834e7fe515d361566eb4a28c65387f` |
| [LedgerHQ/app-ethereum](https://github.com/LedgerHQ/app-ethereum) | `f7985b42` |
| [trezor/trezor-firmware](https://github.com/trezor/trezor-firmware) | `cb8197d1` |

## 1. Safe transaction hashing

### 1.1 The `SafeTx` struct

Field order is identical in every version from `v0.1.0` to `v1.5.0`:

```
to, value, data, operation, safeTxGas, baseGas, gasPrice, gasToken, refundReceiver, nonce
```

Only the **name** of the sixth field changed. `v0.1.0` calls it `dataGas`;
`v1.0.0` and later call it `baseGas`. The name is part of the EIP-712 type
string, so the typehash differs:

| Versions | Type string | Typehash |
|---|---|---|
| `< 1.0.0` | `SafeTx(address to,uint256 value,bytes data,uint8 operation,uint256 safeTxGas,uint256 dataGas,uint256 gasPrice,address gasToken,address refundReceiver,uint256 nonce)` | `0x14d461bc7412367e924637b363c7bf29b8f47e2f84869f4426e5633d8af47b20` |
| `>= 1.0.0` | `SafeTx(address to,uint256 value,bytes data,uint8 operation,uint256 safeTxGas,uint256 baseGas,uint256 gasPrice,address gasToken,address refundReceiver,uint256 nonce)` | `0xbb8310d486368db6bd6f849402fdd73ad53d316b5a4b2644ad6efe0f941286d8` |

Source: `SAFE_TX_TYPEHASH` constants in `contracts/GnosisSafe.sol` (`v0.1.0`
L26–28, `v1.0.0` L26–28, `v1.3.0` L41–43) and `contracts/Safe.sol` (`v1.4.1`
L55–57, `v1.5.0` L60–62). The keccak256 of each string was recomputed and
matches the constant in the source.

### 1.2 The EIP-712 domain

| Versions | Domain type string | Typehash | Encoded as |
|---|---|---|---|
| `< 1.3.0` | `EIP712Domain(address verifyingContract)` | `0x035aff83d86937d35b32e04f0ddc6ff469290eef2f1b692d8a815c89404d4749` | `keccak256(abi.encode(TYPEHASH, safe))` |
| `>= 1.3.0` | `EIP712Domain(uint256 chainId,address verifyingContract)` | `0x47e79534a245952e8b16893a336b85a3d9ea9fa8c573f3d803afb92a79469218` | `keccak256(abi.encode(TYPEHASH, chainid, safe))` |

Consequences:

- Before 1.3.0 the domain has **no chain id**. The same Safe address on two
  chains has the same domain hash there, so a signature for one chain is valid
  on the other (cross-chain replay). The tool must not ask for a chain id to
  compute the hash for these versions, but should still show it for context.
- Before 1.3.0 the domain separator is computed once in `setup()` and stored.
  From 1.3.0 on it is recomputed on every call from `chainid()`.
- No version uses `name` or `version` in the domain.

### 1.3 Final hash

```
structHash   = keccak256(abi.encode(SAFE_TX_TYPEHASH, to, value, keccak256(data), operation,
                                    safeTxGas, baseGas, gasPrice, gasToken, refundReceiver, nonce))
safeTxHash   = keccak256(0x19 ‖ 0x01 ‖ domainSeparator ‖ structHash)
```

Every field is a 32-byte ABI word. `data` is hashed first (EIP-712 rule for
`bytes`). `v1.5.0` rewrote `getTransactionHash` in inline assembly but the
memory layout it hashes (`v1.5.0` `Safe.sol` L436–465) is byte-for-byte the
same encoding. Also, `v1.5.0` removed `encodeTransactionData`, so tools that
read the preimage from the contract over RPC (for example `op-txverify`'s web
page) cannot support it.

Hardware wallets and the Safe UI call `structHash` the **message hash** and
`domainSeparator` the **domain hash**. `blindsight` should use those names.

### 1.4 `execTransaction` and how to read a hash back from chain

```
execTransaction(address to, uint256 value, bytes data, uint8 operation, uint256 safeTxGas,
                uint256 baseGas, uint256 gasPrice, address gasToken, address payable refundReceiver,
                bytes signatures)                                  selector 0x6a761202
```

The **nonce is not a parameter**; the contract uses its own storage `nonce`.
Analysing raw `execTransaction` calldata therefore requires the user to supply
the nonce.

Events that attest the hash on chain:

| Versions | Event | Where the hash is |
|---|---|---|
| `1.0.0` | none on success | (recover signatures instead, see `tests/fixtures/README.md`) |
| `1.1.1`, `1.2.0`, `1.3.0` | `ExecutionSuccess(bytes32 txHash, uint256 payment)` | `data[0:32]` |
| `1.4.1`, `1.5.0` | `ExecutionSuccess(bytes32 indexed txHash, uint256 payment)` | `topics[1]` |

`topic0 = keccak256("ExecutionSuccess(bytes32,uint256)") = 0x442e715f626346e8c54381002da614f62bee8d27386535b2521ec8540898556e`.

### 1.5 Signature kinds (`checkSignatures`)

Each 65-byte signature is `r ‖ s ‖ v`:

| `v` | Meaning |
|---|---|
| `0` | contract signature (EIP-1271); `r` is the signer address |
| `1` | pre-approved hash; `r` is the owner that called `approveHash` (or is `msg.sender`) |
| `27`/`28` | ECDSA over `safeTxHash` (EIP-712 typed-data signature) |
| `> 30` | `eth_sign`: ECDSA over `keccak256("\x19Ethereum Signed Message:\n32" ‖ safeTxHash)`, `v - 4` |

All three Bybit signatures on the attack transaction were `v > 30`: the signers
signed the hash as a personal message, so their devices only had a 32-byte hash
to show. See `docs/incidents.md`.

### 1.6 Gas refund (`handlePayment`)

Refunds only happen when `gasPrice > 0`:

```
receiver = refundReceiver == 0 ? tx.origin : refundReceiver
if gasToken == 0:
    v1.0.0–v1.2.0: payment = (gasUsed + baseGas) * gasPrice
    v1.3.0+:       payment = (gasUsed + baseGas) * min(gasPrice, tx.gasprice)
else:
    payment = (gasUsed + baseGas) * gasPrice        # in gasToken units, never capped
```

Points that matter for a detector:

- The **executor** (anyone holding the signatures) chooses the transaction gas
  limit, so `gasUsed` is not bounded by what the signers saw.
- With an ERC-20 `gasToken`, `gasPrice` is an arbitrary token amount per gas,
  so `baseGas * gasPrice` alone can be the whole token balance.
- With `refundReceiver == 0`, the refund goes to whoever submits the
  transaction, which is attacker-controlled once signatures leak.
- The Safe{Wallet} UI defaults to `safeTxGas = baseGas = gasPrice = 0` and zero
  addresses. In 23 of the 24 real fixtures from 1.3.0+ Safes, all five gas
  fields are zero (the exception is `gas-refund`).

## 2. Administrative functions of the Safe itself

All are `authorized` (only callable by the Safe itself, i.e. via a Safe
transaction with `to == safe`, or via a delegatecall that runs code in the
Safe's context).

| Function | Selector | Versions | Effect |
|---|---|---|---|
| `addOwnerWithThreshold(address,uint256)` | `0x0d582f13` | all | adds an owner, sets threshold |
| `removeOwner(address,address,uint256)` | `0xf8dc5dd9` | all | removes owner (prev pointer, owner), sets threshold |
| `swapOwner(address,address,address)` | `0xe318b52b` | all | replaces an owner |
| `changeThreshold(uint256)` | `0x694e80c3` | all | sets threshold |
| `enableModule(address)` | `0x610b5925` | all | module can execute without owner signatures |
| `disableModule(address,address)` | `0xe009cfde` | all | removes a module |
| `setFallbackHandler(address)` | `0xf08a0323` | `>= 1.1.0` | handler receives every unknown call to the Safe |
| `setGuard(address)` | `0xe19a9dd9` | `>= 1.3.0` | guard runs before/after every `execTransaction`; can brick the Safe |
| `setModuleGuard(address)` | `0xe068df37` | `>= 1.5.0` | guard for module transactions |
| `changeMasterCopy(address)` | `0x7de7edef` | `<= 1.2.0` | **replaces the implementation** |
| `approveHash(bytes32)` | `0xd4d9bdcd` | all | owner pre-approves a hash (used by nested Safes) |

Storage that defines who controls the Safe (from `v1.5.0` sources):

| What | Location |
|---|---|
| singleton / masterCopy (implementation) | slot `0` (first declared variable of the proxy and of the singleton) |
| fallback handler | `keccak256("fallback_manager.handler.address")` = `0x6c9a6c4a39284e37ed1cf53d337577d14212a4870fb976a4366c693b939918d5` |
| guard | `keccak256("guard_manager.guard.address")` = `0x4a204f620c8c5ccdca3fd54d003badd85ba500436a431f0cbda4f558c93c34c8` |
| module guard | `0xb104e0b93118902c651344349b610029d694cfdec91c589c91ebafbcd0289947` |

**How the implementation can be swapped.** From 1.3.0 on there is no
`changeMasterCopy`. The only ways to change slot 0 are:

1. A `DELEGATECALL` (`operation = 1`) to code that writes slot 0. Official
   migration contracts (`SafeMigration`, `SafeToL2Migration`, `SafeToL2Setup`)
   do exactly this, and refuse to run unless called via delegatecall.
2. Any other delegatecall target, which runs arbitrary code with full access to
   storage. This is how both Bybit and WazirX were taken over.
3. For `<= 1.2.0`, a call to the Safe itself with `changeMasterCopy`.
4. A module (modules can request delegatecalls via
   `execTransactionFromModule`), so enabling a module is equivalent in power.

## 3. Official helper contracts

Collected into `data/safe_deployments.json` (43 contract entries, 6 versions,
~440 chains) by `scripts/fixtures/gen_deployments.py`, recording the source
commit. Addresses of the delegatecall-relevant contracts:

| Contract | Version | canonical | eip155 | zksync |
|---|---|---|---|---|
| MultiSend | 1.1.1 | `0x8D29bE29923b68abfDD21e541b9374737B49cdAD` | | |
| MultiSend | 1.3.0 | `0xA238CBeb142c10Ef7Ad8442C6D1f9E89e07e7761` | `0x998739BFdAAdde7C933B942a68053933098f9EDa` | `0x0dFcccB95225ffB03c6FBB2559B530C2B7C8A912` |
| MultiSend | 1.4.1 | `0x38869bf66a61cF6bDB996A6aE40D5853Fd43B526` | | `0x309D0B190FeCCa8e1D5D8309a16F7e3CB133E885` |
| MultiSend | 1.5.0 | `0x218543288004CD07832472D464648173c77D7eB7` | | |
| MultiSendCallOnly | 1.3.0 | `0x40A2aCCbd92BCA938b02010E17A5b8929b49130D` | `0xA1dabEF33b3B82c7814B6D82A79e50F4AC44102B` | `0xf220D3b4DFb23C4ade8C88E526C1353AbAcbC38F` |
| MultiSendCallOnly | 1.4.1 | `0x9641d764fc13c8B624c04430C7356C1C7C8102e2` | | `0x0408EF011960d02349d50286D20531229BCef773` |
| MultiSendCallOnly | 1.5.0 | `0xA83c336B20401Af773B6219BA5027174338D1836` | | |
| SignMessageLib | 1.3.0 | `0xA65387F16B013cf2Af4605Ad8aA5ec25a2cbA3a2` | `0x98FFBBF51bb33A056B08ddf711f289936AafF717` | `0x357147caf9C0cCa67DfA0CF5369318d8193c8407` |
| SignMessageLib | 1.4.1 | `0xd53cd0aB83D845Ac265BE939c57F53AD838012c9` | | `0xAca1ec0a1A575CDCCF1DC3d5d296202Eb6061888` |
| SignMessageLib | 1.5.0 | `0x4FfeF8222648872B3dE295Ba1e49110E61f5b5aa` | | |
| SafeMigration | 1.4.1 | `0x526643F69b81B008F46d95CD5ced5eC0edFFDaC6` | | `0x817756C6c555A94BCEE39eB5a102AbC1678b09A7` |
| SafeMigration | 1.5.0 | `0x6439e7ABD8Bb915A5263094784C5CF561c4172AC` | | |
| SafeToL2Migration | 1.4.1 | `0xfF83F6335d8930cBad1c0D439A841f01888D9f69` | | `0xa26620d1f8f1a2433F0D25027F141aaCAFB3E590` |
| SafeToL2Setup | 1.4.1 | `0xBD89A1CE4DDe368FFAB0eC35506eEcE0b1fFdc54` | | `0x199A9df0224031c20Cc27083A4164c9c8F1Bcb39` |
| SafeToL2Setup | 1.5.0 | `0x900C7589200010D6C6eCaaE5B06EBe653bc2D82a` | | |
| CreateCall | 1.3.0 / 1.4.1 / 1.5.0 | see `data/safe_deployments.json` | | |

Observations from real transactions (see fixtures):

- Safes delegatecall official helpers **from other versions**: a v1.4.1 Safe
  used MultiSend 1.3.0 (`bsc-multisend-130-from-safe-141`); a v1.0.0 Safe used
  MultiSend 1.1.1 (`v100-delegatecall-token-refund`). An allowlist keyed by the
  Safe's own version would produce false positives. The allowlist must contain
  every official helper, matched by `(chain, address)`.
- Canonical addresses come from a deterministic deployment factory, so the
  address commits to the bytecode. Still, the registry records which chains
  each deployment type exists on, and the tool should match per chain.
  zkSync-style chains use different addresses.

### 3.1 MultiSend packed format

`multiSend(bytes transactions)` (selector `0x8d80ff0a`). `transactions` is a
concatenation, with no padding, of:

| Bytes | Field |
|---|---|
| 1 | `operation` (`0` call, `1` delegatecall) |
| 20 | `to` |
| 32 | `value` |
| 32 | `dataLength` |
| `dataLength` | `data` |

The contract loop (`MultiSend.sol`) reads `mload` words without checking
bounds: a truncated trailing entry reads memory past the end of the buffer
instead of being rejected. An `operation` byte other than 0/1 matches neither
`case`, so `success` stays 0 and the whole batch reverts. `blindsight` must be
**stricter than the contract**: any truncation, length overflow, or
operation byte other than 0/1 is a decoding error, reported as such.

Differences:

| | MultiSend | MultiSendCallOnly |
|---|---|---|
| Inner `operation = 1` | executes delegatecall | reverts |
| Must be called via delegatecall | yes (`require(address(this) != multisendSingleton)`, present in 1.1.1 and later) | no check |

### 3.2 Migration contracts

| Contract | Functions (selector) | Guards |
|---|---|---|
| `SafeMigration` (1.4.1, 1.5.0) | `migrateSingleton()` `0xf6682ab0`, `migrateWithFallbackHandler()` `0xed007fc6`, `migrateL2Singleton()` `0x07f464a4`, `migrateL2WithFallbackHandler()` `0x68cb3d94` | delegatecall only; target singleton fixed at deploy time |
| `SafeToL2Migration` (1.4.1) | `migrateToL2(address)` `0xef2624ae`, `migrateFromV111(address,address)` `0xd9a20812` | delegatecall only; nonce must be 0 |
| `SafeToL2Setup` (1.4.1, 1.5.0) | `setupToL2(address)` `0xfe51f643` | delegatecall only; nonce must be 0; used at setup |

## 4. Off-chain messages (stretch)

`SafeMessage(bytes message)` typehash `0x60b3cbf8b4a223d68d641b3b6ddf9a298e7f33710cf3d3a9d1146b5a6150fbca`.
`getMessageHash(message) = keccak256(0x19 0x01 ‖ domainSeparator ‖ keccak256(abi.encode(SAFE_MSG_TYPEHASH, keccak256(message))))`.
`SignMessageLib.signMessage(bytes)` (delegatecall) stores this hash as signed
on-chain. Not in scope for v1; documented for a future `message` command.

## 5. Transaction Service JSON

Fields returned by `GET /api/v1/multisig-transactions/{safeTxHash}/` that feed
the hash (observed on live API responses):

```
safe, to, value (string), data (hex or null), operation (int), gasToken, safeTxGas (int),
baseGas (int), gasPrice (string), refundReceiver, nonce (int), safeTxHash
```

`data: null` means empty calldata. Numeric fields mix JSON numbers and strings,
so the parser must accept both. The service also returns `dataDecoded`, which
`blindsight` must ignore: it is produced by the same infrastructure the threat
model distrusts.

## 6. Existing tools

All of these tools exist because of the same problem, and `blindsight` builds
on their ideas. Inspected at the revisions noted.

### `safe-tx-hashes-util` (pcaversaccio), Bash, `65d8077`
- Computes domain hash, message hash and safeTxHash for transactions and
  off-chain messages; supports nested Safes (`approveHash`) and an interactive
  mode for manual input; optional simulation via an RPC.
- Fetches transactions from the Safe Transaction Service and relies on Foundry
  `cast` and `curl`. Warnings come from the service's `dataDecoded`.
- Warnings: untrusted delegatecall (hardcoded allowlist of MultiSendCallOnly,
  SafeMigration, SignMessageLib addresses), owner/threshold changes (also inside
  batches), non-zero gas token / refund receiver.
- The reference for the community; Safe's own help center links to it.

### `safe-hash` (Cyfrin `safe-hash-rs`), Rust, `7b70ae7`
- Fork/port of the above in Rust. Commands `tx`, `msg`, `typed`. Has an
  `--offline` flag and nested-Safe support. Distributed with `cargo-dist`.
- Depends on the `alloy` umbrella crate, `reqwest` and `tokio`: the binary
  contains an HTTP client; offline is a mode, not a property of the build.
- Warnings: delegatecall, non-zero gas token/refund receiver, a list of
  owner/threshold methods, mismatch between user arguments and API data, and
  an Etherscan "verified contract" check (online).

### `op-txverify` (Optimism), Go, `6b405be`
- Parses and presents Safe transactions, labels known addresses, decodes
  MultiSend and Multicall3 batches, supports `approveHash` nesting.
- Air-gap oriented: a phone page plus QR code transfer to the verifying
  machine. Fetches transactions from the Safe service; the web page reads the
  preimage from the contract via RPC (so no 1.5.0 support there).
- Limited chain set (Ethereum, OP Mainnet, Base, Sepolia on the page).

### `safe-utils` (OpenZeppelin), web UI
- Web front-end inspired by the Bash script, using the Transaction Service.

### Official resources
- Safe help center: "How to verify Safe{Wallet} transactions on a hardware
  wallet" recommends comparing domain and message hashes on the device and
  points to the Bash script.

### What `blindsight` adds (honest differentiation)

`blindsight` is not the first offline tool, nor the first in Rust. Its
concrete differences, each verifiable in the code:

1. **Offline by construction, enforced by policy.** No network crate in the
   dependency tree (`cargo-deny` bans) and a CI job that runs the test suite in
   a network namespace with no interfaces. Other tools can run offline; this
   one cannot do anything else.
2. **Severity-ranked detectors with stable IDs**, per-detector documentation,
   and exit codes, so the tool can gate scripts and CI (`--fail-on`).
3. **Local recursive decoding** of MultiSend batches and nested Safe
   transactions (`execTransaction` / `approveHash` inside calldata), with
   detectors applied at every level. Decoding never comes from a remote
   service.
4. **Explicit "unverified semantics" labelling.** A selector match on an
   unknown contract is presented as a guess, never as fact. This is exactly
   the Bybit and WazirX shape (`transfer`-like selector, unknown target,
   delegatecall).
5. **Address-poisoning check** against a user-supplied address book; addresses
   and hashes are never truncated.
6. **Raw `execTransaction` calldata as input**, for post-mortems of already
   executed transactions.
7. **Terminal output sanitisation** against ANSI/control-character injection
   from decoded strings and user files.
8. **Test vectors validated three ways** (official service, on-chain
   attestation, independent recomputation) across 8 chains and 5 versions.

## 7. Open points

- **v1.2.0 vectors**: no executed v1.2.0 transaction was found in the sample.
  1.2.0 uses the same typehash and domain as 1.1.1 (verified in source), which
  is covered by three Bybit vectors. A v1.2.0 vector would be nice to have.
- **v0.1.0**: not listed in `safe-deployments`. Hashing support would rest on
  the source alone, without a real vector. Decision: not supported;
  `--safe-version 0.1.0` is rejected as an input error.
- **Trezor Model One** (legacy firmware): not checked in source; documented as
  unverified.
