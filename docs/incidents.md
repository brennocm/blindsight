# Incidents

Only incidents whose malicious Safe transaction could be confirmed **on chain**
are listed. For each one: what the public reports say, what the chain says,
and which `blindsight` detectors would have fired. The detector IDs refer to
the catalog in `docs/detectors/CATALOG.md`.

On-chain facts below were read directly from an Ethereum archive node and the
Safe Transaction Service, and the safeTxHash was recomputed independently
(`tests/fixtures/real/bybit.json`, `tests/fixtures/real/wazirx.json`).
Narrative claims are attributed to their sources.

## Bybit, 21 February 2025 (~US$1.5 billion)

### What the reports say

- **FBI PSA I-022625-PSA** (26 Feb 2025): North Korea ("TraderTraitor") was
  responsible for the theft of approximately US$1.5 billion from Bybit on or
  about 21 February 2025. <https://www.ic3.gov/PSA/2025/PSA250226>
- **Sygnia**, "Bybit – What We Know So Far": malicious JavaScript was served to
  the signers from the S3 bucket behind the Safe{Wallet} web app
  (`app.safe.global`). It activated only for specific Safe addresses, swapped
  the transaction content for hardcoded parameters, and was removed about two
  minutes after the malicious transaction executed. The injected code was found
  in the browser caches of all three signers.
  <https://www.sygnia.co/blog/sygnia-investigation-bybit-hack/>
- **Safe{Wallet} statement** (with Mandiant), as reported by the press: a Safe
  developer's machine was compromised and AWS session tokens were hijacked.
  Coverage: <https://thehackernews.com/2025/03/safewallet-confirms-north-korean.html>
- **NCC Group** technical analysis of the transaction and the attacker contract:
  <https://www.nccgroup.com/research/in-depth-technical-analysis-of-the-bybit-hack/>

In short: the signers' interface showed a routine transfer, while the data
sent to their wallets for signing was a different transaction.

### What the chain says

| Field | Value |
|---|---|
| Safe | `0x1Db92e2EeBC8E0c075a02BeA49a2935BcD2dFCF4` (Ethereum) |
| Version | `1.1.1` (`VERSION()` at block 21895237; singleton `0x34CfAC646f301356fAa8B21e94227e3583Fe3F5F`, the official 1.1.1 GnosisSafe) |
| Threshold | 3 |
| Execution tx | `0x46deef0f52e3a983b67abf4714448a41dd7ffd6d32d32da69d62081c68ad7882`, block 21895238, 2025-02-21 14:13:35 UTC |
| `to` | `0x96221423681A6d52E184D440a8eFCEbB105C7242` (not an official Safe contract) |
| `value` | 0 |
| `data` | `0xa9059cbb` + `0xbDd077f651EBe7f7b3cE16fe5F2b025BE2969516` + `0` — shaped like `transfer(address,uint256)` |
| `operation` | **1 (DELEGATECALL)** |
| `safeTxGas` | 45746; other gas fields 0 |
| `nonce` | 71 |
| Domain hash | `0xb3ded2bdbff5db1a87f6d551fa256e9f2bd6517a3bb84f4c2ea863fb3a559622` |
| Message hash | `0xea68fc75e93bf7286b1257680ca8e2033bfadd8e1cb8a23f3ca18f1031ecf1e0` |
| safeTxHash | `0xb3476d061aeb8fc1d605a873c483a2402d88a68a9cdd1a8b47655dd55ba004f8` (matches the `ExecutionSuccess` event and the Transaction Service) |
| Signatures | 3 × `eth_sign` (`v > 30`), recovering to owners `0x1F4EB0a903619ac168b19A82F1a6e2e426522211`, `0x3Cc3A225769900e003E264dd4CB43E90896BC21A`, `0xe3dF2cCEAc61B1aFA311372ecC5B40A3A6585a9E` |
| Storage slot 0 | before: `0x34CfAC646f301356fAa8B21e94227e3583Fe3F5F` (official 1.1.1 singleton); after: `0xbDd077f651EBe7f7b3cE16fe5F2b025BE2969516` |

The three preceding transactions (nonces 68–70) were plain ETH transfers to
`0xf89d7b9c864f589bbF53a82105107622B35EaA40` (30,000, 30,000 and 60,000 ETH);
nonce 70 is fixture `bybit-legit-nonce70`. The attack transaction kept the
same shape (`to`, `value`, `data`) only in the UI.

### How the attack worked

1. The Safe is a proxy whose implementation address lives in storage slot 0.
2. With `operation = 1`, the Safe `DELEGATECALL`s `to`: the attacker's code runs
   **with the Safe's storage**.
3. The attacker contract's `transfer(address,uint256)` writes its first
   argument into slot 0 (NCC Group's decompilation: `stor0 = _to`). The
   `transfer` name was camouflage; the selector only says how arguments are
   laid out, not what the code does.
4. After execution, slot 0 points to `0xbDd0…9516`, which per Sygnia exposed
   `sweepETH` / `sweepERC20` functions. The attacker then drained the wallet
   without needing any signature.
5. The signers signed with `eth_sign`, so their devices could display at most
   the 32-byte safeTxHash.

### What `blindsight` would have said

Given the parameters the signers' wallets were actually asked to sign:

| Detector | Severity | Why it fires |
|---|---|---|
| `BS-DELEGATE-001` untrusted delegatecall | **critical** | `operation = 1` to `0x9622…7242`, not an official Safe helper on chain 1 |
| `BS-SEMANTICS-001` function name is a guess | **critical** (delegatecall) | selector `0xa9059cbb` looks like ERC-20 `transfer`, but the target is not a known token; under delegatecall it is not a token transfer at all |
| `BS-TARGET-001` unknown target | info | target not in registry or address book |
| `BS-REPLAY-001` domain without chain id | low | the Safe is version 1.1.1 |

The report also lists the three signatures of the executed transaction as
`eth_sign` (`v = 31`). Verdict line: `CRITICAL: DO NOT SIGN without
independent review`. Independently, the safeTxHash that `blindsight` prints
for the *intended* transaction (a transfer to the warm wallet, nonce 71) would
not have matched the hash the wallets were signing.

This transaction is the regression test of the project
(`tests/fixtures/real/bybit.json`).

## WazirX, 18 July 2024 (~US$230 million)

### What the reports say

- WazirX's Ethereum multisig was managed through the custody provider Liminal,
  with Ledger devices for WazirX's signers. **Liminal** said its infrastructure
  was not breached and blamed compromised WazirX devices; WazirX attributed the
  incident to a discrepancy between what Liminal's interface showed and the
  transaction actually signed. Coverage of both statements:
  <https://cryptoslate.com/liminal-says-infrastructure-was-not-responsible-for-wazirx-hack-blames-compromised-devices/>
- Analysis of the drain and the contract upgrade: <https://rekt.news/wazirx-rekt>

The primary statements disagree on root cause. What is not in dispute, and
what the chain shows, is the transaction that was signed.

### What the chain says

| Field | Value |
|---|---|
| Safe | `0x27fD43BABfbe83a81d14665b1a6fB8030A60C9b4` (Ethereum) |
| Version | `1.3.0` (singleton `0xd9Db270c1B5E3Bd161E8c8503c55cEABeE709552`, official) |
| Threshold | 4 |
| Execution tx | `0x48164d3adbab78c2cb9876f6e17f88e321097fcd14cadd57556866e4ef3e185d`, block 20331565, 2024-07-18 06:17:47 UTC |
| `to` | `0xfbfFEF83b1C172fE3BC86C1CCB036AB9F3efCAF2` (not an official Safe contract) |
| `data` | `0x804e1f0a` + `0xef279c2ab14960aa319008cbea384b9f8ac35fc6` (selector not in common signature lists) |
| `operation` | **1 (DELEGATECALL)** |
| Gas fields | all 0 |
| `nonce` | 1718 |
| Domain hash | `0xa630c4b736c54422250992ab01205a95e6824e0c34a2ab8d4406521b3d6da09a` |
| Message hash | `0x7cd839f0a7ba33ab90b769cb93dc0aca579aad246b996db5cf34a4f31b7024e0` |
| safeTxHash | `0x4e82121a3bc2fb62c0b06ab5fff5ca965ceab4f51cc949c6e50d85ed63e6aa70` (matches event and Transaction Service) |
| Signatures | 3 × `eth_sign` + 1 approved-hash from the executing owner `0xd967113224C354600B3151E27Aaba53e3034f372` |
| Storage slot 0 | before: `0xd9Db270c1B5E3Bd161E8c8503c55cEABeE709552` (official 1.3.0 singleton); after: `0xef279c2ab14960aa319008cbea384b9f8ac35fc6` |

Same pattern as Bybit, seven months earlier: delegatecall to an unknown
contract that replaces the implementation in slot 0.

### What `blindsight` would have said

| Detector | Severity |
|---|---|
| `BS-DELEGATE-001` untrusted delegatecall | **critical** |
| `BS-DECODE-001` undecodable calldata | medium |
| `BS-TARGET-001` unknown target | info |

Both results are pinned by the regression tests in `tests/detect.rs`.

Regression fixture: `tests/fixtures/real/wazirx.json`.

## Considered but not included

- **Radiant Capital (October 2024).** Reports (Radiant's post-mortem with
  Mandiant, as covered by the press) describe malware on signers' machines
  showing legitimate transactions while devices signed a `transferOwnership`
  of the lending pool contracts. The malicious multisig transaction was not
  located and verified on chain for this document, so it is not included yet.
