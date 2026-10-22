# Detector catalog

Status: **approved** (2026-10-22). Each detector gets its own page
`docs/detectors/<ID>.md` when it is implemented.

## Conventions

- **Severities:** `critical` > `high` > `medium` > `low` > `info`. The report
  verdict is the highest severity found. `--fail-on` (default `high`) sets the
  exit-code threshold.
- **Call tree.** Detectors run on every node of the decoded call tree: the
  top-level `SafeTx`, every MultiSend item, and every nested Safe transaction.
  Each finding carries the path of the node (`root`, `batch[2]`,
  `batch[2] > nested > batch[0]`, …). A detector that only looked at the root
  would be bypassed by wrapping the payload in a batch.
- **Trusted helpers** = contracts in `data/safe_deployments.json` with role
  `multi_send`, `multi_send_call_only`, `sign_message_lib`, `create_call`,
  `migration` or `l2_setup`, matched by `(chain_id, address)`. The Safe's own
  version is irrelevant: real Safes use helpers from other versions (fixtures
  `bsc-multisend-130-from-safe-141`, `v100-delegatecall-token-refund`).
- **Known target** = address in the embedded registry (official Safe contracts,
  curated tokens) or in the user's address book.
- Detectors are pure functions of the decoded tree and the context
  (version, chain, registry, address book, current nonce). No I/O.

## Summary

| ID | Title | Severity | Status | Incident |
|---|---|---|---|---|
| `BS-DELEGATE-001` | Delegatecall to an untrusted contract | critical | stable | Bybit, WazirX |
| `BS-DELEGATE-002` | Delegatecall inside a batch | critical / medium / info | stable | — |
| `BS-SEMANTICS-001` | Function name is a guess (target not verified for that function) | low; critical under delegatecall | stable | Bybit |
| `BS-OWNERS-001` | Owner set change | high; critical if resulting threshold is 1 | stable | — |
| `BS-THRESHOLD-001` | Threshold change | high; critical if new threshold is 1 | stable | — |
| `BS-MODULE-001` | Module enabled / disabled | critical (enable) / medium (disable) | stable | — |
| `BS-GUARD-001` | Transaction guard or module guard change | high | stable | — |
| `BS-FALLBACK-001` | Fallback handler change | high; low if official handler | stable | — |
| `BS-IMPL-001` | Implementation (singleton) change | critical; info if official migration | stable | Bybit, WazirX |
| `BS-REFUND-001` | Gas refund paid by the Safe | medium / high; low if inert | stable | — |
| `BS-APPROVAL-001` | Unlimited or operator approval | high | stable | — |
| `BS-VALUE-001` | Native value transfer | info; high with delegatecall | stable | — |
| `BS-POISON-001` | Address looks like an address-book entry | high | stable | — |
| `BS-TARGET-001` | Unknown target | info | stable | Bybit, WazirX |
| `BS-DECODE-001` | Undecodable or malformed calldata | medium | stable | WazirX |
| `BS-SELF-001` | Call to the Safe itself | info; medium if selector unknown | stable | — |
| `BS-NONCE-001` | Suspicious nonce | medium | stable | — |
| `BS-NESTED-001` | Nested Safe transaction or opaque hash approval | info / high | stable | — |
| `BS-REPLAY-001` | Domain without chain id (pre-1.3.0) | low | stable | — |
| `BS-APPROVAL-002` | Permit2 allowance | high | experimental | — |

## Detectors

### `BS-DELEGATE-001` — Delegatecall to an untrusted contract
- **Severity:** critical.
- **Logic:** any node with `operation = 1` whose `to` is not a trusted helper
  on this chain.
- **Rationale:** a delegatecall runs foreign code with the Safe's storage. It
  can rewrite owners, threshold, modules, guard and the implementation pointer
  in slot 0. There is no "safe" unknown delegatecall target.
- **Incidents:** Bybit (`to = 0x9622…7242`), WazirX (`to = 0xfbfF…CAF2`).
- **False positives:** legitimate libraries meant for delegatecall that are not
  Safe-official (e.g. Zodiac or protocol-specific helpers). No override
  flag in v1; the finding text says how to verify the target.

### `BS-DELEGATE-002` — Delegatecall inside a batch
- **Logic** for every MultiSend item with `operation = 1`:
  - target not a trusted helper → **critical** (in addition to `BS-DELEGATE-001`);
  - target is a trusted helper (e.g. a nested MultiSend) → **medium** (unusual,
    worth a second look);
  - the batch is executed by `MultiSendCallOnly` → **info**: this item makes
    the whole batch revert.
- **Rationale:** `MultiSendCallOnly` exists to forbid exactly this; a
  delegatecall buried in item 7 of 12 is easy to miss in a UI.

### `BS-SEMANTICS-001` — Function name is a guess
- **Logic:** the selector matches a known function (e.g. `transfer`), but the
  target is not a known contract for that function (not a registry token for
  ERC-20 functions, not the Safe itself for admin functions, not a trusted
  helper for MultiSend/migrations). Severity **low** for `operation = 0`;
  **critical** for `operation = 1`.
- **Rationale:** a selector only describes the argument layout. Any contract
  can implement `transfer(address,uint256)` to do anything. The Bybit payload
  was `transfer(0xbDd0…9516, 0)` executed by delegatecall: it overwrote the
  implementation. The decoded call is always printed with a
  `verified` / `unverified (selector match only)` label; this detector makes the
  unverified case a finding.

### `BS-OWNERS-001` — Owner set change
- **Logic:** call to `addOwnerWithThreshold`, `removeOwner` or `swapOwner` on
  the Safe itself (any depth). **High**; **critical** when the resulting
  threshold argument is 1.
- **Output:** owners added/removed/replaced (full addresses, address-book names
  when known) and the new threshold. `removeOwner`/`swapOwner` take a
  `prevOwner` linked-list pointer, shown for completeness.

### `BS-THRESHOLD-001` — Threshold change
- **Logic:** `changeThreshold(n)` on the Safe. **High**; **critical** if `n == 1`.
- **Note:** the current owner count is not known offline, so the tool cannot
  tell whether `n` is valid; the contract reverts if it is not.

### `BS-MODULE-001` — Module enabled or disabled
- **Logic:** `enableModule(m)` → **critical**; `disableModule(prev, m)` →
  **medium**.
- **Rationale for critical** (the brief suggested high): an enabled module
  executes transactions, including delegatecalls, with **no owner
  signatures**. Its power equals an untrusted delegatecall. Disabling is lower
  risk but can remove a recovery or security module.

### `BS-GUARD-001` — Guard change
- **Logic:** `setGuard(g)` (1.3.0+) or `setModuleGuard(g)` (1.5.0+) → **high**.
  The text distinguishes setting a guard (it can block every future transaction
  and brick the Safe) from removing one (`g = 0`, drops a protection).

### `BS-FALLBACK-001` — Fallback handler change
- **Logic:** `setFallbackHandler(h)` → **high**; **low** if `h` is an official
  fallback handler in the registry. The handler receives every call to the Safe
  that matches no function (e.g. EIP-1271 `isValidSignature`), so a malicious
  one can make the Safe "sign" arbitrary messages.

### `BS-IMPL-001` — Implementation change
- **Logic:**
  - `changeMasterCopy(x)` on a ≤1.2.0 Safe → **critical** unless `x` is an
    official singleton, then **info** (highlighted, names the version);
  - delegatecall to an official migration contract (`SafeMigration`,
    `SafeToL2Migration`, `SafeToL2Setup`) → **info** (highlighted, says the
    implementation will change and to what);
  - delegatecall to anything untrusted is already critical under
    `BS-DELEGATE-001`; the text explains that this includes replacing slot 0.

### `BS-REFUND-001` — Gas refund
- **Logic (root `SafeTx` only):**
  - `gasPrice > 0` and `gasToken = 0` → **medium** (1.3.0+, native refund is
    capped by the executor's gas price) or **high** (< 1.3.0, uncapped);
  - `gasPrice > 0` and `gasToken ≠ 0` → **high** (paid in tokens, never capped);
  - `gasPrice = 0` but `gasToken`, `refundReceiver` or `baseGas` non-zero →
    **low** (inert, but not what any normal UI produces).
- **Output:** the formula `(gasUsed + baseGas) × price`, the guaranteed minimum
  `baseGas × gasPrice`, who receives it (`refundReceiver`, or **whoever submits
  the transaction** when zero), and the fact that the executor chooses
  `gasUsed` via the gas limit. Also: with `safeTxGas ≠ 0` or `gasPrice ≠ 0`
  the inner call may fail and the nonce is still consumed and the refund paid
  (`GS013` logic).

### `BS-APPROVAL-001` — Unlimited or operator approval
- **Logic:**
  - ERC-20 `approve(spender, amount)` or `increaseAllowance(spender, amount)`
    with `amount ≥ 2^255` → **high** ("unlimited"; covers `U256::MAX` and
    "max-ish" values). Smaller amounts: **info**, showing the amount (with
    decimals when the token is known);
  - `setApprovalForAll(operator, true)` → **high**; `false` → info.
- **Edge cases tested:** `U256::MAX`, `U256::MAX − 1`, `2^255`, `2^255 − 1`.

### `BS-APPROVAL-002` — Permit2 allowance (experimental)
- **Logic:** call to the canonical Permit2 contract's `approve(token, spender,
  amount, expiration)` with `amount = 2^160 − 1` → **high**. The Permit2
  address and ABI will be verified against Uniswap's source before
  implementation; until then this stays experimental.

### `BS-VALUE-001` — Native value
- **Logic:** `value > 0` → **info**, formatted with 18 decimals and the chain's
  native symbol; with `operation = 1` → **high**: delegatecall ignores `value`
  (verified in `Executor.sol`), so a non-zero value there means the transaction
  was not built by a normal UI.

### `BS-POISON-001` — Address looks like an address-book entry
- **Requires** `--address-book`.
- **Logic:** for every address in the tree (targets, decoded address
  arguments, `refundReceiver`, `gasToken`): not equal to any book entry, but
  its first 4 and last 4 hex digits (case-insensitive) equal those of an entry
  → **high**, naming the entry it imitates.
- **Rationale:** address poisoning relies on UIs and humans checking only the
  start and end. `blindsight` never truncates addresses.

### `BS-TARGET-001` — Unknown target
- **Logic:** `to` of any node is neither in the registry nor the address book
  → **info**.

### `BS-DECODE-001` — Undecodable calldata
- **Logic:** non-empty `data` whose selector is not in the built-in signature
  list or a user ABI (`--abi`) → **medium**; `data` shorter than 4 bytes but
  non-empty → **medium** (malformed); MultiSend payload that fails strict
  unpacking → **high** (the batch cannot be shown faithfully).
- **Rationale:** signing calldata you cannot read is blind signing.

### `BS-SELF-001` — Call to the Safe itself
- **Logic:** `to == safe` → **info** ("administrative operation"), alongside the
  specific detectors. If the selector is not a Safe function → **medium**: the
  call will be routed to the fallback handler.

### `BS-NONCE-001` — Suspicious nonce
- **Requires** `--current-nonce`.
- **Logic:** `nonce < current` → **medium** (already used; this transaction
  can never execute, so why sign it?); `nonce > current + 3` → **medium**
  (pre-signed future transaction that will stay valid until executed);
  `current < nonce ≤ current + 3` → info (queued).

### `BS-NESTED-001` — Nested Safe transaction / hash approval
- **Logic:**
  - calldata is `execTransaction` on another address → **info**, decoded
    recursively; detectors run on the inner transaction;
  - calldata is `approveHash(h)` → **high** ("you are approving an opaque
    hash") unless the user supplies the inner transaction and its computed
    safeTxHash equals `h`, then **info**;
  - nesting deeper than the limit (4 levels) → **high**: the inner
    part was not analysed.

### `BS-REPLAY-001` — Domain without chain id
- **Logic:** Safe version < 1.3.0 → **low**: the signature is valid on every
  chain where a Safe with this address and nonce exists.

## Ideas considered and not proposed

- **Simulation-based checks** (balance changes): need chain state; out of
  scope (offline). The README recommends simulation as a complementary layer.
- **"Large transfer" thresholds**: need prices; any fixed number would be
  arbitrary.
