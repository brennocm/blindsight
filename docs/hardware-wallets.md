# What hardware wallets show when signing a Safe transaction

A Safe owner signs the EIP-712 hash of a `SafeTx`. What the device shows
decides what the owner can actually check. This page records what the firmware
source code shows, so `blindsight` can print the same labels and formats.

Checked against firmware source on 2026-10-22. Device behaviour depends on
firmware version, settings, and how the wallet software sends the request, so
treat this as a guide and always compare against your own screen.

## Summary

| Device / firmware | Shows domain hash | Shows message hash | Format | Shows decoded fields |
|---|---|---|---|---|
| Ledger, Ethereum app (Nano S+/X, Stax, Flex, Apex) | yes, label **`Domain hash`** | yes, label **`Message hash`** | `0x` + 64 **upper-case** hex digits | only if the dApp provides EIP-712 filters (clear signing) |
| Trezor, core firmware (Model T, Safe 3/5/7) | no | optional, title **`Confirm message hash`** | `0x` + 64 lower-case hex digits | yes: domain fields (`Confirm domain`) and, on request, every struct field (`Show full message`) |
| Trezor Model One | not verified | not verified | | |
| Any device when the owner signs with `eth_sign` | no | no | a single 32-byte hash (the safeTxHash), as a personal message | no |

`blindsight` therefore prints domain and message hashes in two forms:
lower-case (as wallets, explorers and the Safe UI print them) and Ledger's
upper-case form, so the owner can compare character by character.

## Ledger

Source: [LedgerHQ/app-ethereum](https://github.com/LedgerHQ/app-ethereum) at `f7985b42`.

- `src/features/sign_message_eip712_common/common_712.c`, `eip712_format_hash()`:
  sets the pair labels `"Domain hash"` and `"Message hash"` and formats each
  32-byte value with `array_bytes_string`.
- `array_bytes_string` (`ethereum-plugin-sdk/src/common_utils.c`) writes `"0x"`
  followed by `format_hex` from the Ledger SDK
  (`ledger-secure-sdk/lib_standard_app/format.c`), which uses the alphabet
  `"0123456789ABCDEF"`. Hence **upper-case** hex.
- When are the hashes shown?
  - In the legacy flow (`ui_sign_712_v0`, `src/nbgl/ui_sign_712.c`), the hashes
    are the only thing shown. This is the blind-signing path when no EIP-712
    descriptor is available.
  - In the full flow (`eip712_v1_ui_logic.c`), the hashes are appended after the
    decoded fields when the setting **"Transaction hash" → "Always display the
    transaction or message hash"** (`N_storage.displayHash`) is enabled.
- Blind signing must be enabled in the app settings for messages the app cannot
  clear-sign ("Blind signing must be enabled in settings").
- Ledger launched a Safe-specific clear-signing product (Ledger Multisig) in
  October 2025, per Ledger's own announcements. Not verified in source here.

## Trezor (core firmware)

Source: [trezor/trezor-firmware](https://github.com/trezor/trezor-firmware) at `cb8197d1`,
`core/src/apps/ethereum/sign_typed_data.py` and `layout.py`.

- The device rebuilds the hash itself from the full typed data
  (`ethereumSignTypedData`), so it can show the actual fields.
- Domain members are confirmed together under **`Confirm domain`**. For a Safe
  that is `chainId` (1.3.0+) and `verifyingContract`, i.e. the Safe address.
- The struct can be displayed field by field (`Show full message`), so the owner
  can read `to`, `value`, `data`, `operation`, the gas fields and `nonce`.
- If the host sends `show_message_hash`, the device checks it equals its own
  computation (`"Message hash mismatch"` otherwise) and displays it under
  **`Confirm message hash`** as `"0x" + message_hash.hex()` (Python's `.hex()`
  is lower-case).
- The domain hash and the final safeTxHash are not displayed.

What to compare on a Trezor: the Safe address and chain id in `Confirm domain`,
every field of the struct, and the message hash when it is shown.

## Hash only (`eth_sign`)

If the wallet software asks the device to sign the safeTxHash as a personal
message (`eth_sign`, signature `v > 30` on chain), the device can only show a
32-byte value. This is what happened in the Bybit attack: all three
signatures on the attack transaction are `eth_sign` signatures (see
`docs/incidents.md`). In that case the only possible check is comparing the
**safeTxHash** shown by the device with the one `blindsight` computes.

## How to compare (summary for the README)

1. Run `blindsight` on a different machine from the one that prepared the
   transaction, with the parameters you expect.
2. On the device, compare the **Domain hash** and **Message hash** (Ledger),
   or the domain fields, struct fields and message hash (Trezor), with
   `blindsight`'s output. On a Ledger, use the upper-case line.
3. Every character must match. A single different character means a different
   transaction.
4. A matching hash proves that you are signing the transaction you gave
   `blindsight`. It says nothing about whether that transaction is safe: read
   the decoded calls and the findings.
