# BS-DELEGATE-002: Delegatecall inside a batch

**Severity:** critical / medium / info

## What it detects

For every entry of a `multiSend` batch with `operation = 1`: **info** if the batch is executed by the official `MultiSendCallOnly` (the entry makes the whole batch revert); **critical** if the entry's target is not an official helper; **medium** if it is an official helper.

## Why it matters

`MultiSendCallOnly` exists to forbid delegatecall entries. With `MultiSend`, a delegatecall in entry 7 of 12 is easy to miss in an interface and has the full power described in `BS-DELEGATE-001`.

## Example

A `MultiSend` batch whose third entry delegatecalls an unknown address.

## Related incidents

None recorded; the pattern is the batched form of the Bybit and WazirX takeovers.

## Known false positives and limits

Batches that intentionally nest official helpers (a `MultiSend` delegatecalling `SignMessageLib`). These get medium, not critical.
