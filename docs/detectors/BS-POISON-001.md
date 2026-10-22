# BS-POISON-001: Address looks like an address-book entry

**Severity:** high

## What it detects

With `--address-book`: any address in the call (target, decoded address arguments, refund fields) that is not in the book but has the same first four and last four hex digits (case-insensitive) as an entry.

## Why it matters

Address poisoning plants look-alike addresses in a victim's history, betting that people and interfaces compare only the start and end. blindsight never shortens addresses and compares all 40 digits.

## Example

Book entry `Treasury = 0x1Db9…FCF4`; the transaction sends to `0x1db9000000000000000000000000000000dafcf4`.

## Related incidents

Repeated address-poisoning thefts of large transfers (2023–2025).

## Known false positives and limits

Vanity addresses that happen to share both ends with an entry (rare).
