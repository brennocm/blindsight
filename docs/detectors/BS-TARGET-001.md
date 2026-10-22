# BS-TARGET-001: Unknown target

**Severity:** info

## What it detects

Any call whose target is not the executing Safe, an official Safe contract, a listed token, Permit2 or an address-book entry.

## Why it matters

Most risks come from what the target does. An unknown target is not a problem by itself, but it is what to verify first.

## Example

`unknown-selector-call` fixture.

## Related incidents

Bybit and WazirX: both targets were unknown contracts.

## Known false positives and limits

Every legitimate contract not in the registry. Add trusted targets to the address book to label them.
