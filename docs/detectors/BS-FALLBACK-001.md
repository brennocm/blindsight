# BS-FALLBACK-001: Fallback handler change

**Severity:** high; low if the handler is official

## What it detects

`setFallbackHandler(h)` called on the Safe that executes it. Low if `h` is an official fallback handler on this chain.

## Why it matters

The fallback handler receives every call to the Safe that matches no Safe function, including EIP-1271 `isValidSignature`. A malicious handler can make the Safe appear to sign arbitrary messages to other protocols. Removing it breaks contract signatures and token callbacks.

## Example

`setFallbackHandler(0x…)` to an unknown contract.

## Related incidents

None recorded.

## Known false positives and limits

Custom handlers deployed by the Safe's own team.
