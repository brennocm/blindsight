# BS-DECODE-001: Undecodable or malformed calldata

**Severity:** medium; high for a malformed batch

## What it detects

A selector that is neither in the built-in table nor in a `--abi` file (medium); data shorter than 4 bytes (medium); a known selector whose arguments do not decode, including dirty high bytes (medium); a `multiSend` payload that cannot be unpacked strictly (high).

## Why it matters

Signing calldata you cannot read is blind signing. A malformed batch is worse: the contract reads it without bounds checks, so what executes may differ from any display of it.

## Example

WazirX: selector `0x804e1f0a` on an unknown contract.

## Related incidents

WazirX (July 2024).

## Known false positives and limits

Calls to contracts whose ABI is not available. Pass it with `--abi ADDRESS=FILE`.
