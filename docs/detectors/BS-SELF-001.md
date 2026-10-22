# BS-SELF-001: Call to the Safe itself

**Severity:** info; medium if the function is not a Safe function

## What it detects

A call (not delegatecall) from a Safe to its own address: info for Safe administrative functions or an empty call, medium for anything else.

## Why it matters

Calls to the Safe itself are how it changes its own configuration; the specific detectors describe what changes. A selector that is not a Safe function is routed to the fallback handler, whose behaviour depends on the installed handler.

## Example

`change-threshold` fixture (info, with `BS-THRESHOLD-001`).

## Related incidents

None recorded.

## Known false positives and limits

Handler-specific functions used on purpose (medium).
