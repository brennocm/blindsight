# BS-THRESHOLD-001: Threshold change

**Severity:** high; critical if the new threshold is 1

## What it detects

`changeThreshold(n)` called on the Safe that executes it.

## Why it matters

The threshold is the number of owner signatures needed. Lowering it weakens the Safe; 1 means any single key controls it. The current number of owners is not known offline; the contract reverts if `n` exceeds it or is 0.

## Example

`changeThreshold(1)` (critical).

## Related incidents

None recorded.

## Known false positives and limits

Planned governance changes.
