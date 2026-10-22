# BS-GUARD-001: Transaction or module guard change

**Severity:** high

## What it detects

`setGuard(g)` (1.3.0+) or `setModuleGuard(g)` (1.5.0+) called on the Safe that executes it. The text distinguishes setting a guard from removing one (`g = 0`) and notes when the root Safe's version lacks the function (the call would reach the fallback handler).

## Why it matters

A guard runs before and after every transaction and can block all of them: a faulty or malicious guard bricks the Safe. Removing a guard drops whatever protection it enforced.

## Example

`multisend-set-guard` fixture.

## Related incidents

None recorded.

## Known false positives and limits

Planned guard installation or removal.
