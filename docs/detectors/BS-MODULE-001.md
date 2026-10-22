# BS-MODULE-001: Module enabled or disabled

**Severity:** critical (enable), medium (disable)

## What it detects

`enableModule(m)` (critical) or `disableModule(prev, m)` (medium) called on the Safe that executes it.

## Why it matters

An enabled module can execute any transaction from the Safe, delegatecalls included, with no owner signature: its power equals an untrusted delegatecall. This is stricter than the original proposal (high) for that reason. Disabling a module is lower risk but can remove a recovery or security mechanism.

## Example

`multisend-enable-module` fixture: a batch that disables one module and enables another.

## Related incidents

None recorded.

## Known false positives and limits

Installing audited modules (Zodiac roles, allowance modules). The finding is still critical: enabling a module must be a deliberate, reviewed decision.
