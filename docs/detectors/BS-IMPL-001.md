# BS-IMPL-001: Implementation (singleton) change

**Severity:** critical; info for official singletons and migrations

## What it detects

`changeMasterCopy(x)` on the executing Safe (1.2.0 and earlier): critical unless `x` is an official singleton, then info. A delegatecall to an official migration contract (`SafeMigration`, `SafeToL2Migration`, `SafeToL2Setup`): info, stating that the implementation changes. Any other way to change the implementation is a delegatecall to an untrusted contract, already critical under `BS-DELEGATE-001`.

## Why it matters

The implementation is the Safe's code. Whoever controls it controls the funds.

## Example

`changeMasterCopy` to an unknown address (critical); `migrateL2Singleton()` delegatecalled to the official `SafeMigration` (info).

## Related incidents

Bybit and WazirX replaced the implementation by delegatecall (reported by `BS-DELEGATE-001`).

## Known false positives and limits

Planned upgrades through official migration contracts (info, not a warning).
