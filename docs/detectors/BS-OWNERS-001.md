# BS-OWNERS-001: Owner set change

**Severity:** high; critical if the new threshold is 1

## What it detects

`addOwnerWithThreshold`, `removeOwner` or `swapOwner` called on the Safe that executes it, at any depth of the tree.

## Why it matters

Owners decide everything. Adding an owner, or dropping the threshold to 1, can hand control of the Safe to a single key.

## Example

`addOwnerWithThreshold(0x…, 1)`: a new owner and a threshold of 1 (critical).

## Related incidents

Changing owners is a common step after a key compromise or social-engineering attack, to lock legitimate owners out.

## Known false positives and limits

Planned owner rotations. The finding states which owner changes and the new threshold so it can be checked against the plan.
