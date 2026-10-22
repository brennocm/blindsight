# BS-SEMANTICS-001: Function name is a guess

**Severity:** low; critical under delegatecall

## What it detects

A call whose selector matches a known function, but whose target is not known to implement it with that operation: an ERC-20 function on a token outside the embedded list or under delegatecall; a Safe function not addressed to the executing Safe; a helper function not delegatecalled to the official contract; any NFT function; a Permit2 function not sent to Permit2. Severity is **low** for a call and **critical** for a delegatecall. Nested Safe transactions are covered by `BS-NESTED-001` instead.

## Why it matters

A selector only says how arguments are laid out. Any contract can implement `transfer(address,uint256)` to do anything. Presenting the decoded name as a fact is exactly what made the Bybit transaction look harmless. See ADR 0006.

## Example

`transfer(0xbDd077f651EBe7f7b3cE16fe5F2b025BE2969516, 0)` delegatecalled to an unknown contract: under delegatecall a token function moves no tokens; the code runs on the Safe's storage.

## Related incidents

Bybit (February 2025): the payload was `transfer`-shaped; its code wrote the first argument into slot 0.

## Known false positives and limits

Transfers of legitimate tokens that are not in the short embedded list (low). Label them with an address book or decode with `--abi` to confirm.
