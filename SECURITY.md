# Security policy

## Supported versions

Only the latest release receives security fixes.

## Reporting a vulnerability

Please report vulnerabilities privately through
[GitHub private vulnerability reporting](https://github.com/brennocm/blindsight/security/advisories/new).
Do not open a public issue.

Include the affected version, the exact input (transaction parameters, JSON or
calldata) and the output you got. You should receive an acknowledgement within
72 hours and a status update within 7 days.

## Scope

In scope, treated as critical:

- A wrong domain hash, message hash or safeTxHash for any supported Safe version
  and chain.
- A transaction that blindsight presents as harmless (or as something it is
  not) while it can change owners, threshold, modules, guards, the fallback
  handler or the implementation, or move funds in a way the report hides.
- Output that can be manipulated by the input, for example terminal control
  sequences or Unicode tricks that hide or rewrite parts of the report.

Also in scope:

- Crashes or excessive resource use on crafted input.
- Any way for blindsight to use the network.
- Weaknesses in release artifacts, their provenance or the dependency policy.

Out of scope:

- Vulnerabilities in the Safe contracts, the Safe{Wallet} interface or hardware
  wallet firmware. Report those to their maintainers.
- Risks that need chain state blindsight does not have (balances, current
  owners) unless the user supplied it.

blindsight holds no keys and signs nothing.
