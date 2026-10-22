# Output formats and exit codes

## Exit codes

| Code | Meaning |
|---|---|
| `0` | Analysis complete: no finding at or above `--fail-on`, and every expected hash matches. |
| `1` | At least one finding at or above `--fail-on` (default `high`). `verify` only. |
| `2` | Input, usage or internal error: no verdict was produced. |
| `3` | An expected hash (`--expect-*`, or `safeTxHash` in a JSON input file) does not match the computed one. Takes precedence over `1`. |

`hash` and `decode` produce no findings, so they exit `0`, `2` or `3`.
A reader that stops early (`blindsight verify … | head`) does not change the
exit code.

## Text output (`--format text`, default)

Sections, in order (each only when relevant to the command):

1. **Verdict**: `HASH MISMATCH: DO NOT SIGN` on any mismatch; then, for
   `verify`, the highest severity (`CRITICAL: DO NOT SIGN without independent
   review`, `HIGH RISK`, `MEDIUM`, or "No high-risk patterns detected") and the
   count per severity.
2. **Hash check**: `MATCH` / `MISMATCH` for each expected hash, with both
   values on mismatch.
3. **Findings**: severity, detector ID, position in the call tree, title and
   explanation.
4. **Hashes**: Safe, chain, version, then `Domain hash`, `Message hash` (each
   also in Ledger's upper-case form) and `safeTxHash`, with a reminder of what
   each wallet shows (`docs/hardware-wallets.md`).
5. **Input warnings**: bad checksums, unknown chain allowed.
6. **Calls**: the decoded tree. Each call shows its path (`root`,
   `batch[2]`, `nested`, …), operation, target with labels, and the decoded
   function with `[verified: …]` or `[UNVERIFIED: name inferred from the
   selector only]`.
7. **Signatures**, when the input was `execTransaction` calldata: the kind of
   each (typed data, `eth_sign`, approved hash, contract).
8. **Raw parameters**: the ten `SafeTx` fields in full.

Addresses are always the full checksummed form; hashes and calldata are never
shortened. Colours are used only on a terminal and never when `NO_COLOR` is
set or `--color never` is given. Every string that comes from the input
(address-book names, ABI names, decoded strings, error messages) is passed
through `sanitize`: control characters, ANSI escapes, bidirectional overrides
and zero-width characters are printed as visible `\u{..}` escapes.

## JSON output (`--format json`)

One JSON object. `schema_version` is `1`; it changes only when a field is
removed or changes meaning. Large integers (values, gas, nonces) are decimal
strings; addresses are checksummed; hashes and byte strings are lower-case
`0x` hex. Free-text fields derived from the input are sanitised as in the text
output.

```text
{
  "schema_version": 1,
  "tool": { "name": "blindsight", "version": "0.1.0" },
  "command": "verify" | "hash" | "decode",
  "safe": { "address", "chain_id", "chain_name" (null if unknown), "version", "domain_has_chain_id" },
  "transaction": { "to", "value", "data", "operation" (0|1), "safeTxGas", "baseGas",
                   "gasPrice", "gasToken", "refundReceiver", "nonce" },
  "hashes": { "domain_hash", "message_hash", "safe_tx_hash" },        (not for decode)
  "hash_checks": [ { "hash": "domain_hash" | "message_hash" | "safe_tx_hash",
                     "source", "expected", "computed", "matches" } ],
  "hash_mismatch": bool,
  "verdict": { "highest_severity" (null if none), "fail_on" },           (verify only)
  "findings": [ { "id", "severity", "title", "detail", "path" } ],      (verify only)
  "calls": Call,                                                         (verify, decode)
  "warnings": [ string ],
  "signatures": [ { "index", "v", "kind": "typed_data" | "eth_sign" | "approved_hash"
                    | "contract" | "invalid", "signer" (or null) } ],
  "exit_code": 0 | 1 | 3
}

Call = { "path", "executor", "to", "to_label", "value", "operation", "data",
         "decoded": Decoded }

Decoded (tagged by "kind"):
  { "kind": "empty" }
  { "kind": "known", "function", "signature", "semantics": { "verified", "reason" },
    "args": [ { "name", "value" } ] }
  { "kind": "user", "signature", "args": [ { "name", "value" } ] }
  { "kind": "batch", "semantics", "call_only", "items": [ Call ] }
  { "kind": "nested", "signature", "semantics", "args", "inner": Call }
  { "kind": "unknown", "selector" (or null) }
  { "kind": "malformed", "function" (or null), "reason" }
  { "kind": "too_deep" }
```
