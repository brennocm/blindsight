# BS-NONCE-001: Suspicious nonce

**Severity:** medium; info if queued

## What it detects

With `--current-nonce`: a nonce below the current one (medium: the transaction can never execute), more than 3 above (medium: a pre-signed future transaction), or 1 to 3 above (info: queued).

## Why it matters

Asking for a signature on a used nonce has no legitimate purpose. A signature for a far-future nonce stays valid until that nonce is used, which gives whoever holds it a long window.

## Example

Current nonce 70, transaction nonce 90.

## Related incidents

None recorded.

## Known false positives and limits

Batches of queued transactions prepared in advance.
