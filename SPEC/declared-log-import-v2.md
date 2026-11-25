<!-- Apache-2.0 — this file ships with the public verifier repo. -->

# SPEC: declared-log-import-v2 — bound DECLARED event-log intake

**Status: NORMATIVE (v2).** This format lets an operator normalize a private
event export into signed DECLARED receipts without treating the import as an
independent observation. The original export stays private. Its SHA-256,
adapter identity, normalized document digest, original event time and import
time bind the resulting evidence.

## 1. Normalized document

The input is one JSON object with exactly `schema`, `source`, and `events`.
`schema` is `swarrm/declared-log/v2`. `source` has exactly:

```json
{
  "system": "example-diary",
  "format": "example-jsonl-v1",
  "adapter_id": "customer-map",
  "adapter_version": "1.0.0",
  "export_sha256": "64 lowercase hexadecimal characters"
}
```

The first four values are 1–128 ASCII letters, digits, underscores, periods,
colons, or hyphens. `export_sha256` is the SHA-256 of the exact original export
bytes. The CLI must read a bounded regular file, reject symlinks, and refuse if
its identity changes during hashing. A v2 import without the original export,
or with a different digest, fails before creating its output directory.

`events` contains 1–1,000 objects with exactly `event_id`, `event_time`,
`correlation_id`, and `payload`. Event identifiers use the same bounded-token
grammar. Event IDs are unique within the document. `event_time` is a valid UTC
whole-second RFC 3339 value ending in `Z`. `correlation_id` is either a bounded
token or `null`; null remains explicitly unjoined. `payload` is a JSON object
and is committed, not copied into the public receipt context.

## 2. Evidence and output

Every emitted receipt has evidence class DECLARED. Its context binds the source
system and format, adapter ID and version, original-export digest, normalized
document digest, hashed event ID, declared event time, import time, and whether
the correlation ID was present. A missing correlation ID creates a stable local
action identifier derived from the event ID; it does not invent a business
correlation.

Successful output uses `swarrm/declared-log-import/v2` and records joined and
unjoined counts plus the signed receipt hashes. Existing output paths refuse
reuse. A failed import retains partial evidence and cannot be counted complete.
The legacy `swarrm/declared-log/v1` input and v1 output remain supported with
their existing fields; v1 cannot claim an original-export binding.

## 3. Assurance boundary

An import proves that Swarrm signed commitments to the supplied bytes and
declared metadata. It does not authenticate the vendor, establish that the
export is complete, independently observe a payment call, or prove payment or
settlement. Vendor-specific formats require a separately versioned adapter and
tests. Correlation by an equal identifier remains DECLARED unless another
governed source independently establishes the corresponding event.
