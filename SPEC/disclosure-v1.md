<!-- Apache-2.0 -->
# evd/disclosure v1 — selective disclosure (NORMATIVE, Build 9.5)

A receipt commits to payloads with salted, domain-separated hashes
(`SHA-256(domain ‖ 0x00 ‖ nonce ‖ 0x00 ‖ payload)`; canonical.py). The
payload and nonce stay with the CUSTOMER (payloads never persist hosted-side
— structural, not policy). Disclosure is the customer's choice to release
(payload, nonce) for ONE field of ONE receipt to ONE audience.

## 1. The package

```json
{"schema": "evd/disclosure/v1",
 "receipt_hash": "<hex — the receipt whose commitment is being opened>",
 "field": "prompt",
 "domain": "evd/v1/prompt",
 "nonce_hex": "<the client-held salt>",
 "payload_b64": "<the payload bytes>"}
```

The vault that holds nonces is CLIENT-side (the gateway/recorder nonce
jsonl); payload bytes live wherever the customer keeps their data. Nothing
in this flow uploads either to hosted storage — the sentinel test in
`tests/test_disclosure.py` byte-scans the hosted DBs to prove it.

## 2. Offline verification (`evd verify bundle.json --disclose pkg.json`)

1. The bundle must verify (all the usual checks).
2. `receipt_hash` must be an entry in the bundle.
3. The receipt's `commitments[field]` must equal the recomputed
   `SHA-256(domain ‖ 0x00 ‖ nonce ‖ 0x00 ‖ payload)`.
Any failure → NOT VERIFIED. A wrong payload or nonce cannot pass: the
committed hash was fixed at capture time, before anyone knew what would be
disputed. `--disclose` is repeatable; the JSON report carries a
`disclosures` object.

## 3. Live disclosure (auditor portal)

`POST /portal/{grant}/disclose` with a package: the portal recomputes the
commitment against the SCOPED receipt live and renders green (match) / red
(mismatch). The payload and nonce exist server-side only for the lifetime
of the request; nothing is stored. Every disclosure attempt is receipted
(`evd.disclosure.released`, context = {receipt_hash, field, verified} — no
payload material). Out-of-scope receipt hashes are a 404, not an oracle.

## 4. Limitations (honest)

- Disclosure is per-field, all-or-nothing for that field: partial/redacted
  disclosure of a committed blob is not possible in v1 (no Merkle-ized
  payloads; a post-v1 increment).
- The local nonce vault is plaintext jsonl in v1; encrypting it at rest is
  a hardening item (docs/HARDENING_PLAN.md).
- A disclosure proves what WAS committed; it cannot prove the absence of
  other commitments elsewhere.
