<!-- Apache-2.0 -->
# evd/disclosure v1 — selective disclosure (NORMATIVE, Build 9.5)

A receipt commits to payloads with salted, domain-separated hashes
(`SHA-256(domain ‖ 0x00 ‖ nonce ‖ 0x00 ‖ payload)`; canonical.py). The
standard evidence log persists the commitment, not the payload body. Custody of
the nonce depends on the capture surface: recorder/Node deployments keep it in
the customer volume, while the hosted gateway retains it in the tenant's
encrypted service vault and necessarily handles the payload in transit.
Disclosure is the holder's choice to release `(payload, nonce)` for ONE field
of ONE receipt to ONE audience.

## 1. The package

```json
{"schema": "evd/disclosure/v1",
 "receipt_hash": "<hex — the receipt whose commitment is being opened>",
 "field": "prompt",
 "domain": "evd/v1/prompt",
 "nonce_hex": "<the client-held salt>",
 "payload_b64": "<the payload bytes>"}
```

Nonce vaults are AES-256-GCM encrypted at rest. Recorder and Node deployments
keep the vault and key in their local data volume; the hosted gateway uses a
service-side tenant vault. Payload bytes remain in the caller's source system
after capture, except that a hosted gateway necessarily relays them in transit.
The standard receipt/log databases contain commitments and bounded metadata,
not the disclosed payload/nonce pair.

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
- Vault encryption does not make a live process compromise harmless: the
  capture process can access nonce plaintext while operating, and hosted
  custody is not customer-exclusive custody.
- A disclosure proves what WAS committed; it cannot prove the absence of
  other commitments elsewhere.
