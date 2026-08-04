<!-- Apache-2.0 -->
# bundle/v1 — Evidence Bundle Specification

Status: DRAFT (implemented by `core/store.py::export_bundle`,
`verify/verifier.py`)

## 1. Purpose

A bundle is a **self-contained, offline-verifiable** evidence package. An
auditor with the bundle and the open-source verifier needs nothing else —
no API access, no cooperation from the log operator, no network.

## 2. Structure

```json
{
  "schema": "evd/bundle/v1",
  "origin": "evd://tenant/<id>",
  "target_checkpoint": { "body": {...}, "kid": "...", "sig": "..." },
  "entries": [
    { "envelope": { DSSE }, "leaf_index": N, "inclusion_proof": ["<hex>", ...] }
  ],
  "checkpoint_chain": [
    { "checkpoint": {...} },
    { "checkpoint": {...}, "consistency_from_prev": ["<hex>", ...] }
  ],
  "jwks": { "keys": [ ... ] }
}
```

## 3. Verification algorithm (normative — `verify_bundle`)

1. **Keys**: every JWK's `kid` matches its key material; reject aliases.
2. **Target checkpoint** signature verifies.
3. **Chain**: every checkpoint signature verifies; `prev_hash` links hold;
   `tree_size` monotone; single `origin`; every step ships a consistency
   proof that verifies old_root → new_root. A missing or failing proof is a
   FAIL (rewritten history).
4. **Head**: `target_checkpoint` is the chain head.
5. **Entries**: per receipt — DSSE signature(s) verify; schema is
   `evd/receipt/v1`; `receipt_hash` recomputed from payload; inclusion
   proof verifies `(recomputed hash, leaf_index)` under the target root;
   timestamps use receipt-v1's canonical extended UTC form; and the legacy
   privileged-co-signature rule in receipt-v1 §5 is satisfied before replaying
   key, authority, lineage, Node, finding, gap, coverage, or registration state.
6. Verdict is the conjunction. Any single failure ⇒ NOT VERIFIED.

## 4. Trust model & known limits (honest by design)

- The bundle proves integrity relative to the log's public keys. An auditor
  MUST obtain the log's kid from an independent channel (published JWKS,
  anchored key-transparency entries, or a prior trusted bundle) — a bundle
  alone cannot defeat an attacker who forges *everything including the
  keys*. E2 anchoring closes this: the anchored checkpoint hash pins the
  history to a public chain and an RFC 3161 timestamp no key swap can
  reproduce. (Anchor attachment format: anchor-v1, next increment.)
- Selective disclosure of payloads = revealing `(payload, nonce)` for a
  specific commitment; the verifier recomputes and compares (§receipt-v1).
- E3 policy attestation blocks are carried in `commitments`/`context` and
  enforced by requiring the edge `kid` — profile TBD in policy-v1.
