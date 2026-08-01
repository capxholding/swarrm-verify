<!-- Apache-2.0 -->
# log/v1 — Tenant Transparency Log Specification

Status: DRAFT (implemented by `core/merkle.py`, `core/checkpoint.py`,
`core/store.py`)

## 1. Construction

One log per tenant. The log is an **RFC 6962 Merkle tree** (SHA-256):

- leaf hash = `SHA-256(0x00 ‖ leaf_data)`
- node hash = `SHA-256(0x01 ‖ left ‖ right)`
- `MTH` per RFC 6962 §2.1; empty root = `SHA-256("")`.

**Leaf data = the 32-byte digest `receipt_hash`** (not the envelope). The
tree commits to receipt bodies via their hashes; envelopes and payloads stay
out of proofs. Leaf indices are dense, 0-based, append-only. Physical
isolation per tenant (one store per log) — cross-tenant queries are
structurally impossible, not filtered.

## 2. Checkpoints

A checkpoint is a signed statement of the log's state:

```json
{"schema":"evd/checkpoint/v1","origin":"evd://tenant/<id>",
 "tree_size":N,"root_hash":"<hex>","ts":"<RFC3339>","prev_hash":"<hex|''>"}
```

- Canonicalized (RFC 8785), signed Ed25519 in DSSE
  (`application/vnd.evd.checkpoint.v1+json`).
- `prev_hash` = SHA-256 of the previous checkpoint body (chain).
- Verifiers MUST check: signatures, linkage, `tree_size` monotonicity,
  same `origin` — and Merkle **consistency proofs** between consecutive
  checkpoints (RFC 6962 §2.1.2 / RFC 9162 §2.1.4.2). A log that rewrites
  history cannot produce them.

## 3. Proofs

- **Inclusion** (receipt → checkpoint): RFC 6962 audit path; verify per
  RFC 9162 §2.1.3.2 against `(leaf_index, tree_size, root_hash)`.
- **Consistency** (checkpoint → later checkpoint): RFC 6962 §2.1.2 proof;
  verify per RFC 9162 §2.1.4.2 (including the initial LSB normalization and
  the power-of-two prepend rule).

## 4. Evidence levels

| Level | Adds | Backed by |
|---|---|---|
| E0 | receipt exists, intact | DSSE signature |
| E1 | cannot be silently altered/deleted | inclusion + consistency under signed checkpoints |
| E2 | independent time + public commitment | checkpoint anchored (L2 tx) + RFC 3161 timestamp (a qualified TSP in production; non-qualified dev TSAs are always labeled as such) — *attachment format TBD in anchor-v1* |
| E3 | non-repudiation for both operator & log; controls attested | edge co-signature (customer KMS) + policy attestation block |

## 5. Key transparency (NORMATIVE as of Build 4)

Key lifecycle events are ordinary receipts with `agent_id="_system"` and
`action_type` ∈ {`evd.key.created`, `evd.key.rotated`, `evd.key.revoked`},
`commitments={}` and a PLAINTEXT context (public key material hides nothing):

```json
{"jwk": {…RFC 8037 OKP/Ed25519…}, "effective_ts": "<RFC 3339>",
 "prev_kid": "<rotations only>", "continuity_sig": "<rotations only, b64>"}
```

Rules (all normative):
1. **Genesis** — leaf 0 of every log MUST be an `evd.key.created` entry,
   SELF-SIGNED by the key it declares. Its receipt hash is the log's
   **trust root**: the one value a customer pins out-of-band (shown in
   `/evd/health` and the verifier output). An empty store rejects any other
   first entry.
2. **Sponsored creation** — later `evd.key.created` entries (e.g. an edge
   recorder's key) must be signed by an already-active key.
3. **Rotation** — signed by the OLD key; `continuity_sig` is the old key's
   Ed25519 signature over the new JWK's RFC 8785 canonical bytes. Rotation
   ADDS the new key; the old key remains valid until revoked (in-flight
   material must not break).
4. **Revocation** — signed by an active key; the revoked kid is invalid for
   any material whose ts is after `effective_ts`. History before it stands.
   Key entries are never deleted or superseded in place.
5. **Verifier key authority = the log.** Bundles auto-include every key
   entry covered by the target checkpoint (with inclusion proofs). The
   verifier replays them — genesis self-signature, sponsor signatures,
   continuity signatures, dense `_system` sequence — and derives ALL keys
   (including revoked ones, needed for history). The bundle's `jwks` field
   is a cross-check only: a kid it carries that the log doesn't witness, or
   different key material, → NOT VERIFIED.
6. **Time semantics** — checkpoints signed by a key revoked before their
   `ts`, and receipts signed by a key revoked before their `ts_server`,
   → NOT VERIFIED.

**Documented limitation:** omission of the LATEST key event (tail
truncation) is not detectable purely offline; mid-history omissions are
caught by the dense `_system` sequence. The customer's tail check is the
out-of-band trust root plus checkpoint freshness (and, at E2, the anchored
checkpoint chain).

## 6. Scaling note (non-normative)

The scaffold recomputes roots/proofs from all leaves (O(n)); correct to
~10^5 leaves per log. The production increment is cached subtree tiles
(c2sp tlog-tiles pattern) behind the same interface — no API change.
