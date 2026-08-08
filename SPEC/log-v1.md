<!-- Apache-2.0 -->
# log/v1 — Tenant Transparency Log Specification

Status: NORMATIVE v1 (implemented by `core/merkle.py`, `core/checkpoint.py`,
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
| E1 | a presented receipt is intact and included in the presented authenticated history | inclusion + consistency under signed checkpoints; no claim that every relevant action was captured/exported |
| E2 | **withdrawn label**; carried anchor/timestamp material is a claim | any future release requires chain/TSA trust inputs supplied independently of the bundle |
| E3 | **withdrawn label**; a second signature may verify without proving independence | any future release requires externally grounded counterparty identity/control, not keys carried by the subject |

## 5. Key transparency (NORMATIVE as of Build 4)

Key lifecycle events are ordinary receipts with `agent_id="_system"` and
`action_type` ∈ {`evd.key.created`, `evd.key.rotated`, `evd.key.revoked`},
`commitments={}` and a PLAINTEXT context (public key material hides nothing):

```json
{"jwk": {…RFC 8037 OKP/Ed25519…}, "effective_ts": "<RFC 3339>",
 "role": "<sponsored recorder creation only>",
 "prev_kid": "<rotations only>", "continuity_sig": "<rotations only, b64>",
 "operator_authorization": {"…": "optional managed-custody signed command"}}
```

Rules (all normative):
1. **Genesis** — leaf 0 of every log MUST be an `evd.key.created` entry,
   SELF-SIGNED by the key it declares. Its receipt hash is the log's
   **trust root**: the one value a customer pins out-of-band (shown in
   `/evd/health` and the verifier output). An empty store rejects any other
   first entry.
2. **Sponsored creation** — later `evd.key.created` entries (e.g. an edge
   recorder's key) must be signed by an already-active key. A managed edge key
   is authorized for `/evd/ingest` only when this signed entry explicitly has
   `role="recorder"`; absence of a role grants no recorder authority.
3. **Rotation** — signed by the OLD key; `continuity_sig` is the old key's
   Ed25519 signature over the new JWK's RFC 8785 canonical bytes. Rotation
   ADDS the new key; the old key remains valid until revoked (in-flight
   material must not break). Managed production additionally carries its
   separately verified offline operator authorization in
   `operator_authorization`; it is issuer-witnessed audit metadata and does not
   change generic offline key-log replay rules.
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
   → NOT VERIFIED. Receipt, key-event `effective_ts`, and checkpoint times use
   receipt-v1's canonical extended UTC form; permissive ISO variants are not
   comparable authority times and make the bundle NOT VERIFIED. A receipt whose
   `ts_server` exceeds by more than 300 seconds the signed `ts` of the first
   chain checkpoint whose `tree_size` covers its leaf index → NOT VERIFIED (a
   checkpoint proving the log already held a receipt refutes any later
   admission claim; a leaf no presented checkpoint covers is unconstrained by
   this rule).

**Documented limitation:** omission of the LATEST key event (tail
truncation) is not detectable purely offline in general; mid-history omissions
are caught by the dense `_system` sequence. The customer's tail check is the
out-of-band trust root plus checkpoint freshness and, where used, independently
verified external anchor state. The current release awards no E2 label.

One case IS refutable from the bytes, and it is the case that mattered most.
The JWKS is derived from ACTIVE keys, so a bundle whose `evd.key.revoked` entry
has been deleted says two contradictory things about the same key: the replayed
log calls it live, and the bundle's own JWKS omits it. The verifier now checks
both directions of that agreement, so a key revoked for cause cannot be made
valid again by a list filter. Note what the stated mitigation does NOT cover
here: the target checkpoint remains the genuine, freshest, byte-identical signed
head whose root commits to the deleted leaf, and the trust root is unchanged —
so both freshness and the pinned root pass on the tampered bundle. An attacker
who also edits the JWKS to match is still bounded only by the out-of-band root.

## 6. Scaling note (non-normative)

The scaffold recomputes roots/proofs from all leaves (O(n)); correct to
~10^5 leaves per log. The production increment is cached subtree tiles
(c2sp tlog-tiles pattern) behind the same interface — no API change.
