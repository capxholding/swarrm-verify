<!-- Apache-2.0 -->
# receipt/v1 — Action Receipt Specification

Status: DRAFT (implemented by `core/receipt.py`; test vectors in `tests/`)

## 1. Overview

A **receipt** is a signed, canonical statement that an agent performed an
action. Receipts are the atom of evidence: they are what gets logged,
proven, exported, and verified. A receipt proves *activity and integrity*
("this call happened; this record is unaltered") — it does not prove the
payload was truthful (tamper-proof, not lie-proof).

## 2. Encoding

- Body: JSON, canonicalized per **RFC 8785 (JCS)**. All hashing and signing
  operate on canonical bytes. Two semantically equal bodies MUST produce
  identical bytes.
- Envelope: **DSSE** (`payloadType` + base64 payload + signatures), with
  PAE = `"DSSEv1" SP len(type) SP type SP len(body) SP body`.
- `payloadType` MUST be `application/vnd.evd.receipt.v1+json`.
- Signature algorithm: **Ed25519**. `keyid` = base64url(SHA-256(raw public
  key))[:16] — deterministic from key material; verifiers MUST reject a JWK
  whose `kid` does not match its key.

**Size cap (normative).** The RFC 8785 canonical body MUST NOT exceed
**8192 bytes**. Producing an oversize receipt is a producer-side error:
producers MUST refuse to sign it (receipts are metadata; anything bigger is
payload smuggling). Verifiers do NOT enforce the cap — existing logs may
legally contain historic receipts, and the verifier judges signatures and
proofs, not the producer's budget.

## 3. Body fields (all REQUIRED)

| Field | Type | Meaning |
|---|---|---|
| `schema` | string | `"evd/receipt/v1"` |
| `tenant_id` | string | issuing tenant |
| `agent_id` | string | acting principal, registered per tenant |
| `seq` | int | per-`(tenant, agent)` monotonic counter starting at 1. A gap is evidence of a missing receipt — the system is honest about its own holes |
| `action_type` | string | namespaced, e.g. `llm.chat`, `tool.call`, `payment.execute` |
| `commitments` | object | field → hex commitment (see §4) |
| `context` | object | non-secret metadata (model ref, endpoint, status). MUST NOT contain payloads |
| `parents` | array | receipt hashes of causal parents (the receipt DAG; session → step → tool call) |
| `ts_client` | string | RFC 3339 UTC, client clock |
| `ts_server` | string | RFC 3339 UTC, log clock |
| `idempotency_key` | string | client-chosen; the log deduplicates on `(tenant_id, idempotency_key)`, first write wins |

**`receipt_hash`** = SHA-256(canonical body), lowercase hex. This value is
the Merkle leaf (see log-v1) and the value `parents` references.

## 4. Commitments

`commitment = SHA-256( domain ‖ 0x00 ‖ nonce ‖ 0x00 ‖ payload )`, hex.

- `domain` MUST begin with `evd/v1/` (domain separation: a prompt commitment
  can never be replayed as an output commitment).
- `nonce` MUST be ≥ 16 random bytes (32 recommended), held by the client
  (edge shape) or a nonce vault. Prevents dictionary attacks on
  low-entropy payloads.
- Payloads never enter receipts, the log, or bundles. **Selective
  disclosure** = revealing `(payload, nonce)` to a chosen party, who
  recomputes the commitment.
- Streaming: producers MAY compute the commitment incrementally
  (`domain ‖ 0x00 ‖ nonce ‖ 0x00` then chunks); the result MUST equal the
  one-shot computation.

## 5. Signatures & dual attestation (E3 profile — NORMATIVE as of Build 5)

An envelope carries 1..n signatures over the same PAE bytes:

- **E0/E1/E2**: the log's issuing key (per tenant).
- **E3 (dual attestation)**: additionally, an edge-recorder key held at the
  *customer's* edge. Verifiers enforcing E3 MUST require both `keyid`s.
  Neither party alone can then forge or repudiate a receipt.

**Which kid is which, and the flow (normative):**

1. **Registration** — the recorder key is generated at the customer edge
   (file-based in v1; KMS is a post-gate increment) and enters the tenant
   log as a SPONSORED `evd.key.created` entry (log-v1 §5): the entry is
   signed by the tenant ISSUER key. Until registered, the hosted side
   rejects the recorder's uploads (HTTP 403) — they wait in the edge spool.
2. **Capture** — the recorder signs each receipt with the RECORDER key
   (primary signature) and spools locally. Payload bytes, nonces, and vault
   content NEVER leave the edge on the evidence plane; envelopes carry
   commitments only (the sentinel test enforces this).
3. **Ingest** — `POST /evd/ingest`. The hosted side verifies that at least
   one envelope signature is (a) cryptographically valid and (b) from a kid
   the LOG has registered and not revoked. It then COUNTER-SIGNS with the
   issuer key and appends. The appended envelope carries both signatures.
4. **Verification rule** — E3 holds for a receipt iff
   `verify_envelope(env, log_keys, require_kids={issuer_kid, recorder_kid})`
   passes, with both kids drawn from the LOG's key history (log-v1 §5) and
   valid at the receipt's `ts_server`.

**Ordering** — the recorder assigns per-agent monotonic `seq` at the edge;
the spool preserves capture order and `sync()` stops at the first failure,
so hosted leaf order matches edge seq order with zero silent gaps.

## 6. Verification (normative for verifiers)

1. `payloadType` is exactly the receipt type; envelope has ≥1 signature.
2. Every signature verifies over PAE(payloadType, payload) with a key whose
   `kid` matches its material. Unknown `kid` ⇒ FAIL (no unsigned-key
   tolerance).
3. `schema` == `evd/receipt/v1`.
4. `receipt_hash` is recomputed from payload bytes — never trusted from
   context.
5. Inclusion in the log is checked per log-v1 §4 using the recomputed hash.

**Ed25519 strictness (decided, not accidental)** — both shipped verifiers
deliberately use *non-strict* Ed25519 verification: the Python verifier via
`cryptography` (OpenSSL's RFC 8032 check) and the Rust verifier via
`ed25519-dalek`'s `verify` (not `verify_strict`). This guarantees the two
implementations accept exactly the same signature set, so a bundle can never
verify under one verifier and fail under the other. The extra canonicity
rejections of strict mode buy nothing here: `receipt_hash` commits to the
payload bytes alone (rule 4) and signatures are attached, never hashed, so
signature malleability cannot alter what a receipt proves.
