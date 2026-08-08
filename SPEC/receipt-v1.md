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

Signed timestamps use exactly canonical extended UTC:
`YYYY-MM-DDTHH:MM:SS[.1..6 fractional digits]Z`. Basic dates, ISO week dates,
space separators, offsets, impossible calendar dates, leap seconds, and more
than six fractional digits are invalid. This fixed form makes chronological
comparison identical across verifier implementations.

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

## 5. Signatures & dual attestation (wire profile; E3 label withdrawn)

An envelope carries 1..n signatures over the same PAE bytes:

- **E0/E1 and carried anchor/timestamp material**: the log's issuing key (per
  tenant). No E2 label currently ships.
- **dual-attestation wire shape**: additionally, an edge-recorder key held at
  the *customer's* edge. Verifiers checking that shape MUST require both
  `keyid`s. The offline E3 assurance label is withdrawn: keys carried in the
  same bundle do not independently establish counterparty identity or control
  domain merely because both signatures verify.
  Neither party alone can then forge or repudiate a receipt.

**Which kid is which, and the flow (normative):**

1. **Registration** — the recorder key is generated at the customer edge
   (file-based in v1; KMS is a post-gate increment) and enters the tenant
   log as a SPONSORED `evd.key.created` entry (log-v1 §5): the entry is
   signed by the tenant ISSUER key and carries `context.role="recorder"`.
   Registration requires the tenant's admin API credential; that credential
   never runs in the recorder. Until registered, the hosted side rejects the
   recorder's uploads (HTTP 403) — they wait in the edge spool.
2. **Capture** — the recorder signs each receipt with the RECORDER key
   (primary signature) and spools locally. Payload bytes, nonces, and vault
   content NEVER leave the edge on the evidence plane; envelopes carry
   commitments only (the sentinel test enforces this).
3. **Ingest** — `POST /evd/ingest`. This is a narrow managed-recorder
   admission boundary, never a generic receipt append API. The hosted side
   applies the ordered law below and only then COUNTER-SIGNS with the tenant
   issuer key and appends. The appended envelope carries the edge and issuer
   signatures.
4. **Dual-signature verification rule** — the two-signature wire condition holds iff
   `verify_envelope(env, log_keys, require_kids={issuer_kid, recorder_kid})`
   passes, with both kids drawn from the LOG's key history (log-v1 §5) and
   valid at the receipt's `ts_server`. This does not award E3 or establish that
   the named key holders are independent.

**Legacy privileged-co-signature rule.** Offline verifiers MUST reject a
multi-signed receipt when `agent_id` begins `_`, or when `action_type` begins
`evd.key.`, `authority.`, `source.`, `action.`, `lineage.`, `node.`,
`evd.finding.`, `evd.gap.`, `evd.coverage.`, or `registration.`. These
namespaces drive key, authority, or other privileged replay and their
legitimate builders are issuer-only; an edge+issuer shape proves exposure to
the superseded generic managed-ingest path. This forensic rule deliberately
does not invalidate historical multi-signed `x.*`/custom evidence. Such leaves
remain evidence, while the managed upgrade audit may flag them as outside the
current positive admission profile. `interaction.message` remains an admitted
bilateral action.

**Ordering** — the recorder assigns per-agent monotonic `seq` at the edge;
the durable journal/spool preserves accepted capture order and `sync()` stops at
the first failure, so hosted leaf order matches that accepted sequence.
Concurrent sync calls serialize, and a receipt appended while a sync is awaiting
ingest MUST remain after that sync removes its successfully delivered prefix.
Bounded-storage/reserve refusal is an explicit cannot-retain gap, not a
losslessness claim.
`ts_server` is the recorder-observed capture time (the server side of the
customer's local relay), not managed-ingest arrival time; this preserves the
truth of receipts that remain offline in the spool before upload.

### 5.1 Managed ingest admission law

The following checks occur in this order. A rejection is a 4xx response and
MUST NOT add an issuer signature, append a leaf, or alter key, authority,
registration, lineage, Node, finding, or coverage state.

1. **Authenticate and stream-bound.** Resolve `x-api-key` to exactly one tenant
   and require its exact `recorder` role before opening a tenant store. The
   admin credential returned by signup is rejected here, and the recorder
   credential is rejected by every admin/console/portal/OTel route. Stream the
   HTTP request through a **16,384 byte** hard limit before JSON parsing; both
   declared and chunked overflows return 413.
2. **Parse the exact upload profile, before cryptography.** The request is
   exactly `{ "envelope": ... }`; the DSSE envelope has exactly `payload`,
   `payloadType`, and `signatures`; `payloadType` is the receipt/v1 media type;
   base64 is canonical; duplicate JSON keys are forbidden; and the decoded
   payload is at most **8192 bytes**. The payload MUST already be the RFC 8785
   canonical bytes of one `evd/receipt/v1` body with the required §3 fields
   and their declared types (plus only the additive `session_id` /
   `session_inferred` pair). `seq` is in `1..2^63-1`. An upload carries **1..7
   distinct 64-byte Ed25519 recorder signatures**. The verifier-wide cap is
   **nine**: the managed issuer appends its current signature and, only during
   the signed bounded issuer-rotation overlap, its immediately preceding
   issuer signature. No edge upload may consume either issuer slot.
3. **Bind tenant and constrain the edge role.** The signed `tenant_id` MUST
   equal the tenant authenticated by the API key. `agent_id` MUST NOT begin
   `_`. The managed edge action profile is a positive allow-list:
   `llm.chat`, `tool.call`, `data.read`, `payment.execute`,
   `interaction.message`, `policy.decision`, `guardrail.blocked`,
   `human.approve`, `human.override`, `human.reject`,
   `human.escalation_timeout`, `agent.deployed`, `agent.config_changed`,
   `agent.tool_granted`, and `agent.revoked`. Every other
   namespace is denied until explicitly admitted; in particular `evd.key.*`,
   `authority.*`, `action.*`, `source.*`, `registration.*`, `lineage.*`,
   `node.*`, and `passport.*` are internal producer paths and can never arrive
   through an edge upload. Plaintext `context` keys MUST be a subset of the
   selected action's `context-v1` dial plus the four universal lineage /
   correlation keys; an undeclared key is rejected as payload smuggling.
   Values are also schema-checked: universal IDs and ordinary declared fields
   are strings; `requested_tool_names` / `arg_keys` are arrays of strings;
   declared booleans are JSON booleans; counters/durations are nonnegative
   int64 values (never booleans); `status` is a string or nonnegative int64.
   The frozen bands and `result_kind` use the exact `context-v1` enums. Nested
   objects and arrays on scalar fields are payload smuggling and are rejected.
4. **Resolve idempotency under the tenant store lock.** Reusing an
   `idempotency_key` for different payload bytes is 409. An exact retry is
   acknowledged with the already-stored leaf index and payload hash only when
   its edge signature list exactly matches the stored envelope before the
   final issuer signature. It consumes no quota and is still acknowledged
   after prospective recorder-key revocation: no new claim is being admitted.
   A matching unfinalized quota reservation is reconciled best-effort; control
   DB failure MUST NOT withhold the 200 for an already-durable tenant leaf.
5. **Authenticate every signature for a new leaf.** Every uploaded signature
   MUST be valid over the PAE bytes under a distinct, currently active key in
   this authenticated tenant's key log whose signed key-creation event carries
   `role="recorder"`. Unlabelled historical keys and issuer keys are not
   recorders. One valid signature never masks an unknown, malformed, revoked,
   unlabelled, issuer-role, or invalid extra signature.
6. **Reserve and append once.** Before quota, reject an already-recorded
   `(agent_id, seq)` with 409. Only a genuinely new, fully admitted leaf takes
   one tenant receipt quota unit. The control plane atomically creates a
   durable `(tenant_id, idempotency_key, receipt_hash)` reservation and debit;
   an exact retry reuses it, a different hash is 409, and exhaustion is 429.
   If quota remains, and only then, the hosted issuer counter-signs and appends
   while the tenant store lock is held, then finalizes the reservation. A
   signer/append failure or process loss can leave one conservative reservation
   but can never double-debit its retry.

These failures are fail-closed for evidence admission but remain fail-open for
the business action: the recorder returns the upstream response, keeps the
signed receipt in its durable ordered spool, and retries without fabricating a
successful evidence write.

**Managed migration.** A fresh signup returns `api_key` (admin) and
`recorder_api_key` (ingest only). Existing recorder deployments MUST move the
runtime `EVD_API_KEY` to the secret returned once by admin-authenticated
`POST /evd/api-keys/recorder`; issuance atomically revokes that tenant's prior
recorder API credentials. They MUST also register a NEW edge signing key
through the admin-authenticated `/evd/keys/register` route. Historical
unlabelled keys are intentionally not inferred to be recorders.

`GET /evd/ingest/keys` accepts only that exact recorder credential and returns
the authenticated tenant id, active public keys whose immutable key-log event
explicitly grants `role="recorder"`, and known permanently ineligible kids.
Recorder sync MUST validate the exact response schema, tenant binding, JWK kid
derivation, and every spooled DSSE signature before using this view. This lets
K1-signed spool entries drain after a local move to registered K2 while K1 is
still active. Unknown kids remain spooled pending registration; a known
unroled/revoked kid may be durably quarantined. Managed ingest MUST repeat all
§5.1 tenant, role, profile, and cryptographic checks; discovery is a safe local
replay decision, never admission authority.

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
