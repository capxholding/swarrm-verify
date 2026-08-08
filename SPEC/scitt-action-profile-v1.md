<!-- Apache-2.0 — this file ships with the public verifier repo. -->

# SPEC: scitt-action-profile-v1 — SCITT registration for Verified Action Certificates

**Status: NORMATIVE (v1). Profile frozen BEFORE implementation (B25.1).**
SCITT is the standard registration layer, not the product. One Swarrm
Transparency Service (TS) registers **commitment-only** certificate
statements — it appends the digest of a Signed Statement and returns a
Receipt; it never sees the certificate content. SCITT proves issuer
attribution and transparent append-only registration — never statement
truth, complete source coverage, action time, or legal admissibility.

COSE is a **small reviewed adapter** (`core/cose.py`, `verify-rs/src/cose.rs`)
over the B24 CBOR codecs (`cbor2` / `ciborium`) — no general trust framework.
Signing reuses the existing Ed25519 keys as COSE alg **-8 (EdDSA)**; the kid
is the existing rule `base64url(SHA-256(pubkey))[:16]`, carried as its ASCII
bytes. As with B24, **cross-language canonical-byte vectors MUST pass before
any SCITT code relies on the COSE adapter** (tests/golden/cose/): `cbor2`-built
and Rust-built COSE_Sign1 bytes are byte-identical.

## 1. Deterministic COSE_Sign1

A COSE_Sign1 is the CBOR array (tag 18) `[protected: bstr, unprotected: map,
payload: bstr / null, signature: bstr]`, encoded under the B24 deterministic
CBOR profile (SPEC/certificate-v1.md §1: definite lengths, no floats/tags
inside our maps, text-or-int keys sorted by encoded bytes). The `protected`
bstr wraps a deterministically-encoded header map. The signature is EdDSA over
the `Sig_structure` `["Signature1", protected, h'' (external_aad), payload]`,
itself deterministically CBOR-encoded. Header labels used (COSE registry):
`1`=alg, `3`=content type (tstr), `4`=kid (bstr), `15`=CWT_Claims map
(`1`=iss tstr, `2`=sub tstr). VDS labels for receipts: `395`=verifiable data
structure id, `396`=VDS proofs map.

## 2. Signed Statement

`application/vnd.swarrm.action-statement+cose` — a COSE_Sign1 signed by the
certificate **issuer** key.
- protected: `{1: -8, 3: "application/vnd.swarrm.action-certificate+cbor",
  4: kid, 15: {1: <issuer id>, 2: <certificate_id hex>,
  "evd_scope_digest"?: <64 lowercase hex>}}`. The optional text claim is
  mandatory on the managed endpoint and binds the HTTP entitlement scope into
  the issuer-signed bytes; a header alone is never authorization.
- payload: the **32-byte `certificate_id`** (the commitment — the ONLY thing
  the TS receives; the certificate itself never leaves the customer).
- `statement_digest` = `SHA-256(signed_statement_bytes)`.

## 3. Registration flow (B25.4 — evidence, not assertion)

Certificate creation NEVER waits for the TS. Before submission the issuer logs
a **`RegistrationIntent`** receipt (`statement_digest`, `scope_digest`,
`created_at_checkpoint` = the issuer's current tenant checkpoint body_hash,
signed). Each delivery attempt logs a **`RegistrationAttempt`** receipt
(`intent_id`, `endpoint`, `attempted_at_checkpoint`, `transport_outcome`,
`retry_count`, signed). Derivation (already in the verdict engine,
verified-action-v1 §2.15, now fed by REAL artifacts):
- **REGISTERED** — a valid Receipt (§4) covers the statement.
- **PENDING** — a signed Intent AND ≥1 signed Attempt exist, no valid Receipt
  yet. Intent alone is **UNREGISTERED**, never pending.
- **UNREGISTERED** — otherwise.
A later Receipt attaches without changing any underlying action artifact or
proof semantics — the certificate core and its `certificate_id` are immutable.

## 4. Receipt

`application/vnd.swarrm.scitt-receipt+cose` — a COSE_Sign1 signed by the **TS**
key.
- protected: `{1: -8, 4: <TS kid>, 395: 1}` where `395:1` = the
  `RFC9162_SHA256` verifiable data structure.
- unprotected: `{396: {-1: [tree_size: uint, leaf_index: uint,
  [* audit_path: bstr]]}, -2: {root, size, ts, prev}}` — the RFC 9162 / RFC
  6962 inclusion proof plus the enclosing TS checkpoint body (root hex, size,
  ts, prev_hash — the same `evd/checkpoint/v1` body the global tree signs).
- payload: the **32-byte checkpoint body_hash** = `SHA-256(JCS(checkpoint
  body))`. Binding the body_hash (not just the root) ties the receipt to the
  exact checkpoint the public anchor + RFC 3161 token cover.

The TS log is append-only; its leaf value is the 32-byte `statement_digest`
(RFC 6962 leaf hash `SHA-256(0x00 ‖ statement_digest)`, per `core/merkle.py`).

## 5. Independent time (B25.3)

The TS checkpoint body_hash is batched into the SAME public anchor (Base) and
RFC 3161 worker as every other checkpoint (`anchor/worker.run_once`,
duck-typed). A timestamp is **qualified** only under a currently valid,
trust-listed provider (`EVD_TSA_QUALIFIED=1`); otherwise the report says
non-qualified timestamp. The anchor/TST attach to the receipt's checkpoint
body_hash, closing the loop to public time without the TS holding time itself.

## 6. Verification (both engines, byte-identical) — `verify_scitt_receipt`

At the certificate boundary, the verifier first resolves the named
Transparency Service to a locally supplied `scitt_ts_keys` trust anchor. The
pack cannot supply that anchor. Given `signed_statement`, `receipt`, that local
root, the certificate issuer key log and the `certificate_id`, ALL must hold or
the result is `scitt_receipt_valid = false` (fail-closed, hostile input never
crashes):
1. Parse both as COSE_Sign1 (caps before crypto: ≤ 64 KiB each, depth ≤ 16).
2. Issuer signature on `signed_statement` verifies under a key in the
   certificate's own bundle key-log; the protected profile is exact (`alg=-8`,
   the frozen content type, non-empty CWT `iss`, CWT `sub` equal to the
   lowercase-hex `certificate_id`, and an optional well-formed signed scope);
   its payload is exactly the same 32-byte `certificate_id`.
3. `statement_digest = SHA-256(signed_statement)`.
4. The exact root-signed registration policy in §7 verifies under the locally
   selected root and authorizes the complete TS key set, origin, profile and
   statement-size ceiling. The carried JWKS must equal that set exactly.
5. The separately signed outer checkpoint verifies under a policy-authorized
   TS key and names the policy's exact origin. TS signature on `receipt`
   verifies under the same policy-authorized key set.
6. From the receipt: recompute `body_hash = SHA-256(JCS(checkpoint body))`;
   it must equal the receipt payload.
7. The receipt's inner checkpoint body must equal the signed outer checkpoint
   body. The inclusion proof's `tree_size` must equal that checkpoint's size
   and `leaf_index < tree_size`.
8. RFC 9162 inclusion: `statement_digest` at `leaf_index` in `tree_size`
   proves to `checkpoint.root` via the audit path (`core/merkle.verify_inclusion`).
9. The checkpoint body_hash may separately carry an anchor and/or TST —
   these UPGRADE (independent time), they never gate `scitt_receipt_valid`.

**`scitt_receipt_valid` is VERIFIER-DERIVED at the certificate layer** — the
certificate verifier runs §6 whenever a registration layer is present and
OVERRIDES any producer-supplied flag. A producer can never self-assert
REGISTERED; the mark's registration axis is recomputed from the receipt bytes.

## 7. Offline trust pack (B25.5)

`evd/scitt-pack/v1` has the exact required fields `{ schema, certificate_id,
signed_statement, receipt, checkpoint, registration_policy, ts_jwks }` and the
only optional fields `{ anchor_record, tst_record }`. The certificate JSON
carries the two COSE envelopes as hexadecimal text; `checkpoint` is an exact
`SignedCheckpoint` (`body`, `kid`, `sig`). Unknown fields are rejected.

`registration_policy` has exactly `{ schema, policy_version, ts_origin,
accepted_profiles, max_statement_bytes, ts_keys, signature }`. Its schema is
`evd/registration-policy/v1`; `accepted_profiles` is exactly
`["scitt-action-profile-v1"]`; and `max_statement_bytes` is no greater than
65,536 and no smaller than the carried statement. `signature` is the Ed25519
signature by the locally configured TS root over RFC 8785 canonical JSON of
the other fields. Each `ts_keys` entry binds one derived kid to one strict
public Ed25519 JWK. The pack's `ts_jwks.keys` array must byte-for-data equal the
policy's ordered JWK array; it cannot add, omit or substitute a key.

This pack is self-contained only after the relying party supplies the named
TS root out of band. Subject-carried JWKs never anchor themselves. With that
local anchor it contains everything required to re-derive REGISTERED offline;
optional independently verified anchor/time records may strengthen the
separate time axis.

## 8. Transparency Service (B25.2) — the service, not the trust path

The TS authenticates the statement issuer, allow-lists profile/version/size
(the published, versioned `registration_policy`), appends the exact
`statement_digest`, signs a checkpoint over the new tree head, and returns the
Receipt. Registration policy and TS trust roots are themselves published and
versioned. **No second TS, HeadDeriver, continuity trustee, key-custody
consortium or custom consensus is required for the first paid or production
use** — one TS, the existing public anchor, and RFC 3161 time.

**Managed admission is fail-closed and prospective.** `POST /scitt/register`
requires a tenant API credential and `x-evd-scope-digest` (exactly 32 bytes as
lowercase hex). The Signed Statement signature MUST verify under a currently
active key in that tenant's append-only key log, and a NEW statement digest is
appended only when an active service entitlement covers that exact
tenant/scope at server time. Missing credentials, an unknown or revoked issuer
key, missing scope, an unavailable entitlement store, wrong scope, expiry, or
suspension MUST NOT append a leaf. The same already-registered statement may
be retried after lapse to recover its existing receipt: that creates no new
mark and keeps expiry prospective. Entitlement state is not embedded in the
statement, Receipt, checkpoint, or trust pack and is never read by offline
verification; historical receipt validity is therefore unchanged by later
commercial state.
The retry exception is scoped to the exact durable `(tenant_id,
covered_scope_digest, statement_digest)` registration tuple. The shared SCITT
Merkle leaf remains deduplicated by `statement_digest`, but a first use of a
known statement by a different tenant or covered scope is a new managed
registration and MUST pass that tenant/scope's active `managed-scitt-v1`
entitlement gate before the service records its tuple or returns a receipt. An
entitlement for another `service_profile` MUST NOT authorize managed SCITT.
Commercial entitlement commands are detached, canonical JSON facts signed by a
dedicated commercial-admin key; tenant API credentials do not authorize them.
Within each `(tenant_id, covered_scope_digest, service_profile)` timeline, a
distinct command's signed `signed_at` value MUST be strictly later than every
accepted command's canonical RFC 3339 UTC value. An exact replay of the same
signed `command_id` is a no-op; a stale or equal-timestamp distinct command
MUST be refused. This prevents a withheld pre-suspension command from
reactivating a scope while leaving exact historical receipt recovery
unaffected.
For managed admission the header scope MUST equal the protected signed
`evd_scope_digest` claim before the entitlement gate runs. The endpoint streams
the body under the policy's 64 KiB ceiling; `Content-Length` and chunked bodies
over that ceiling are rejected with 413 before COSE parsing or signature work.

### 8.1 Checkpoint boot audit, rollback pin and anchor target

Opening the Transparency Service log is a cryptographic audit, not merely a
SQLite integrity check. The implementation MUST reject a checkpoint history
unless all of the following hold: checkpoint JSON and fields parse strictly;
the `prev` chain is linear for the frozen TS origin; every checkpoint signature
verifies under the configured TS key; stored body hashes equal their signed
bodies; leaf indexes are dense and every leaf is exactly 32 bytes; and every
checkpoint root recomputes from the exact retained leaf prefix named by its
tree size. Anchors and RFC 3161 tokens MUST name a checkpoint retained by that
audited chain.

A production TS also requires an externally retained signed high-water
checkpoint. The pin is supplied from a root/service-owned regular file outside
`scitt.db`; it must be an exact member of the locally verified chain. A missing,
invalid, rolled-back or forked pin fences every new managed registration. One
empty-log registration is the only bootstrap exception, so the first signed
head can be created and retained; exact historical registration retries remain
recoverable because they append no new leaf or managed-registration tuple.

Public anchoring uses the role-specific TS signer and database as an explicit
`scitt` worker target. The worker MUST refuse a missing database rather than
create a substitute history. Operations MUST alert separately when an enabled
public-anchor path leaves the current TS checkpoint unanchored beyond the
configured age and when a production TS head lacks its external rollback pin.

## 9. Claim boundary

A Receipt proves: this issuer signed a statement committing to this
`certificate_id`, and that statement's digest was appended to an append-only
log whose head is independently timestamped and anchored. It proves nothing
about the certificate's content, the action's truth, coverage completeness, or
legal effect. Statement substitution, a forged receipt, a forked tree, a wrong
registration policy/root, and a stale checkpoint each fail §6.
