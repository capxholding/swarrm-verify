<!-- Apache-2.0 — this file ships with the public verifier repo. -->

# SPEC: scitt-action-profile-v1 — SCITT registration for Verified Action Certificates

**Status: NORMATIVE (v1). Profile frozen BEFORE implementation.**
SCITT is the standard registration layer, not the product. One Swarrm
Transparency Service (TS) registers **commitment-only** certificate
statements — it appends the digest of a Signed Statement and returns a
Receipt; it never sees the certificate content. SCITT proves issuer
attribution and transparent append-only registration — never statement
truth, complete source coverage, action time, or legal admissibility.
§10 names the exact standards revision this profile is written against and
enumerates every divergence from it.

COSE is a **small reviewed adapter** (`core/cose.py`, `verify-rs/src/cose.rs`)
over the certificate CBOR codecs (`cbor2` / `ciborium`) — no general trust
framework.
Signing reuses the existing Ed25519 keys as COSE alg **-8 (EdDSA)**; the kid
is the existing rule `base64url(SHA-256(pubkey))[:16]`, carried as its ASCII
bytes. As with the certificate profile, **cross-language canonical-byte
vectors MUST pass before
any SCITT code relies on the COSE adapter** (tests/golden/cose/): `cbor2`-built
and Rust-built COSE_Sign1 bytes are byte-identical.

## 0. Profiled revision and divergences

This profile is of **`draft-ietf-scitt-architecture-22`** (latest revision
2025-10-10), published June 2026 as **RFC 9943**, *An Architecture for
Trustworthy and Transparent Digital Supply Chains*. The Internet-Draft
revision is named because that is the identifier this document used before
the RFC was assigned; RFC 9943 is the stable successor of that exact draft.
This is a **profile**, not a claim of conformance. Where the profile is
deliberately stricter than RFC 9943, that is a documented divergence, not
an accident to be quietly dropped.

### Divergences

Each item is a place we differ from RFC 9943 / the draft, with the reason
a reader should not have to rediscover by diffing the two documents.

1. **Commitment-only registration.** RFC 9943 permits registering a Signed
   Statement whose payload is the artifact (or a statement about it). This
   profile's statement payload is exactly the 32-byte `certificate_id`.
   Reason: payloads never persist server-side; the TS appends a digest and
   must never see certificate content.

2. **EdDSA / COSE alg -8 only.** RFC 9943 and COSE allow other signature
   algorithms. This profile admits only Ed25519 as alg `-8`.
   Reason: boring crypto only — reuse the existing Ed25519 keys; no
   algorithm agility in the trust path.

3. **One VDS: `RFC9162_SHA256` (COSE header `395: 1`).** RFC 9942 registers
   a family of verifiable data structures. This profile uses only RFC 9162
   SHA-256 inclusion over the existing RFC 6962 log.
   Reason: `core/merkle.py` is the CT golden-vector implementation; a second
   VDS would be novel cryptography in the trust path.

4. **The Transparency Service is outside the trust path.** RFC 9943 places
   the TS at the centre of the architecture as the keeper of the VDS. Offline
   verification here requires a *locally supplied* TS trust anchor; a pack
   cannot supply that anchor, and a producer cannot self-assert REGISTERED.
   Reason: a TS that can equivocate is not a trust root. Public anchor plus
   RFC 3161 close time without the TS holding time itself.

5. **Registration is asynchronous.** RFC 9943 describes a registration flow
   the issuer can wait on. Certificate creation here never waits for the TS.
   Reason: fail-open — evidence machinery may never block agent traffic.

6. **One TS, no federation.** RFC 9943 contemplates multiple transparency
   services. This profile requires one TS for first production use.
   Reason: plural transparency services (1.6) is a later property and must not be simulated
   by standing up a second private log and calling it federation.

7. **Managed admission is a product layer, not a SCITT claim.** Tenant API
   credentials, `x-evd-scope-digest`, and commercial entitlements are not in
   RFC 9943.
   Reason: tenant isolation and billing are operator concerns. Entitlement
   state is not embedded in the statement, Receipt, checkpoint, or trust
   pack and is never read by offline verification, so historical receipt
   validity is unchanged by later commercial state.

8. **Receipt payload is the checkpoint `body_hash`.** RFC 9943 receipts wrap
   a VDS proof; this profile's receipt payload is
   `SHA-256(JCS(checkpoint body))`, not merely the Merkle root.
   Reason: bind the receipt to the exact checkpoint the public anchor and
   RFC 3161 token cover, so a root-only match against a different checkpoint
   body cannot pass.

## 1. Deterministic COSE_Sign1

A COSE_Sign1 is the CBOR array (tag 18) `[protected: bstr, unprotected: map,
payload: bstr / null, signature: bstr]`, encoded under the deterministic
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

## 3. Registration flow (asynchronous — evidence, not assertion)

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

## 5. Independent time

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

## 7. Offline trust pack

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

## 8. Transparency Service — the service, not the trust path

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

## 10. Standards base — the revision profiled, and every divergence

This profile is written against **`draft-ietf-scitt-architecture-22`**
(2025-10-10), published as **RFC 9943** (Proposed Standard, June 2026) with
an unchanged section layout — the architecture citations below hold for both
texts. Receipt structures profile **RFC 9942** (COSE Receipts): the `395`
(`vds`) and `396` (`vdp`) labels in §1 and §4 are that RFC's final registered
assignments, and `RFC9162_SHA256 = 1` is its registered tree algorithm. The
lists below were derived by reading both documents' normative text in full
against both verification engines (`verify/scitt.py`, `verify-rs/src/scitt.rs`).
Anything not listed is intended to conform; a mismatch found later is a defect
in THIS section and must be corrected here, never argued around.

Naming a revision is not an interoperability claim. A receipt is portable only
when an independent SCITT implementation demonstrably verifies one of ours and
we verify one of theirs; until that demonstration exists this profile claims
conformance-with-divergences, nothing more.

### 10.1 Restrictions — the standard's open choices, closed (conformant)

- **R1 — one algorithm.** `alg` is frozen to EdDSA (`-8`) for statements and
  receipts. RFC 9943 §9.6 recommends cryptographic agility; this profile
  refuses it: one reviewed signing path in two engines, no downgrade surface.
- **R2 — kid-only identity, no X.509.** RFC 9943 §6's `x5t`/`x5chain` path is
  conditional on using X.509 certificates; this profile never does. Issuer
  trust is the certificate bundle's append-only key log; TS trust is the
  locally supplied root (§6–§7). The §6 URI and length rules on `iss` bind
  only when `x5t`/`x5chain` is present, so they do not apply here.
- **R3 — deterministic encoding.** Every envelope is encoded under the
  deterministic CBOR profile (§1). RFC 9943 mandates no encoding profile;
  byte-identical cross-engine verification does.
- **R4 — closed maps.** Protected headers and CWT claims must equal the
  profile exactly; an unknown label or claim fails verification, and the
  statement's unprotected header must be the empty map (stricter than RFC
  9943 §6.3, which empties it only before sequence inclusion). RFC 9943's
  CDDL leaves these maps open (`* label => any`); an ignored header is an
  unread claim carrier, so nothing is ignored. The one extension carried
  under this rule is the `evd_scope_digest` CWT claim (§2), permitted by
  that open CDDL.
- **R5 — commitment-only payload, always.** RFC 9943 §6.2 permits statements
  over a hash for large or sensitive payloads; this profile makes that the
  ONLY mode (§2: the payload is exactly the 32-byte `certificate_id`). The
  content type (`3`) names the certificate format the commitment refers to,
  not the 32-byte digest itself — stated here because RFC 9943 leaves
  hashed-statement content typing unspecified.
- **R6 — no consistency receipts.** RFC 9943 §3 requires Receipt profiles to
  support inclusion proofs and leaves other proof types optional (RFC 9942
  §5.3). Cross-head consistency is carried by the checkpoint `prev` chain,
  the public anchor and the RFC 3161 token (§5) instead.

### 10.2 Divergences — where these bytes do NOT conform, and why

- **D1 — receipts carry no CWT claims.** RFC 9943 §6 requires the protected
  header of a Receipt to include CWT claims (`15`) with `iss` and `sub`; this
  profile's receipt protected header is exactly `{1, 4, 395}` (§4). Reason:
  the TS identity a relying party trusts is the root-signed registration
  policy's exact key set and origin, verified at §6 steps 4–5 — an in-band
  self-asserted `iss` is an unverified naming surface, and `sub` has no
  referent for a digest-leaf receipt. Cost, stated: a generic RFC 9943
  consumer rejects these receipts.
- **D2 — receipt payload is the checkpoint body_hash, attached.** RFC 9942
  §5.2.1 makes the (detached) payload the Merkle tree root. Here it is the
  attached 32-byte `SHA-256(JCS(checkpoint body))` (§4). Reason: the root
  alone cannot be matched against the public anchor and RFC 3161 token —
  binding the full body (root, size, ts, prev) is what closes §5's loop to
  independent time.
- **D3 — the inclusion proof is one bare triple.** RFC 9942 §5.2.1 encodes
  `396: {-1: [+ bstr]}`, each entry a `.cbor`-wrapped `[size, leaf, path]`.
  This profile encodes `396: {-1: [tree_size, leaf_index, [* bstr]]}` — one
  proof, unwrapped (§4). Reason: frozen before RFC 9942 stabilized; the
  wrapper adds a second decode layer with no verification value here, and
  the exact bytes are pinned by the cross-language golden corpus.
- **D4 — private unprotected label `-2`.** The receipt's unprotected header
  carries the enclosing checkpoint body at label `-2` (§4) — a private-use
  label, not a COSE-registered parameter (RFC 9942's `-2` is a label inside
  the `396` proofs map, a different position). Reason: §6 steps 6–7
  recompute the payload from this body; declared here so it is never
  mistaken for a registered assignment.
- **D5 — the log registers digests, not Signed Statements.** RFC 9943's
  Statement Sequence, replayability (§5.1.3) and registration auditability
  (§5.1.1.2: "the Signed Statements themselves") assume the TS retains the
  statements. Here the leaf is the 32-byte `statement_digest` and the TS
  retains nothing else (§4, §8). Reason: this is the profile's core privacy
  property — the TS never sees or stores certificate content; the issuer
  retains the statement and supplies it to the relying party. Cost, stated:
  TS-side audit reproduces admission over digests; content-level audit
  requires the issuer.
- **D6 — the registration policy is signed and pinned, not registered.**
  RFC 9943 §5.1.1.1 requires policies and trust anchors to be made
  transparent by registering them as Signed Statements on the VDS, applying
  the most recently committed one. Here the policy is a versioned,
  root-signed canonical-JSON document, carried in the pack and verified
  against a locally supplied root (§7). Reason: D5 makes the log
  commitment-only — policy content on it would breach that property — and a
  root-signature check against a local anchor does not depend on the log's
  own operator for policy discovery. RFC 9943 §5.1.2's "preconfigured
  Registration Policy and trust anchors" bootstrapping mode is the permanent
  mode here.
- **D7 — no Transparent Statement, no label `394`.** RFC 9943 §7 attaches
  Receipts into the statement's unprotected header (`394`). Here the
  registered leaf commits to the COMPLETE statement bytes with an empty
  unprotected map (§2, R4), so attaching anything afterwards would change
  the digest and break its own inclusion proof. The receipt travels beside
  the statement in the trust pack (§7), which also carries what `394`
  cannot: policy, JWKS and checkpoint. Reason: envelope immutability IS the
  commitment; a mutable envelope cannot be the thing a digest-leaf pins.
- **D8 — vendor-tree media types.** This profile uses
  `application/vnd.swarrm.action-statement+cose` and
  `application/vnd.swarrm.scitt-receipt+cose`, not RFC 9943 §10.1/§10.2's
  `application/scitt-statement+cose` and `application/scitt-receipt+cose`.
  Reason: after D1–D3 these envelopes are not generically consumable, and
  wearing the registered types would claim an interoperability the bytes do
  not deliver. A revision that closes D1–D3 may adopt the registered types.
