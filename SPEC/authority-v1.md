<!-- Apache-2.0 — this file ships with the public verifier repo. -->

# SPEC: authority-v1 — organisation roots, runtime binding, grants, action lifecycle

**Status: NORMATIVE (v1). Wire names frozen once shipped.**
Consumes `evd/receipt/v1` (SPEC/receipt-v1.md) unchanged: every object here is an
ordinary receipt with a new `action_type`. No new envelope. Verdict derivation
rules over these receipts live in SPEC/verified-action-v1.md; contract shapes
referenced here are CDDL-frozen in SPEC/cddl/verified-action-v1.cddl.

## 1. Actors and agents

- Org-level events are appended under the reserved internal agent **`_authority`**
  (dense seq is NOT required; verifiers must not assume density). `_authority` is
  exempt from lineage rules exactly like `_system`.
- `action.intent` / `action.submitted` are appended under the **acting agent's own
  `agent_id`** and thread `birthtag_id`/`revision_id` like any other receipt.
- Envelope signatures remain the log's issuer/recorder keys per receipt-v1. The
  ROOT's approval is carried **inside** `context` as a detached signature
  (`root_sig`) — mirroring the key log's `continuity_sig` precedent.

## 2. Detached signature rule (`root_sig`, `self_sig`, `transfer_sig`)

A detached signature over a document `doc` (a JSON object) is:

```
sig = base64( Ed25519_sign( key, b"evd/v1/authority/" + action_type + b"\x00" + JCS(doc) ) )
```

where `JCS` is RFC 8785 canonicalization and `doc` is the receipt's `context`
object WITHOUT the signature field itself (and without any other `*_sig` field).
Domain separation is the literal prefix shown; verifiers MUST reject a signature
verified under any other prefix. For `transfer_sig` the prefix is
`b"evd/v1/passport/transfer\x00"` and `doc` is the transfer object (§7).

## 3. Action types (all nine; exact context fields)

Plaintext context keys are listed exhaustively; anything else is a dial
violation (SPEC/context-v1.md). Commitments use domains `evd/v1/authority/<field>`.

### 3.1 `authority.root.enrolled` (agent `_authority`)
context: `root_jwk` (public OKP JWK) · `root_kid` · `legal_entity` (string) ·
`enrolment_basis` (string naming the verified evidence basis) · `effective_ts` ·
`self_sig` (by the ROOT key over the context minus `self_sig` — proof of
possession). commitments (optional): `enrolment_evidence`.
**Rules:** `root_kid` MUST equal the kid derived from `root_jwk` (receipt-v1 kid
rule). The enrolled root key MUST NOT be any key witnessed by the log's
`evd.key.*` history (separation of duties: the org root is a customer-held key,
never the plane's). `self_sig` MUST verify. A root may be superseded only by a
later `authority.root.enrolled` whose context carries `prev_root_kid` and a
`prev_root_sig` by the previous root (same detached rule, doc = context minus
both sig fields); absent that chain a second enrolment is a CONFLICT.
**subject id:** `org_id` = receipt_hash of the first valid enrolment.
**Claim boundary:** enrolment records who was enrolled and on what stated basis.
It does not make Swarrm the customer's authority, and a signature over
`enrolment_basis` proves who asserted the basis, never that it is so.

### 3.2 `authority.principal.bound` (agent `_authority`)
context: `birthtag_id` · `revision_id` · `principal` (workload/service identity,
string) · `runtime_kid` (the kid that must sign the bound agent's receipts) ·
`environment` · `valid_from` · `valid_to` · `org_root_kid` ·
`prev_binding_id` (optional) · `concurrent_with` (optional list of binding_ids,
explicit concurrency) · `root_sig`.
**subject id:** `binding_id` = receipt_hash.

### 3.3 `authority.grant.issued` (agent `_authority`)
context: `subject_birthtag_id` · `binding_id` (optional) · `action_classes`
(list) · `scope` (canonical scope descriptor object: `org` · `source_system` ·
`account` · `action_classes` · `selector`) · `limits` (static object; see
declaration types in A_BUILD B27.2A — `FLOW`/`STOCK`/`ONE_SHOT` shapes) ·
`policy_commitment` (hex digest) · `valid_from` · `valid_to` · `org_root_kid` ·
`transfers_grant_id` (optional; mandate transfer, §6) · `root_sig`.
**subject ids:** `grant_id` = receipt_hash; `grant_version` = 1.
`mandate_id` = the `grant_id` at the head of the `transfers_grant_id` chain
(follow the chain to the first grant; that receipt_hash IS the mandate_id — it
is derived, never declared, and survives Birthtag change).

### 3.4 `authority.grant.revised` (agent `_authority`)
context: `grant_id` · `prev_grant_version` (int) · `grant_version`
(= prev+1) · the FULL new grant document fields (same keys as 3.3) ·
`effective_ts` · `org_root_kid` · `root_sig`.
A revision is never a revoke-plus-reissue; the chain `grant_id` +
monotonically increasing `grant_version` is what band recomputation reads.
Two receipts claiming the same `(grant_id, grant_version)` with different
receipt hashes are a CONFLICT (a rewrite attempt) — the verifier never picks
a winner.

### 3.5 `authority.grant.revoked` (agent `_authority`)
context: `grant_id` · `effective_ts` · `org_root_kid` · `root_sig`.
Revocation is prospective from `effective_ts`; history is never rewritten.

### 3.6 `source.bound` (agent `_authority`)
context: `source_system` · `account` · `credential_identity` ·
`mapping_version` · `event_key_field` · `finality_rule` · `valid_from` ·
`valid_to` · `org_root_kid` · `root_sig`.
commitments (optional): `source_manifest`.
**subject id:** `source_binding_id` = receipt_hash. (Full SourceManifest
semantics are consumed in B23; the binding shape is frozen here.)

### 3.7 `source.binding.revoked` (agent `_authority`)
context: `source_binding_id` · `effective_ts` · `org_root_kid` · `root_sig`.

### 3.8 `action.intent` (acting agent)
Written BEFORE submission. context: `action_id` (opaque, created before
execution, reused across retries) · `action_class` · `grant_id` ·
`grant_version` · `binding_id` · `policy_version` ·
`assurance_transcript_digest` (optional, hex — B28 seam; frozen now because it
changes signed bytes). commitments: `inputs` · `context_doc`.
**subject id:** `intent_id` = receipt_hash.
`action.intent` claims neither hidden reasoning nor a successful outcome.

### 3.9 `action.submitted` (acting agent)
context: `action_id` · `source_ref` (optional, the reference returned by the
source). commitments: `request` (the exact request as submitted).

## 4. `intent_interval` (the only admissible time for an intent)

An intent's time is NEVER a producer timestamp. It is an interval derived from
log position and independently timed checkpoints:

- A checkpoint is **independently timed** iff the bundle carries an anchor
  record and/or TST for its `body_hash`; its `independent_ts` is the EARLIEST of
  its anchor `block_ts` and TST `gen_time` values (earliest proof of existence).
- `lower` = `independent_ts` of the LAST independently timed checkpoint with
  `tree_size <= leaf_index(intent)`; `null` if none.
- `upper` = `independent_ts` of the FIRST independently timed checkpoint with
  `tree_size > leaf_index(intent)`; `null` if none.

A narrower bracket is a stronger claim — the honest reason to anchor often.
Authority (§5) must cover the ENTIRE interval; a `null` bound cannot be
covered, so an unanchored log yields authority `NOT_VERIFIED` — the weaker
claim, by design.

## 5. Verifier derivation: identity · authority · intent

All three are verifier-derived; no producer may award itself a result. Closed
results: `VERIFIED`/`NOT_VERIFIED`/`CONFLICT` (identity, authority),
`RECORDED`/`NOT_RECORDED`/`CONFLICT` (intent). When bundle integrity is
`INVALID`, all three render their weakest value.

**Root replay.** Replay `authority.root.enrolled` in leaf order: first valid
enrolment fixes `org_id` and the active root; supersession follows the
`prev_root_sig` chain. An enrolment failing §3.1 rules is ignored for the
chain (and noted); a second unlinked enrolment → identity `CONFLICT`.

**identity = VERIFIED** iff: the acting agent's lineage passes birthtag-v1
rules; a `authority.principal.bound` exists whose `birthtag_id`/`revision_id`
match the agent's lineage, whose `root_sig` verifies under the active enrolled
root at that receipt's log position, whose `runtime_kid` signed the
`action.intent` envelope, and whose `[valid_from, valid_to]` covers the entire
`intent_interval`.
**identity = CONFLICT** iff two bindings whose validity windows overlap name
the same `runtime_kid` without each listing the other in `concurrent_with`, or
root enrolment conflicts (above), or lineage yields conflicting establishments.
Otherwise **NOT_VERIFIED** (including: no binding, forged `root_sig`,
substituted runtime key, revision mismatch, unauthorised passport import §7,
`null` interval bound).

**authority = VERIFIED** iff: a grant chain (`authority.grant.issued` plus
zero or more `authority.grant.revised`, each `root_sig`-valid under the active
root, versions dense from 1) exists whose subject matches the agent's
`birthtag_id` (or whose mandate chain reaches it via §6), whose effective
document at EVERY instant of the `intent_interval` (status replay: apply
issue/revisions/revocation by `effective_ts` across the whole interval)
includes `action.intent.action_class` in `action_classes`, has a validity
window covering the whole interval, and is not revoked at any instant of it.
Dynamic limits render `NOT_VERIFIED` unless their required state is
independently evidenced — a declaration is not evidence (GROUNDING RULE).
**authority = CONFLICT** iff two mutually `root_sig`-valid statements about the
same grant cannot both hold: duplicate `(grant_id, grant_version)` with
different hashes, or two grants disagreeing on the same authority field at the
same effective time for the same subject+scope.
Otherwise **NOT_VERIFIED** (pre-grant, post-revocation, wrong class, expired,
forged `root_sig`, missing grant, unbounded interval).

**intent = RECORDED** iff exactly one well-formed `action.intent` exists for
`action_id`, with required commitments present, and (when `action.submitted`
exists) at a strictly earlier leaf index.
**intent = CONFLICT** iff two or more distinct `action.intent` receipts exist
for one `action_id`. Otherwise **NOT_RECORDED**.

## 6. Mandate lineage

`mandate_id` is derived (§3.3), so it cannot be renamed away. A grant whose
`transfers_grant_id` references a prior grant carries that mandate forward to a
new Birthtag; unresolved findings follow the mandate. `scope_relation` between
two scope descriptors is derived by mechanical comparison of the canonical
descriptor predicates (SPEC/verified-action-v1.md §scope_relation); an opaque
digest can never yield `UNRELATED`.

## 7. BirthtagPassportV1 — portable migration

`evd/passport/v1` = `{ schema, birthtag_id, bundle, transfer }` where `bundle`
is an ordinary `evd/bundle/v1` containing the agent's establishment/revision
chain, the key log, and inclusion/consistency evidence; `transfer` =
`{ birthtag_id, successor_root_kid, effective_ts, transfer_sig }`.
`transfer_sig` is the detached signature (§2, passport prefix) by a key that is
ACTIVE in the passport bundle's own key log at export.

Import: the new deployment appends `lineage.adopted` whose context ALSO carries
`imported_birthtag_id` (= the passport's `birthtag_id`) and `passport_digest`
(= SHA-256 hex of `JCS(passport)`), then creates a fresh
`authority.principal.bound` under its own enrolled root. The permanent ID of
the migrated agent IS `imported_birthtag_id`; it never changes.

Verification: the passport bundle must verify standalone; `birthtag_id` must
equal its establishment receipt hash; `transfer_sig` must verify and its
`successor_root_kid` must equal the importing log's enrolled root kid. A copied
passport whose transfer does not name the importing root (or lacks a valid
`transfer_sig`) renders identity `NOT_VERIFIED` for the migrated agent.

Children: a child agent receives its OWN Birthtag plus a signed parent
reference; ephemeral workers reuse the parent's Birthtag plus an
instance/session id in `principal` — identity spam is not lineage.

## 8. Export rule

`export_bundle` MUST force-include, with inclusion proofs, every
`authority.*`/`source.*` receipt of the `_authority` agent covered by the
target checkpoint, exactly as key and lineage entries are force-included. A
bundle whose action verdicts are to be derived without them is not a defect —
the verdicts simply render their weak values.

## 9. Non-goals

No global identity service, wallet, reputation score or blockchain identity.
No claim that a policy commitment proves the policy was followed. No runtime
authentication: Birthtag remains lineage; the PrincipalBinding is the runtime
link and it is time-bounded, root-approved and revocable.
