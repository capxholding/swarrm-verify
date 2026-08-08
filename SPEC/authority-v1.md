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
`assurance_transcript_digest` + `challenge_envelope_hash` +
`presentation_envelope_hash` + `asa_envelope_hash` (optional as one all-or-none
B28 group, lowercase SHA-256 hex; derived from the exact signed envelopes).
commitments: `inputs` · `context_doc`.
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

Two rules keep `independent_ts` from becoming a producer timestamp by the back
door. A TST's `gen_time` is cross-checked against the genTime inside a token
whose signature, chain and imprint are verified; `block_ts` had no counterpart,
and offline it is an unsigned string in an additive member that any holder or
forwarder can edit. Both rules are backed by signatures already in the bundle:

- **Not before signing.** A checkpoint cannot be anchored before it existed, and
  its `ts` is signed, so an anchor record whose `block_ts` precedes it is
  REJECTED (`anchors_ok` false). Without this, backdating two strings moved an
  intent recorded 17 days after its grant was revoked into the grant window and
  flipped authority to `VERIFIED`, through the certificate layer, exit 0.
- **Clamped to what contains it.** Checkpoint N is a prefix of every later
  checkpoint, so a proof that N+1 existed by T proves N did too. Each
  `independent_ts` is therefore clamped to the earliest proven for it or for any
  checkpoint containing it. Without this, post-dating one `block_ts` produced an
  INVERTED interval (`lower` after `upper`) — and "covers the ENTIRE interval"
  is vacuously true of an interval that cannot exist, so an action taken BEFORE
  its grant was issued verified as authorised.

What remains unproven offline — that the anchor transaction exists at all, and
that it is not post-dated within the window these rules allow — needs `--live`.
The CLI renders an unconfirmed anchor as a claim, never a tick.

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

## 10. B28 proof-bearing authority profile

The receipt forms above remain the historical evidence authority model. B28
adds closed, deterministic-CBOR authority objects under the
`swarrm-b28/*/v1` schemas; it does not reinterpret an ordinary evidence issuer
as organisational authority.

### 10.1 Closed principals

| principal | permitted operation |
|---|---|
| Organisation Governance Root | sign every authority-state mutation |
| Passport & Status Authority | issue a credential from active supplied state; sign a read-only status snapshot |
| Action Authority | reserve capacity and issue an exact ASA inside an active root grant |
| Admin passkey | authenticate and select an existing template within one root-bound role |
| Agent key | registration PoP, holder proof, B28 messages, intents and receipts |
| Tenant evidence issuer | evidence receipts/checkpoints only |

Only the root creates, revises, supersedes or revokes templates,
`AdminBindingV1` objects, mandates, limit grants, delegations, passports/agents,
agent successor links and assumed-risk releases. A Passport Authority signature
cannot widen or create those facts. A console account without a valid active
`AdminBindingV1` has no selection authority.

B28 Beta supports an offline, dual-controlled organisation-root successor
ceremony. It does not turn server administration into root recovery: the
currently enrolled old root authorizes the exact successor core and the new
root proves possession by signing those identical bytes. Loss of the old root
without a previously signed successor remains unrecoverable by the hosted
service. Favourable `PASS` remains disabled independently of this continuity
mechanism.

### 10.2 Closed signed object set

- `RootDelegationV1` binds tenant/root, delegation id, passport and action
  authority keys, and validity. The two authority keys and their derived kids
  MUST differ; a single delegated key cannot hold both roles.
- `RootRotationV1` binds one tenant's current root/version to exactly one new
  root, encrypted-bundle digest, prior-rotation digest and strictly increasing
  effective time. It is carried in its dedicated deterministic-CBOR
  dual-signature envelope, not a single-signer CWT.
- `RegistrationTemplateV1` binds an immutable versioned template to owner,
  purpose, mandate/config digests and validity.
- `AdminBindingV1` binds tenant/root, binding id, WebAuthn credential id, exact
  COSE public key, RP ID, closed role, validity and initial `ACTIVE` state.
- `AdminSelectionV1` binds an active binding to the exact template/version and
  proposed-agent digest, with a one-use WebAuthn challenge and assertion.
- `AgentPoPV1` binds Birthtag/revision, dedicated agent kid, proposed-agent
  digest and one-use challenge; the dedicated agent key signs it.
- `AgentCredentialV1` binds tenant/root/delegation, Birthtag and revision,
  dedicated agent key, owner, purpose, mandate/config commitments, template,
  principal binding, selection/PoP digests, issuance checkpoint and validity.
  Passport Authority and agent sign the same credential core.
- `LimitGrantV1` binds exact actor/recipient, operation, fixed unit, kind,
  ceiling/windows, validity and maximum unresolved exposure.
- `AuthorityMutationV1`, `AuthorityCheckpointV1`, `StatusSnapshotV1` and
  `AssumedRiskReleaseV1` have the state semantics below.

All maps have exact key sets, unsigned epoch seconds and fixed-width byte
identifiers. Text decimal quantities are canonical unsigned integers with no
FX or float interpretation. A unit is exactly `iso4217:AAA:minor-N`
(`AAA` uppercase, `N` one decimal digit), `ucum:TOKEN` or `count:TOKEN`
(`TOKEN` 1..48 printable non-space ASCII bytes); action and grant strings must
match byte-for-byte and are never converted. Ed25519 signatures are tagged
COSE_Sign1 under exact protected headers; WebAuthn alone uses ES256/P-256.

### 10.3 Root mutations and authenticated state

Root succession is separate from authority-map mutation. `RootRotationV1`
contains the tenant and organisation id, successor sequence (initial root is
version 1), random rotation id, prior envelope digest (all-zero only for the
first successor), old/new root public keys, kids and SHA-256 fingerprints,
old/new encrypted-bundle digests, and effective time. The old and new Ed25519
keys and their derived kids MUST differ. Both keys sign exactly:

```text
"swarrm-b28/root-rotation/v1\0" || deterministic-CBOR(RootRotationV1)
```

The envelope has exactly `schema`, `core`, `old_signature` and
`new_signature`. A service starts from its already enrolled old key; embedded
keys do not create trust. In one transaction it verifies both signatures,
tenant/current-root/bundle binding, next sequence, previous envelope digest and
strictly increasing effective time; appends the immutable envelope; and
compare-and-swaps the current public root. Replays, stale records, forks,
future-effective records and reuse of any historical root fail closed.
The local continuity verifier starts from an independently pinned initial root
and replays the complete gap-free sequence; dual signatures without that
starting anchor prove possession but do not establish an organisation.

Hosted state is root-versioned. After the compare-and-swap, an old cached
authority is fenced before it can issue or import another artifact, and the
new root begins with an empty authority map: delegations, grants, credentials
and checkpoints must be newly authorized. Historical directories, rotation
envelopes and pre-rotation evidence are retained. A relying party that retains
the old anchor can continue to verify pre-rotation evidence; root succession
does not rewrite or invalidate those historical signatures.

State key:

```text
SHA-256("swarrm-authority-state/v1\0" || kind || "\0" || object_id)
```

The second NUL terminates the variable-length textual `kind`; it is part of the
v1 domain separation and prevents a suffix of one kind from becoming a prefix
of another kind's binary object identifier.

The leaf value is deterministic CBOR over the key, closed state
`ACTIVE|REVOKED|SUPERSEDED`, positive version and canonical object digest.
Entries sort lexicographically by state key and use RFC 6962 leaf/node hashing.

Before signing, the local root tool verifies the current append-only-log
checkpoint, recomputes the complete supplied map, applies the exact sorted
changes, and signs a mutation containing tenant/root, next sequence,
previous/new map roots, changes and effective time. The service compares and
commits sequence, previous root, event and new state in one transaction. It
never accepts a caller-supplied partial map as the complete state.

The hosted implementation persists a separate high-water pin for that state.
Because the authenticated map and hosted registry are separate SQLite
databases, every import first commits a `PREPARED` journal entry containing the
exact prior and target checkpoint envelopes, their digests, the operation
digest and, for a grant import, the exact grant accounting identity. Only then
may it update the authority database. Recovery recognizes only the exact prior
or exact target described by that journal: an exact prior remains pending for
a byte-identical retry; a complete exact target is promoted; a partial grant
target remains pending; and rollback, fork or any other divergence fails
closed. While a journal entry is pending, passport signing, ASA reservation and
all other authority mutations are refused. For a grant import, active capacity
accounting is installed before the hosted grant material, and publication of
that material and promotion of the high-water pin occur in one hosted-registry
transaction. No database may infer completion merely because the other moved.

Membership is a standard inclusion path. Non-membership requires an empty tree,
a verified boundary neighbor, or verified adjacent predecessor/successor leaves
which straddle the requested key. `AuthorityCheckpointV1` binds the root-signed
map head to the append-only authority-log root and size. Rollback or a fork is a
contradiction, never merely stale state.

### 10.4 Status and passport issuance

A Passport Authority receives the active root delegation, template,
AdminBinding, verified AdminSelection, agent PoP and complete proofs. It may
sign only a credential whose fields equal that supplied active state. A new
mandate, revision or successor first requires a root mutation; an earlier
credential is immutable.

A status snapshot contains checkpoint and proof-set digests, state time and a
short expiry. Its signature attests to those supplied proofs only. A B28
presentation embeds the checkpoint, objects and proofs so the relying party can
recompute them rather than trusting references or a server-side “not revoked”
claim.

Current authority is conjunctive: the presentation proves active membership
for the credential's mandate and configuration commitments and for an
`agent_head` keyed by Birthtag. The head value binds the exact credential
digest, and its authenticated-state version equals the credential revision.
An older passport cannot remain current after its mandate/config is revoked or
its Birthtag head is superseded.

Freshness is bounded: the proof is true at the signed checkpoint. A missing,
expired or locally unregistered checkpoint is `INDETERMINATE`; a verified
revocation, rollback or fork is `FAIL`. Existing Birthtags and evidence history
are adopted additively and are never rewritten.

### 10.5 WebAuthn selection

WebAuthn v1 accepts ES256 on P-256 only. The verifier checks the exact RP ID
hash, allowed HTTPS origin, type, one-use challenge, credential id, user
presence and user verification flags and rejects attested-credential data,
extension data and reserved flag bits. Backup eligibility and backup state are
accepted, but backup state without backup eligibility is rejected. A zero/zero
counter transition is treated only as “counter unsupported”; every other
accepted transition must strictly increase.

The organisation root signs those exact before/after counters and backup flags
in `AdminConsumptionV1`, alongside the challenge, selection and credential
digests, binding id and counter version. The same final root mutation updates
the authenticated `admin_counter` state keyed by binding id to that exact core
digest and version as the current head; earlier immutable per-challenge
consumptions remain active. A presentation for an earlier agent proves its own
consumption and requires the current head version to be no lower, rather than
requiring the head to retain the historical digest. The local root tool derives the first-use zero counter from
verified non-membership. For reuse, preparation carries the prior root-signed
consumption; the local tool verifies its digest/version against the complete
authenticated map, uses its exact `sign_count_after`, and atomically advances
the counter version with the registration mutation. Omission, rollback and two
concurrent branches from the same counter head fail closed. The verified
selection must name the same active binding and template/version used in the
issued credential.
