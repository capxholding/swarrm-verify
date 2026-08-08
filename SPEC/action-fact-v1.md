<!-- Apache-2.0 — this file ships with the public verifier repo. -->

# SPEC: action-fact-v1 — B21.7 contract objects (frozen here, consumed later)

**Status: NORMATIVE (v1). Shapes are frozen in
SPEC/cddl/verified-action-v1.cddl — the CDDL is the shape authority; this
document adds semantics only. No build may reference a type a later build
defines: B22/B23 populate these objects, B24 binds the registration objects,
B25 operates the registration service, B28 implements the handshake — none of
them defines a shape.** Verdict derivation over these objects lives in
SPEC/verified-action-v1.md; conformance rows live in `ci/verdict_matrix.json`
(referenced below as *matrix:* by dimension name).

## 1. Common conventions

- **Canonical form.** The canonical bytes of any object are RFC 8785 (JCS)
  canonical JSON. The **canonical digest** of an object is the SHA-256 hex of
  its JCS bytes.
- **Detached signatures.** Where an object carries `signature` (or a `*_sig`
  field), it is a detached Ed25519 signature per SPEC/authority-v1.md §2:
  `base64(sign(key, b"evd/v1/<name>\x00" + JCS(doc)))` where `<name>` is the
  middle segment of the object's `schema` (e.g. `evd/surface/v1` →
  `evd/v1/surface`) and `doc` is the object without any `*_sig`/`signature`
  field. Commitments inside objects use domains `evd/v1/...` likewise.
- **Timestamps** are RFC 3339 UTC, compared per the frozen normalization rule.
- **Weak-claim doctrine** governs every consumer: a malformed, missing or
  partial object never raises; it degrades to the weak verdict value.
- No object in this file carries, or may ever gain, an aggregate score field.

## 2. AgentActionClaim (`evd/claim/v1`)

The agent's own statement of what it did. **Deliberately a separate object
from `SourceEvent`**: the claim and the authoritative system's event are
different kinds of statement made by different parties, and the product exists
to compare them — one merged record would imply they are the same kind of
thing and would let a producer write the comparison result.
- `action_id` — opaque, created before execution, reused across retries;
  identical to `action.intent.action_id` (SPEC/authority-v1.md §3.8).
- `value`/`currency`/`counterparty`/`external_ref` — claimed, not proven.
- `inputs_commitment`/`context_commitment` — hex digests under
  `evd/v1/authority/inputs` and `evd/v1/authority/context_doc`.
A claim proves nothing by itself; matrix: `outcome` (`CLAIM_ONLY`).

## 3. SourceEvent (`evd/source-event/v1`)

The authoritative system's statement, as evidenced by a `SourceProof`.
- `event_key` — the source's immutable key for the event; the linkage
  candidate identity.
- `source_identity_ref` — names the `SourceIdentity` the proof verifies under.
- `outcome`/`finality` — the source's result and finality state, in its own
  vocabulary; the mapping is fixed by `SourceBatch.mapping_version`.
- `source_effect_time` — the SOURCE clock. Never reconciled with our clock or
  with `intent_interval` (SPEC/verified-action-v1.md §2.7); rendered as the
  source's statement.
- `proof_digests` — digest pointers into retained proof material (§7).
An event with no matching claim renders `outcome = ORPHAN`.
Matrix: `outcome`, `linkage`, `temporal_binding`.

## 4. ActionFact (`evd/action-fact/v1`)

The **pairing** of exactly one claim with zero or one event, plus the derived
`linkage` and `outcome` — **never a merged record**. The claim's fields and
the event's fields keep their provenance; material comparison (fields named
per action class in the SourceManifest, never chosen at comparison time)
happens across the pair. B23 populates and matches; it defines nothing.
Canonical digest: SHA-256 of JCS of the whole pairing.
Matrix: `linkage`, `outcome`.

## 5. SourceIdentity (`evd/source-identity/v1`)

What `source_signature` and `control_domain` are derived **against**.
- `declared_control_domain`/`declared_controller` — declarations. They bind
  the declarer and can support `OVERLAPPING` (admission against interest);
  they can never produce `INDEPENDENT` (§9).
- `keys[]` — pre-bound verification keys with validity windows; a
  `SourceProof` verifying under a key NOT pre-bound here yields
  `source_signature = NONE`, not `ASYMMETRIC`.
- `rotation_pointer` — where the source publishes rotations; informative.
Matrix: `source_signature`, `control_domain`.

## 6. SourceBatch (`evd/source-batch/v1`)

Manifest of one scan or delivery. **The batch, not the individual event, is
what coverage is computed over**: a single verified event proves itself, never
that nothing else happened in the period.
- `cursor_start`/`cursor_end` — the opaque cursor range this batch closes (§8).
- `filter_digest` — digest of the filter/query used; a digest is opaque, so a
  batch alone never establishes scope comparability (§16).
- `mapping_version` — pins the outcome/finality mapping used for its events.
- `declared_count`/`event_key_root` — count and ordered event-key root; a
  mismatch between them and the delivered events is a gap finding.
- `finality_watermark` — the point up to which the source considers events
  final; events past it may still change and cannot be `final`.
- `exclusions`/`gaps` — explicit, never silent; any entry in `gaps` forces
  coverage `GAPPED`.
- `population_proof` — qualifies for `SOURCE_PROVEN_POPULATION` only when
  `source_scope_defined` and `verified` are both true: the SOURCE must define
  the scope; a source-signed count over an operator-supplied filter does not
  qualify.
Matrix: `coverage`, `coverage_basis`.

## 7. SourceProof (`evd/source-proof/v1`)

Raw provenance for one event or batch: `proof_type` (asymmetric signature ·
MAC · authenticated read transcript · client attestation), `material_digest`,
`key_identity`, `verified`. It carries no interpretation; derivation belongs
to the verifier.

**Retention rule (normative — this reverses part of commit-and-discard).**
Proof material is RETAINED: encrypted in the customer vault, digest-addressed
by `material_digest`, never inlined — and it MUST survive through certificate
generation and export, because a discarded signature cannot be re-verified by
a recipient years later. Commit-and-discard applies to *business payload
content the customer has not elected to retain*, never to proof material.
A `SourceProof` whose material cannot be resolved by digest degrades the
dimension it supports to its weak value; it never blocks the pipeline.
Matrix: `source_signature`, `client_attestation`, `node_observation`.

## 8. Cursor semantics (normative; no object of their own)

Cursors are **opaque, monotonic and source-defined**. The connector MUST
persist a cursor only after the batch it closes is durably written — never
before. Cursor rollback, cursor reuse, or a gap between consecutive ranges is
a finding and forces coverage `GAPPED`. Cursors are **never reconstructed or
inferred**: a lost cursor is a gap, not a guess. Matrix: `coverage`
(`GAPPED`).

## 9. ControlDomainEvidence (`evd/control-evidence/v1`)

What grounds `INDEPENDENT`, since a declaration cannot (GROUNDING RULE):
- `legal_evidence` — externally retrieved registry data: `source_registry`,
  `registry_id`, `ultimate_controller`, `retrieved_at`, `retrieval_proof`.
  All five present, or the object grounds nothing.
- `key_provenance` — `method ∈ {DOMAIN_CONTROL, TRUST_LIST, EXTERNAL_CA}`
  with evidence and a validity window covering the evaluation.
- `evaluator` + `signature` — who evaluated; attribution, not truth.
`INDEPENDENT` additionally requires `legal_evidence.ultimate_controller ≠
operator_ultimate_controller` (SPEC/verified-action-v1.md §2.3). Declarations
remain collected separately: they bind the declarer, make a false claim
attributable, and may establish `OVERLAPPING` — never `INDEPENDENT`. Any
element absent or ungrounded → `UNKNOWN`. Matrix: `control_domain`.

## 10. PopulationIndex (`evd/population-index/v1`)

An append-only root alone proves entries are **intact and ordered — NOT
exhaustive**: it cannot show that a relevant item never entered the log. The
missing half is the **dense per-organisation admission counter**: every
mandate, grant, finding and certificate receives a gapless sequence number at
admission, so a never-admitted item leaves a visible hole exactly as a
missing receipt does.
- `dense_seq_range` — the gapless admission range the result covers.
- `checkpoint_ref`/`consistency_proof_ref` — registered checkpoint and
  consistency proof anchoring the tree state.
- `query_descriptor` — a canonical `ScopeDescriptor` (§16), never a digest.
- `result_root`/`count`/`signature` — the answered population and who signed.
`population_status = PROVEN` only with EVERY element present; any element
missing → `INDETERMINATE`. Matrix: `population_status`.

## 11. NodeAttestation (`evd/node-attestation/v1`)

Third-party statement about a Customer Evidence Node's integrity:
`attester_identity` + `attester_control_domain` (the attester is subject to
the same control-domain doctrine), `deployment_id`, `node_public_key`,
`measured_digest`, `method` (the node-integrity-basis it supports),
validity window, `continuity_requirements`, `revocation_pointer`.

**Lifecycle (prospective only; history is never rewritten):**
`ISSUED → LAPSED` (a continuity requirement broke) `→ EXPIRED` (validity
window ended) `→ REVOKED` (attester revocation, effective from its
`effective_ts` forward). Only a valid, in-window, unrevoked `ISSUED`
attestation supports its `method`; absent/invalid/expired/revoked/lapsed →
`LOG_WITNESSED_SOFTWARE`, and an `INDEPENDENTLY_ATTESTED` Node is a validated
starting state, not a scan witness. Matrix: `node_integrity_basis`,
`coverage_basis` (`ATTESTED_NODE_FULL_SCAN`).

## 12. AgentSurfaceManifest / SurfaceEntry (`evd/surface-manifest/v1`, `evd/surface/v1`)

A signed declaration of each capability surface in scope (runtime lifecycle ·
tool calls · agent-to-agent messages · credential issue/use · network egress ·
downstream effects · heartbeats/cursors). Per entry:
- `mechanism_declaration` — what the operator claims; `ENFORCED`/`OBSERVED`
  render only with `evidence_source_ref` present, else the surface derives
  `DECLARED` (or `UNKNOWN` if unparseable).
- `controller_grounded_independent`/`controller_admits_overlap` — feed the
  per-surface `control_domain` under §9 doctrine; an enforced boundary whose
  controls the operator owns is `ENFORCED` + `OVERLAPPING`, and both render.
- `coverage_closed`/`coverage_gap` — per-surface, per-period coverage inputs.
- `effective_from`/`effective_to` — the declared interval; `signature` binds
  the entry to the declarer.
**Scope semantics:** activity on a surface class not in the manifest renders
that class `OUT_OF_SCOPE` — explicitly, never implicitly clean. Unexplained
activity on a declared surface renders `BOUNDARY_BREACH`. The manifest also
names the surfaces over which `history_state = CLOSED_SINCE_BIRTH(surfaces)`
may ever be claimed — never the agent globally.
Matrix: `surface_mechanism`, `surface_scope`, `history_state`.

## 13. Registration and view objects (frozen HERE; B24 binds, B25 operates)

### 13.1 ScopeRegistration (`evd/scope-registration/v1`)
A registry-signed statement that a scope is registered for a term.
- `covered_scope_digest`/`scope_description_digest` — what is covered and its
  human description, both digest-committed.
- `policy_version`/`policy_digest` — the policy consumed by the historical,
  now-withdrawn mark derivation.
- `band_commitment` — commitment to the fee band; never a score.
- `entitlement_status` + `prev_registration_id` — an append-only chain
  `ISSUED → AMENDED → EXPIRED/SUSPENDED`; amendments link, never overwrite.
`registration_status = REGISTERED` iff a valid registration covers scope and
term. Matrix: `registration_status`, `mark`.

### 13.2 RegistrationIntent / RegistrationAttempt
(`evd/registration-intent/v1`, `evd/registration-attempt/v1`)
A signed intent to register plus signed submission attempts, each pinned to a
log checkpoint. `PENDING` requires a signed intent AND at least one signed
attempt — an intent alone is `UNREGISTERED`, never pending (an intent to
register is not a submission). Matrix: `registration_status` (`PENDING`).

### 13.3 VerificationViewManifest (`evd/view-manifest/v1`)
Names exactly which certificate fields a view discloses and withholds, the
policy version, and the mark rendered for that view. Withholding any gated
field forces `technical_eligibility = NOT_RECOMPUTED` and
`mark = NOT_RECOMPUTED` — never a pass. Matrix: `technical_eligibility`,
`mark` (`NOT_RECOMPUTED`).

## 14. Retired pre-B28 handshake seams

The dictionary-era `evd/trust-*/v1` and `evd/status-snapshot/v1` objects are
retained only so historical artifacts remain readable. They are **not** the
current B28 protocol, producers MUST NOT emit them as Counterparty Assurance
v1, and their legacy verifier route is disabled. In particular, a legacy
`authority_proof_kind`, `disclosed_limit`, producer-selected trust policy, or
status reference cannot satisfy B28 identity, authority, freshness, replay or
transcript checks.

The sole normative B28 profile is `swarrm-b28/v1` in
SPEC/handshake-v1.md: deterministic CBOR in one tagged COSE_Sign1 envelope,
with proof-bearing authority state and an exact action-specific authorization.
The legacy matrix dimensions `authority_proof` and `assurance_linkage` remain
part of the evidence/certificate verifier only; they do not stand in for a B28
verdict.

## 15. ConnectorHealth (`evd/connector-health/v1`)

Operational telemetry: last successful cursor and its wall time, lag,
consecutive failures, credential validity remaining, declared vs observed
algorithm family, degradation reason. **Health degrades COVERAGE; it never
blocks execution** and never silently pauses a scan — a sick connector yields
`GAPPED`/`UNKNOWN` coverage, not a stopped agent. An observed algorithm
family differing from the declared one is a finding. Matrix: `coverage`.

## 16. ScopeDescriptor (canonical and comparable)

`org · source_system · account · action_classes · selector{kind, predicates}`.
The point of the descriptor is mechanical comparability: `scope_relation` and
population queries run over its predicates. **An opaque digest can never
yield `UNRELATED`** — two different digests say nothing about whether their
populations intersect, so a digest-only scope renders `UNKNOWN`, never
silently `UNRELATED`. Selector predicates are normalised (sorted keys, sorted
value lists) before JCS so equal scopes have equal digests.
Matrix: `scope_relation`, `population_status`.

## 17. Claim boundary

These objects record who stated what, under which key, over which scope and
period. They do not prove hidden reasoning, activity outside the bound source
scope, the truth of a colluding or compromised accepted source, the solvency
or legal enforceability of any guarantee, or that a committed policy was
followed. A signature over a declaration proves who said it, never that it is
so; every consumer must degrade to the weaker claim at every ambiguity.
