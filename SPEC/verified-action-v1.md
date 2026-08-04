<!-- Apache-2.0 — this file ships with the public verifier repo. -->

# SPEC: verified-action-v1 — verdict vocabulary, derivations, conformance

**Status: NORMATIVE (v1). Values and derivations frozen; extending them
requires updating the conformance matrix, both engines and their fixtures in
the same commit (three-roles rule).**

Two documents are defined here, both JSON (CDDL in
SPEC/cddl/verified-action-v1.cddl):

- **`evd/verdict-input/v1`** — the canonical evidence-input document. It
  aggregates contract objects (SPEC/action-fact-v1.md) plus the
  bundle-derived authority facts (SPEC/authority-v1.md §5). Producers never
  write verdicts into it; it carries evidence only.
- **`evd/verdict-vector/v1`** — the verifier-derived result vector. Every
  field below is derived by the engine; no producer may award itself any
  value. Python (`verify/action.py`) and Rust (`verify-rs/src/action.rs`)
  MUST derive identical vectors from identical inputs.

**The weak-claim doctrine (governing rule):** at every ambiguity the engine
returns the weaker claim — `UNKNOWN`, `UNPROVEN`, `INSUFFICIENT`,
`NOT_VERIFIED`, `NOT_RECOMPUTED`, `INDETERMINATE`, or no mark. A value whose
name implies independence, completeness or externality derives only from
evidence outside the party it constrains; a signature over a declaration
proves who said it, never that it is so.

## 1. Dimensions and closed results

| Dimension | Closed results (weak default in *italics*) |
|---|---|
| identity | VERIFIED · *NOT_VERIFIED* · CONFLICT |
| authority | VERIFIED · *NOT_VERIFIED* · CONFLICT |
| intent | RECORDED · *NOT_RECORDED* · CONFLICT |
| outcome | CORROBORATED · *CLAIM_ONLY* · CONTRADICTED · ORPHAN (null when neither claim nor event) |
| linkage | DIRECT · DETERMINISTIC · AMBIGUOUS · *NONE* |
| coverage | CLOSED · GAPPED · *UNKNOWN* |
| integrity | VALID · *INVALID* |
| source_signature | ASYMMETRIC · SHARED_SECRET · NOT_RECOMPUTED (per-view) · *NONE* |
| control_domain | INDEPENDENT · OVERLAPPING · *UNKNOWN* |
| node_observation | OBSERVED · *NOT_OBSERVED* |
| client_attestation | ATTESTED · *NONE* |
| coverage_basis | SOURCE_PROVEN_POPULATION · ATTESTED_NODE_FULL_SCAN · *INSUFFICIENT* |
| node_integrity_basis | HARDWARE_ATTESTED · INDEPENDENTLY_ATTESTED · *LOG_WITNESSED_SOFTWARE* |
| temporal_binding | PROVEN_SOURCE_ECHO · PROVEN_INDEPENDENT · *UNPROVEN* |
| surface mechanism (per surface) | ENFORCED · OBSERVED · DECLARED · *UNKNOWN* |
| surface scope | DECLARED · *OUT_OF_SCOPE* · BOUNDARY_BREACH |
| accountability_basis | SPONSOR_ASSERTED · PARENT_GUARANTEED · INSURER_CORROBORATED · BONDED_OR_ESCROWED · *UNKNOWN* |
| assurance_linkage | DIRECT · DETERMINISTIC · AMBIGUOUS · *NONE* |
| scope_relation | RELATED · UNRELATED · *UNKNOWN* |
| population_status | PROVEN · *INDETERMINATE* |
| history_state | CLOSED_SINCE_BIRTH(surfaces) · NO_EVIDENCED_HISTORY_IN_PRESENTED_SCOPE · null (evidenced history exists) |
| authority_proof (handshake seam) | ACTION_SPECIFIC_AUTHORIZATION · DISCLOSED_LIMIT · *NONE* |
| technical_eligibility | ELIGIBLE · INELIGIBLE · *NOT_RECOMPUTED* |
| registration_status | REGISTERED · PENDING · *UNREGISTERED* |
| mark (render) | UNMARKED_ASSURANCE_WITHDRAWN · UNMARKED_TECHNICAL · UNMARKED_UNREGISTERED · PENDING_REGISTRATION · *NOT_RECOMPUTED* — **no value awards assurance; see §2.15** |

`assurance_linkage` is NEVER merged with `linkage`: one binds a counterparty
handshake to this action, the other binds an authoritative source event to it.

## 2. Derivation rules (normative; anchors are referenced by the matrix)

### 2.1 identity · authority · intent · integrity · intent_interval
Derived from the bundle per SPEC/authority-v1.md §4–§5 (or supplied to the
engine pre-derived, for contract-side fixtures). `integrity` is `VALID` only
when every signature, inclusion proof, chain link, key-history replay and
anchor referenced by the disclosed view verifies; any single failure yields
`INVALID` — there is no partial integrity. When integrity is `INVALID`,
identity/authority/intent render their weak defaults.

### 2.2 source_signature
`ASYMMETRIC` iff a `SourceProof` of type `asymmetric_signature` carries a
signature that VERIFIES under a key this relying party named in its trust
context (verify/trust.py) AND that key is pre-bound in `SourceIdentity`. The
producer's `verified: true` flag is IGNORED — it is a declaration, and a
subject could set it. `SHARED_SECRET` iff a MAC verifies under a shared secret
the relying party named — possession by *some* holder; it cannot attribute the
event to the source rather than the operator and never becomes `ASYMMETRIC` at
any volume.

`NOT_RECOMPUTED` iff THIS view withholds the proof material (`source_proofs` in
`view.withheld_fields`). This is per-view exactly like `mark`, and it exists
because `NONE` means *the source did not sign* — a materially different fact
about a counterparty from *the source signed and this view cannot check it*.
Rendering the second as the first understates evidence that genuinely exists,
and records a bank that signs its webhooks identically to one that does not.
The common case is a connector that verifies a webhook signature at intake over
the RAW delivery: B22.9 retains that material digest-addressed, so it never
travels to a relying party by default — and a fuller disclosure view carrying
the signed bytes lets the recipient recompute and earn `ASYMMETRIC`.
`NOT_RECOMPUTED` is NOT favourable: every mark path requires `ASYMMETRIC`.

Else `NONE`.

### 2.3 control_domain
`INDEPENDENT` iff a complete `ControlDomainEvidence` grounds it externally:
`legal_evidence` (source_registry, registry_id, ultimate_controller,
retrieved_at, retrieval_proof — all present) AND `key_provenance.method ∈
{DOMAIN_CONTROL, TRUST_LIST, EXTERNAL_CA}` with evidence and validity AND
evaluator + signature present AND `legal_evidence.ultimate_controller ≠
operator_ultimate_controller`. `OVERLAPPING` iff any declaration admits
overlap (admission against interest) or grounded evidence shows a shared
controller. Declarations alone, or any element absent/ungrounded → `UNKNOWN`.

### 2.4 node_observation · client_attestation · node_integrity_basis
`OBSERVED` iff the Node actually performed an authenticated read and signed
what it saw; never inferred from a signature it did not witness. The scan
statement MUST NAME WHAT IT SAW: `scan.batch_digest` is the SHA-256 of the JCS
bytes of the `batch` in the same verdict input, and the verifier recomputes it.
For an observed Node scan, that batch MUST carry valid `period_start` and
`period_end`; the digest therefore binds the source batch and its coverage
period, not only its cursor frame.
A scan block carrying only its booleans is byte-identical for every clean scan
one Node ever performs, so a genuine signature over it would verify beside any
source, period or cursor range — a signature that binds no material. A missing
or mismatched `batch_digest` is `NOT_OBSERVED`.
`ATTESTED` iff a client co-attested batch/export is present (rendered as the
client's own statement). `node_integrity_basis` from a valid, in-window,
unrevoked `NodeAttestation.method`; absent/invalid/expired/revoked/lapsed →
`LOG_WITNESSED_SOFTWARE`.

### 2.5 coverage_basis · coverage
`SOURCE_PROVEN_POPULATION` iff the source itself cryptographically proves the
bounded population/sequence for the period over a scope IT defines (a
source-signed count over an operator-supplied filter does NOT qualify).
`ATTESTED_NODE_FULL_SCAN` iff a complete, cursor-gap-free scan was performed
by a `HARDWARE_ATTESTED` Node — an `INDEPENDENTLY_ATTESTED` Node is a
validated starting state, not a witness, and a `LOG_WITNESSED_SOFTWARE` Node
that could be silently replaced cannot be the sole proof nothing was omitted:
both yield `INSUFFICIENT`. `complete` and `cursor_gap_free` are the subject's
own booleans, so this basis additionally requires `node_observation` to be
`OBSERVED` (§2.4): attestation proves a Node's INTEGRITY BASIS, never that some
particular scan was complete, and reading those flags outside a signed, bound
scan statement let an attested deployment declare a scan that never ran. Coverage: any cursor gap/rollback/reuse, batch gap
or open fork finding → `GAPPED`; complete gap-free scope with basis ≠
`INSUFFICIENT` → `CLOSED`; else `UNKNOWN`. Coverage may only be `CLOSED` when
the basis is not `INSUFFICIENT`.

### 2.6 linkage · outcome
Candidates are events matching the claim by (priority order) source-echoed
`action_id`, returned immutable source reference, policy-approved unique
field. 0 candidates → `NONE`; ≥2 → `AMBIGUOUS` (the verifier never picks a
winner); exactly 1 → `DIRECT` if matched by echoed `action_id`, else
`DETERMINISTIC`. Outcome: claim with no uniquely-linked final event →
`CLAIM_ONLY`; claim and uniquely-linked event disagreeing on a MATERIAL field
(named per action class in the SourceManifest, never chosen at comparison
time) → `CONTRADICTED` (terminal; never softened, never suppressed); claim
uniquely linked, final, no material disagreement → `CORROBORATED`; event with
no agent claim → `ORPHAN`. `AMBIGUOUS`/`NONE` are outcomes of linkage, not
errors; with them the outcome cannot reach `CORROBORATED`.

### 2.7 temporal_binding (the three times)
`intent_interval` and `source_effect_time` are never reconciled into one
clock. `PROVEN_SOURCE_ECHO` iff the source event causally embeds something
that could not have existed before the intent: the signed intent digest, our
`action_id`, or the challenge nonce, echoed back. `PROVEN_INDEPENDENT` iff
BOTH the intent record AND the source event carry independently attested
clock bounds from a party that is neither the operator nor Swarrm, and the
intervals are disjoint in the correct order. Everything else — including a
source merely declaring its clock synchronised, or only our record being
timestamped — is `UNPROVEN`. `UNPROVEN` blocks the MARK only; a
`CORROBORATED` outcome stands regardless.

### 2.8 surfaces
Per declared surface, three orthogonal fields, never collapsed: `mechanism`
(`ENFORCED`/`OBSERVED` only with an evidence source reference; a bare
declaration → `DECLARED`; unparseable → `UNKNOWN`), `control_domain` (same
derivation as 2.3 per surface — an enforced boundary whose controls the
operator owns is `ENFORCED` + `OVERLAPPING`, and both render), `coverage`
(2.5, scoped to the named surface AND period). Activity on an undeclared
surface class renders that class `OUT_OF_SCOPE` — explicitly, never
implicitly clean. Unexplained activity on a declared surface renders
`BOUNDARY_BREACH`.

### 2.9 accountability_basis
Strongest qualifying value of: `BONDED_OR_ESCROWED` > `INSURER_CORROBORATED`
(both require external grounding by a non-subject party) >
`PARENT_GUARANTEED` (parent-signed) > `SPONSOR_ASSERTED` (sponsor's own
signed binding — the name admits it is an assertion). Binding kinds are
exactly `SPONSOR` / `PARENT` / `INSURER` / `BOND_ESCROW` (exact string match;
any other kind never qualifies — no fuzzy matching in the trust path). A
binding qualifies only if signed AND agent-, mandate-, value- and
time-specific; otherwise `UNKNOWN`. Swarrm proves the named parties signed the artifacts; it never
asserts any guarantee is legally enforceable.

### 2.10 assurance_linkage
Intent without `assurance_transcript_digest` → `NONE` (normal and
unremarkable). Presented transcript digest equal to the intent's bound digest
→ `DIRECT`; exactly one candidate presentation matched via challenge nonce →
`DETERMINISTIC`; a transcript that does not match the intent it claims, or
multiple candidates → `AMBIGUOUS`.

### 2.11 scope_relation
Requires canonical scope descriptors (org, source_system, account,
action-class set, normalised selector). Either side digest-only/missing →
`UNKNOWN` (never silently `UNRELATED`). Different org, or selector kinds not
mechanically comparable → `UNKNOWN`. Same org/system/account with
intersecting classes and intersecting selector predicates → `RELATED`
(detected by comparison, not by anyone's declaration). Comparable and
provably disjoint on some axis → `UNRELATED`. Aggregation over candidates:
any `RELATED` → `RELATED`; else any `UNKNOWN` → `UNKNOWN`; else `UNRELATED`.

### 2.12 population_status
`PROVEN` iff the `PopulationIndex` carries the dense per-organisation
admission-sequence range, tree size, registered checkpoint ref, consistency
proof ref, canonical (comparable) query descriptor, result root, count and
signature. Any element missing → `INDETERMINATE` (an append-only root alone
proves entries are intact and ordered, not that every relevant item entered).

### 2.13 history_state
`CLOSED_SINCE_BIRTH(surfaces)` iff born with evidence and coverage closed
since birth over the NAMED manifest surfaces — never the agent globally;
every unnamed surface renders `OUT_OF_SCOPE` in the same presentation. No
evidenced history in the presented scope →
`NO_EVIDENCED_HISTORY_IN_PRESENTED_SCOPE`. Evidenced history exists → null
(history is presented as population-rooted facts, not a state).

### 2.14 authority_proof (B28 seam; shape frozen now)
`ACTION_SPECIFIC_AUTHORIZATION` iff root-signed and binding ALL of: exact
`action_id`, action class, exact value+currency, challenge nonce, authorising
and subject parties, `grant_id` AND `grant_version`, issue time, expiry, and
a unique replay id. `DISCLOSED_LIMIT` iff the relevant limit is disclosed
under selective disclosure and covers the action. A bare boolean or
commitment-plus-assertion → `NONE` (a commitment cannot prove a predicate
over its own preimage).

### 2.15 technical_eligibility · registration_status · mark
`technical_eligibility` = `NOT_RECOMPUTED` if any gated field is withheld
from this view (gated: identity, authority, intent, integrity, linkage,
outcome, coverage, coverage_basis, temporal_binding, fork findings, SCITT
receipt); `ELIGIBLE` iff identity VERIFIED ∧ authority VERIFIED across the
ENTIRE intent_interval ∧ intent RECORDED ∧ integrity VALID ∧ linkage ∈
{DIRECT, unique DETERMINISTIC} ∧ outcome CORROBORATED ∧ coverage CLOSED with
basis ≠ INSUFFICIENT ∧ no open fork finding ∧ temporal_binding ≠ UNPROVEN ∧
valid SCITT receipt; else `INELIGIBLE`.
`registration_status` = `REGISTERED` iff a valid `ScopeRegistration` covers
scope and term; `PENDING` iff a signed `RegistrationIntent` AND ≥1 signed
`RegistrationAttempt` exist (intent alone is `UNREGISTERED`, never pending);
else `UNREGISTERED`.
`mark` render, STRICT precedence (more than one condition may hold; the
verifier must not choose): 1. `NOT_RECOMPUTED` (evaluated first — without
inputs no other state is knowable) · 2. `PENDING_REGISTRATION` ·
3. `UNMARKED_UNREGISTERED` · 4. `UNMARKED_TECHNICAL` · 5. mark shown.
**THE MARK IS WITHDRAWN (owner audit 2026-08-03). NO INPUT AWARDS A MARK.**
Both former award paths — `VERIFIED_CORROBORATED` (ELIGIBLE ∧ REGISTERED ∧
source_signature `ASYMMETRIC` ∧ control_domain `INDEPENDENT`) and
`VERIFIED_OBSERVED` (ELIGIBLE ∧ REGISTERED ∧ node_observation `OBSERVED` ∧
node_integrity_basis `HARDWARE_ATTESTED`) — now render
`UNMARKED_ASSURANCE_WITHDRAWN`, and both values are REMOVED from the
`mark-render` enum in the CDDL. This is a **wire-format change**, made
deliberately: a format that still admits an unsafe value invites a producer to
emit it.

The reason: those conditions were satisfiable from a subject's own
declarations. `source_signature` reached `ASYMMETRIC` from a `verified: true`
boolean plus key-**name** equality, with **no signature bytes verified against
a pre-bound source key**; `control_domain` reached `INDEPENDENT` from truthy
strings in `control_evidence`. A subject could therefore award itself the top
mark, which is precisely the deception this document exists to prevent.

Restoring either value requires its inputs to be verified proof bytes checked
against trust roots supplied **independently of the subject's own submission**,
and is itself a wire-format change. Until then: ELIGIBLE ∧ REGISTERED with
neither path satisfied still renders `UNMARKED_TECHNICAL` (the evidence did
not qualify), `client_attestation` alone reaches no mark, and the two
dimensions are always rendered alongside the projection — the render states
are never a substitute for the pair.

## 3. Claim/threat matrix (what each deception renders as)

| Threat | Rendered result |
|---|---|
| agent lies about value/result/reference | outcome `CONTRADICTED` |
| agent omits an action; source effect exists | outcome `ORPHAN` |
| claim with no final source event | outcome `CLAIM_ONLY` |
| forged/absent org root approval on binding | identity `NOT_VERIFIED` |
| workload key enrols itself as root | identity `NOT_VERIFIED` (enrolment invalid) |
| substituted runtime key signs the intent | identity `NOT_VERIFIED` |
| two undeclared concurrent bindings, one key | identity `CONFLICT` |
| grant rewrite (same id+version, different content) | authority `CONFLICT` |
| action before grant validity / after revocation | authority `NOT_VERIFIED` |
| two intents for one action_id | intent `CONFLICT` |
| post-hoc intent (no anchored bracket) | authority `NOT_VERIFIED` (unbounded interval) |
| copied passport, unauthorised binding | identity `NOT_VERIFIED` |
| HMAC event dressed as source-signed | source_signature `SHARED_SECRET`, never `ASYMMETRIC` |
| operator-controlled "independent" source | control_domain `OVERLAPPING`/`UNKNOWN` |
| software-Node full scan claimed complete | coverage_basis `INSUFFICIENT`, coverage ≠ `CLOSED` |
| cursor gap/rollback/fork | coverage `GAPPED` |
| two matching source candidates | linkage `AMBIGUOUS` (no winner) |
| withheld gated field under selective disclosure | `NOT_RECOMPUTED`, never a pass |
| accepted-source collusion | explicit limit — not detected; stated in every report |

## 4. Conformance: the three-roles matrix (machine-readable)

`ci/verdict_matrix.json` (`evd/verdict-matrix/v1`) enumerates EVERY value of
every dimension above with: `derivation` (an anchor into this spec),
`gate` (what reads the value), ≥1 `positive_fixtures` entry and, wherever a
near-miss is meaningful, `negative_fixtures`. `scripts/check_verdict_matrix.py`
fails CI when: a value has no fixture; a referenced fixture file does not
exist; a fixture's expected vector disagrees with the matrix (positive must
yield the value, negative must not); the matrix's value sets disagree with
the CDDL enums. Fixtures live in `tests/golden/verdicts/` (verdict-input
documents + `expected_vectors.json`) and `tests/golden/bundles/` (authority
bundles + `expected_authority.json`, which also pins the byte-identical
subject IDs). Both engines run both fixture sets; Python and Rust must agree
on every row.

## 5. Parity: property-based differential harness

`scripts/gen_differential.py` generates verdict-input documents from the
schema mirror `ci/verdict_input_schema.json` with a seeded stdlib PRNG (no
new dependencies): valid documents plus structured mutations (dropped fields,
weakened evidence, flipped booleans, duplicated candidates). A unit test
pins the schema mirror to the CDDL enum-for-enum, so generation is
CDDL-derived without a CDDL runtime. The harness runs the Python engine and
the Rust engine (`cargo test --test differential`, corpus dir via
`SWARRM_DIFF_DIR`) over the same corpus and fails on ANY vector divergence.
CI generates a fresh corpus per run (seed = run id); fixtures remain the
regression anchors, never the parity guarantee.

## 6. Claim boundary

Swarrm proves registered evidence and deterministic comparison. It does not
prove hidden reasoning, activity outside the bound source scope, the truth of
a colluding/compromised accepted source, or that any guarantee is legally
enforceable. The mark is technical policy conformance — not a legal opinion,
statutory audit, admissibility ruling, insurance decision or guarantee that
an accepted source was truthful.
