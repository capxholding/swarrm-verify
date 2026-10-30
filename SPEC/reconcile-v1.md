<!-- Apache-2.0 — this file ships with the public verifier repo. -->

# SPEC: reconcile-v1 — corroboration, deterministic matching, coverage

**Status: NORMATIVE (v1).** Reconciliation: the two-way comparison that makes
both
deception directions visible. The Node independently scans every event in the
bound source scope (node-v1); it never merely looks up references the agent
supplied. Everything here is deterministic — no model participates, ever.
Reconciliation NEVER computes verdicts itself: it builds
`evd/verdict-input/v1` documents; the ONE derivation path is the
verified-action verdict engine (verified-action-v1 §2), implemented identically in Python and Rust.

## 1. Correlation (`action_id` / `external_ref`)

`action_id` is opaque, created BEFORE execution, reused across every retry;
where the source supports it, an opaque token derived from it is placed in
the source's normal reference/idempotency field (the manifest's
`correlation_field`). `external_ref` carries the source's returned reference.
Neither ever contains business data. Carriage is ADDITIVE: `action_id` and
`external_ref` join `birthtag_id`/`revision_id` as universal plaintext
context keys (context-v1 §1b) — settable via SDK event parameters, the
gateway headers `x-evd-action-id` / `x-evd-external-ref`, and the OTel
attributes `evd.action_id` / `evd.external_ref`.

## 2. SourceManifest approval (consumes authority-v1 §3.6)

The manifest document (committed under `source.bound`, root-approved) fixes,
BEFORE the coverage period: source identity + account/environment, read
credential identity and scope (mechanically read-only), query/filter,
`mapping_version`, `event_key_field`, finality/correction rules,
`correlation_field` (nullable), and `material_fields` **per action class**.
Scans against a source with no effective root-approved binding, or with a
`mapping_version` differing from the bound manifest, raise a
`mapping_substituted` finding and degrade the period's coverage — never
silently proceed.

Production log-stream manifests carry `enumeration_property: UNKNOWN` and
the configured enumeration declaration. A local landing does not prove origin
or population. The coverage document retains both under its receipt digest.
`swarrm node doctor` exposes the generated manifest as a draft; the existing
root approval requirement applies before it can bind a coverage period.

## 3. Claims

An `AgentActionClaim` is assembled per `action_id` from the agent's own log:
`action.intent` (class, commitments) + `action.submitted` (`source_ref`) +
the correlated business receipt when present. A claim exists iff an intent
exists; agent activity with no intent is out of claim scope (it is still in
the coverage population as unclaimed agent traffic).

## 4. Matching (deterministic; the verifier never picks a winner)

Candidates for a claim are events matching by ANY of, priority naming only
the label: (1) source-echoed `action_id` (the event's `correlation_field`
value or reference equals the claim's `action_id` token) → the match is an
ECHO; (2) returned immutable source reference (`event.reference ==
claim.external_ref`); (3) a manifest-approved unique-field equality. Events
are deduplicated by immutable `event_key` BEFORE matching (a replayed
delivery is one event). Candidates are counted FLAT across methods:
0 → linkage `NONE`; ≥2 → `AMBIGUOUS` (an outcome, not an error);
exactly 1 → `DIRECT` iff matched by echo, else `DETERMINISTIC`.

### 4.1 Unique-field surplus

Flat counting has a consequence that must be stated rather than discovered:
where a claim is AMBIGUOUS over N events, all N are consumed, so none of them
is an orphan. An action the agent did NOT record, against a unique-field
value it DID use in the same period, therefore produces no orphan and no
contradiction — only a fact saying which event it was could not be told.

For each unique field the SourceManifest declares, a period therefore also
states, per value: how many events the source stated, how many claims the
agent made, and the SURPLUS `events − claims` where that is positive. The
surplus is a COUNT and carries no event key: it says how many actions the
source states beyond what was claimed, never which of them was unclaimed.
Naming one would require an echo channel; where the manifest declares no
`correlation_field`, no such naming is derivable and none is offered.

A value absent from both populations produces no row: absence on both sides
is silence, and a zero-surplus row would read as a cleared period. A value
whose claims equal or exceed its events produces no row either — a count that
fired when the agent had claimed everything would be an accusation, which §5
forbids for exactly this reason.

Surplus rows must name a declared unique field and a nonempty value, with
nonnegative integer claim counts, strictly larger integer event counts and
an exact positive difference. Boolean/string coercion, duplicate field/value
rows and unknown fields are refused. Rows are ordered by field then value.
The committed total sums these **field-level** differences; it is not a count
of distinct unclaimed actions across multiple fields and must not be labeled
as one. A valid row shape does not independently authenticate either population.
An older caller that supplies no reconciliation result omits both surplus
fields; this means uncomputed, not a measured zero. Callers that perform
reconciliation must pass its complete surplus result, including an explicit
empty list when there are no positive differences.

## 5. `CONTRADICTED` (terminal, never softened)

For a uniquely linked pair, the manifest's `material_fields` for the claim's
action class — never fields chosen at comparison time — are compared:
amount/value, currency, counterparty/recipient, result/status, and event
time outside the manifest's declared tolerance. Any material disagreement →
outcome `CONTRADICTED`, regardless of finality. It is never softened to
`CLAIM_ONLY`, never resolved by preferring either side, never suppressed by
a practitioner. Unique link + final event + no material disagreement →
`MATCHED`; unique link + non-final event → `CLAIM_ONLY` (pending
finality); event with no claim → `ORPHAN`.

**Renamed in 1.4 (was `CORROBORATED`).** The value states a deterministic
field-level match between the claim and the linked event — nothing more. The
former word imported independent-confirmation strength the mechanism does not
prove; independence lives entirely in the control-domain evidence and §8
depth. Engines emit only `MATCHED`. The derivation path never parses outcome
words from carried artifacts (verifiers recompute the vector from
`verdict-input`), so no engine accepts either spelling as input; a reader of
persisted ≤1.3.x artifacts (facts, vectors, rendered reports) MUST treat
`CORROBORATED` as the deprecated ≤1.3.x spelling of the same value.

**The floor (NORMATIVE).** A manifest's per-class `material_fields` EXTEND
the comparison; they can never retract it. The floor is
`{value, currency, counterparty}` — the implemented subset of the list
above — and a verifier MUST compare the floor union the manifest's named
fields, whatever the manifest says or omits. A manifest naming a narrower
set, an absent `material_fields`, or an action class relabelled so the
lookup misses, all recompute the floor.

**Order-free, and MISMATCH dominates (NORMATIVE).** Every effective field is
evaluated before the outcome is decided. A verifier MUST NOT return on the
first field one side is missing: a producer-inserted one-sided field would
otherwise mask a real disagreement behind an earlier `UNCOMPARABLE`, which
is exactly the softening this section forbids.

**Undeclared fields (NORMATIVE).** A disagreement on a field carried by both
the claim and the source event, which is neither declared in the
verified-action-v1 types nor named by the manifest, makes the pair
`UNCOMPARABLE` — never `MATCHED`, because such a field is material by
construction in a Node build, and never `CONTRADICTED`, because a bare name
collision between two independently authored vocabularies is not proof of a
lie and this outcome is terminal.

## 6. Coverage (per bounded period; the batch is the unit)

The `evd/coverage-manifest/v1` document commits, per source and period:
cursor start/end, filter digest, declared count, ordered event-key root,
finality watermark, gaps, exclusions, the agent population (claim set), the
orphan set, and the §4.1 unique-field surplus with its total. The surplus is
committed here rather than left to a renderer because it is the ONLY trace of
an action the source states and no claim covers when the matching was
AMBIGUOUS: in that case the candidate events are consumed and the orphan set
is empty, so a period that dropped the surplus would read as fully
reconciled. It is receipted under `_node` (context: period bounds,
counts, roots, `coverage_doc_digest`; commitment: the canonical document).

**Binding the comparison conventions (NORMATIVE, verifier side).** When a
certificate's embedded bundle carries an `evd.coverage.recorded` receipt, the
carried `coverage_doc` MUST be the document that receipt signed:
`sha256_hex(canonical_bytes(coverage_doc))` MUST equal a signed
`context.coverage_doc_digest`. That single equality binds the whole mapping
convention block — `correlation_field`, `unique_fields`, `finality_rule`,
`material_fields` — none of which is otherwise echoed or cross-checked.
Absence of the receipt is not a failure: bundles that carry none are
verified with the conventions unbound, and the residual is stated in
certificate-v1 §7.

> OPEN (producer side). `build_coverage` copies into the document it digests
> exactly those conventions the SourceManifest declares, so a source that
> declares none leaves the binding above inert and the §4.4 material
> recomputation with nothing to read; `compile_certificate` detects that case
> and records a limitation rather than asserting a proof it cannot make.
> What remains open is embedding the coverage receipt in the carried bundle,
> so the conventions can be tied to a signed digest. Closing this
> is a coordinated producer-side change, recorded here so the gap is visible
> rather than implied.
Engine inputs are built honestly from Node state:
- gap-class findings (`cursor_gap`, `cursor_rollback`, `cursor_reuse`,
  `count_mismatch`, `event_root_mismatch`, `mapping_substituted`) each
  contribute a `batch.gaps` entry; an open `fork_divergence` or
  `continuity_gap` finding sets `fork_findings_open`.
- **Triage recomputation (completes the finding/triage lifecycle):** a finding
  triaged
  `RESOLVED_FACTUAL` no longer contributes its gap entry — coverage changes
  ONLY because the verifier re-derives from the updated finding set, never
  because anyone declared it. `ACCEPTED_LIMITATION` KEEPS its gap entry
  (accepted is not erased). An untriaged finding past its window sets
  `scan.complete = false` — completeness is unattested while findings pend —
  which derives coverage `UNKNOWN`.
- `scan`/`node_attestation` fields per node-v1; the basis derivation is
  engine §2.5 unchanged (a software Node's complete scan stays
  `INSUFFICIENT`).
- **The requested period must itself be observed and finalized.** A batch from
  some other window never makes `scan.performed` or `scan.complete` true merely
  because it exists in the source's chain. A normalized event with a
  source-effect time inside the period proves a scan was performed there, but
  one event cannot prove the negative population fact that nothing else
  happened later in the window. `scan.complete` therefore additionally
  requires an RFC 3339 `finality_watermark` reaching through the period end
  (also the only way to attest a genuinely empty window). A cursor-shaped
  watermark cannot be placed on a wall clock. If prior batches exist but the
  period was never reached, the manifest names `period_not_scanned` and
  coverage is `GAPPED`; if it was reached but not finalized, the signed scan is
  performed but incomplete and coverage remains `UNKNOWN` absent another
  sufficient population proof. No batch at all yields pending/`UNKNOWN`.
Only a gap-free, replayed full scope with a sufficient basis derives
`CLOSED`. A source outage never closes the affected window and catches up
deterministically from the persisted cursor.

## 7. Corrections

Reversals, corrections and late-finality changes create LINKED new facts:
the new `ActionFact` carries `correction_of` = the digest of the prior fact
and a fresh comparison against the corrected event. History is never
overwritten; a previously issued certificate is not made retroactively
false — the correction is a new fact with its own verdicts.

## 8. Corroboration depth

Where two or more sources with INDEPENDENT control domains each uniquely
corroborate one action, the fact records `corroboration_depth` = the count
of distinct corroborating independent sources. Depth is recorded, never
assumed; one source is never counted twice under different names (identity
is the bound `SourceIdentity`, not the connector instance).

## 9. Claim boundary

Reconciliation proves the registered evidence and the deterministic
comparison. It does not prove hidden reasoning, activity outside the bound
source scope, or the truth of a colluding/compromised accepted source —
collusion must span every named source at depth ≥2, and that residual is
stated in every report.

## 10. Two-party dispute package

`evd/dispute-artifact/v1` carries exactly `schema`, `case_ref`,
`party_labels`, `contested_claims`, `bundles`, and `reconciliation`.
`case_ref` is nonempty text. `party_labels` is an ordered pair of distinct,
nonempty strings; `bundles` is an object with exactly these two keys and
object values. `contested_claims` is a sorted, unique list of nonempty
strings. The producer may canonicalize a list or tuple of requested claims;
a consumer MUST refuse a noncanonical carried list. A string is not a claim
list. `reconciliation` is an object. Missing/extra fields and incorrect types
refuse before either bundle is verified.

After shape admission, the consumer independently verifies both bundles,
requires distinct origins and genesis trust roots, and recomputes the entire
`evd/two-party-reconciliation/v1` document. It MUST compare the complete
carried document with the recomputation, including scope, party facts,
receipt hashes, statements and summary. Verifying only the embedded bundles
is insufficient. Labels and case references identify the presented case;
they are not independently authenticated legal identities. No reconciliation
adjudicates fault or establishes that an unsupported event did not occur.

The Rust/WASM `verify_dispute_json(package_json)` byte entrypoint accepts at
most 128 MiB, rejects duplicate JSON members, and returns exactly `schema`,
`verdict`, `reconciliation` and `package_digest`. Its result schema is
`evd/dispute-verification-result/v1`. `VERIFIED` carries the recomputed
reconciliation and SHA-256 of the canonical complete package. On
`NOT_VERIFIED`, both data members are null. This verdict verifies the
package's stated provability; it does not resolve the underlying dispute.

For compatibility, v1 distinct material values retain the producer's
`json.dumps(value, sort_keys=True)` ordering, with ASCII escapes and Python
floating-point exponent spelling. This comparison representation is separate
from the package digest's RFC 8785 canonicalization. Boolean and numeric
values remain distinct, including in carried summary counts.
