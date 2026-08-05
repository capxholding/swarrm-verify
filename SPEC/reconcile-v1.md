<!-- Apache-2.0 — this file ships with the public verifier repo. -->

# SPEC: reconcile-v1 — corroboration, deterministic matching, coverage

**Status: NORMATIVE (v1).** B23: the two-way comparison that makes both
deception directions visible. The Node independently scans every event in the
bound source scope (node-v1); it never merely looks up references the agent
supplied. Everything here is deterministic — no model participates, ever.
Reconciliation NEVER computes verdicts itself: it builds
`evd/verdict-input/v1` documents; the ONE derivation path is the B21 verdict
engine (verified-action-v1 §2), implemented identically in Python and Rust.

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

## 5. `CONTRADICTED` (terminal, never softened)

For a uniquely linked pair, the manifest's `material_fields` for the claim's
action class — never fields chosen at comparison time — are compared:
amount/value, currency, counterparty/recipient, result/status, and event
time outside the manifest's declared tolerance. Any material disagreement →
outcome `CONTRADICTED`, regardless of finality. It is never softened to
`CLAIM_ONLY`, never resolved by preferring either side, never suppressed by
a practitioner. Unique link + final event + no material disagreement →
`CORROBORATED`; unique link + non-final event → `CLAIM_ONLY` (pending
finality); event with no claim → `ORPHAN`.

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
`UNCOMPARABLE` — never `CORROBORATED`, because such a field is material by
construction in a Node build, and never `CONTRADICTED`, because a bare name
collision between two independently authored vocabularies is not proof of a
lie and this outcome is terminal.

## 6. Coverage (per bounded period; the batch is the unit)

The `evd/coverage-manifest/v1` document commits, per source and period:
cursor start/end, filter digest, declared count, ordered event-key root,
finality watermark, gaps, exclusions, the agent population (claim set) and
the orphan set. It is receipted under `_node` (context: period bounds,
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

> OPEN (producer side, 2026-08-05). Today `build_coverage` emits NONE of the
> four conventions into the document it digests, and `compile_certificate`
> does not embed the coverage receipt in the bundle it carries. Until both
> land, the binding above is inert in production and the §4.4 material
> recomputation reads a member the real Node has never written. Closing this
> is a coordinated producer-side change, recorded here so the gap is visible
> rather than implied.
Engine inputs are built honestly from Node state:
- gap-class findings (`cursor_gap`, `cursor_rollback`, `cursor_reuse`,
  `count_mismatch`, `event_root_mismatch`, `mapping_substituted`) each
  contribute a `batch.gaps` entry; an open `fork_divergence` or
  `continuity_gap` finding sets `fork_findings_open`.
- **Triage recomputation (completes B22.13):** a finding triaged
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

## 7. Corrections (B23.7)

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
