<!-- Apache-2.0 — this file ships with the public verifier repo. -->

# SPEC: certificate-v1 — the portable Verified Action Certificate

**Status: NORMATIVE (v1). Profile frozen BEFORE implementation (B24.1).**
Media type `application/vnd.swarrm.action-certificate+cbor`. The certificate
is a deterministic-CBOR projection COMPILED from artifacts that first pass
ordinary verification; it is never a new source of authority. The external
signed wrapper is B25's SCITT profile; internal receipts remain DSSE/JCS.

## 1. Deterministic CBOR profile (the codec contract)

RFC 8949 §4.2.1 Core Deterministic Encoding, restricted:
- definite lengths only; no tags; no indefinite items; **no floats**;
- data model: `null`, `bool`, signed 64-bit integers, UTF-8 text, byte
  strings, arrays, and maps with TEXT keys only;
- map keys sorted by the bytewise-lexicographic order of their ENCODED bytes;
- the payload objects are the SAME JSON-compatible structures the rest of the
  stack uses (bundle, verdict-input, coverage doc), so every structure has
  both a JCS/JSON form and exactly one CBOR form.
Codecs (owner sanction O·1, §0.2·3): Python `cbor2` (canonical mode), Rust
`ciborium` primitives under a canonical emitter (ciborium does not sort map
keys itself — the emitter does, and it is part of the verifier surface).
**Cross-language canonical-byte golden vectors MUST pass before any
certificate code relies on the codec** (tests/golden/cbor/): for every
vector, `cbor2` bytes == Rust emitter bytes, byte-identical.

## 2. Three objects (never merged)

1. **Certificate core** (`evd/certificate/v1`) — immutable, per action,
   identical for every recipient; no view-specific and no
   registration-specific material. `certificate_id` = SHA-256 hex over the
   core's deterministic-CBOR bytes.
2. **View envelope** (`evd/certificate-view/v1`) — per recipient; carries
   the `VerificationViewManifest`, optional disclosure packages, and the core
   bytes **only for a full view**; signed separately. A view naming any
   withheld field MUST omit `core`, otherwise the supposedly hidden bytes are
   still trivially decodable. Many envelopes commit to one core.
3. **Registration artifacts** (`RegistrationIntent` / `RegistrationAttempt`
   / `ScopeRegistration`, action-fact-v1 §13) — reference `certificate_id`
   and therefore live OUTSIDE the core. Resolution order is core → envelope
   → registration; a verifier renders WHICH layers it holds and never
   pretends to a layer it lacks.

## 3. Core contents (frozen key set; CDDL in SPEC/cddl/certificate-v1.cddl)

`schema` · `subject` (action_id, action_class, origin, subject_ids) ·
`bundle` (the complete `evd/bundle/v1` for the action: lineage, enrolment,
binding, grant, intent/submission receipts, checkpoint chain, anchors, TSTs)
· `claim` · `events` · `event_matches` · `source_identity` ·
`control_evidence?` · `batch` · `scan` · `coverage_doc`
(`evd/coverage-manifest/v1`) · `node_attestation?` (first-class, with its
measurement basis) · `open_findings` (EVERY open finding for the covered
period — an omitted finding is a silent overclaim) · `proof_digests`
(retained source-proof material, digest-addressed) ·
`assurance_transcript_digest?` + `presentation_digest?` (B28 seam) ·
`agent_context_digest` (SHA-256 over JCS of `{surface_manifest_digest,
org_bindings_digest, mandate_lineage_digest}` as they stood at the
`intent_interval` — the artifacts themselves are NOT inline; a B28
presentation must reproduce this digest; a verifier holding only the
certificate renders "context bound, not carried", never "absent") ·
`verdict_input` (the complete `evd/verdict-input/v1`) · `limitations`
(closed text codes, enumerated below) ·
`current_through` (the historical cut-off; current status never collapses
into it) · `policy_version` · `attachments?` (digest manifest for large
external material — attachments can never change the verdict).

**The closed limitation codes (NORMATIVE).** §3 declared closure without
enclosing the set; the set is exactly:

- `AGENT_CONTEXT_UNBOUND` — present **iff** `agent_context_digest` is the
  all-zeros digest. A BICONDITIONAL, not a convention: the compiler emits the
  pair or neither, so a core carrying one without the other refutes itself on
  its face. Stripping the code while leaving the zeros made a
  context-UNBOUND certificate read as context-bound with no error at all.
- `ACCEPTED_SOURCE_COLLUSION_OUT_OF_MODEL` — a trust-model statement (§7),
  legal but not internally refutable, so its presence is not enforced.
- `COVERAGE_CONVENTIONS_UNBOUND` — present **iff** the bundle carries NO
  `evd.coverage.recorded` receipt whose signed `coverage_doc_digest` equals
  SHA-256(JCS(`coverage_doc`)). Also a BICONDITIONAL, and VERIFIER-DERIVED: the
  verifier computes the binding itself and refuses a core that disagrees in
  either direction, so a producer can neither omit the code when it applies nor
  assert it when the conventions really are bound. It applies to every
  certificate the shipped compiler emits today, because
  `node/coverage.py::build_coverage` writes none of the four mapping
  conventions (`correlation_field`, `unique_fields`, `finality_rule`,
  `material_fields`) — so §4.4's material recomputation is VACUOUS in
  production and a certificate silent about that is making a false proof. A
  limitation is cheaper than a false proof. When the Node begins emitting and
  signing the conventions, the code disappears on its own.

A list member outside this set, a duplicate member, or a non-text member is
an invalid certificate. `limitations` carries no more than 10 000 members.

A NON-zero `agent_context_digest` is a COMMITMENT a B28 presentation must
reproduce, never a verified fact: nothing in `evd/bundle/v1` carries
`surface_manifest_digest`, `org_bindings_digest` or
`mandate_lineage_digest`, so no verifier reading the certificate alone can
check it. This is the same "context bound, not carried" rendering the
paragraph above requires, stated as its verification consequence.

## 4. Verification (both implementations, byte-identical results)

1. **Caps before crypto** (H5 pattern; hostile input never crashes):
   core ≤ 1 MiB; envelope+core+disclosures (ordinary complete pack) ≤ 16 MiB;
   CBOR nesting ≤ 64; events ≤ 10 000; event_matches ≤ 10 000;
   open_findings ≤ 10 000; limitations ≤ 10 000; attachments ≤ 1 000;
   disclosures ≤ 256; verify budget ≤ 2 s / ≤ 256 MiB on the reference laptop.
   Over-cap → rejected, fail-closed.
   The CDDL key sets of `CertificateCore` and of `subject` are CLOSED and
   ENFORCED closed, in the same gate and before the caps: a member outside
   the declared set is rejected outright with no vector rendered, because it
   is attacker-authored text riding inside the identity block and no signed
   carriage for it exists. `subject_ids` stays OPTIONAL — the weak families
   correctly carry none. Closure is NOT extended to the nested maps; see the
   scan-member inconsistency noted in §4.4.
2. `certificate_id` recomputed over the core bytes; envelope/registration
   references must match it.
3. The embedded `bundle` passes ordinary `verify_bundle`.
4. **Cross-checks — the producer-shaped `verdict_input` is NOT authoritative:**
   `subject.origin` must equal the embedded bundle's verified origin;
   `subject.action_class` must equal `verdict_input.action.action_class`; and
   `verdict_input.authority` must equal `authority_facts(bundle)` recomputed;
   every `event_matches` flag must equal the trivially recomputable
   comparisons over the carried `claim`/`events`/manifest fields (echo,
   reference equality, unique-field equality, material-field comparison);
   `coverage_doc` counts/roots must be internally consistent with `events`
   and `batch`. Any mismatch → integrity `INVALID` (never a partial pass).

   The conventions carried in `coverage_doc` are NOT authoritative either:

   - **The material floor.** `coverage_doc.material_fields` for the claim's
     class EXTENDS the reconcile-v1 §5 floor `{value, currency, counterparty}`
     and can never retract it. An absent, emptied, narrowed or
     class-relabelled entry recomputes the floor, not the empty comparison.
     (An earlier reading of this section — "an absent convention recomputes
     the weak value" — is what let a deleted `material_fields` restore a clean
     pass on a core whose own claim contradicted its own event.)
   - **The signed coverage document.** When the embedded bundle carries an
     `evd.coverage.recorded` receipt, `sha256_hex(canonical_bytes(coverage_doc))`
     MUST equal a signed `context.coverage_doc_digest` (reconcile-v1 §6). One
     equality binds `correlation_field`, `unique_fields`, `finality_rule` and
     `material_fields` together.
   - **The consumed action identity.** `verdict_input.action` must name signed
     material. With a signed `action.intent` it must equal that intent's
     context. Without one, a non-empty `action_id` must be named by some
     signed receipt's `context.action_id`, and a non-empty `action_class` must
     be a signed non-`action.*` `action_type` for that id, a signed
     `context.action_class`, or a member of a signed grant's
     `context.action_classes`. An EMPTY action_id or class is exempt — it
     displays nothing, so there is nothing to bind.
   - **The claim identity.** A carried `claim` must agree with `subject` on
     `action_id` and `action_class`. An ABSENT claim is exempt (`? claim`).
   - **The covered population.** When both are carried,
     `claim.action_id` must be an element of `coverage_doc.claim_refs`: the
     counts alone let a document report `CLOSED` over a population that does
     not contain the certified action.
   - **The limitation list.** Enforced against §3's closed set and its
     biconditional.

   **The honest asymmetry.** These bind WHICH fields are compared and WHAT
   THE AGENT CLAIMED — both recomputable from signed receipts in the embedded
   log. They do NOT bind WHAT THE SOURCE SAID: `scan_batch_digest` binds
   `event_key_root`, i.e. event KEYS, not values, so no signature reachable
   offline covers a source event's amount. The event side of the material
   comparison is carried, not verified.

   NOTE (spec inconsistency, 2026-08-05): certificate-v1.cddl declares `scan`
   with 5 members while verified-action-v1.cddl declares `VerdictInput.scan`
   with 8 (`batch_digest`, `node_id`, `signature`), and the echo check
   REQUIRES the two to be equal — every production scan carries all 8. The
   golden `batch` member likewise omits members `SourceBatch` marks
   mandatory. The two CDDLs need reconciling; until then key-set closure must
   NOT be extended to the nested maps.
5. The verdict vector derives ONLY via the B21 engine (`derive_vector`) from
   a carried full core. A full view has an empty `withheld_field_set`; its
   manifest's `mark_result` must equal the recomputed mark, else the envelope
   is invalid. A selective view has a non-empty `withheld_field_set`, MUST NOT
   carry `core`, and therefore renders view-only with no recomputed vector or
   mark (never a pass, never implied). Because the view issuer's witnessed key
   log is itself inside the omitted core, the current artifact-alone API also
   cannot authenticate the selective manifest signature: it returns
   `VIEW_SIGNATURE_UNVERIFIED`. A future verifier may clear that error only
   from an independently supplied trusted view-issuer key, never from the
   coreless artifact itself. A view that both names a withheld field and
   embeds `core` is invalid with `WITHHELD_CORE_PRESENT`.
6. Editing ANY carried field fails a check above or produces a correctly
   WEAKER recomputed result — never acceptance of the edited headline.
   Contradicted/gapped evidence still compiles into an honest certificate;
   the compiler never suppresses adverse facts.

## 5. Compiler (producer-side, outside the trust path)

`compile_certificate` consumes only artifacts that FIRST pass ordinary
verification (`RefusesUnverifiedEvidence` otherwise), assembles the core,
enforces every cap at compile time (an over-cap core is a compile error
naming the offending member — e.g. a checkpoint chain too long for the
budget; operators control cadence and scope), and computes `certificate_id`.
`mint_view` embeds that core only when the withheld set is empty; a selective
view carries the digest commitment and manifest, never the hidden core bytes.
Adverse verdicts are compiled verbatim.

## 6. Report rendering (B24.4)

Human text derives exclusively from verified fields. A coreless selective
manifest's field labels are not rendered as facts because its signer cannot be
authenticated from that artifact alone. When an authenticated view carries
the required verification material, a committed field whose
disclosure is absent renders exactly **"committed, not disclosed"** — never
plaintext, never an implication of absence. Disclosed values recompute their
commitments via `evd/disclosure/v1` before rendering. A partial view says in
words that a fuller view may recompute more.

## 7. Claim boundary

The certificate proves registered evidence, deterministic comparison and the
recomputed verdict vector for ONE action, through the stated cut-off. It does
not prove hidden reasoning, activity outside the bound scope, the truth of a
colluding accepted source, or anything about views it does not carry.

RESIDUAL (2026-08-05). When the embedded bundle carries no
`evd.coverage.recorded` receipt, the certificate's comparison conventions —
`correlation_field`, `unique_fields`, `finality_rule`, `material_fields` —
rest on nothing signed. The §4.4 material floor bounds the damage on the
fields it covers, but `finality_rule` has no safe normative default (sources
spell finality "settled", "booked", "POSTED"), so a certificate carrying no
coverage receipt does not prove which finality rule its comparison used. That
residual is stated here, in prose, rather than machine-readably in each
certificate that carries it; making it a per-certificate limitation code is a
separate decision, because it would stamp a new code on every certificate the
compiler emits.
