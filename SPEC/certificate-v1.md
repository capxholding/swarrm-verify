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
(closed text codes incl. `ACCEPTED_SOURCE_COLLUSION_OUT_OF_MODEL`) ·
`current_through` (the historical cut-off; current status never collapses
into it) · `policy_version` · `attachments?` (digest manifest for large
external material — attachments can never change the verdict).

## 4. Verification (both implementations, byte-identical results)

1. **Caps before crypto** (H5 pattern; hostile input never crashes):
   core ≤ 1 MiB; envelope+core+disclosures (ordinary complete pack) ≤ 16 MiB;
   CBOR nesting ≤ 64; events ≤ 10 000; event_matches ≤ 10 000;
   open_findings ≤ 10 000; attachments ≤ 1 000; disclosures ≤ 256;
   verify budget ≤ 2 s / ≤ 256 MiB on the reference laptop.
   Over-cap → rejected, fail-closed.
2. `certificate_id` recomputed over the core bytes; envelope/registration
   references must match it.
3. The embedded `bundle` passes ordinary `verify_bundle`.
4. **Cross-checks — the producer-shaped `verdict_input` is NOT authoritative:**
   `verdict_input.authority` must equal `authority_facts(bundle)` recomputed;
   every `event_matches` flag must equal the trivially recomputable
   comparisons over the carried `claim`/`events`/manifest fields (echo,
   reference equality, unique-field equality, material-field comparison);
   `coverage_doc` counts/roots must be internally consistent with `events`
   and `batch`. Any mismatch → integrity `INVALID` (never a partial pass).
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
