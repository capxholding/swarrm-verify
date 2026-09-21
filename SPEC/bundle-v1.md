<!-- Apache-2.0 -->
# bundle/v1 — Evidence Bundle Specification

Status: NORMATIVE v1 (implemented by `core/store.py::export_bundle`,
`verify/verifier.py`)

## 1. Purpose

A bundle is a **self-contained, offline-verifiable** evidence package. An
auditor with the bundle and the open-source verifier needs nothing else —
no API access, no cooperation from the log operator, no network — to verify its
base E1 integrity. E2/E3 require the explicit external trust inputs defined in
§4 and therefore are never awarded by this self-contained offline path.

## 2. Structure

```json
{
  "schema": "evd/bundle/v1",
  "origin": "evd://tenant/<id>",
  "checkpoint_chain_profile": "evd/checkpoint-chain/sparse-proof-v1",
  "target_checkpoint": { "body": {...}, "kid": "...", "sig": "..." },
  "entries": [
    { "envelope": { DSSE }, "leaf_index": N, "inclusion_proof": ["<hex>", ...] }
  ],
  "checkpoint_chain": [
    { "checkpoint": {...} },
    { "checkpoint": {...}, "consistency_from_prev": ["<hex>", ...] }
  ],
  "jwks": { "keys": [ ... ] },
  "export_manifest": {
    "body": {
      "schema": "evd/export-manifest/v1",
      "origin": "evd://tenant/<id>",
      "target_checkpoint_hash": "<hex>",
      "ts": "<canonical extended UTC>",
      "receipt_hashes": ["<hex>", ...],
      "producer": {
        "version": "<release>", "metadata_sha256": "<hex>",
        "capability_digest": "<hex>", "capabilities": { ... }
      },
      "version_transition": "<hex>"
    },
    "kid": "...", "sig": "..."
  }
}
```

`checkpoint_chain_profile` is OPTIONAL. Absence means the original complete,
directly linked checkpoint history. Its only v1 value is
`evd/checkpoint-chain/sparse-proof-v1`: a proof-preserving network profile for
long-running logs. Unknown or malformed values fail verification.

`export_manifest` is OPTIONAL and additive. Everything else in a bundle is
signed except the bundle itself: entries are individually signed and
individually proven included, so deleting one leaves every remaining signature
valid, every inclusion proof valid, and the same target root. The manifest is a
signed statement of the receipt SET, so removal (and injection) become
detectable. It is signed over its own payload type
`application/vnd.evd.export-manifest.v1+json`, so it can never be replayed as a
receipt or a checkpoint.

`producer` inside the manifest body is OPTIONAL and names the published swarrm
distribution that built the export: `version` is its release version and
`metadata_sha256` is the lowercase hex SHA-256 of that distribution's `METADATA`,
which an installer copies verbatim out of the wheel. It is ABSENT whenever the
producer cannot establish that it is running a published distribution — a source
tree, an editable install and a local-path install all record nothing, because a
version naming an artifact the producer is not running would be a false statement
inside signed bytes. Absence is normal and is never an error. Verifiers MUST
ignore manifest-body members they do not recognise: the signature is computed
over the body AS RECEIVED, so an unknown member is covered by it without either
engine having to understand it, and the schema string does NOT change when one is
added. Existing verifiers therefore keep verifying bundles that carry `producer`,
and new verifiers keep verifying bundles that do not.

`capability_digest` inside `producer` is the lowercase hex SHA-256 of the RFC
8785 form of the semantic constants the producing code holds: the closed receipt
member set, the checkpoint fields, the receipt, checkpoint, bundle and manifest
schema strings and payload types, the Merkle leaf and node prefixes, the
canonical-form depth cap, and a commitment domain separator. It is computed at
run time from those live constants, never written as a literal. Unlike `version`
and `metadata_sha256` it is present WHENEVER `producer` is, including from a
source tree, an editable install and a local-path install: it describes the code
that is running, which is knowable in every one of those cases, so `version` and
`metadata_sha256` MAY be absent from a `producer` that still carries a digest. A
producer that emits `producer` at all MUST emit `capability_digest`.

WHAT IT PROVES. The same constants that produce the digest also determine the
shapes the rest of the bundle carries, so the declaration can be checked against
the evidence beside it rather than believed. A producer that copies release Y's
digest while running X still emits X's receipt member set, X's schemas and X's
canonical form, and the declared digest then contradicts the evidence it was
signed with. Adopting Y's constants so that the two agree IS running Y for
everything those constants decide. Forging the marker therefore requires
performing what the marker attests.

WHAT IT DOES NOT PROVE, all of which are load-bearing. **It identifies a
CONSTANT GENERATION, not a release.** The digest is a function of the constants
alone, so every release that leaves them untouched emits the same digest:
1.1.0, 1.1.1, 1.1.2 and 1.1.3 all produce `e9c9df8e…`, one digest across four
published releases. A digest therefore names a SET of releases in
`report/version_capabilities.json`, and the release cross-check can only report
a declaration that falls outside the whole set — inside one generation it
distinguishes nothing, and a reader who treats the digest as pinning a single
release is claiming a resolution it does not have. It binds the CONSTANTS, not
the program: a release that changes behaviour where no digested constant
reaches — a rule, a bound, an ordering — produces the same digest, and that
change is invisible here. It does not bind the running code to a published
artifact; that is what `metadata_sha256` reaches for. A digest no reader has
recorded yields NO verdict, because an unrecognised digest is a build nobody
wrote down rather than evidence of a lie, so the check is only as complete as
the recorded releases. And a producer may omit `producer` entirely: **silence is
not a clean bill of health**, since omitting the declaration is exactly what a
producer with something to hide would do, and the absence of a finding is the
absence of a declaration to check.

The cross-check is CLAIMS-LEVEL and advisory, exactly as the feature comparison
is. It lives in `report/version_interval.py`, is driven by the data table
`report/version_capabilities.json`, and does NOT change the verdict — a bundle
that verifies still verifies, and a contradiction renders as a finding beside
it. Making it fatal would require both engines to compute the digest and agree
on the constant set entry for entry, the way they must agree on every other
verdict input; that is a verifier change rather than a report change, and the
verifier line budget does not currently afford it.

## 3. Verification algorithm (normative — `verify_bundle`)

1. **Keys**: every JWK's `kid` matches its key material; reject aliases.
2. **Target checkpoint** signature verifies.
3. **Chain**: every checkpoint signature verifies; the first supplied
   checkpoint is genesis (`prev_hash == ""`); `tree_size` is monotone; and the unsigned outer
   `bundle.origin`, target-checkpoint origin, and every chain origin are the
   same value. In the default profile every later `prev_hash` directly links to
   its carried predecessor. In the sparse-proof profile it MUST be non-empty,
   but may name an omitted intermediate checkpoint. Every carried non-genesis
   step in both profiles ships an RFC 6962 consistency proof that verifies the
   prior carried root → current carried root. A missing/failing proof, an
   undeclared skip, or any other profile value is a FAIL.
4. **Head**: `target_checkpoint` is the chain head.
5. **Entries**: per receipt — DSSE signature(s) verify; schema is
   `evd/receipt/v1`; `receipt_hash` recomputed from payload; inclusion
   proof verifies `(recomputed hash, leaf_index)` under the target root;
   timestamps use receipt-v1's canonical extended UTC form; and the legacy
   privileged-co-signature rule in receipt-v1 §5 is satisfied before replaying
   key, authority, lineage, Node, finding, gap, coverage, or registration state.
6. **Export manifest**, if present: `kid` equals the target checkpoint's `kid`
   and that key is a non-`recorder` issuer after replaying signed key roles
   (including rotation/creation ancestry). Its signature verifies against that
   replayed key, never `bundle.jwks`; `body.ts` is canonical extended UTC and
   EXACTLY equals the signed target-checkpoint `body.ts`, so a revoked key cannot
   backdate a fresh manifest. `body.origin` equals both `bundle.origin` and the
   target-checkpoint origin; `body.target_checkpoint_hash` equals the target
   checkpoint's `body_hash()`; and `body.receipt_hashes` is SET-EQUAL to the
   recomputed hashes of the entries carried. Set equality — not subset — so a
   manifest cannot excuse an injected entry either. Both engines MUST agree on
   these points, which is where the `anchor_records` divergence came from:
   member ABSENT or `null` ⇒ valid, no completeness claim; member present but
   not an object ⇒ NOT VERIFIED; `receipt_hashes` not a list of strings, or over
   `MAX_ENTRIES` ⇒ NOT VERIFIED; comparison is over sets, so duplicates collapse
   identically. Unrecognised body members (`producer`, and whatever is added
   after it) are IGNORED for the verdict and left inside the canonical bytes the
   signature covers — an engine that stripped or rejected them would both break
   the signature and diverge from the other.
7. Verdict is the conjunction. Any single failure ⇒ NOT VERIFIED.

For a bounded sparse-proof export, the producer MUST first validate the entire
stored checkpoint hash chain, then carry genesis, the target head, and the
earliest anchored and timestamped checkpoint covering every carried entry.
This preserves every carried receipt/state proof and its earliest available
carried timing evidence while bounding redundant checkpoint signatures. The
verifier reports that the intermediate checkpoint history itself was not
carried; sparse proof is never rendered as a complete checkpoint-history export.

## 4. Trust model & known limits (honest by design)

- The bundle proves integrity relative to the log's public keys. An auditor
  MUST obtain the log's kid from an independent channel (published JWKS,
  anchored key-transparency entries, or a prior trusted bundle) — a bundle
  alone cannot defeat an attacker who forges *everything including the
  keys*. Independently verified external anchor/TSA state can constrain that
  attack, but carried `anchor_records`/`tst_records` do not: the subject also
  supplies them. Offline verification awards no E2 label. Under the explicit
  live profile, a displayed receipt earns E2 only when a covering checkpoint is
  re-read from Base (`8453`) or Base Sepolia (`84532`) in that run and its RFC
  3161 token terminates at a TSA root the relying party supplied out of band;
  see SPEC/anchor-v1.md. E3 is cumulative: every E2 condition must hold, both
  issuer and recorder signatures must verify, the recorder must be active in
  authenticated log state under the non-issuer `recorder` role, and the relying
  party must supply that recorder key out of band. Verified recorder possession
  without E2 remains an inspectable fact and awards no level.
- **A bundle without an export manifest makes no completeness claim.** Absence
  is not failure — bundles predate the manifest, and a replica holding no
  private key (`scripts/restore_check.py` reads a restored `.db` with public
  material only) exports honestly without one. Absence therefore verifies, and
  the verifier reports completeness as UNKNOWN rather than assuming it: a third
  state (`export_complete: null`), rendered by the CLI as
  `VERDICT: VERIFIED (completeness unproven — no export manifest)` and made
  fatal on request with `--require-manifest`. An attacker who strips the
  manifest along with the entries therefore gets a VISIBLE downgrade instead of
  an invisible edit; they cannot forge one without a log key. Making the
  manifest's ABSENCE detectable needs a commitment from outside the bundle (an
  anchor, or a manifest hash published beside the download link).
- The manifest does not make the PRODUCER honest. A key holder can sign a
  manifest that omits a receipt at export time; `export_bundle`'s force-
  inclusion of findings, lineage, authority and key entries remains the
  producer-side control. What the manifest adds is that such an omission is now
  a signed, non-repudiable statement, contradicted by any second export or by
  the log itself. It also says nothing about receipts the producer never
  exported — a root over an operator-selected set proves the set is intact,
  never that it is complete.
- **`producer` is a SELF-DECLARATION, not proof of provenance.** It is the
  subject describing the subject — the producer holds the signing key, so a
  producer willing to lie can sign whatever version it likes, the same defect
  receipt-v1 §5 records for every other producer-asserted field. Two things it
  DOES achieve. It is tamper-evident: it sits inside the signed body, so no
  third party on the path — a holder, a relay, a mailbox, a bucket — can alter
  or strip it without breaking the manifest signature, which is a claim about
  everyone except the signer. And it is falsifiable: `metadata_sha256` is
  reproducible from the published distribution, whose PEP 740 attestation is
  Sigstore-bound to the source repository and publishing workflow that the
  producer cannot forge, so a producer can no longer name a release that was
  never published. What it does NOT establish is that the code which ran was the
  code in that release; a producer can declare a real release it is not running.
  Closing that needs an attester the producer does not control — a hosted
  countersignature under the tenant issuer key on managed ingest (receipt-v1 §5),
  which moves the claim from the customer to the operator, or hardware
  attestation, which is the only form that removes trust in the producer
  entirely. Neither is in scope for an offline bundle, and this field must not be
  described as proving which version ran.
- **A declared version can still be CONTRADICTED by the evidence carrying it.**
  Evidence declaring one version while carrying a feature only some other
  version could emit is a contradiction the producer signed both halves of. A
  floor (the minimum version able to emit a feature) catches backdating; a
  ceiling (a feature REMOVED in some version) catches forward-dating, and is the
  shape of the withdrawn assurance marks, which were deleted from the
  `mark-render` enum rather than left unemitted. This check is CLAIMS-LEVEL and
  advisory: it lives in `report/`, is driven by the data table
  `report/version_features.json`, and does NOT change the verdict — a bundle
  that verifies still verifies, and a contradiction renders as a finding beside
  it. Making it fatal would require both engines to carry the table and agree on
  it entry for entry, the way they must agree on every other verdict input;
  that is a verifier change, not a report change, and the verifier line budget
  does not currently afford it. Note also that no `evd/bundle/v1` member has ever
  been removed, so every ceiling today is observable only on artifacts that
  CONTAIN a bundle, such as a certificate.
- **A DOWNGRADE claim is refuted by the log rather than by us.** A producer
  appends a `node.version.changed` receipt — an ordinary `evd/receipt/v1` under
  the internal `_node` agent, carrying `to`, and after the first also `from` and
  the `prev_transition` it succeeds — the first time a process observes a
  producing swarrm the log does not already record. `to` and `from` are
  `{version, metadata_sha256, capability_digest}`, the same three values
  `producer` declares. The log is dense and append-only and its checkpoints are
  anchored and RFC 3161 timestamped, so that receipt's position is fixed by a
  third party. A producer that recorded itself
  running 1.2.0 therefore cannot later hand out evidence from a later leaf
  declaring 1.1.0 produced it: the contradiction is between two things it signed
  itself, and there is no leaf left to insert a retroactive downgrade into. A
  downgrade that really happened stays recordable, by being recorded BEFORE the
  evidence it explains — the mechanism constrains CHANGES to the story, never
  its origin, and a producer that has lied identically since its first receipt
  is untouched. The receipt is emitted only when the running distribution is
  identifiable under the same rule `producer` uses, so a producer that cannot
  name a published release records nothing rather than a version it is guessing
  at — even though the digest alone would be knowable, because a transition
  naming no fetchable artifact is a statement a reader cannot follow up.
  `report/version_transition.py` reads it, at the same claims level and with
  the same advisory standing as the feature-table check above: a bundle carrying
  no transition preceding its receipts is reported as UNCONSTRAINED, never as
  having passed, because an export that simply omits the transition must earn
  nothing by it.
- **The CAPABILITY DIGEST inside a transition is what gives the constants a
  third party's date.** `version` is a string anyone can type; the digest has to
  be earned by adopting the constants it is computed from. Dating only the
  version had the two markers the wrong way round — the marker that costs
  nothing was the one a timestamp authority attested, and the marker that costs
  something was attested by nobody. With the digest inside the dated value, a
  producer that today declares a constant set it was not running is contradicting
  a leaf a TSA already dated, exactly as a version downgrade already is. It also
  makes a change of CONSTANTS ALONE a transition: two builds both calling
  themselves 1.1.4 while disagreeing about what a receipt is now spend a dated
  leaf on the difference, which no version comparison could ever have seen.
  Only the digest travels, not the constant set: a receipt payload is capped at
  8192 bytes (receipt-v1 §1) and the canonical set is 1105 of them, which the
  chained `from` would carry a second time, while preimage resistance already
  makes dating the digest as binding as dating the set — a reader who needs to
  READ the constants has them beside the declaration in `producer.capabilities`,
  admitted there only where they reproduce the digest. The escape that carriage
  closes in the manifest has no analogue here: an altered constant set produces
  a DIFFERENT dated digest, which is a finding rather than the absence of one.
  WHAT THIS DOES NOT ESTABLISH, and it is the same limit `producer` carries one
  level up: it dates the constants a producer RECORDED, never the constants it
  was RUNNING. A producer holding the log key can write any digest it likes into
  the transition; what it cannot do is write one LATER, or write one that agrees
  with a declaration it changes afterwards. Nor does it reach past the digested
  constants — a build that alters a rule no constant covers records an identical
  digest and passes. The comparison is `report/version_transition.py`'s and is
  advisory: a declared digest that differs from the dated one is CONTRADICTED, a
  transition that records no digest (every one written before this field existed)
  leaves the declared constants UNCONSTRAINED, and an export declaring no digest
  is unconstrained too — in all three of the silent cases **silence is not a
  clean bill of health**. A digest declared with no `version` beside it is still
  read, because an unpublished build declares exactly that and is the population
  whose provenance is weakest.
- **`version_transition` names the newest transition the log holds.** OPTIONAL,
  the receipt hash, absent when the log holds none. Deleting a transition from
  the chain is already impossible — the log is dense — but an export carries a
  CHOSEN subset, so a producer could carry the evidence and leave the
  transition behind. The manifest closes that: it is signed alongside
  `receipt_hashes`, so the hash of a transition the export does not carry still
  travels with it, and a reader who sees a name it has no receipt for knows
  precisely what to ask for. This binds the producer to its own statement and
  stops an intermediate holder from editing or stripping the name; it does not
  and cannot constrain the signer, who was free not to record the transition at
  all. Verifiers ignore the member, as §4 requires of unrecognised ones — it
  changes no verdict, and it is read where the transition itself is read.
  `report/version_transition.py` reports WITHHELD, distinct from the ordinary
  NOT_APPLICABLE, when the manifest names a transition the export does not
  carry, and names the receipt to request. The distinction is the whole point:
  collapsing the two would give a deliberate omission the same silence as a
  minimal export, which is exactly what naming the transition denies it.
- **A CAPABILITY DIGEST is the one part of the declaration a lying producer
  cannot simply type.** `version` is a string; `capability_digest` is computed
  at run time from the constants the running code holds, and those same
  constants govern the receipt member set, the schemas and the canonical form
  the rest of the bundle carries. Declaring another release's digest leaves it
  beside evidence its constant set could not have produced, and the signature
  covers both halves, so the producer has signed its own counterexample.
  Adopting the constants that would make the two agree IS running that code for
  everything those constants decide, which is why faking the marker requires
  doing the thing the marker attests — the only unforgeability available
  without hardware attestation. WHAT IT DOES NOT ESTABLISH. It identifies a
  CONSTANT GENERATION rather than a release: 1.1.0 through 1.1.3 share one
  digest, so a recorded digest names a SET of releases and the cross-check can
  only catch a declaration outside that set. It binds the
  CONSTANTS, not the program: a version that changes a rule where no digested
  constant reaches emits an identical digest and is invisible here, which is
  why this is a floor under the declaration rather than proof of which code
  ran. It does not bind the code to a published artifact — `metadata_sha256`
  reaches for that and does not fully reach it either. THE CONSTANTS TRAVEL
  WITH THEIR DIGEST, in `capabilities`. Without them a reader could only look
  the digest up, and a build that altered any digested constant would be
  unrecognised and have every shape comparison switched off — editing the code
  would have been the cheapest escape from the check that exists to catch
  edited code. Carried, the set is admitted only where it REPRODUCES the
  declared digest, the same bar a table row clears, so carriage confers no
  trust: the producer chose those constants, and all they settle is whether its
  own evidence agrees with them. Naming which RELEASE a constant set belongs to
  still needs the recorded table, which is only as complete as the releases
  someone wrote down, so an unrecognised digest yields NO verdict on the
  version rather than a failure. And the producer may decline to emit `producer` at all, so
  **silence is not a clean bill of health**. The check is advisory and lives in
  `report/`; it does not change the verdict, and making it fatal would require
  both engines to compute the digest and agree on the constant set entry for
  entry, which the verifier line budget does not currently afford.
- **A THIRD PARTY'S CLOCK bounds the declared version from ABOVE, without
  relying on the producer's honesty at any point.** An RFC 3161 timestamp token
  verified under a TSA root the RELYING PARTY supplies carries a `gen_time` that
  third party signed over a checkpoint body hash. A checkpoint attested at T
  existed at or before T, so a release PUBLISHED after T cannot be the code that
  produced it. Publication instants are DATA in `report/version_releases.json`,
  taken from the earliest upload time PyPI reports for each version; they are
  public, so **a reader checks the table rather than trusting it**. On the live
  path only, a chain anchor's `block_ts` counts the same way, because
  `verify/live.py::check_anchor_live` re-read the block; OFFLINE it must never
  be used, since `block_ts` is an unsigned string any holder or forwarder edits.
  WHAT THIS PROVES: the named release did not exist when a third party attested
  this evidence. WHAT IT DOES NOT PROVE, all of which are load-bearing. It
  bounds the version from ABOVE only — a producer claiming an OLDER version than
  it ran is untouched, and the feature floor is the weaker, opt-in instrument
  for that direction. It bounds the attested CHECKPOINTS, not the export act:
  nothing offline attests when an export ran, so a producer that upgrades after
  the last attested checkpoint and then exports reports identically to one
  naming a release it never ran, which is why the finding reads as "the named
  release postdates this evidence" and stays advisory. It applies ONLY to
  bundles carrying a verified token under a supplied root: an E1-only bundle
  gets nothing from it, and the report states that the check DID NOT APPLY
  rather than implying a pass — **silence is not a clean bill of health**. A
  version the release table does not name yields NO verdict, not a failure,
  because a bound invented for an unnamed release would report the table
  instead of the evidence. And trust moves to the relying party's own pinned TSA
  root, which is the correct place for it but is still a trust assumption: an
  adversary who never anchors and never timestamps is never bounded at all.
- **A COMPOSED VERDICT over the instruments above, which can never read better
  than its weakest input.** Each check states honestly what it did not do, and a
  reader handed several such paragraphs still has no answer to the question they
  asked. `report/version_provenance.py` composes them into one status —
  CONTRADICTED, WITHHELD, UNCONSTRAINED, PARTIALLY_CONSTRAINED, CONSTRAINED —
  under three rules, each of which exists to stop a specific misreading. One
  CONTRADICTED input makes the whole verdict CONTRADICTED, so four quiet checks
  cannot outvote the one that found something. One WITHHELD input holds the
  verdict there whatever else held, because a producer that names a receipt and
  does not send it must not collect a green box for the comparisons it did
  allow. One silent input keeps the verdict below CONSTRAINED however many
  others held, and the silent ones are NAMED in the document rather than
  omitted: **silence is not a clean bill of health**, and a check that did not
  apply must never be printed in the words used for one that held. The verdict
  also separates two questions the capability digest is easily read as answering
  together — whether a constant set reproduces the declared digest, which a
  reader running the producer's own code settles for free, and which RELEASE
  that set belongs to, which only the recorded table can name. WHAT A
  CONSTRAINED VERDICT DOES NOT ESTABLISH is printed beside it under every
  outcome, because the composed verdict is exactly the shape of thing a reader
  takes for a guarantee: the producer holds the signing key, so all of this
  raises the cost of a false version claim and turns one into a contradiction a
  reader can point at, and none of it makes the claim impossible to make. Only
  an attester the producer does not control would — a hosted countersignature
  under an operator key, or hardware attestation — and neither is available
  inside an offline bundle. Claims-level and advisory like everything it
  composes: no verifier line, no public symbol, no verdict change.
- **CROSS-ARTIFACT MONOTONICITY catches a lie no single artifact contains, and
  only for a reader who holds MORE THAN ONE.** A producer that records no
  transitions can hand one counterparty a bundle declaring 1.2.0 and another a
  bundle from LATER leaves of the same log declaring 1.1.0. Neither artifact
  contradicts itself and each reader sees a clean report; held together they are
  two signed statements the log's own checkpoints order, and the producer
  authored both halves. `report/version_provenance.py::cross_artifact_contradictions`
  reports four rules: a later-ordered artifact declaring an EARLIER version; two
  artifacts declaring one version under different capability digests, which needs
  no ordering because one release holds one constant set; a later-ordered
  artifact naming NO newest transition where an earlier one named one, which a
  dense append-only log cannot honestly do; and a later-ordered artifact naming
  as newest a receipt an earlier one already carried beside a DIFFERENT newest,
  which would require a leaf to move forward. ORDERING IS BY SIGNED
  `tree_size` ALONE. The manifest `ts` is signed, but signed by the PRODUCER, so
  it orders nothing a producer would not happily re-sign and is carried for the
  reader rather than compared; `bundle.origin` is unsigned and is never read, or
  a holder could suppress the comparison with a one-word edit. Two artifacts at
  one tree size are left UNORDERED. WHAT IT DOES NOT ESTABLISH. It is
  OPPORTUNISTIC, not a guarantee: most readers hold exactly the bundle they were
  sent, and finding nothing is not evidence that the producer told everyone the
  same story, only that this reader could not tell. It orders the targeted log
  STATES, not the export acts, so a producer signing a fresh manifest against an
  older checkpoint places that declaration earlier — paying for it in reach,
  since such an artifact carries only the receipts that existed then. A genuine
  ROLLBACK reads identically to a lie, so the finding says the producer's account
  of itself moved backwards and does NOT say which of the two statements is
  false; the honest way to roll back remains recording the change as a transition
  before the evidence it explains. And it assumes the artifacts sit on ONE chain:
  a producer running two divergent logs under one origin breaks that assumption
  and is committing a worse offence, which a consistency proof between the two
  target checkpoints catches directly and this comparison does not attempt.
- Selective disclosure of payloads = revealing `(payload, nonce)` for a
  specific commitment; the verifier recomputes and compares (§receipt-v1).
- Legacy dual-attestation blocks may be carried in `commitments`/`context` and
  their two signatures can be checked. They do not establish independent
  counterparty control and never award E3. The only E3 route is the cumulative
  receipt-envelope profile above. E1/E2/E3 are post-action evidence levels and
  are separate from the Counterparty Assurance handshake; no evidence level
  supplies a Counterparty Assurance identity, authority, exact-action or
  replay verdict.
