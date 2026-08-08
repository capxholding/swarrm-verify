<!-- Apache-2.0 -->
# bundle/v1 — Evidence Bundle Specification

Status: NORMATIVE v1 (implemented by `core/store.py::export_bundle`,
`verify/verifier.py`)

## 1. Purpose

A bundle is a **self-contained, offline-verifiable** evidence package. An
auditor with the bundle and the open-source verifier needs nothing else —
no API access, no cooperation from the log operator, no network.

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
      "receipt_hashes": ["<hex>", ...]
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
   identically.
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
  supplies them. The current release awards no E2 label (SPEC/anchor-v1.md).
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
- Selective disclosure of payloads = revealing `(payload, nonce)` for a
  specific commitment; the verifier recomputes and compares (§receipt-v1).
- Legacy dual-attestation blocks may be carried in `commitments`/`context` and
  their two signatures can be checked. They do not establish independent
  counterparty control, and the current release awards no E3 label.
