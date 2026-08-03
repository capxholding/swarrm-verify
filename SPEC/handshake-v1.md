<!-- Apache-2.0 — this file ships with the public verifier repo. -->

# SPEC: handshake-v1 — Counterparty Assurance (B28)

**Status: NORMATIVE (v1).** Before transacting, Agent A asks Agent B to prove
present state **against A's own policy** — not to reveal a score. The contracts
(`AgentTrustChallengeV1`, `AgentTrustPresentationV1`, `StatusSnapshotV1`,
`TrustPolicyV1`) are frozen in SPEC/cddl/verified-action-v1.cddl (the B28 seams,
frozen in B21). This spec defines the handshake logic (`handshake/`).

**This is machine-verifiable state, NEVER a trust score.** No aggregate,
average, rating, or index exists anywhere — combining two facts into one number
is a score with extra steps, and it is forbidden (grep-enforced in CI over the
schemas, and `tests/test_handshake.py` over `handshake/`).

## 1. The flow (local, offline, Swarrm never in the path)

1. A builds an `AgentTrustChallengeV1`: a nonce, the proposed action
   description + class, A's policy digest, A's identity, an expiry
   (`handshake.build.build_challenge`).
2. B returns an `AgentTrustPresentationV1`: proof its key controls this Birthtag
   revision, an **authority proof for THIS exact action** (§2), a
   `StatusSnapshotV1` with `status_as_of` + its checkpoint, an optional
   transcript digest, and a mandatory **non-assertion block**.
3. A's verifier evaluates it **locally** against A's `TrustPolicyV1` and returns
   `{verdict ∈ PASS|FAIL|INDETERMINATE, reasons, vector}`
   (`handshake.verify.verify_presentation`). **Swarrm's availability never
   determines whether two other parties can transact** (design law 1).

## 2. Authority is a predicate, not a boolean

A commitment cannot prove a predicate over its own preimage. Exactly two
admissible constructions, both rendered:
- **`ACTION_SPECIFIC_AUTHORIZATION`** (default) — a root-signed authorization for
  THIS action, binding ALL of: `action_id`, action class, exact value +
  currency, the challenge nonce, authorising + subject parties, `grant_id` AND
  `grant_version`, issue time, expiry, a unique replay id, and the root signature
  (`root_sig`) over exactly that set. Missing any binding renders authority
  `NOT_VERIFIED`. When cryptographically verified it shows the root authorised
  this exact action — a different and sufficient claim, and it discloses no limit.
- **`DISCLOSED_LIMIT`** — B discloses the relevant limit and the verifier
  compares directly (leaks the limit to that counterparty).

A bare boolean or a commitment-plus-assertion is `NOT_VERIFIED`. A range proof
over a hidden limit is explicitly NOT permitted (ZK stays roadmap-only).

**The root signature is CRYPTOGRAPHICALLY verified, against a trust anchor the
relying party holds (claims ≤ mechanism).** `verify_presentation` takes a
REQUIRED `trusted_roots` argument mapping authorising-party id → the root's
Ed25519 public key. There is no such thing as verifying a signature against a key
the presentation hands you, so the anchor is the relying party's, supplied at the
call. `root_sig` is a real detached Ed25519 signature over the domain-separated,
JCS-canonical binding set; the four outcomes are exhaustive and the bad state is
unrepresentable in the API, not disclaimed in prose:

| trust anchor | root known? | signature | verdict |
|---|---|---|---|
| absent / empty | — | — | `INDETERMINATE` (`NO_TRUST_ANCHOR_SUPPLIED`) |
| supplied | no | — | `INDETERMINATE` (`UNKNOWN_ROOT`) |
| supplied | yes | fails | `FAIL` (forged / tampered authorization) |
| supplied | yes | verifies | `PASS` reachable |

A present-but-unverified `root_sig` is a **declared** input; it can never yield an
independent `PASS` (B28.2 "never a favourable default" + the grounding rule that a
declared input cannot produce an independent verdict). `PASS` means the signature
actually verified — never merely "structurally complete". `key_proof` (that B's
key controls the Birthtag) is verified the same way once B's lineage anchor is
supplied; the two compose. This is the mechanism that lands with the first
relying-party integration (`P·D`), and the API already refuses to pretend
otherwise: without an anchor you get `INDETERMINATE`, never `PASS`.

## 3. The failure modes this prevents (all test-proven)

- **Freshness is the relying party's call; staleness is `INDETERMINATE`, never
  `PASS`** — the CRL/OCSP failure mode.
- **A revoked grant is refused even from an otherwise-valid cached presentation.**
- **Replay** — a presentation bound to one challenge nonce fails against a
  different action.
- **Absence is NOT refusal** — no presentation → `INDETERMINATE` (or per A's
  `on_indeterminate`), NEVER a fabricated refusal. Only a **signed refusal**
  renders as an evidenced refusal.
- **History is scope-qualified and cherry-proof** — a newly born agent with a
  verified sponsor, attested runtime and `CLOSED_SINCE_BIRTH` over its named
  surfaces PASSes while presenting no operating history; a history predicate
  without a proven population root renders `INDETERMINATE`.

## 4. Binding into the certificate

Both parties bind the handshake transcript digest into their interaction
receipt and the eventual certificate (the B21.6B `assurance_transcript_digest`
seam). `assurance_linkage` (`DIRECT`/`DETERMINISTIC`/`AMBIGUOUS`/`NONE`) is its
own dimension, NEVER merged with source `linkage`; a transcript that does not
match the intent it claims renders `AMBIGUOUS` (verdict goldens `va_assurance_*`).

## 5. Guardrails

`PASS` never renders as a bare green tick — the vector and the non-assertion
block travel with the verdict. `Swarrm Verified` remains strictly post-action;
nothing here pre-certifies anything. Checks are free and local, forever —
metering a safety check suppresses safety checks.
