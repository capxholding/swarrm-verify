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
- **`ACTION_SPECIFIC_AUTHORIZATION`** (default) — root-signed authorization for
  THIS action, binding ALL of: `action_id`, action class, exact value +
  currency, the challenge nonce, authorising + subject parties, `grant_id` AND
  `grant_version`, issue time, expiry, and a unique replay id. Missing any
  binding renders authority `NOT_VERIFIED`. It proves the root authorised this
  exact action — a different and sufficient claim, and it discloses no limit.
- **`DISCLOSED_LIMIT`** — B discloses the relevant limit and the verifier
  compares directly (leaks the limit to that counterparty).

A bare boolean or a commitment-plus-assertion is `NOT_VERIFIED`. A range proof
over a hidden limit is explicitly NOT permitted (ZK stays roadmap-only).

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
