<!-- Apache-2.0 — this file ships with the public verifier repo. -->

# SPEC: payments-iso20022-v1 — the payments action class on ISO 20022 rails

**Status: NORMATIVE (v1).** The profile binding the `payment.execute` action
class to ISO 20022: the agent's claim binds to the `pain.001` instruction it
authored, the bank's `camt.053` statement (node-v1 `bulk_file`,
reconcile-v1) is the authoritative read-back, and reversals arrive as
reconcile-v1 §7 linked corrections. Everything rail-specific here is DATA — a
field map and this document. The verifier and the reconciler contain no
vendor or rail branch; the engines ship unchanged, and a verifier that has
never heard of ISO 20022 verifies these certificates identically.

## 1. Scope and claim boundary

One profile claim = one credit transfer transaction (`CdtTrfTxInf`) the agent
initiated. The profile proves that the registered claim deterministically
matches (or fails to match) the booked statement entry for that transaction.
It does not prove the instruction reached the bank (an unbooked instruction
renders `CLAIM_ONLY`, never a failure), does not read `pain.002` or
`camt.052` as authoritative (§5), and inherits every reconcile-v1 §9 bound.
The statement's enumeration property is exactly the node-v1 bulk-file
landing shape's (`PERIOD_STATEMENT_BALANCE_ASSERTED` with its stated
limits); this profile neither strengthens nor weakens it.

## 2. Claim binding (`pain.001` → `evd/claim/v1`)

Per `CdtTrfTxInf`, namespace-agnostic paths, any `pain.001.001.03+` shape:

- `action_id` ← `PmtId/EndToEndId`, which MUST carry the opaque agent-side
  `action_id` token (reconcile-v1 §1: created BEFORE execution, reused across
  retries, never business data). SEPA carries `EndToEndId` end to end and the
  statement echoes it, so the echo match is `DIRECT` by construction.
  Duplicate `EndToEndId` values within one document are refused.
- `value` ← the SIGNED account-perspective amount: `-` + the `Amt/InstdAmt`
  lexical value. A credit transfer initiation claims a DEBIT; the sign
  convention is the bulk-file mapping's documented value normalisation
  (node-v1), so the claim compares byte-equal against the statement entry. `EqvtAmt` is refused — an
  amount stated in another currency cannot bind a deterministic claim value.
- `currency` ← `Amt/InstdAmt@Ccy` (ISO 4217 alphabetic code).
- `counterparty` ← `Cdtr/Nm` (alternatives `Cdtr/Pty/Nm`).

**Normalisation rule (the per-connector definition of done requires one
wherever text is compared):** `value`, `currency` and `counterparty`
compare as exact strings after whitespace trim — no case folding, no
transliteration, no amount re-formatting. Author `InstdAmt` in the
minor-unit-complete form the bank books (`42.00`, not `42.0`). Stated bound:
a bank that rewrites the creditor name in its statement renders the pair
`UNCOMPARABLE`/`CONTRADICTED` rather than being fuzzily repaired; the named
evolution, if a pilot's bank demonstrates rewriting, is binding
`counterparty` to the creditor IBAN — a v2 decision, not a silent v1 repair.

**Integrity identities, refused loudly:** `GrpHdr/NbOfTxs` MUST equal the
count of `CdtTrfTxInf` elements, and `GrpHdr/CtrlSum`, when present, MUST
equal the exact decimal sum of the instructed amounts. A truncated or padded
file binds no claims.

**Timing is the rail's fact, not the agent's.** `ReqdExctnDt` is an
instruction, not an assertion of booking time, so the manifest's material
fields for this class are EXACTLY the reconcile-v1 §5 floor
`{value, currency, counterparty}`. Naming `source_effect_time` would make
`CORROBORATED` structurally unreachable for an initiation-bound claim (a one-sided
material field can never corroborate). A claim MAY still carry
`source_effect_time`; if it does, the manifest tolerance comparison applies
in the adverse direction only.

The exact authored `pain.001` bytes are digested (SHA-256) and the digest
SHOULD be committed through the normal `action.intent` inputs-commitment
machinery — the claim then binds to the very file the bank received, and a
later dispute replays byte-for-byte.

## 3. CBPR+ structured addresses, pinned from day one

Wherever a `PstlAdr` appears (debtor, creditor, agents), it MUST be
structured: `AdrLine` is refused outright, and a present address MUST carry
at least `TwnNm` and `Ctry`. The CBPR+ coexistence period for unstructured
addresses ends November 2026; this profile never admits the legacy form, so
no deployed mapping needs a migration. An address-free party is admissible —
the pin governs the form of what is stated, never forces a statement.

## 4. Authoritative read-back

The read-back source is the `camt.053` statement through the node-v1
`bulk_file` landing shape and the `camt053-v1` field map (a source
template: one `"template"` field instead of eight). The statement is the population: complete for its
declared period with the opening/closing balance identity verified
arithmetically (the coverage basis stays as that connector declares it,
reconcile-v1 §6 — this profile adds no coverage claim). Reversal entries are ordinary entries in that
identity; a returned payment still sums.

## 5. Finality

- `Sts` `BOOK` → `final`. Only a booked statement entry corroborates.
- `Sts` `PDNG` → `pending`; the pair renders `CLAIM_ONLY` until booked.
- `pain.002` status reports and `camt.052` intraday notifications are
  acknowledgments — the bank's message about intent, not the booked fact.
  They MUST NOT be mapped as authoritative events under this profile. A
  payment "accepted" then never booked is `CLAIM_ONLY`, which is the honest
  reading.

## 6. Corrections (reversals as reconcile-v1 §7 linked facts)

A booked entry with `RvslInd` true is a CORRECTION: the map sets its
finality to `corrected`, so it leaves the normal matching population and can
never render a spurious `AMBIGUOUS` against the original.

**Back-link resolution, in the mapping layer:** the rail names the ORIGINAL
`EndToEndId`; the §7 vocabulary links by the prior event's `event_key`. The
connector resolves the reversal's reference to the unique non-correction
event carrying that `EndToEndId` within the bounded scan — deterministically,
never picking a winner. Zero or multiple candidates leave the raw reference
(the reversal then renders `ORPHAN` — visible, never silently dropped) and
add a named batch gap (`reversal_unresolved:` / `reversal_ambiguous:`);
neither gap is a population defect, so the statement's population proof is
untouched.

**The linkage bound is the SCAN, not the period (NORMATIVE, and the
practically dominant case).** Resolution runs in the mapping layer while a
scan is read, so it sees only the statements THAT scan admits. A reversal
links only when its original is in the same scan. Where the customer drops
one statement per period — the ordinary arrangement — a return booked in a
later statement than its original does NOT link: it renders `ORPHAN` under
`reversal_unresolved:`. That is a stated limit, never a silent one — the gap
names it and the orphan is visible. Same-statement reversals and
multi-statement drops (backfill, batched delivery) do link. Carrying the
linkage across scans needs durable state the connector interface does not
have today, and doing it in the reconciler would put a rail branch in the
proof core; it is deliberately not closed here.

A PENDING reversal stays a pending normal entry — an
unbooked return is not yet a rail fact.

**Reading rule (reconcile-v1 §7):** history is never overwritten and the original
certificate is never made retroactively false. A fact carrying
`correction_of` whose prior fact is `CORROBORATED` reads "the rail reversed a
genuinely executed payment" — the fresh comparison against the return entry
will typically state the material divergence. `CONTRADICTED` WITHOUT
`correction_of` remains what it always was: a material disagreement on the
claim itself.

## 7. Artifacts and second mappings

ISO 20022 message definitions and XSDs are openly published at iso20022.org;
CBPR+ usage guidelines are readable via free swift.com MyStandards
registration. No SWIFT membership, licence, or vendor relationship is a
dependency of this profile. `DATEV` or any second format mapping is added
ONLY when a DACH pilot names it in writing (the connector registry's Rule 1);
the shape and this profile are the deliverable, mappings stay declarative.
