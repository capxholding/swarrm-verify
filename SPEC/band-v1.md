<!-- Apache-2.0 — this file ships with the public verifier repo. -->

# SPEC: band-v1 — the published value-band function

**Status: NORMATIVE (v1). Structure frozen; thresholds are a launch
hypothesis, revisited only after three production contracts.**

The band function is **public, versioned, and deterministic**. It maps a
customer's declared prospective authority to a price band. It is computed
**customer-side** (in the Node or by the customer's attester); Swarrm's
commercial plane receives only the resulting **band**, an **input
commitment**, and an **attestation** — never the customer's limits, budgets or
transaction records. **The band function reads no evidence, and no proof-path
code reads the band, the price, or any commercial field.**

## 1. The function

```
required_band = max(
  authority_band(  aggregate non-overlapping authority across active covered grants ),
  criticality_floor( highest computed mandate criticality ) )
```

Two dimensions only (authority, criticality floor). The higher wins; they are
NEVER multiplied. Birthtag count is NOT a dimension (breadth is removed — it
would incentivise the identity compression that `ORPHAN` detection depends on).

## 2. Authority declaration types (FROZEN)

Every declared authority is exactly one of:
- **`FLOW(cap, period, timezone, term_cap?)`** — a recurring limit. `period`
  and `timezone` are required. `term_cap` is optional; when present it is the
  banding number. When absent, banding uses `cap × periods-in-term` (the
  conservative reading) and the order MUST state which applied — an order
  silent on this is incomplete → `INDETERMINATE` → `NO_REGISTRATION`.
- **`STOCK(max_outstanding)`** — a standing exposure the agent may alter;
  banding uses peak permitted outstanding, never the sum of changes.
- **`ONE_SHOT(amount, count)`** — bounded discrete authority; banding uses
  `amount × count`.

Overlapping grants sharing an evidenced pool count once; otherwise they sum.
One shared pool contributes the **largest EUR-equivalent authority** of its
member grants, so permuting the declaration list cannot change the band.
Overlap asserted but unevidenced renders the aggregate `UNKNOWN`.

The v1 implementation is deliberately stricter than a claim of evidence: a
free-form `shared_pool` label is **not** the signed shared-limit object above.
Until a published verifier can authenticate that object and bind both grants to
it, every shared-pool claim yields `INDETERMINATE` → `NO_REGISTRATION`; it may
not reduce the aggregate.

## 3. Currency / FX

Every grant declares its currency. Banding converts at the **ECB euro
reference rate published on the order date** (or the last publication day
before it), **fixed for the whole term**. If the ECB does not publish the
pair, the fallback is the customer's own audited reporting rate for that date,
named in the order. Never a floating rate.

The frozen input fields are `currency` (three uppercase ASCII letters) and,
for every non-EUR declaration, `fx_rate_to_eur`, `fx_source`, and `fx_date`.
`fx_rate_to_eur` is the positive decimal multiplier in EUR per one declared
currency unit; `fx_source` is the non-empty source named in the order; and
`fx_date` is an ISO `YYYY-MM-DD` publication/reporting date. EUR has an implicit
multiplier of exactly 1; a contradictory supplied multiplier is invalid.
Missing, zero, negative, non-finite, or malformed FX input yields
`INDETERMINATE`. Implementations use decimal (not binary floating-point)
arithmetic and compare the exact converted aggregate to the inclusive band
ceilings. Each decimal input is bounded to 128 coefficient digits and an
absolute base-10 exponent of 128; a larger representation is out of profile
and yields `INDETERMINATE` rather than allocating input-sized arithmetic
precision.

The v1 implementation does not yet independently verify an ECB publication or
an audited-rate document. A self-declared rate, source and date are therefore
insufficient: non-EUR declarations currently yield `INDETERMINATE` →
`NO_REGISTRATION` until that verification profile ships. This is intentional;
it forbids a fabricated low rate from down-banding a scope.

The managed v1 entitlement gate applies the same rule to its opaque commercial
fact: a command carrying non-empty FX metadata is rejected rather than treating
the self-declared rate as an auditable exception. It can be enabled only with a
published, independently verified FX profile.

## 4. Criticality enum (PUBLISHED, derived, never judged)

Derived from declared action class + reversibility + external effect:
- `IRREVERSIBLE_EXTERNAL_VALUE_TRANSFER` → floor C
- `SAFETY_OR_LEGALLY_HIGH_RISK` → floor C
- `REGULATED_OR_CUSTOMER_RIGHTS_EFFECT` → floor B
- `REVERSIBLE_EXTERNAL_EFFECT` → floor A
- `INTERNAL_RECORD_CHANGE` → floor A
- `READ_ONLY` → no floor

Any human-judged criticality is forbidden — it reintroduces the negotiation
this model eliminates.

## 5. Band table (STRUCTURE FROZEN; fees per policy pack v0.2, 2026-08-28)

| Band | Aggregate authority | Criticality floor | Annual fee |
|---|---:|---|---:|
| A | ≤€25M | `REVERSIBLE_EXTERNAL_EFFECT` · `INTERNAL_RECORD_CHANGE` | €100K |
| B | ≤€250M | `REGULATED_OR_CUSTOMER_RIGHTS_EFFECT` | €300K |
| C | ≤€2.5B | `IRREVERSIBLE_EXTERNAL_VALUE_TRANSFER` · `SAFETY_OR_LEGALLY_HIGH_RISK` | €900K |
| D | ≤€25B | — | €2.5M |
| Strategic | above D — **explicitly purchased only, never algorithmically selected** | — | €5M+ |

**Fees are dated and prospective (NORMATIVE).** The table above is policy pack
**v0.2**, effective 2026-08-28. A contract is billed the schedule that was in
effect when it **started**; a revision never re-prices a live contract, in
either direction, and there is no mid-term step. Policy pack **v0.1**
(effective 2026-08-01: A €50K, B €150K, C €500K, D €1.5M, Strategic €3M+)
therefore remains the correct and checkable fee basis for every contract that
started before 2026-08-28, and an invoice line names the schedule version it
was computed under so the amount can be checked against the published pack.

Only the fee column changes between packs. The band STRUCTURE — thresholds,
criticality floors, attestation duties, `INDETERMINATE` handling — is frozen
and is what `band_function_version` names, so a fee revision does **not**
advance it and does not affect the validity of any registered entitlement.

Criticality is a coarse FLOOR that tops out at C. Missing, empty or
unresolvable declaration **or criticality** inputs yield `INDETERMINATE` →
`NO_REGISTRATION` (never the Strategic band — an algorithm that can invoice
€3M for a blank field is a liability). Strategic is reachable only by explicit
purchase.

## 6. Self-enforcement (scope-qualified)

Within a CLOSED registered scope, the same signed authority that sets the
price decides whether an action qualifies for the mark: understate the
authority and the resulting action evidences itself as outside mandate.
Outside a registered scope this does not hold — understatement there yields no
mark, not a breach.

## 7. Privacy — customer-side computation only

The customer signs the mandate inputs; the published function computes the
band customer-side. The commercial plane receives only `{band, input_commitment,
attestation}`. Independent attestation of the calculation is **mandatory at
Band C+ and wherever the criticality floor is
`IRREVERSIBLE_EXTERNAL_VALUE_TRANSFER` / `SAFETY_OR_LEGALLY_HIGH_RISK`;
optional below**. An active C+ entitlement must carry a content-addressed
`sha256:<digest>` reference to that attestation; a non-empty label is not an
attestation. The commercial plane is structurally incapable of leaking or
being subpoenaed for customer transaction data — it never holds any.

## 8. Neutrality (non-negotiable)

`AuthorityGrant` defines what an agent may operationally do; `RegistryScope`
selects which grants receive paid registration; price is computed from the
grants inside that scope. **Commercial status never changes an authority
verdict or any evidence.** Opposite evidence outcomes under the same signed
order produce identical invoice lines. Price, band, payment, findings and
record counts never enter the public certificate; identical proof gets the
same verifier result regardless of payer or fee.

## 9. Base-product tier schedule (v1)

The base product prices on a (`throughput_tier`, `value_tier`) pair under
`value_tier_formula_version="v1"`; Node rows keep the band table above. The
schedule carries the band function's own discipline: **public, versioned,
deterministic; sales cannot override it; a repriced tier is a NEW version,
never an edit of a frozen one.** `"v1"` denotes the complete observed formula
— the ≥1% rule, the FX ranking and the fee vectors below (owner-adopted
2026-08-26).

- **`throughput_tier`** — prospectively ELECTED reserved leaf capacity per
  annual term. An election, never a meter: realised volume is neither
  measured for pricing nor trued up. Inclusive ceilings: `cap-1m` 10⁶ ·
  `cap-10m` 10⁷ · `cap-100m` 10⁸ · `cap-1b` 10⁹ leaves. The reading that
  informs an election or renewal is ANCHOR-ONLY (owner decision 2026-08-26):
  the latest checkpoint's `tree_size` — the anchored total leaf count, never
  a billable/system classification and never a read of any leaf.
- **`value_tier`** — OBSERVED, never declared: the customer's highest
  routinely-present `amount_band` — the highest `"10^N CUR"` plaintext band
  (SPEC/context-v1.md §2) appearing in **≥1% of value-bearing leaves in the
  term** — read mechanically off the customer's own leaf log. Cross-currency
  bands are ranked by their euro value at the ECB euro reference rate on the
  order date, fixed for the term (the term-fixed ECB FX rule). Coverage is
  dial-scoped: today `payment.execute` carries `amount_band` (and
  `mandate.assigned` carries `amount_cap_band`); a class with no
  amount-bearing dial entry prices on throughput alone until SPEC adds one.
  Tiers by the euro-value exponent N of the highest routine band —
  floor(log10) of the band's euro value, which for an EUR band is its own
  exponent: `vb-1k` N≤3 · `vb-10k` N=4 · `vb-100k` N=5. A reading with a
  missing input — no anchor, a value-bearing leaf without its band, a
  currency without a term-fixed rate, or no value-bearing leaves at all —
  is `INDETERMINATE` → no quote, per §5's discipline: nothing is
  auto-selected and nothing is invoiced from a blank.

**Annual fee is ADDITIVE: `fee(t, v) = capacity_fee[t] + coverage_fee[v]`.**
Capacity: `cap-1m` €3,000 · `cap-10m` €4,000 · `cap-100m` €5,500 · `cap-1b`
€7,500. Coverage: `vb-1k` €12,000 · `vb-10k` €22,000 · `vb-100k` €44,000.

A routinely-present band of `"10^6 CUR"` or above, and any unknown tier
string, is refused: the base product never quotes it, validation rejects the
row and nothing is auto-selected (the Strategic discipline of §5) — that
customer is a Node conversation, where the same money buys source
corroboration and the attestation machinery. Both dimensions are fixed
prospectively in the signed order; no retroactive true-up in either
direction — upward crossings step up prospectively, reductions apply at
renewal.
