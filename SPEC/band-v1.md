<!-- Apache-2.0 — this file ships with the public verifier repo. -->

# SPEC: band-v1 — the published value-band function (B27.2A)

**Status: NORMATIVE (v1). Structure frozen; thresholds are a launch
hypothesis, revisited only after three production contracts (B27.2A).**

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

## 5. Band table (STRUCTURE FROZEN; fees per policy pack v0.1, O·7 2026-08-01)

| Band | Aggregate authority | Criticality floor | Annual fee |
|---|---:|---|---:|
| A | ≤€25M | `REVERSIBLE_EXTERNAL_EFFECT` · `INTERNAL_RECORD_CHANGE` | €50K |
| B | ≤€250M | `REGULATED_OR_CUSTOMER_RIGHTS_EFFECT` | €150K |
| C | ≤€2.5B | `IRREVERSIBLE_EXTERNAL_VALUE_TRANSFER` · `SAFETY_OR_LEGALLY_HIGH_RISK` | €500K |
| D | ≤€25B | — | €1.5M |
| Strategic | above D — **explicitly purchased only, never algorithmically selected** | — | €3M+ |

Criticality is a coarse FLOOR that tops out at C. Missing or unresolvable
required declarations yield `INDETERMINATE` → `NO_REGISTRATION` (never the
Strategic band — an algorithm that can invoice €3M for a blank field is a
liability). Strategic is reachable only by explicit purchase.

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
optional below**. The commercial plane is structurally incapable of leaking or
being subpoenaed for customer transaction data — it never holds any.

## 8. Neutrality (non-negotiable)

`AuthorityGrant` defines what an agent may operationally do; `RegistryScope`
selects which grants receive paid registration; price is computed from the
grants inside that scope. **Commercial status never changes an authority
verdict or any evidence.** Opposite evidence outcomes under the same signed
order produce identical invoice lines. Price, band, payment, findings and
record counts never enter the public certificate; identical proof gets the
same verifier result regardless of payer or fee.
