<!-- Apache-2.0 -->
# evd/mandate v1 — session-start mission capture (`mandate.assigned`)

Status: NORMATIVE (Build 32). Wire names are frozen once shipped.

## 1. Purpose

The log proves what an agent did; this receipt records what it was TOLD to
do — "who told this agent to do what, under which limits" — declared by the
customer's orchestrator at task-acceptance time. It exists so an Evidence
Report can render assigned → did → source-confirms, and so log order proves
the mandate existed before the actions it governs (an assigned-before-acted
property that holds even though the mandate's content is customer-declared).

Why a new wire type instead of an existing one (A_BUILD §0.2 rule 10):
`lineage.born/adopted` commits a `mandate_document` once per AGENT lifetime,
and `authority.grant.issued` is an org-root-signed system receipt — a
per-task assignment is repeatable, per-session, and orchestrator-declared,
which matches neither cardinality nor door.

## 2. The receipt

`action_type` = `mandate.assigned`, an ordinary `evd/receipt/v1` body.
It is emitted through the SDK (a self-report door): no new capture door, no
channel connectors, not in the managed-edge ingest allow-list, and the
`mandate.` namespace is NOT privileged (edge co-sign stays permitted, as for
any customer action type).

Context (plaintext, dial row in SPEC/context-v1.md §1):

| field | meaning |
|---|---|
| `principal_display` | display name of who assigned, as known to the orchestrator |
| `source_channel` | one of `slack` · `email` · `ticket` · `ui` · `queue` · `other` |
| `action_classes[]` | declared allowed action classes (strings; same vocabulary as authority grants) |
| `amount_cap_band` | order-of-magnitude cap band `10^N CUR` (SPEC/context-v1 §2) |
| `expires` | RFC 3339 canonical UTC expiry of the mandate |

The channel's own record reference (permalink / message-id / ticket id) is
carried in the universal correlation key `external_ref` (reconcile-v1 §1):
opaque, never validated, never interpreted. It is the future path to
source-side corroboration, not a present claim.

Commitments (salted, domain-separated, disclosable later):

| name | domain | payload |
|---|---|---|
| `instruction` | `evd/v1/x/instruction` | the verbatim instruction bytes |
| `principal_id` | `evd/v1/x/principal_id` | the assigner's identity (human or system) |
| `amount_cap_exact` | `evd/v1/x/amount_cap_exact` | canonical decimal text of the exact cap |

Domains deliberately use disclosure-v1's generic lane (`evd/v1/x/<field>`,
the lane `record()` commitments already use): the frozen per-field domain
map lives inside the verifier walls, so binding dedicated `mandate.*`
domains there is not possible without verifier growth — and the generic
lane makes every mandate commitment formally openable through
`evd/disclosure/v1` packages today. Domains freeze with the wire.

The instruction text and the assigner's identity never appear in plaintext
anywhere — payload discipline identical to every other payload. The report
renders only the first 8 hex characters of the `instruction` commitment as
the fingerprint.

## 3. Placement

The mandate receipt SHOULD be the session's first receipt (emit at task
acceptance, right after opening the session). This is conventional, never
enforced: a mandate recorded late stays VERIFIED and the report says so.
Multiple mandate receipts in one session are allowed; the report renders the
first (by leaf index) and derives nothing across them.

## 4. What is derived, what is declared

- DECLARED stays declared. The receipt arrives through a self-report door;
  the report labels it `DECLARED (orchestrator-supplied; corroborable via
  {channel} record)` and nothing may present it as independently attested.
- The ONLY derived claim is log position: whether every other receipt in the
  session follows the first mandate receipt in leaf-index order. No semantic
  compliance checking — we do not attest whether actions "complied with" the
  instruction text; we don't attest meaning.
- A session without a mandate renders "no mandate recorded" — absence
  visible, never an error.

## 5. Verifier impact

None. `mandate.assigned` receipts verify like any receipt (signature +
inclusion) in both engines; presence, absence, or ordering of a mandate MUST
never flip VERIFIED/NOT VERIFIED. Neither engine dispatches on this action
type.

## 6. Out of scope (future, own handoffs)

Source-side corroboration of `external_ref` (Node connector); feeding
`limits` into band self-enforcement derivations; mandate-vs-behavior
comparison; any taxonomy of task types beyond `action_classes` strings.
