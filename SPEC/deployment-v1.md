<!-- Apache-2.0 -->
# evd/deployment v1 — asserted deployment posture (`deployment.declared`)

Status: NORMATIVE. Wire names are frozen once shipped.

## 1. Purpose

The log proves what the agent did through the installed doors; this receipt
records the posture the customer ASSERTS about those doors: which capture
doors are installed, whether the provider credential is held by the gateway
rather than the agent (docs/RUNBOOK_DEPLOY.md, the agent-side credential
rule), which tool surfaces are wrapped, and whether the egress allow-list is
applied. It buys what the mandate receipt buys and nothing
more: the customer's claim, frozen at declaration time, so it cannot be
quietly revised after an incident, and disputable against the customer's
own configuration management.

A new wire type needs a sentence explaining why no existing action type
can carry it, so here it is:
`agent.session_started` is a recorder witnessing its OWN resolved routing
config at its own startup — observed, per recorder process;
`lineage.born/adopted` commits once per AGENT lifetime; `mandate.assigned`
is per task. A posture claim is per DEPLOYMENT, customer-asserted rather
than observed, and re-emitted on change — it matches none of those
cardinalities or doors.

## 2. The receipt

`action_type` = `deployment.declared`, an ordinary `evd/receipt/v1` body.
It is emitted through the SDK (a self-report door): no new capture door,
not in the managed-edge ingest allow-list, and the `deployment.` namespace
is NOT privileged.

Context (all plaintext, dial row in SPEC/context-v1.md §1):

| field | meaning |
|---|---|
| `doors_installed[]` | capture doors the customer declares installed (strings, e.g. `gateway`, `mcp_wrap`, `otel`, `sdk`) |
| `provider_credential_in_gateway` | boolean: the provider key is held by the gateway and never by the agent |
| `tool_surfaces_wrapped[]` | tool surfaces the customer declares wrapped (strings) |
| `egress_allowlist_applied` | boolean: the customer's egress allow-list is in force |

There are no commitments: the posture IS the claim, and every field must
stay queryable and disputable. Nothing here is a payload or a secret —
credentials of any kind must never appear (the boolean states WHERE a
credential lives, never what it is). Both arrays are always present, so an
empty declaration (`[]`) is distinguishable from an absent field.

## 3. Emission

Emit at deployment start; re-emit whenever the declared posture changes.
This is conventional, never enforced — a late, missing, or repeated
declaration stays VERIFIED. The report renders the LATEST declaration by
leaf index (re-emission on change makes the latest the current claim) and
derives nothing else across multiple declarations.

## 4. What is derived, what is declared

- DECLARED stays declared. The receipt arrives through a self-report door;
  the report labels it `DECLARED (customer-supplied; disputable against the
  customer's own configuration management)` and nothing may present it as
  independently attested or observed.
- The ONLY derived claim is which declaration is latest by leaf index.
- **GUARDRAIL (normative): a deployment declaration must
  never award or influence an evidence level, must never imply capture
  completeness, and must never flip VERIFIED/NOT VERIFIED.** It is a claim
  about configuration, not about capture; a customer who declares a clean
  posture and runs a leaky one produces a receipt that is honestly recorded
  and simply false, which is what DECLARED has always meant.

## 5. Verifier impact

None. `deployment.declared` receipts verify like any receipt (signature +
inclusion) in both engines; presence, absence, content, or ordering of a
declaration MUST never flip VERIFIED/NOT VERIFIED. Neither engine
dispatches on this action type.

## 6. Out of scope

The agent-minted action counter; source-side corroboration of a declared
posture against configuration-management records; reconciliation against
egress records; feeding declared posture into any derivation or verdict.
