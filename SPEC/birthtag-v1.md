<!-- Apache-2.0 -->
# birthtag-v1 — agent lineage receipts

Status: **NORMATIVE** (v1). Wire names are frozen once shipped.

Every agent's evidence history has a verifiable beginning. A receipt proves an
action happened; lineage proves *which recorded history* the acting agent
belongs to, from a fixed, anchored starting point. It is a VIN and a logbook,
not a driver's licence: runtime identity is out of scope — this binds whatever
identity exists to permanent evidence lineage.

## Action types (the `agent.*` lifecycle namespace — NEVER `evd.*`)

| action_type | meaning |
|---|---|
| `lineage.born` | created with the evidence layer present; mandate recorded |
| `lineage.adopted` | first sight of a pre-existing agent; prior history explicitly unevidenced |
| `lineage.revised` | model / config / tools / mandate changed |

## The lineage receipt

- `agent_id` = the deployed acting agent, never the underlying LLM.
- **Lineage is established at the agent's first-observed seq**, not
  necessarily seq 1: a pre-existing agent (receipts already recorded, or a log
  predating this spec) is `adopted` at its current next seq with
  `context.lineage_from_seq` = that seq. `_system` seq 1 is the key-log
  genesis and is never a lineage receipt. For an agent whose first-ever
  receipt is its lineage receipt, seq MUST be 1.
- At most ONE establishment receipt (`born` | `adopted`) per agent per log.
  A second one is a hard verification failure.
- commitments (salted, domain-separated per receipt-v1 §4; each selectively
  disclosable): `system_prompt`, `tool_manifest`, `config`,
  `mandate_document`, `created_by_id` (the creating principal's identifier is
  PII — always committed, never plaintext).
- context (plaintext, per the context-v1 dial): `kind` (`born|adopted`),
  `model_ref`, `code_digest`, `purpose` (short, human-readable),
  `created_by_role`, `owner_org` (legal entity, not a person),
  `lineage_from_seq` (adopted only), `prior_history` = `"unevidenced"`
  (adopted only).
- `lineage.revised` carries the same commitment slots (changed ones) and
  context `{revises: <birthtag_id>, reason}`.

## IDs are derived, never allocated

- `birthtag_id` = the `receipt_hash` of the establishment receipt.
- `revision_id` = the `receipt_hash` of the latest `lineage.revised`, or the
  `birthtag_id` if none.
- No registry, no ID service, nothing to run. The establishment receipt does
  NOT carry its own `birthtag_id` (it cannot contain its own hash) — it IS
  the birthtag.

## Threading

Every subsequent receipt for the agent SHOULD carry `context.birthtag_id`
and `context.revision_id` (universal lineage keys, allowed for every action
type in the context-v1 dial). Emission surfaces that cannot know the lineage
(e.g. edge-signed envelopes ingested later) omit them; absence is advisory,
never an error.

## Export rule

`export_bundle` MUST force-include every exported agent's lineage receipts
(establishment + all revisions) with inclusion proofs, exactly as key
entries are force-included: the verifier's lineage authority is the log.

## Verification rules (both implementations, shared golden fixtures)

Hard failures (NOT VERIFIED):
1. Two establishment receipts for one agent in one log.
2. A receipt whose `context.birthtag_id` does not equal the derived
   birthtag of that agent's establishment receipt present in the bundle.
3. A receipt whose `context.revision_id` matches no
   establishment/revision receipt of that agent present in the bundle,
   when at least one such receipt is present.

Advisory (VERIFIED, reported):
- No lineage data for an agent → `lineage: not established`.
- `birthtag_id`/`revision_id` referenced but the lineage receipt absent
  from the bundle (foreign or hand-filtered bundle) → `lineage: referenced,
  not included`.
- `adopted` renders as "lineage established <ts>; prior history not
  evidenced".

## Fail-open (mandatory)

A receipt from an agent with no establishment entry is never rejected.
Capture surfaces auto-emit `lineage.adopted` (idempotency key
`lineage-<agent_id>`) on first sight and proceed; any lineage error during
capture degrades to emission WITHOUT the lineage keys. Blocking traffic on
missing lineage violates design law 1.

## Reserved for a later version

`parent` (agent-to-agent lineage graph: clone/subagent/template) is
deliberately NOT in v1. A parent link is only meaningful if the verifier
binds it (the parent's establishment receipt present + inclusion-proven,
optionally parent-key co-signed). Shipping it as unverified plaintext
would freeze a graph primitive nothing checks. It returns in a later
version WITH a binding rule.

## Non-goals

Global registry · wallet · reputation · authentication · cross-tenant
lookup · approval workflows · runtime identity (SPIFFE/A2A's job).
