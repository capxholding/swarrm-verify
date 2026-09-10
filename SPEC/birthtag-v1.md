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
  (adopted only), and the ADDITIVE `field_provenance` string (context-v1
  §1a): per-field `asserted` vs `observed:<basis>` labels for `model_ref`,
  `tool_manifest`, `code_digest` and `created_by_id`, so a report can say
  which values a door observed and which a human typed. Capture surfaces
  MAY populate those four from live observation when the caller omits them;
  an explicit caller value always wins and is labelled `asserted`; an
  ambiguous observation populates nothing (observation never guesses).
  `observed:mcp-wrap` specifically requires a strict initialize request and
  response for the same supported protocol, the subsequent
  `notifications/initialized`, one correlated root `tools/list` request, and a
  final JSON-RPC result with no request cursor, continuation cursor, or
  partial-result marker. `swarrm init` binds each wrapped server to the bounded
  `mcpServers` object key it actually rewrites; that configured key groups the
  advisory snapshot across restarts and server renames. A direct legacy wrap
  without `--server-id` may use bounded `serverInfo.name` only under a
  single-server identity epoch; a second distinct self-report makes the epoch
  incomplete. A configured key and `serverInfo.name` are identifiers, not
  evidence of who operated the server. The complete array is admitted as one
  unit: at most 256 tools, every name nonempty/bounded/control-free, no
  duplicates, and a bounded canonical persisted snapshot; the empty list is
  valid. Malformed, paginated, oversized, expired, changed, uninitialized,
  persistence-failed, or mutually different snapshots populate nothing and
  invalidate older state until every expected identity has a later complete
  refresh. Tool names are never sliced, filtered, deduplicated, or unioned.
  A birth emitted by `swarrm init` MUST also populate the existing `config`
  commitment with canonical `evd/init-configuration-binding/v1`: a `files`
  object whose exact members are `.env`, `mcp.json`, and `.mcp.json`, each
  either null when absent or `sha256:<lowercase hex>` over the bounded bytes
  init admitted. Raw configuration bytes are not placed in that manifest.
  Init rechecks this snapshot through a pre-commit admission guard. Because
  POSIX cannot atomically transact an uncooperative editor's files with the
  receipt database, the committed digest manifest is the durable statement;
  a later file change invalidates the run's success but cannot make the birth
  claim that the older snapshot remained current.
- `lineage.revised` carries the same commitment slots (changed ones) plus
  `revised_by_id` (the revising principal's identifier is PII — always
  committed, never plaintext; generic disclosure lane `evd/v1/x/revised_by_id`,
  since the verifier's per-field domain map is frozen) and context
  `{revises: <birthtag_id>, reason, revised_by_role, change_ref}` —
  `change_ref` names the change record (merged PR, CloudTrail event id,
  change ticket) that authorized the revision, carried untouched.
- Attribution: creation is attributed at birth (`created_by_id` /
  `created_by_role`) and revision at revision (`revised_by_id` /
  `revised_by_role`). Both are customer-declared self-reports; neither
  attribution is corroborated until the record named by `change_ref` (or the
  channel record in `external_ref`) is actually read. Presence or absence of
  either moves no verdict.

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
