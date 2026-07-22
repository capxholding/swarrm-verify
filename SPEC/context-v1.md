<!-- Apache-2.0 -->
# evd/context v1 — the context dial (what is plaintext, what is committed)

Status: NORMATIVE (Build 6). This table is the single authority for which
fields may appear in a receipt's PLAINTEXT `context` per `action_type`.
Extending it requires a PR that updates the leak test
(`tests/test_context_dial.py`) in the same change. Anything not listed as
plaintext for its action type is either COMMITTED (salted commitment,
disclosable later by the payload holder) or must not exist anywhere.

## 1. The dial (normative table)

| action_type | PLAINTEXT context (queryable) | COMMITTED (disclosable) | NEVER anywhere |
|---|---|---|---|
| `llm.chat` | model, endpoint, status, stream, finish_reason, input_tokens, output_tokens, requested_tool_names[], latency_ms | full request (`prompt`), full response (`output`) | raw user identifiers in context |
| `tool.call` | tool_name, server_name, duration_ms, is_error, arg_keys[] (top-level keys only), result_kind (text/json/binary/none), result_size_band | tool.args, tool.result | any arg/result VALUES in context |
| `data.read` | source_system, query_kind, record_count_band, duration_ms | query, result_set_hash | record contents in context |
| `human.approve/override/reject` | decision, approver_role, latency_band | approver_id, justification | approver PII in context |
| `human.escalation_timeout` | waited_ms, escalation_target_role | escalation_target_id | — |
| `payment.execute` | currency, amount_band, counterparty_class, mandate_present | amount_exact, counterparty_id, mandate_ref | amounts/counterparty in context |
| `agent.deployed/config_changed/tool_granted/revoked` | change_kind, model_ref, tool_name (grants) | config blobs (prompt text etc. as commitments) | prompt text in context |
| `interaction.message` | sender, receiver, transport, rel_seq, bilateral | message (the canonical transported payload) | message content in context |
| `policy.decision` | engine, engine_version, decision, policy_bundle_hash | policy_input, policy_output | io values in context |
| `guardrail.blocked` | guardrail_name, rule_kind, action_taken | trigger_content | trigger content in context |
| `evd.alert.raised` | rule_id, severity, triggering_receipt_hashes[], window | — | payload of any triggering receipt |
| `evd.key.*` / `evd.report.*` / `evd.grant.*` / `evd.disclosure.*` | (system — full plaintext, no secrets exist here) | — | — |

## 2. Bands (normative)

- `amount_band` = `"10^N CUR"` (floor of log10 of the absolute amount, plus
  ISO currency), e.g. €49.90 → `"10^1 EUR"`.
- `result_size_band` / `record_count_band` ∈ {`0`, `<1k`, `<100k`, `≥100k`}
  (bytes for results, rows for record counts).
- `latency_band` ∈ {`<1s`, `<1m`, `<1h`, `≥1h`}.

## 3. Sessions (normative algorithm — implemented in Build 7)

1. `x-evd-session` header present → use it, `session_inferred=false`.
2. else an OpenAI-style `user` field (or `metadata.conversation_id`) is
   present → `session_id = "s_" + hex16(SHA-256(tenant‖agent‖value))`,
   `session_inferred=true`.
3. else the same `(api_key, agent_id)` pair has produced a receipt less
   than 15 minutes ago → reuse that session; else a new random `s_…`.
   `session_inferred=true`.

Parenting: within a session, `parents=[previous receipt_hash]` unless
`x-evd-parent` is given. `session_id` and `session_inferred` are ADDITIVE
receipt/v1.1 fields; verifiers treat unknown fields as opaque. Inferred
causality is ALWAYS labeled — reports render an "inferred" badge and never
present heuristic grouping as explicit.

## 4. Capture-surface obligations

Every capture surface (gateway, MCP wrap, future OTel/SDK) MUST pass the
leak test: fuzzed payload/argument/result sentinels may never appear
anywhere in a receipt outside commitment values, and each receipt's
plaintext context keys must be a subset of the table for its action_type.
The MCP wrap additionally guarantees BIT-PERFECT relay: it reads traffic,
it never rewrites, reorders, retries, or filters it.
