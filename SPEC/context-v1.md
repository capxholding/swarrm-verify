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
| `lineage.born` / `lineage.adopted` | kind, model_ref, code_digest, purpose, created_by_role, owner_org, lineage_from_seq, prior_history | system_prompt, tool_manifest, config, mandate_document, created_by_id | creator PII in context; prompt/mandate text in context |
| `lineage.revised` | revises, reason | system_prompt, tool_manifest, config, mandate_document | prompt/mandate text in context |
| `evd.key.*` / `evd.report.*` / `evd.grant.*` / `evd.disclosure.*` | (system — full plaintext, no secrets exist here) | — | — |
| `authority.root.enrolled` | root_jwk, root_kid, legal_entity, enrolment_basis, effective_ts, prev_root_kid, prev_root_sig, self_sig (system — public key material + detached sigs, SPEC/authority-v1.md §3.1) | enrolment_evidence | private keys of any kind |
| `authority.principal.bound` | birthtag_id, revision_id, principal, runtime_kid, environment, valid_from, valid_to, org_root_kid, prev_binding_id, concurrent_with, root_sig (§3.2) | — | private keys of any kind |
| `authority.grant.issued` | subject_birthtag_id, binding_id, action_classes, scope, limits, policy_commitment, valid_from, valid_to, org_root_kid, transfers_grant_id, root_sig (§3.3) | — | private keys of any kind |
| `authority.grant.revised` | grant_id, prev_grant_version, grant_version, subject_birthtag_id, binding_id, action_classes, scope, limits, policy_commitment, valid_from, valid_to, transfers_grant_id, effective_ts, org_root_kid, root_sig (§3.4) | — | private keys of any kind |
| `authority.grant.revoked` | grant_id, effective_ts, org_root_kid, root_sig (§3.5) | — | private keys of any kind |
| `source.bound` | source_system, account, credential_identity, mapping_version, event_key_field, finality_rule, valid_from, valid_to, org_root_kid, root_sig (§3.6) | source_manifest | private keys of any kind |
| `source.binding.revoked` | source_binding_id, effective_ts, org_root_kid, root_sig (§3.7) | — | private keys of any kind |
| `action.intent` | action_id, action_class, grant_id, grant_version, binding_id, policy_version, assurance_transcript_digest (§3.8) | inputs, context_doc | input/context values in context; private keys of any kind |
| `action.submitted` | action_id, source_ref (§3.9) | request (the exact request as submitted) | request values in context; private keys of any kind |
| `source.batch.recorded` | source, cursor_start, cursor_end, mapping_version, declared_count, event_key_root, finality_watermark, gaps, exclusions (system — node-v1 §3) | batch (the canonical SourceBatch document) | credentials; master keys; payload bytes |
| `node.registered` | deployment_id, node_kid, measured_digest, attestation_state, attestation_method (node-v1 §7) | attestation (the signed NodeAttestation document) | credentials; master keys; private keys of any kind |
| `node.heartbeat` | epoch, beat, spool_depth, cursors (source → sha256(cursor)), cursors_digest (node-v1 §7) | — | raw cursor values; credentials; master keys |
| `node.upgraded` | release_digest, config_digest, prev_node_kid, prev_final_heartbeat, cursors, cursors_digest, vault_root, successor_kid, handover_start, handover_end, emergency, org_root_kid, root_sig (node-v1 §7) | — | credentials; master keys; private keys of any kind |
| `evd.finding.raised` | rule_id, source, period, evidence_digests (node-v1 §8) | — | payload bytes of any evidenced material |
| `evd.finding.triaged` | finding_id, state, practitioner_id, practitioner_sig (node-v1 §8) | statement (the practitioner's factual statement) | coverage claims of any kind (coverage changes only by recomputation, B23) |
| `evd.gap.declared` | scope, period, reason (node-v1 §8) | — | credentials; master keys; payload bytes |

## 1b. Universal lineage keys (birthtag-v1)

`birthtag_id` and `revision_id` are allowed as PLAINTEXT context on EVERY
action type (they are receipt hashes — derived, non-secret, no PII). They
are the only universal context keys; everything else stays per-type.

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
