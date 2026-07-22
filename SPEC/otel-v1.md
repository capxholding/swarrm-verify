<!-- Apache-2.0 -->
# evd/otel v1 — OTLP → receipts mapping (NORMATIVE, Build 10)

`POST /evd/otlp` accepts OTLP/HTTP **JSON** encoding (protobuf is out of
scope in v1; configure the collector's `otlphttp` exporter with
`encoding: json`). ONLY GenAI-semconv model and tool spans map to receipts;
every other span is dropped by design and the counts are returned in the
response (`evd.dropped_non_genai`, `evd.dropped_over_cap`) — drops are
visible, never silent. Per-export cap: 500 receipts.

## Mapping table

| OTel (GenAI semconv) | receipt |
|---|---|
| `gen_ai.operation.name` ∈ {chat, text_completion, generate_content} | `action_type: llm.chat` |
| `gen_ai.operation.name` = execute_tool | `action_type: tool.call` |
| resource `service.name` | `agent_id` |
| span_id | `idempotency_key` (`otlp-<span_id>` — natural dedup on retry) |
| startTimeUnixNano | `ts_client`; end−start → `latency_ms`/`duration_ms` |
| `gen_ai.request.model` / `gen_ai.response.model` | context.model (response wins) |
| `gen_ai.usage.input_tokens` / `output_tokens` | context tokens (only if present — never guessed) |
| `gen_ai.response.finish_reasons` | context.finish_reason (first) |
| `gen_ai.tool.name` | context.tool_name |
| span status ERROR | context.status 500 / is_error true |
| `gen_ai.conversation.id` (else trace_id) | `session_id = s_ + hex16(SHA-256(tenant‖service‖basis))`, `session_inferred: true` |
| `gen_ai.prompt`, `gen_ai.completion`, tool args/result attributes | **COMMITTED** (salted commitments; nonces to the tenant vault) — never plaintext context |

Everything emitted conforms to the context dial (SPEC/context-v1.md); the
drift test covers this surface. Malformed spans are skipped fail-open —
an exporter is never given a 5xx because one span was odd.

## Collector example

See `docs/otel-collector-example.yaml`: an `otlphttp` exporter with JSON
encoding, api key header, pointed at `/evd/otlp`.
