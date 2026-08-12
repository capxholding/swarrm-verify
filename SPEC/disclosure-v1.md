<!-- Apache-2.0 -->
# evd/disclosure v1 — selective disclosure (NORMATIVE, Build 9.5)

A receipt commits to payloads with salted, domain-separated hashes
(`SHA-256(domain ‖ 0x00 ‖ nonce ‖ 0x00 ‖ payload)`; canonical.py). The
standard evidence log persists the commitment, not the payload body. Custody of
the nonce depends on the capture surface: recorder/Node deployments keep it in
the customer volume, while the hosted gateway retains it in the tenant's
encrypted service vault and necessarily handles the payload in transit.
Disclosure is the holder's choice to release `(payload, nonce)` for ONE field
of ONE receipt to ONE audience.

## 1. The package

```json
{"schema": "evd/disclosure/v1",
 "receipt_hash": "<hex — the receipt whose commitment is being opened>",
 "field": "prompt",
 "domain": "evd/v1/prompt",
 "nonce_hex": "<the client-held salt>",
 "payload_b64": "<the payload bytes>"}
```

Nonce vaults are AES-256-GCM encrypted at rest. Recorder and Node deployments
keep the vault and key in their local data volume; the hosted gateway uses a
service-side tenant vault. Payload bytes remain in the caller's source system
after capture, except that a hosted gateway necessarily relays them in transit.
The standard receipt/log databases contain commitments and bounded metadata,
not the disclosed payload/nonce pair.

## 2. Offline verification (`evd verify bundle.json --disclose pkg.json`)

1. The bundle must verify (all the usual checks).
2. `receipt_hash` must be an entry in the bundle.
3. The receipt's `commitments[field]` must equal the recomputed
   `SHA-256(domain ‖ 0x00 ‖ nonce ‖ 0x00 ‖ payload)`.
Any failure → NOT VERIFIED. A wrong payload or nonce cannot pass: the
committed hash was fixed at capture time, before anyone knew what would be
disputed. `--disclose` is repeatable; the JSON report carries a
`disclosures` object.

### 2.1 Closed field/domain profile

The package has exactly the six members in §1. `receipt_hash` is 64 lowercase
hex characters; `nonce_hex` is strict even-length hex decoding to at least 16
bytes; `field` and `domain` are nonempty Unicode scalar strings containing no
C0, DEL or C1 control. The domain begins with the literal `evd/v1/` and MUST be
one of these field bindings:

| field | permitted domain(s) |
|---|---|
| `payload` | `evd/v1/payload` |
| `prompt` | `evd/v1/prompt`, `evd/v1/llm.prompt` |
| `output` | `evd/v1/output`, `evd/v1/llm.output` |
| `tool.args`, `tool.result` | `evd/v1/tool.args`, `evd/v1/tool.result` respectively |
| `message` | `evd/v1/interaction.message` |
| `policy_input`, `policy_output` | `evd/v1/policy.input`, `evd/v1/policy.output` respectively |
| `approver_id`, `justification`, `escalation_target_id` | `evd/v1/approver_id`, `evd/v1/justification`, `evd/v1/escalation_target` respectively |
| `config` | `evd/v1/agent.config`, `evd/v1/lineage/config` |
| `query`, `trigger_content` | `evd/v1/query`, `evd/v1/guardrail.trigger` respectively |
| `amount_exact`, `counterparty_id`, `mandate_ref` | `evd/v1/payment.amount`, `evd/v1/payment.counterparty`, `evd/v1/payment.mandate` respectively |
| `system_prompt`, `tool_manifest`, `mandate_document`, `created_by_id` | `evd/v1/lineage/<field>` |
| `enrolment_evidence`, `source_manifest`, `inputs`, `context_doc`, `request` | `evd/v1/authority/<field>` |
| `batch`, `attestation`, `statement`, `doc` | `evd/v1/node/batch`, `evd/v1/node/attestation`, `evd/v1/node/triage`, `evd/v1/node/coverage` respectively |

The custom-event escape hatch is the only structural rule: every safe field
may use exactly `evd/v1/x/` followed by that same field. No other domain is
valid. In particular, a cryptographic match does not permit a package to name
one field while using another field's domain. Receipt commitment values with no
binding above (for example an already-computed result-set digest) are not
selectively disclosable under v1.

## 3. Live disclosure (auditor portal)

`POST /portal/{grant}/disclose` with a package: the portal recomputes the
commitment against the SCOPED receipt live and renders green (match) / red
(mismatch). The payload and nonce exist server-side only for the lifetime
of the request; nothing is stored. Every disclosure attempt is receipted
(`evd.disclosure.released`, context = {receipt_hash, field, verified} — no
payload material). Out-of-scope receipt hashes are a 404, not an oracle.

## 4. Limitations (honest)

- Disclosure is per-field, all-or-nothing for that field: partial/redacted
  disclosure of a committed blob is not possible in v1 (no Merkle-ized
  payloads; a post-v1 increment).
- Vault encryption does not make a live process compromise harmless: the
  capture process can access nonce plaintext while operating, and hosted
  custody is not customer-exclusive custody.
- A disclosure proves what WAS committed; it cannot prove the absence of
  other commitments elsewhere.
