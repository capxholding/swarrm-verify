<!-- Apache-2.0 -->
# evd/policy v1 — policy attestation (NORMATIVE, Build 11)

A `policy.decision` receipt attests that an EXTERNAL policy engine (OPA is
the reference) evaluated a policy and produced a decision. We never run the
engine; we make its run disputable.

- context (plaintext): `{engine, engine_version, decision,
  policy_bundle_hash}` — the SHA-256 of the exact policy bundle that ran.
  Tampering with any of these after the fact breaks the receipt signature
  and its inclusion proof (tested).
- commitments: `policy_input`, `policy_output` (canonical JSON, salted) —
  disclosable via evd/disclosure/v1 when a dispute needs the io.

This gives "controls attested": an Evidence Report over a period can state,
per receipt, that decision D was produced by engine E version V running the
bundle whose hash is H — and the customer can later disclose exactly what
went in and out. OPA integration = compute `policy_bundle_hash` over the
bundle tarball you ship to OPA, call `EvdClient.policy_decision(...)` after
each evaluation (or from an OPA decision-log webhook).

Related dispute-grade families (dial rows in SPEC/context-v1.md):
`human.approve/override/reject` + `human.escalation_timeout` (webhook
`POST /evd/human`; approver identity/justification committed — **non-goal:
we never run approval workflows**), `agent.deployed/config_changed/
tool_granted/revoked` (config blobs committed), `data.read` (query
committed, counts banded), `guardrail.blocked` (trigger content committed).
