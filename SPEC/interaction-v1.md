<!-- Apache-2.0 -->
# evd/interaction v1 — agent↔agent evidence (NORMATIVE, Build 10.5)

One receipt per transported message between two agents. Transport-agnostic:
the receipt commits to the CANONICAL bytes the transport actually carried.

## The profile

- `action_type: interaction.message`
- context (plaintext, per the dial): `{sender, receiver, transport, rel_seq,
  bilateral}`
- commitment: `message` over the canonical transported payload, domain
  `evd/v1/interaction.message` (salted; nonce stays with the sender)
- signatures: the SENDER signs; the RECEIVER co-signs when reachable
  (`bilateral: true` — verify with `require_kids={sender_kid, receiver_kid}`,
  both witnessed by the key log per log-v1 §5). When the counterparty cannot
  co-sign, the receipt is still emitted with `bilateral: false` —
  **degradation never blocks the interaction**, it labels the evidence.
- `rel_seq`: dense per unordered relationship pair — a withheld message is a
  VISIBLE gap, not silence. An alternate history (rewritten message) fails
  signature + inclusion checks like any tamper.

## Bindings

| transport | message bytes committed |
|---|---|
| `a2a` | the canonical A2A message JSON |
| `mcp` | the canonical JSON-RPC `tools/call` request or response |
| `ap2` | the canonical AP2 mandate object (receipts can wrap payment mandates without translation — same RFC 8785 canonicalization) |

## NON-goals (explicit — these stay out)

No relay, no escrow, no interaction state machines. This profile is
evidence ABOUT interactions, not an interaction bus; per-transaction
infrastructure is a deliberate year-2 boundary. Standards motion (proposing
this profile in the A2A/MCP communities) starts after the first production
partner — the spec you are reading is the artifact.
