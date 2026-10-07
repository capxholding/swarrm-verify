<!-- Apache-2.0 -->
# evd/cocommit v1 — client co-commitment (`cocommit.head.signed`)

Status: NORMATIVE. Wire names are frozen once shipped.

## 1. Purpose

The strongest available answer to "why should I trust your recorder?" is the
one that asks the customer to believe nothing about it: the customer's own
agent independently commits to every action it takes and signs that with a
key the gateway never sees. If the gateway altered anything the customer's
own attestation disagrees; if the deployment leaked actions around the
gateway, the client's own count exceeds the receipts. This does not make the
gateway trustworthy — it makes the gateway irrelevant to integrity for
whoever adopts the tier.

One mechanism serves two adversaries (the action counter extends the
relay-integrity tree instead of building a separate counter):

- **The altered relay.** The client hashes the exact bytes it sent
  and received. A gateway that alters a relayed byte produces receipts over
  bytes whose digests are NOT in the client's signed tree; the client's
  inclusion proof for the true digests still verifies against its own head.
- **The leaky deployment.** The client counts EVERY action it took,
  routed or not — an unrouted code path, a direct call left in after
  testing, a second instance started without the config, drift — because
  those keep counting honestly. A signed head asserting 400 against a log
  holding 397 is the whole of the evidence, with no new primitive.

Bound, stated here so it cannot be overclaimed downstream: an agent that
skips the recorded call **and** its own counter together is out of reach of
this mechanism — every part of it asks the agent's own runtime to report on
itself. That adversary is out of this document's scope.

## 2. The client tree

The client accumulates one leaf per action into a local RFC 6962 Merkle tree
— the same construction the evidence plane runs (`core/merkle.py` /
`core/merkle_build.py`: leaf hash `SHA-256(0x00‖data)`, node hash
`SHA-256(0x01‖l‖r)`, MTH per §2.1) — and periodically signs only the head
(every N actions or T seconds). One signature covers hundreds of actions;
any individual action later proves inclusion in the client-signed head with
ordinary neighbour codes.

Leaf data is the RFC 8785 canonical JSON of one **client action record**:

| member | meaning |
|---|---|
| `v` | `1` |
| `client_seq` | the agent-minted per-action counter: the leaf index, 0-based, monotone by construction |
| `kind` | the client's own classification of the action (e.g. `llm.chat`, `tool.call`, free string) |
| `action_id` | the reconcile-v1 §1 correlation id when the action was also routed; absent otherwise |
| `request_sha256` | hex SHA-256 of the exact request bytes the client sent; absent if none |
| `response_sha256` | hex SHA-256 of the exact response bytes the client received; absent if none |

Absent members are OMITTED, never null. The record carries **digests only**
— no payload bytes, no PII, ever. Losing the client's raw traffic loses the
ability to open a digest, never confidentiality.

## 3. The signed head

The head statement is the RFC 8785 canonical JSON of:

| member | meaning |
|---|---|
| `v` | `1` |
| `tenant` | the tenant id the covering receipts carry |
| `agent_id` | the agent this tree counts |
| `head_root` | hex MTH root over leaves `0..head_size` |
| `head_size` | leaf count = total actions the client has taken (the action counter) — MUST be ≥ 1 |
| `prev_head_root` | hex root of the previously signed head; omitted on the first head |
| `prev_head_size` | leaf count of the previously signed head; omitted with `prev_head_root` |

`prev_head_root`/`prev_head_size` appear together or not at all, and
`head_size` MUST be ≥ `prev_head_size`. The signature is Ed25519 (asymmetric
ONLY — **never HMAC**: a shared secret would put the forging key in the
gateway's hands and defeat the entire threat model) over

    "evd/v1/cocommit.head" ‖ 0x00 ‖ canonical_bytes(statement)

under a **client-held key the gateway never sees**. Key custody follows the
recorder local-key shape (`core/signer.load_or_create_key`): a 32-byte seed
file created once, `0600`, symlink-refused, private to the client process.
The client key MUST NOT be the issuer key or any key the recording plane
holds; the SDK refuses to emit a head whose key equals the log's issuer key.
The public half is registered with the relying party out of band (the same
channel as `trust["recorder_keys"]`); a public key carried inside evidence
is discovery material, never a trust input.

## 4. The receipt

`action_type` = `cocommit.head.signed`, an ordinary `evd/receipt/v1` body
emitted through the SDK (a self-report door, exactly like `mandate.assigned`)
and admissible at the managed edge so a hosted client can deliver one POST
per signed head. Context (plaintext, dial row in SPEC/context-v1.md §1 —
public roots, counters, key ids and detached signatures; no secrets exist
here):

| field | meaning |
|---|---|
| `head_root` | hex, from the statement |
| `head_size` | integer, from the statement |
| `client_kid` | key id of the client key (derived from the public half) |
| `client_pub` | base64url raw Ed25519 public key (32 bytes) — discovery only, NOT a trust input |
| `client_sig` | base64 detached signature over the domain-separated statement |
| `prev_head_root` | hex; omitted on the first head |
| `prev_head_size` | integer; omitted with `prev_head_root` |

There are no commitments: every value is already a digest, counter, key id
or signature. `tenant` and `agent_id` are the receipt body's own; a verifier
of `client_sig` reconstructs the statement from receipt body + context.

## 5. Report rendering — DECLARED class, its own label

The report renders presence and count comparison as a **DECLARED-class
observation** carrying the label `GATEWAY_INDEPENDENT_CAPTURE`:

- presence: which agent, which client key, the signed head fingerprint and
  the client-counted total;
- the count comparison: `head_size` of the agent's LAST head in the bundle
  against the number of the agent's ACTION receipts before that head in the
  same bundle. The comparison basis is fixed so orchestration rows cannot
  fake a gap: it counts the receipt types that record what the agent DID —
  `llm.chat`, `tool.call`, `data.read`, `payment.execute`,
  `interaction.message` and custom `x.*` types — and excludes rows that
  record what happened TO the agent (lineage, mandate, human, policy,
  guardrail, agent lifecycle, system rows). More client-counted actions
  than receipts is the leaky-deployment signal; fewer means the
  co-commitment does not cover part of the log. Both directions render
  with their numbers; a partial export produces the same arithmetic and
  the report says so;
- monotonicity: heads whose `head_size` decreases across the bundle render
  as a non-monotone counter observation.

**GUARDRAILS (normative, decided before any code was written):**

1. A client co-commitment MUST NEVER award or influence an evidence level —
   **in particular it never awards E3**. E3 means a counterparty attested:
   independence from outside the customer. This is independence from *our
   gateway*, and both parties sit inside the customer; if it could award E3
   a customer could manufacture E3 alone, violating §0.2 grounding. A
   co-committed receipt with no counterparty signature remains E2-max, plus
   the label.
2. It MUST NEVER imply capture completeness. Matching counts are the
   client's own claim agreeing with the log, not proof nothing was skipped
   (§1 bound: skipping call and counter together is invisible here).
3. It MUST NEVER flip VERIFIED/NOT VERIFIED. Presence, absence, count
   mismatch, bad signature bytes or a non-monotone chain change rendering
   only.

## 6. Verifier impact

None in v1. `cocommit.head.signed` receipts verify like any receipt
(signature + inclusion) in both engines; neither engine dispatches on this
action type, and `public_verifier_symbols` is unchanged. Checking
`client_sig` under a relying-party-registered client public key is a
deliberately DEFERRED verifier leg (it needs a `trust` input and a budget
decision); until it ships, the report labels the signature as carried, not
verified, and derives nothing from its validity.
