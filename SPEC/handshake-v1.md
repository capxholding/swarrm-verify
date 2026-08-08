<!-- Apache-2.0 — this file ships with the public verifier repo. -->

# SPEC: handshake-v1 — Counterparty Assurance (B28)

**Status: NORMATIVE BETA (`swarrm-b28/v1`).** The verifier evaluates the full
vector, but every otherwise-favourable result is exported as
`INDETERMINATE/PASS_DISABLED_BETA`; the public API exposes neither a score nor a
`WOULD_PASS` result. Official `PASS` remains gated on the independent review,
revocation drill and limited relying-party rollout in `docs/A_BUILD.md`.

B28 proves identity, present proof-bearing authority and durable replay
acceptance for one exact action. It does not predict conduct, prove an outcome,
or promise that post-action evidence will be created. No `Swarrm Verified` mark
ships in B28 v1; any future designation can only be post-action.

## 1. Authority and custody

The relying party imports and digest-pins its local trust pack before receiving
an exchange. The raw verifier exchange has no `trust_pack` or
`trust_pack_digest` field, so a presentation cannot select, replace or rotate
the configuration that verifies it. A presentation may not introduce a trust
anchor, embedded JWK, `jku`, `x5u`, certificate URL or network discovery
mechanism. Any unpinned root fails closed. An additional locally pinned root is
an independent trust anchor, not proof of succession; B28 v1 defines no
in-presentation succession mechanism.

A trust pack contains 1..64 sorted unique roots. Implementations freeze the
parsed anchor map and rederive it from the canonical bytes and stored digest at
verification entry; mutable process state cannot silently replace a pinned key.

Only the organisation Ed25519 root may authorize state mutations: templates,
mandates, grants, revocations, delegations, agent succession, AdminBindings and
assumed-risk releases. The Passport & Status Authority may
issue an immutable passport from already-authorized state and sign a short-lived
read-only snapshot. The Action Authority may reserve capacity and issue an exact
ASA inside an active root grant. `RootDelegationV1` requires distinct key
material and derived kids for those two delegated roles. Neither hosted authority
exposes a mutation endpoint that can manufacture root authority.

The authority plane supports the dual-signed `RootRotationV1` continuity
ceremony in `authority-v1.md`: the enrolled old root authorizes the successor
and the new root proves possession over identical bytes. The v1 presentation
verifier does not derive or import trust anchors from an embedded rotation
record; relying parties retain locally pinned historical anchors, and
favourable `PASS` remains disabled.

The root is created by the signed, hash-pinned local CLI. A served webpage never
handles root secret material. The custody bundle uses AES-256-GCM and scrypt
`N=2^18, r=8, p=1`; canonical envelope metadata is AAD. Enrollment completes
only after a different process opens the saved bundle and signs a fresh one-use
server challenge. Swarrm retains the public root and encrypted-bundle digest,
not the seed or recovery phrase. The accurate custody claim is “customer-
controlled, locally generated and capable of being kept offline.”

## 2. Proof-bearing authority state

Each root mutation is an `AuthorityMutationV1` over the tenant, strictly
increasing sequence, previous/new authenticated-map roots, exact changed keys
and object digests, effective time and root key. The service atomically rejects
a stale previous root or sequence before appending the event.

The state key is
`SHA-256("swarrm-authority-state/v1\0" || kind || "\0" || object_id)`. The
second NUL terminates the variable-length textual kind. Leaves bind that
key to a canonical state/version/object digest. The map is lexicographically
ordered and uses the RFC 6962 hashing primitives. Membership uses an inclusion
path. Non-membership is proven by the empty root, one boundary neighbor, or
adjacent predecessor/successor proofs which straddle the requested key.

`AuthorityCheckpointV1` binds the root-signed map head to the append-only
authority log. A status snapshot embeds that checkpoint and the proofs it signs;
it cannot select a different state. A presentation embeds—not merely
references—the root delegation, registration template, `AdminBindingV1`,
WebAuthn `AdminSelectionV1`, agent registration PoP, passport, grant/delegation,
checkpoint, snapshot, the membership proofs for root-controlled objects, and
the Action Authority-signed ASA. The root map does not carry an entry for each
ASA: requiring one would turn every delegated issuance into individual root
approval, contradicting the grant model.

The proof set includes the exact active mandate and agent-config commitments,
keyed by their respective digests, plus `agent_head` keyed by Birthtag. The
head binds the exact passport digest and its state version must equal the
credential revision. Revoking a mandate/config or superseding a Birthtag head
therefore invalidates an older otherwise-active credential.

A proof establishes state at its checkpoint. Registration is typed local
verifier state, not a bare digest allow-list: every registered checkpoint is an
exact `(digest, tenant, organisation_root, sequence)` record. The presented
current checkpoint must match all four fields and the locally retained
authority head; the passport's issuance checkpoint must be registered for the
same tenant and root at a sequence no later than the presented checkpoint.
Cross-tenant digest reuse and a future issuance checkpoint therefore fail
closed. A verified revocation, rollback or fork is `FAIL`. An expired, missing
or locally unregistered checkpoint is `INDETERMINATE`.

`AdminConsumptionV1` root-signs the accepted WebAuthn `sign_count_before`,
`sign_count_after`, backup eligibility/state, binding id and counter version.
The final root mutation updates `admin_counter`, keyed by that binding id, to
the latest signed core digest/version. Every immutable per-challenge
`admin_consumption` remains separately proven. A presentation carries both:
its exact historical consumption and the current active counter head, whose
version must be at least the historical version. A later legitimate ceremony
therefore cannot revoke older agents merely by advancing the shared head; a
missing, rolled-back or inactive proof is `FAIL`. Neither the presentation nor
verifier caller supplies a default or alleged prior counter.
First use requires authenticated non-membership. Later ceremonies carry the
prior root-signed consumption in their authority context, verify it against the
complete map, and advance from its exact counter/version; stale concurrent
branches cannot both become the next root head.

## 3. One semantic and wire profile

The semantic profile is `swarrm-b28/v1`; the EAT profile URI is
`https://swarrm.ai/spec/eat/b28/cwt/v1`. B28 v1 supports exactly one encoding:
deterministic CBOR in a tagged COSE_Sign1 with media type
`application/eat+cwt`. JWT/JWS is not implemented, advertised or negotiable.

Ed25519/EdDSA is fixed. The protected header, typed-core schema and EAT profile are exact;
the protected map is exactly `{1:-8, 3:"application/eat+cwt", 4:kid}` and
unprotected headers are empty. The signed payload is exactly the numeric CWT
claim map `{265: <EAT profile URI>, -65537: <typed core map>}`: claim 265 is
the EAT profile and -65537 is the IANA private-use claim for this typed core.
No other payload claims or text claim keys are accepted. Reject unknown fields,
floats, coercion, noncanonical CBOR, indefinite values, duplicate map keys and
trailing bytes. The verifier derives every typed semantic core digest from the
inner canonical core bytes; an envelope cannot declare its own favourable
digest.

`PresentationCoreV1` contains a mandatory signed `non_assertion` text field.
Its value is exact and versioned; no paraphrase or omission is accepted:

```text
This proves identity, current proof-bearing authority and durable replay at a bounded checkpoint. It does not evaluate Node, source, coverage, history or post-action evidence readiness in v1, predict behaviour, certify an outcome, establish later evidence, or express a Swarrm opinion.
```

The field is part of the typed core and therefore of the presentation signature
and semantic digest. A renderer MUST carry it beside the verdict; it is not a
detachable disclaimer for an otherwise broader claim.

## 4. Exact action and challenge-first flow

`ActionCoreV1` contains exactly:

```text
schema, action_id:bstr32, asa_id:bstr32, actor:AgentRefV1,
operation:text, parameter_schema:text, parameter_digest:bstr32,
value:canonical-unsigned-decimal-text, unit:text,
source:ResourceRefV1, destination:ResourceRefV1,
counterparty:PartyRefV1, recipient:AgentRefV1,
grant_id:bstr32, grant_version:uint,
policy_version:text, policy_digest:bstr32,
nonce:bstr32, expires_at:uint
```

No field is nullable. Floats, sentinel endpoints and FX are forbidden. `unit`
has one of exactly three ASCII forms: `iso4217:AAA:minor-N`, where `AAA` is
three uppercase letters and `N` is one decimal digit; `ucum:TOKEN`; or
`count:TOKEN`, where `TOKEN` is 1..48 printable non-space ASCII bytes. The
grant and action must carry the identical unit string; no verifier performs
conversion or normalization. Every `uint` is non-negative but must fit the
shared signed-CBOR range `0..2^63-1`. An operation which cannot identify exact
source and destination is unsupported and therefore `INDETERMINATE`.

1. B proposes random 32-byte `action_id` and `asa_id` values; the proposal is
   not authorization.
2. A creates the nonce and signs the complete action in `ChallengeCoreV1`. Its
   accepted-encodings list is exactly `[application/eat+cwt]`.
3. B verifies the challenge and action, obtains an ASA, and signs a presentation.
4. A verifies locally and calls `verify_and_consume` before any execution.

The relying party supplies `max_action_lifetime_s` as an unsigned integer in
`1..300`. The signed window `action.expires_at - challenge.issued_at` must not
exceed that local limit; otherwise the result is
`INDETERMINATE/ACTION_LIFETIME_EXCEEDS_LOCAL_POLICY`. The hosted Action
Authority applies the same 300-second maximum before it reserves capacity or
signs an ASA.

The presentation creation time is no earlier than the ASA issuance, authority
checkpoint and status time, no later than the relying party's trusted local
clock, and inside the challenge/action window. A signed refusal likewise may
not be future-dated. Bilateral acceptance records the trusted local consumption
time, not a participant-claimed presentation time.

The two boundaries have distinct stable reasons: a timestamp before signed
assurance material is `*_OUTSIDE_ASSURANCE` (or `*_OUTSIDE_CHALLENGE`), while a
participant timestamp after the verifier's trusted clock is
`*_OUTSIDE_LOCAL_CLOCK`.

A valid, unexpired cached ASA remains locally verifiable while the Action
Authority is unreachable; a local verifier cannot observe that outage. If B
cannot obtain a new ASA, there is no valid presentation and the result is
`INDETERMINATE`.

## 5. Grants, reservations and exact retry

`LimitGrantV1` is the customer root's automatic approval policy. It constrains
Swarrm as a delegated Action Authority; it never says the root personally
approved an individual action. Fixed-unit `ONE_SHOT`, `FLOW` and `STOCK` grants
use checked integer/decimal arithmetic and no FX.

The Action Authority keys idempotency by
`(authority_delegation_id, asa_id)`. An exact retry returns identical stored ASA
bytes; changed challenge or action bytes fail. It checks challenge signature,
actor, recipient, grant/version, unit, expiry and remaining capacity before
reserving and signing.

**Bounded v1 limitation — no offline per-ASA revocation proof.** A presentation
proves the current root delegation and exact active grant/head, then verifies
the Action Authority signature, exact binding and short ASA expiry. It does
not prove an individual ASA status in the root map. Superseding or revoking the
delegation or grant invalidates every presentation under it; `REVOKED_HELD` is
issuer-local, conservative capacity accounting and is not an offline
individual-revocation signal. A fresh, separately delegated Action-Authority
revocation snapshot would be a new profile, not an implied v1 capability.

```text
SIGNING_PENDING -> ABORTED_BEFORE_SIGNATURE | SIGNING_IN_FLIGHT
SIGNING_IN_FLIGHT -> ISSUED_HELD | UNCERTAIN_HELD
ISSUED_HELD -> COMMITTED | RELEASED_PROVEN_UNUSED | REVOKED_HELD | UNCERTAIN_HELD
REVOKED_HELD -> UNCERTAIN_HELD
UNCERTAIN_HELD -> RELEASED_ASSUMED_RISK
```

Only `SIGNING_PENDING` can restore capacity without proof. A
`RELEASED_PROVEN_UNUSED` transition needs a cryptographically verified,
operation-specific terminal proof and is otherwise unreachable in v1. An
uncertain reservation can be released only by an append-only, root-signed
assumed-risk event. Reuse then requires a new root-signed grant version which
explicitly carries the maximum unresolved exposure.

## 6. Verification, consumption and verdicts

The vector covers passport identity, live-key control, root chain,
template/admin/PoP issuance, fresh status, binding, grant, delegation, exact
action, ASA/reservation, challenge, transcript and replay. Contradictions are
`FAIL`; missing anchors, stale state, unsupported policy or unavailable durable
replay are `INDETERMINATE`.

An official favourable result requires a relying-party-controlled durable store
which atomically claims both `(tenant, organisation_root,
authority_delegation_id, asa_id)` and `(tenant, actor_organisation_root,
action_id)`:

- first exact insertion: `PASS`, `should_execute=true`;
- exact retry: identical acceptance, `PASS`, `should_execute=false`;
- changed bytes under the key: `FAIL`;
- a fresh ASA which reuses an already consumed action ID: `FAIL`;
- unavailable, non-shared or full store: `INDETERMINATE`;
- a crash after consumption burns the ASA and never authorizes a second action.

The beta replaces both favourable cases with
`INDETERMINATE/PASS_DISABLED_BETA` and `should_execute=false`. This release
cannot authorize execution.

Node/source/coverage/history and post-action evidence readiness are
`NOT_EVALUATED_V1`. Any policy requiring one of them cannot receive `PASS`.
Absence or silence is not a signed refusal; only a valid refusal envelope proves
refusal.

## 7. Carriage and bilateral binding

A2A v1 carriage uses exactly one inline `raw` Part with
`mediaType=application/eat+cwt`, exact profile/schema metadata and canonical
base64 in JSON. URL Parts, automatic fetch, multiple copies and favourable-copy
selection are forbidden.

The semantic transcript digest and exact challenge, presentation and ASA
envelope hashes are bound into a co-signed `interaction.message`, the acting
agent's `action.intent`, and any later certificate. A changed binding under the
same transcript idempotency key fails; an exact retry returns the identical
stored receipt. Its acceptance time is the relying party's first durable local
consumption time and is reused unchanged on every retry; participant timestamps
cannot select it.

The production acceptance protocol is explicitly split across the two agents.
After local verification and durable replay consumption, A writes an immutable
`PREPARED` co-signing journal row and signs the exact acceptance receipt body.
A sends that partial envelope, the acceptance core and the already verified
exchange material to B. B independently re-derives the core and bindings,
verifies A's signature using only A's public key, and co-signs the identical
DSSE payload with B's key. A verifies B's returned signature and atomically
commits the reserved row. Crashes leave the same immutable bytes recoverable;
they never cause a new receipt body or a second replay authorization. No
process needs, receives or loads both agents' private keys.

Producer APIs do not accept caller-supplied B28 digests or merely parseable
envelopes for those later bindings. The normative flow is
`verify_consume_and_prepare` → remote `countersign_prepared_acceptance` → local
`finalize_prepared_acceptance`; only finalization returns the opaque
consumed-exchange handle. `verify_consume_and_record` is a compatibility
wrapper for tests or deployments where both signing principals deliberately
co-reside; it is not the hosted custody protocol. `action.intent` and
certificate compilation accept only the finalized handle, verify the signing
party and exact action ID again, and derive all four bindings from it.
Interaction sender/receiver labels are deterministic digests of the signed
AgentRefs, never caller aliases. Before appending `action.intent`, the producer
requires the actor Birthtag and revision to match an existing E1 lineage and
derives the principal binding from the verified passport; callers cannot
redirect the transcript to another lineage or binding. An adverse or merely
prepared exchange returns no usable evidence handle.
