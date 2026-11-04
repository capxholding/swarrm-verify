<!-- Apache-2.0 — this file ships with the public verifier repo. -->

# SPEC: m365-action-gateway-v1 — Microsoft 365 Copilot and Copilot Studio actions

Status: NORMATIVE for Swarrm 1.4 and later. Implemented by `proxy/m365.py`;
pinned by `tests/test_m365_gateway.py`, which cites these sections.

## 1. What this door captures, and what it cannot

The model turn of a Microsoft 365 Copilot or Copilot Studio agent runs inside
Microsoft. It is not reachable by a proxy the customer controls, and this
profile does not pretend otherwise. **This door captures actions**: the
connector or tool calls an agent makes to the customer's own systems. An
action is recorded as an ordinary `tool.call` receipt — the same receipt the
MCP wrapper writes — so verifiers, reports and packs need no new vocabulary.

It does not capture prompts, completions, grounding, or the agent's reasoning.
It is not Purview audit, and it is not equivalent to a camera on the model.
A report that carries these receipts proves which actions were invoked, by
which application, with which arguments and which results — and nothing about
the conversation that led there.

## 2. The route

`POST {base}/m365/actions/{name}`

This section describes `capture-only`. Section 8 adds mandatory permission and
pre-forward evidence admission for the local count profile.

- `{name}` MUST match `^[a-z][a-z0-9_.-]{0,63}$`. It is a path segment, an
  OpenAPI `operationId`, and the receipt's `tool_name`, so it is an identifier.
- The request body MUST be a JSON object of at most 262,144 bytes. Anything
  else is refused before any upstream contact (`400` or `413`). Enforce the
  bound while reading the stream; stop at the first over-limit chunk without
  consuming its tail, regardless of the declared `Content-Length`. Arguments
  must use duplicate-free UTF-8 JSON within the shared commitment profile,
  including the idempotency envelope depth; out-of-profile values return `400`.
- `Authorization: Bearer <token>` MUST carry an Entra ID access token that
  satisfies section 3. Absence or refusal is `401` with a closed reason code;
  the token is never echoed and no receipt is written.
- On acceptance the gateway forwards the body to the upstream configured for
  `{name}` through the exact-authority outbound client (no proxy environment,
  no redirects, no DNS rebinding), then records the exchange, then returns
  the upstream's JSON body and status with an `x-swarrm-receipt` header
  naming the receipt's idempotency key.
- The caller's bearer token MUST NOT be forwarded upstream. The upstream is
  the customer's own system; it authenticates the gateway, not the agent.
- An upstream transport failure returns `502` and records a receipt with
  `is_error: true` and no result. An upstream HTTP error status is passed
  through and likewise recorded as an error. A result is never fabricated.
- Capture is fail-open. If recording the exchange fails after the upstream
  has answered, the gateway still returns the upstream's status and body (or
  `502` with no `receipt` member when there was no upstream answer), records
  an `evd.gap.mcp` receipt with reason `evidence_emit_failed`, and replaces
  `x-swarrm-receipt` with `x-swarrm-evidence-gap: evidence_emit_failed`. It
  never answers `500` for an action that has already run, because a caller's
  retry would repeat it.

## 3. Token verification (fail closed, no network in the request path)

Verification MUST reject unless every rule holds, in this order:

1. Exactly three base64url segments; header and claims decode to duplicate-free
   UTF-8 JSON objects under the shared bounded JSON profile. Parser/depth
   refusals return the closed `malformed` reason before signature processing.
2. `alg` is exactly `RS256`. `none`, HMAC and every other algorithm are
   refused BEFORE key lookup, so a header cannot select a weaker path.
3. `kid` names a key in the PINNED JWKS, and that key is RSA with `alg`
   absent or `RS256`.
4. The RSASSA-PKCS1-v1_5 SHA-256 signature verifies over `header.payload`.
5. `iss` equals the configured issuer exactly
   (`https://login.microsoftonline.com/{tenant}/v2.0` for v2 tokens).
6. `aud` equals the configured audience, or is a list containing it.
7. `tid` equals the configured tenant.
8. `exp` and `nbf` are JSON integers, excluding booleans; `now ≤ exp + skew`
   and `now + skew ≥ nbf`, with skew fixed at 60 seconds. A different skew
   configuration is refused before serving.
9. A subject (`oid`, else `sub`) and an application (`azp`, else `appid`)
   are present as strings.

`kid` MUST be a nonempty string; malformed key identities produce the closed
`kid` refusal before key lookup. Usable RS256 signing-key identifiers MUST be
unique. Invalid RSA material or a pin without a usable signing key refuses
startup. Unusable algorithms and non-signing keys cannot satisfy a token.
When `key_ops` is present, it MUST be a list of unique strings containing
`verify`; a key with any other shape or without that operation is unusable.

After detaching the verifier and registry, serving MUST bind the prepared
verifier's tenant and audience to the detached gateway configuration before
accepting requests. Preparation detaches the pin and
action registry from caller-owned mutable objects and serializes both bounded
manifests before startup. Later changes to those input objects MUST NOT change
served routes, manifests, receipt identity or token admission; a configuration
or key update requires a new prepared gateway.

The JWKS is pinned in a file the operator controls. It is NOT fetched in the
request path: a request path that fetches signing keys is one that can be
redirected. Microsoft rotates signing keys on a cadence; section 4 is the
operator's duty in consequence.

## 4. Identity: what the receipt says, and what it means

The receipt context carries `actor`:

| field         | claim            | meaning                                             |
|---------------|------------------|-----------------------------------------------------|
| `source`      | —                | fixed `entra-id-access-token`                       |
| `issuer`      | `iss`            | the tenant's Entra issuer, exactly                  |
| `tenant`      | `tid`            | the issuing tenant                                  |
| `subject`     | `oid`, else `sub`| the principal the token was issued for              |
| `application` | `azp`, else `appid` | the client application presenting the token     |
| `scopes`      | `scp`            | space-separated delegated scopes, split             |
| `roles`       | `roles`          | application roles, strings only                     |

The receipt's `agent_id` is the `application`.

**What this proves.** The caller presented a token for this gateway's
audience, signed by a key the operator pinned for that tenant, naming that
application and subject. **What it does not prove.** That a human authorised
the action, that the subject is who the tenant directory says, or anything
about the agent's instructions. These fields are what the ISSUER asserted;
the gateway verified the assertion's signature and binding, not the world.
In Swarrm's vocabulary the identity is SOURCED from the issuer, never
VERIFIED by Swarrm, and reports MUST NOT render it as more.

**Key rotation duty.** The operator MUST refresh the pinned JWKS from the
tenant's discovery document on Microsoft's rotation cadence, through the
guarded outbound client, as a deliberate step. A stale pin fails closed: every
token signed by an unpinned key is refused with reason `kid`.

## 5. Commitments (which bytes are canonicalised)

| commitment    | domain                | bytes                                              |
|---------------|-----------------------|----------------------------------------------------|
| `tool.args`   | `evd/v1/tool.args`    | the request body, as canonical JSON (`core.canonical`) |
| `tool.result` | `evd/v1/tool.result`  | the upstream response body as canonical JSON; `{}` when there is none |

An upstream body outside the shared JSON object/commitment profile is recorded
as `{"_raw": <first 4096 UTF-8 characters, decoding errors replaced>}` and
committed as that object, retaining the upstream status. Nonce
custody is the MCP wrapper's (`mcpwrap.proxy.EvidencePlane`): this profile
adds no second custody path.

The idempotency key is `sha256(canonical({action, subject, body, nonce}))`
with a fresh 8-byte nonce per capture-only request (32 bytes under section 8), so a replayed body under a different
identity, or the same identity twice, yields distinct receipts rather than a
silent merge.

## 6. Manifests

Both documents are generated from the one action registry the gateway
serves, so they cannot drift from the routes:

- `GET /m365/connector/swagger.json` — **Swagger 2.0**, because Power
  Platform custom connectors (Copilot Studio) import 2.0 and not 3.x.
- `GET /m365/plugin/openapi.json` — **OpenAPI 3.0.3**, for Microsoft 365
  Copilot API plugins.
- `swarrm m365 manifests` writes both plus an `apiProperties.json` skeleton
  declaring Entra OAuth2 with the configured audience.

Each exposes one `POST /m365/actions/{name}` per registered action, with the
action's `body_schema` as the request schema and `{audience}/.default` as the
single scope. Producing the manifests requires no JWKS pin, so a client can be
handed its import files before keys are exchanged.

## 7. Onboarding, in order

1. Register the gateway as an application in the customer's Entra tenant;
   record its audience (Application ID URI or client id).
2. List the actions the agent may take and their upstream URLs.
3. `swarrm m365 manifests --tenant … --audience … --action … -o DIR`; import
   `apiDefinition.swagger.json` + `apiProperties.json` as a Copilot Studio
   custom connector, or `openapi.json` as an M365 Copilot API plugin.
4. Pin the tenant's JWKS; start the gateway with the same registry.
5. The first action call produces the first receipt.

## 8. Local count permission profile (1.5)

`M365GatewayConfig.permission_profile` selects `capture-only` (the existing
behavior above) or `m365-local-count/v1`. The latter requires a `CountPolicy`
and explicit `CountBinding` entries for each application/action. Unknown modes,
missing policy, duplicate bindings and foreign evidence tenants refuse at the
actual application factory. Manifests and action responses name the selected
profile. `swarrm m365 manifests --permission-profile …` declares the intended
runtime profile; generating import files does not issue permission.

A binding names the application's existing evidence Birthtag and revision and
an imported, customer-root-signed `LimitGrantV1`. The registered agent, mandate,
configuration, root delegation, grant version and grant head must remain active
under the existing checkpoint/freshness policy. The grant uses operation
`m365.action`, unit `count:m365-actions`, kind `FLOW` or `ONE_SHOT`, and the
customer's own organization as recipient. Each admitted invocation consumes
one unit. This permission counts calls; it does not cap payment values or
establish a financial mandate.

The grant's `action_scope_digest` is SHA-256 over
`swarrm/m365-local-count/v1\0` followed by canonical JSON containing exactly:
`profile`, evidence `tenant`, `entra_tenant`, `issuer`, `audience`,
`application`, `action`, exact `upstream`, `body_schema`, hexadecimal `birthtag`
and integer `revision`. `profile` is `m365-local-count/v1`. The schema is part
of the route binding; this profile grants that route's admitted JSON-object
calls, not additional business predicates inferred from schema metadata.

Admission debits the existing authority store atomically. The separate local
consumption ledger shares the unchanged population bound and grant accounting;
it never creates an ASA or counterparty exchange. An exact consumed request
cannot authorize a second send. Conflicting request bytes refuse. A crash,
failed evidence write or uncertain upstream result does not refund capacity.
Only the customer's existing root-governed grant lifecycle can change limits.
The versioned store migrates exact legacy layouts; missing consumption history,
unknown versions and schema rollback refuse rather than recreating a ledger.

Before forwarding, the gateway retains `action.intent` and `action.submitted`
through the existing evidence writer and encrypted nonce custody, then
revalidates permission. Intent uses class `m365.action`, the count grant ID and
version, registered principal-binding ID and policy version
`m365-local-count/v1`. These are local-profile identifiers, not a conversion to
the monetary grant profile in authority-v1 §3.3. Inputs, identity/scope evidence
and the exact prepared logical request remain commitments. Submission records
the gateway handoff attempt; it does not prove delivery or business completion.
The immutable outbound body must match preparation. Missing permission returns
`403`; unavailable permission/evidence custody returns `503` before forwarding.

Governed calls use a fresh 32-byte nonce in the existing action-ID derivation.
`x-swarrm-action-id` carries the resulting opaque ID to the upstream and caller;
the Entra bearer token is never forwarded. The correlated `tool.call` uses that
same universal action ID. Interrupted forwarding retains an observation gap and
propagates the original interruption. Post-action capture failure retains the
existing explicit fail-open gap response, never a fabricated receipt or retry.

This local permission profile does not enable Counterparty Assurance `PASS`.
Real-tenant compatibility remains distinct from emulator verification.
