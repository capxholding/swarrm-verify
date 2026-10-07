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

- `{name}` MUST match `^[a-z][a-z0-9_.-]{0,63}$`. It is a path segment, an
  OpenAPI `operationId`, and the receipt's `tool_name`, so it is an identifier.
- The request body MUST be a JSON object of at most 262,144 bytes. Anything
  else is refused before any upstream contact (`400` or `413`).
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

1. Exactly three base64url segments; header and claims decode to JSON objects.
2. `alg` is exactly `RS256`. `none`, HMAC and every other algorithm are
   refused BEFORE key lookup, so a header cannot select a weaker path.
3. `kid` names a key in the PINNED JWKS, and that key is RSA with `alg`
   absent or `RS256`.
4. The RSASSA-PKCS1-v1_5 SHA-256 signature verifies over `header.payload`.
5. `iss` equals the configured issuer exactly
   (`https://login.microsoftonline.com/{tenant}/v2.0` for v2 tokens).
6. `aud` equals the configured audience, or is a list containing it.
7. `tid` equals the configured tenant.
8. `exp` and `nbf` are integers; `now ≤ exp + skew` and `now + skew ≥ nbf`,
   with skew fixed at 60 seconds.
9. A subject (`oid`, else `sub`) and an application (`azp`, else `appid`)
   are present as strings.

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

An upstream body that is not a JSON object is recorded as
`{"_raw": <first 4096 characters>}` and committed as that object. Nonce
custody is the MCP wrapper's (`mcpwrap.proxy.EvidencePlane`): this profile
adds no second custody path.

The idempotency key is `sha256(canonical({action, subject, body, nonce}))`
with a fresh 8-byte nonce per request, so a replayed body under a different
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
