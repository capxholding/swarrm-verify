<!-- Apache-2.0 -->
# evd/ap2-mapping v1 — AP2 mandates ↔ Swarrm evidence (payments class)

Status: INFORMATIVE. A correspondence mapping, not a wire format and not a
conformance claim. The executable `ap2` binding named in
`SPEC/interaction-v1.md` §Bindings ships only after one production partner
selects the transport (the standing platform-table rule); this document is the
mapping that binding will implement, shipped now so the correspondence is
public before the partner exists. Nothing here changes the verifier, the B28
closure, or any wire format.

## 1. Pinned revision

Mapped against **`google-agentic-commerce/AP2`, branch `main`, commit
`e1ea56db72a6385bce3e5c1112b3a56ce60acb43`** (committed 2026-04-29, fetched
2026-09-07): `code/sdk/python/ap2/models/mandate.py`,
`…/models/payment_request.py`, `…/models/contact_picker.py`. AP2 represents
its mandates as W3C-Verifiable-Credential-style signed objects: the
CartMandate carries a merchant JWT; the PaymentMandate carries a user
authorization expressed as a verifiable presentation (e.g. sd-jwt-vc).

The same revision also carries a newer checkout-mandate chain
(`code/sdk/schemas/ap2/{checkout,open_checkout,open_payment,payment}_mandate.json`).
**v1 of this mapping covers the three named mandates only; the checkout chain
is explicitly NOT COVERED** and re-mapping at the next AP2 revision is a
standing duty — a stale mapping is a false claim.

## 2. The seam, stated plainly

**AP2 answers, before the fact: was this agent allowed to spend?** Mandates
are pre-action authorization artifacts — the user's intent, the merchant's
signed cart, the payment network's visibility object.

**Swarrm corroborates, after the fact: did it actually settle?** Signed,
append-only receipts record what the agent did; for the payments action class
the agent-claimed instruction reconciles against the authoritative account
statement read-back (`camt.053`), and corrections render as linked new facts
(`correction_of`) — history is never overwritten.

Different layers; no compliance gap in either direction:

- AP2 does not prove settlement, retention, or tamper-evident history.
- Swarrm does not issue, validate, enforce or execute AP2 mandates. Verifying
  an AP2 JWT or verifiable presentation is AP2-side work. A B28 `PASS` speaks
  only for Swarrm's own grant system (proof-bearing authority at consumption);
  it never means "an AP2 mandate authorized this," and no AP2 verification
  result ever becomes a Swarrm verdict.

Between the two sits one shared convenience: AP2 mandate objects and Swarrm
receipts use the same RFC 8785 canonicalization, so **a receipt can wrap an
AP2 mandate object without translation** (`SPEC/interaction-v1.md`
§Bindings). Wrapping commits tamper-evidently to the mandate *bytes*; it does
not interpret or validate the mandate.

## 3. Correspondence at the object level

| AP2 object | pre-action question it answers | Swarrm correspondence (its own layer) |
|---|---|---|
| `IntentMandate` | what did the user allow the agent to pursue | `mandate.assigned` receipt (`SPEC/mandate-v1.md`): who told this agent to do what, under which limits — customer-declared, with log order proving assigned-before-acted; `LimitGrantV1` (B28, `SPEC/handshake-v1.md` §5): the root's automatic approval policy |
| `CartMandate` | what exact transaction did the merchant offer and sign | `ActionCoreV1` (B28, `SPEC/handshake-v1.md` §4): operation, exact value/unit, source, destination, counterparty, bounded expiry — signed challenge-first, per action |
| `PaymentMandate` | what does the payment network get to see about the agentic transaction | B28 presentation + ASA at consumption (proof-bearing authority); after the fact, the payments action class: agent-claimed `pain.001` instruction reconciled against the authoritative `camt.053` read-back |

## 4. Field-level census

Every field of the three mandates (and every type they embed) appears in
exactly one row below with exactly one disposition:

- **CORRESPONDS** — a Swarrm object or claim answers the same question at
  Swarrm's layer. Correspondence, not equivalence; differences are noted.
- **WRAPPED-ONLY** — explicitly not covered semantically. The bytes ride
  tamper-evidently inside a wrapping receipt; Swarrm attaches no meaning to
  them, and whatever the field governs stays AP2-side.

### 4.1 `IntentMandate` (6 fields)

| field | disposition | correspondence / note |
|---|---|---|
| `user_cart_confirmation_required` | CORRESPONDS | when a confirmation happens it is recorded as a `human.*` oversight receipt, so the Evidence Report shows whether a human confirmed; *enforcing* the flag pre-action stays AP2-side |
| `natural_language_description` | CORRESPONDS | `mandate.assigned` mission capture (`principal_display`, `action_classes[]`, `source_channel`) records what the agent was told to do; customer-declared — Swarrm proves it was declared before the actions, not that it is true |
| `merchants` | CORRESPONDS | each executed action's exact `counterparty`/`destination` is signed in `ActionCoreV1`; whether every executed counterparty stayed inside the allowlist is an after-the-fact reconciliation over receipts — allowlist *enforcement* stays AP2-side |
| `skus` | WRAPPED-ONLY | no product-catalog semantics in Swarrm; constraint bytes ride wrapped and inside `parameter_digest` |
| `requires_refundability` | WRAPPED-ONLY | product policy, AP2-side; an actual refund, if it settles, appears as a linked new fact (`correction_of`) — never as rewritten history |
| `intent_expiry` | CORRESPONDS | `mandate.assigned.expires` (RFC 3339 UTC) records mission expiry; B28's per-action window is deliberately narrower (§5) |

### 4.2 `CartMandate` (2 fields) and `CartContents` (5 fields)

| field | disposition | correspondence / note |
|---|---|---|
| `CartMandate.contents` | — | composite; its five fields are the rows below |
| `CartMandate.merchant_authorization` (JWT: `iss`,`sub`,`aud`,`iat`,`exp`,`jti`,`cart_hash`) | WRAPPED-ONLY | Swarrm never validates merchant JWTs; the signed bytes ride wrapped. Note the `cart_hash` parallel in §5 |
| `CartContents.id` | WRAPPED-ONLY | linkage identity; a binding SHOULD bind the cart id into `parameter_digest` so the assured action names the cart it executes |
| `CartContents.user_cart_confirmation_required` | CORRESPONDS | as in 4.1 — occurrence recorded via `human.*` receipts; enforcement AP2-side |
| `CartContents.payment_request` | — | composite; the W3C tree is §4.3 |
| `CartContents.cart_expiry` | CORRESPONDS | B28 `expires_at` bounds the assured action; window semantics differ (§5) |
| `CartContents.merchant_name` | CORRESPONDS | `ActionCoreV1.counterparty:PartyRefV1` is the exact signed party; a display name is not a party reference — a binding maps, never equates |

### 4.3 The embedded W3C `PaymentRequest` tree

| field | disposition | correspondence / note |
|---|---|---|
| `PaymentRequest.method_data[]` (`PaymentMethodData.supported_methods`, `.data`) | WRAPPED-ONLY | payment-method negotiation is network-side |
| `PaymentRequest.details` | — | composite (`PaymentDetailsInit`, below) |
| `PaymentRequest.options` (`PaymentOptions.request_payer_name/.request_payer_email/.request_payer_phone/.request_shipping/.shipping_type`) | WRAPPED-ONLY | PII-collection prompts; no Swarrm semantic |
| `PaymentRequest.shipping_address` (`ContactAddress`: `city`,`country`,`dependent_locality`,`organization`,`phone_number`,`postal_code`,`recipient`,`region`,`sorting_code`,`address_line[]` — all 10) | WRAPPED-ONLY | postal PII; rides only as wrapped bytes |
| `PaymentDetailsInit.id` | WRAPPED-ONLY | linkage identity (see `payment_details_id`, §4.4) |
| `PaymentDetailsInit.display_items[]` | WRAPPED-ONLY | line-item display; the settled total, not the display list, is what reconciles |
| `PaymentDetailsInit.shipping_options[]` (`PaymentShippingOption.id/.label/.amount/.selected`) | WRAPPED-ONLY | fulfilment logistics |
| `PaymentDetailsInit.modifiers[]` (`PaymentDetailsModifier.supported_methods/.total/.additional_display_items/.data`) | WRAPPED-ONLY | per-method price modifiers, network-side |
| `PaymentDetailsInit.total` | CORRESPONDS | `ActionCoreV1.value` + `unit` — canonical unsigned decimal text, `iso4217:AAA:minor-N`; float seam in §5 |
| `PaymentItem.label` | WRAPPED-ONLY | display text |
| `PaymentItem.amount` | CORRESPONDS | via `PaymentCurrencyAmount` below |
| `PaymentItem.pending` | CORRESPONDS | a pending amount becomes final only in the authoritative `camt.053` read-back; the change renders as a linked new fact, never an edit |
| `PaymentItem.refund_period` | WRAPPED-ONLY | policy; an executed refund settles as `correction_of` |
| `PaymentCurrencyAmount.currency` | CORRESPONDS | `unit` = `iso4217:AAA:minor-N` carries the ISO 4217 code with explicit minor units |
| `PaymentCurrencyAmount.value` | CORRESPONDS | **float in AP2, forbidden in B28** — the binding seam in §5 |
| `PaymentResponse.request_id` | WRAPPED-ONLY | linkage to the originating request |
| `PaymentResponse.method_name` | WRAPPED-ONLY | chosen method label |
| `PaymentResponse.details` | WRAPPED-ONLY | method-specific (tokenized) payload; never interpreted |
| `PaymentResponse.shipping_address` / `.shipping_option` | WRAPPED-ONLY | as above |
| `PaymentResponse.payer_name` / `.payer_email` / `.payer_phone` | WRAPPED-ONLY | payer PII; no Swarrm semantic |

### 4.4 `PaymentMandate` (2 fields) and `PaymentMandateContents` (6 fields)

| field | disposition | correspondence / note |
|---|---|---|
| `PaymentMandate.payment_mandate_contents` | — | composite; rows below |
| `PaymentMandate.user_authorization` (VP / sd-jwt-vc; kb-jwt with `aud`, `nonce`, `sd_hash`, `transaction_data` = hashes over CartMandate + PaymentMandateContents) | WRAPPED-ONLY | validating the VC chain stays AP2/issuer-side. The parallel question — "was this authorized under Swarrm's own system?" — is answered by the B28 challenge → ASA → presentation chain with grant lineage; parallel evidence, never a substitute (§5) |
| `PaymentMandateContents.payment_mandate_id` | WRAPPED-ONLY | linkage identity; a binding SHOULD bind it into `parameter_digest` |
| `PaymentMandateContents.payment_details_id` | WRAPPED-ONLY | linkage to `PaymentDetailsInit.id` |
| `PaymentMandateContents.payment_details_total` | CORRESPONDS | `ActionCoreV1.value` + `unit` (float seam, §5) |
| `PaymentMandateContents.payment_response` | — | composite (§4.3 `PaymentResponse` rows) |
| `PaymentMandateContents.merchant_agent` | CORRESPONDS | `ActionCoreV1.counterparty:PartyRefV1` / `recipient:AgentRefV1` — exact signed identities |
| `PaymentMandateContents.timestamp` | CORRESPONDS | participant-claimed creation time; B28 records the verifier's **trusted local consumption time**, never a participant-claimed presentation time (§5) |

Module-level transport labels (`CART_MANDATE_DATA_KEY`,
`INTENT_MANDATE_DATA_KEY`, `PAYMENT_MANDATE_DATA_KEY`,
`CONTACT_ADDRESS_DATA_KEY`) are A2A extension payload keys — a binding-time
transport concern with no field semantics; recorded here so the census drops
nothing.

## 5. Seams a binding must resolve (recorded now, not discovered later)

1. **Float vs decimal.** `PaymentCurrencyAmount.value` is a float; B28
   forbids floats and requires canonical unsigned decimal text with explicit
   minor units. A binding must define lossless decimal conversion (refusing
   values that do not convert exactly) — it must never round.
2. **Time semantics.** AP2 mandate timestamps are participant-claimed. B28
   bilateral acceptance records the relying party's trusted local consumption
   time. A binding maps the two as distinct facts; it never presents one as
   the other.
3. **Expiry windows.** `intent_expiry` / `cart_expiry` are free-range ISO
   8601; B28's signed action window is bounded (`expires_at − issued_at` ≤
   the relying party's `max_action_lifetime_s`, at most 300 s). A cart that
   outlives the action window needs a fresh B28 ceremony per assured action.
4. **Hash binding.** AP2 binds `cart_hash` / `transaction_data` hashes over
   canonical JSON; B28 derives every semantic digest from the inner canonical
   core bytes, so an envelope cannot declare its own favourable digest. Same
   design instinct, different hash domains — a binding maps them explicitly
   and never equates one for the other.

## 6. Claim discipline

This document states readiness and correspondence only. It makes **no** claim
that Swarrm conforms to AP2, that wrapping a mandate constitutes AP2
participation, that a B28 `PASS` implies any AP2 mandate was valid, or that
any AP2 verification outcome is a Swarrm verdict. B28's signed
`non_assertion` text and the `PASS_NOT_ENABLED` containment are unchanged by
this mapping.

CHECK census: IntentMandate 6/6 · CartMandate 2/2 · CartContents 5/5 ·
PaymentRequest 4/4 · PaymentDetailsInit 5/5 · PaymentItem 4/4 ·
PaymentCurrencyAmount 2/2 · PaymentShippingOption 4/4 · PaymentOptions 5/5 ·
PaymentMethodData 2/2 · PaymentDetailsModifier 4/4 · PaymentResponse 8/8 ·
ContactAddress 10/10 · PaymentMandate 2/2 · PaymentMandateContents 6/6 — every
field of the pinned models appears above with a disposition; the checkout-
mandate chain is the one named exclusion (§1). Nothing is silently dropped.
