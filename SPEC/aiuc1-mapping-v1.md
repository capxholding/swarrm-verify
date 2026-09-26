<!-- Apache-2.0 -->
# AIUC-1 evidence mapping v1 — revision-pinned (NORMATIVE for the claim it licenses)

This document is the artifact that makes **"satisfies AIUC-1 evidence
requirements (as mapped, revision 2026-07-15)"** a checkable sentence
(see CHECK below). It licenses exactly that sentence and nothing stronger.
Swarrm satisfies evidence requirements of the standard; it never replaces,
grades, or administers the standard. Certification is AIUC's act, an AIUC-1
score is AIUC's number, and no Swarrm surface computes, stores, or renders
any such score: the trust/rating field family — `aggregate_rating`,
`aggregate_score`, `rating`, `reputation_score`, `trust_index`,
`trust_rating`, `trust_score` — is CI-banned in
`ci/architecture_policy.json` `banned_schema_fields`. The `risk_index` /
`risk_rating` / `risk_score` additions are queued on
`plan/v2-partner-surfaces` (`382e8085`) and have NOT reached this tree, so
they are named here as coming, never as already enforced (see the CHECK).
The insurer dashboard remains behind a written pull request from the
insurer — this mapping is a document against a public standard, not insurer
tooling. Market context, stated as context and not as a claim: ElevenLabs'
$50M Lloyd's-backed policy was priced on its AIUC-1 score (February 2026);
what an insured party needs from us is producible evidence, which is what
the rows below name.

## §0 Revision pin

Written against **AIUC-1 as served at `aiuc-1.com`, release of
2026-07-15**, retrieved and measured 2026-09-07. The standard updates
quarterly (January 15, April 15, July 15, October 15; releases to date:
2025-07-22 launch, 2025-10-01, 2026-01-15, 2026-04-15, 2026-07-15; next
scheduled 2026-10-15). The 2026-07-15 release changed 8 requirements and
41 controls, adding the coding-agent requirements (A008, B010 among them)
and retiring/renumbering others.

**Measured shape at the pin — derived from the site's own embedded
per-control dataset (`application: Core | Supplemental`), which every
requirement page ships in full; two independently retrieved page snapshots
carried byte-identical datasets:**

- 53 requirement records; **51 active** (43 badged Mandatory, 8 badged
  Optional); E007 and E014 are retired (merged into E004 and E017 at the
  Q1-2026 update per the changelog).
- 144 control records; **142 active**: **82 Core (mandatory)** and 60
  Supplemental (optional); E007.1 and E014.1 are retired placeholders.
- Vocabulary: the site renders `Core` as **"Should include"** and
  `Supplemental` as **"May include"** on each requirement page; the words
  "mandatory"/"optional" appear only on requirement badges. A Core control
  under an Optional-badged requirement binds only where the organization
  opts into that requirement — 13 of the 82 are conditional in that sense
  and are marked in the table.
- **Supersedes the launch-era shape** "51 requirements / 130 controls /
  65 mandatory / 65 optional" still quoted by secondary sources and by
  this build item's own planning sentence: at the 2026-07-15 text the
  mandatory (Core) count is **82**, not 65. The mapping CHECK is read
  against the pinned revision's Core set.

A mismatch found later between this pin and the standard's text of
2026-07-15 is a defect in THIS document and must be corrected here, never
argued around.

## §1 Classification rule (mechanical, so the table is checkable)

Every active Core control appears in §2 **exactly once**, in exactly one
class:

- **SATISFIED** — a named Swarrm artifact is, or directly carries, the
  operational-record evidence the control demands. Each such row names the
  artifact and its SPEC. Where the control also demands an organizational
  component (a runbook, a policy), the row says which part stays the
  operator's.
- **out of scope** — Swarrm neither holds nor claims the control, for one
  of three stated sub-reasons: **org** (policies, contracts, third-party
  assessor reports, the operator's product UI), **infra** (the operator's
  platform/IAM/network security configuration), or **prevention** (runtime
  guardrails, filters, and limiters — by position: Swarrm is deliberately
  the flight recorder, not the cage, so prevention-layer substance cannot
  be ours). Where a Swarrm receipt family evidences the operator's control
  *operating*, the row records it as a **carrier** note without claiming
  satisfaction.
- **GAP** — inside Swarrm's evidentiary remit with no artifact yet. At
  this pin the honest count is **zero**; the nearest misses are recorded
  in §3 so the next recheck re-examines them rather than rediscovering
  them.

Totals at this pin: **82 rows — 2 SATISFIED · 80 out of scope · 0 GAP**.
The satisfied set is deliberately small, and its size is the point: a row
earns SATISFIED only where a Swarrm artifact **is** the record the control
asks for, verified field by field against the SPEC that defines it. Both
survivors are the log itself — the tool-call record (D003.3) and the
logging implementation behind it (E015.1). Everything else the operator
owns, either because it is organizational or because it is a preventive
control, and Swarrm is deliberately the flight recorder rather than the
cage. Where a Swarrm receipt family makes the operator's own control
disputable after the fact, the row says so as a **carrier** note and
claims nothing further.

**Correction history, kept because a compliance mapping that quietly
restates itself is worthless.** The first draft of this document claimed
**9** satisfied rows. An adversarial review on 2026-09-07 — one reviewer
per row, each instructed to refute — broke **seven** of them against the
tree, and every refutation was then confirmed by hand:

- **Wrong artifact named.** D003.3 cited `SPEC/action-fact-v1.md` for tool
  identity and parameters; that spec carries neither. The real tool-call
  log is the `tool.call` receipt of `evd/receipt/v1`, whose fields are
  listed in SPEC/context-v1.md. The row now cites it correctly. D003.1 and
  B006.1 cited `SPEC/handshake-v1.md` and `SPEC/mandate-v1.md`, in which
  the string "tool" does not occur at all.
- **Completeness asserted where the SPECs refuse it.** "Every action is a
  receipt" contradicts SPEC/receipt-v1.md §1 ("does not independently
  prove … that capture was complete") and the E1 row of SPEC/log-v1.md
  ("no claim that every relevant action was captured/exported").
- **Prevention claimed where only recording is delivered.** `node/egress.py`
  is an allow-list over **Swarrm's own** Node's outbound traffic, not the
  agent's service access, so it cannot answer B006.1 or D003.1.
- **Wrong verdict vocabulary.** "Out-of-authority attempts derive
  `CONFLICT`/`INVALID`" is false: authority resolves
  `VERIFIED`/`NOT_VERIFIED`/`CONFLICT` (SPEC/authority-v1.md), and an
  out-of-authority action is `NOT_VERIFIED`.
- **Inconsistent treatment of one receipt family.** `guardrail.blocked`
  was a carrier note for A006.1, C003.1 and E010.2 but a satisfying
  artifact for B002.2 and C004.2. It is now a carrier everywhere.

The lesson is recorded rather than buried: an overclaiming mapping fails
at the first assessor who follows a citation, and it would take the
product's honesty with it.

## §2 The mapping — all 82 active Core controls, each exactly once

### Pillar A — Data & Privacy

| Control | Title | Class | Basis / note |
|---|---|---|---|
| A001.1 | Documentation: Policy for input data ownership, usage and retention | out of scope | org |
| A001.2 | Config: Data retention implementation | out of scope | org · carrier: `agent.config_changed` receipts commit retention/deletion config blobs |
| A002.1 | Documentation: Output usage and ownership policy | out of scope | org |
| A003.1 | Config: Data access scoping | out of scope | prevention · carrier: `data.read` receipts commit the query and result-set hash, counts banded |
| A004.1 | Documentation: User guidance on confidential information | out of scope | org |
| A005.1 | Documentation: Consent for combined data usage | out of scope | org |
| A005.2 | Config: Customer data isolation controls | out of scope | infra · note: Swarrm's own evidence plane is tenant-isolated (per-tenant trees, SPEC/log-v1.md) — but this control names the AI system's isolation, which is the operator's |
| A006.1 | Config: PII detection and filtering | out of scope | prevention · carrier: `guardrail.blocked` receipts evidence the filter operating |
| A007.1 | Documentation: Model provider IP infringement protections | out of scope | org |
| A008.1 | Config: Secrets detection in user inputs | out of scope | prevention |
| A008.2 | Config: Secrets handling in generated code | out of scope | prevention |
| A008.3 | Config: Secure storage of user-provided credentials | out of scope | infra |

### Pillar B — Security

| Control | Title | Class | Basis / note |
|---|---|---|---|
| B001.1 | Report: adversarial testing results | out of scope | org · carrier: SCITT registration (SPEC/scitt-action-profile-v1.md) anchors the report digest, making the report's existence-at-time disputable |
| B002.1 | Config: Adversarial input detection and alerting | out of scope | prevention *(binds on opt-in: requirement B002 is Optional)* |
| B002.2 | Logs: Adversarial incident and response | out of scope | org · carrier: where the operator emits `guardrail.blocked` receipts they become tamper-evident and disputable (SPEC/context-v1.md), but nothing in the family encodes *adversarial* — the same family carries A006.1, C003.1 and E010.2 here — and the response record the control asks for is the operator's *(binds on opt-in: requirement B002 is Optional)* |
| B002.3 | Documentation: Updates to detection config | out of scope | org · carrier: `agent.config_changed` receipts are a tamper-evident record of each detection-config change *(binds on opt-in: requirement B002 is Optional)* |
| B003.1 | Documentation: Technical information disclosure guidelines | out of scope | org *(binds on opt-in: requirement B003 is Optional)* |
| B004.1 | Config: Anomalous usage detection | out of scope | infra |
| B004.2 | Config: Rate limits | out of scope | infra |
| B004.3 | Report: External pentest of AI endpoints | out of scope | org |
| B004.4 | Documentation: Vulnerability remediation | out of scope | org |
| B005.1 | Config: Input filtering | out of scope | prevention *(binds on opt-in: requirement B005 is Optional)* |
| B006.1 | Config: Agent service access restrictions | out of scope | infra · note: `node/egress.py` is an allow-list over **Swarrm's own** evidence Node's outbound traffic (SPEC/node-v1.md §5–§6), not over the agent's service access — a neighbouring concern, not this control · carrier: `tool.call` receipts record which MCP server each call reached |
| B006.2 | Config: Agent security monitoring and alerting | out of scope | prevention · carrier: captured agent calls are receipts (SPEC/receipt-v1.md), so monitoring built on them is disputable; the alerting and dashboards the control asks for are the operator's. No completeness is claimed — SPEC/receipt-v1.md §1 refuses it explicitly |
| B007.1 | Config: User access controls | out of scope | infra |
| B007.2 | Documentation: Access reviews | out of scope | org |
| B008.1 | Config: API and agentic interface authentication | out of scope | infra |
| B008.2 | Config: API and agentic interface transport security | out of scope | infra |
| B009.1 | Config: Output volume limits | out of scope | prevention |
| B010.1 | Config: Secure defaults for common vulnerability classes | out of scope | prevention |
| B010.2 | Config: Secure defaults for authentication and authorization | out of scope | prevention |
| B010.3 | Config: Safe dependency specification in generated code | out of scope | prevention |

### Pillar C — Safety

| Control | Title | Class | Basis / note |
|---|---|---|---|
| C001.1 | Documentation: AI risk taxonomy | out of scope | org |
| C001.2 | Documentation: Risk taxonomy reviews | out of scope | org |
| C002.1 | Documentation: Pre-deployment test and approval records | out of scope | org · carrier: `human.approve` + `agent.deployed` receipts make the deployment gate disputable (approver identity and config blobs committed) |
| C003.1 | Config: Harmful output filtering | out of scope | prevention · carrier: `guardrail.blocked` |
| C003.2 | Config: Guardrails for high-risk advice | out of scope | prevention |
| C004.1 | Config: out-of-scope guardrails | out of scope | prevention |
| C004.2 | Logs: Out-of-scope attempts | out of scope | prevention · carrier: `guardrail.blocked` (guardrail_name, rule_kind, action_taken plaintext; trigger content committed) — the dial PERMITS these fields, it does not require them, so carriage is the operator's choice; same treatment as A006.1/C003.1/E010.2 *(binds on opt-in: requirement C007/C008 optional-tier siblings)* |
| C005.1 | Config: Risk detection and response | out of scope | prevention |
| C006.1 | Config: Output sanitization | out of scope | prevention |
| C006.2 | Demonstration: Content handling and labelling for untrusted content | out of scope | org |
| C007.1 | Documentation: Definition of high-risk output criteria | out of scope | org *(binds on opt-in: requirement C007 is Optional)* |
| C007.2 | Config: High-risk detection mechanisms | out of scope | prevention *(binds on opt-in: requirement C007 is Optional)* |
| C008.1 | Logs: AI risk monitoring | out of scope | org · carrier: the append-only receipt log (SPEC/log-v1.md) makes whatever the operator monitors tamper-evident; per-scope publication health is the anchor worker's local job state, has no SPEC and reaches no certificate, so it is NOT evidence for an assessor *(binds on opt-in: requirement C008 is Optional)* |
| C009.1 | Demonstration: User intervention mechanisms | out of scope | org *(binds on opt-in: requirement C009 is Optional)* |
| C010.1 | Report: Harmful output testing | out of scope | org |
| C011.1 | Report: Out-of-scope output testing | out of scope | org |
| C012.1 | Third-party evaluation report assessing customer-defined risk | out of scope | org |

### Pillar D — Reliability

| Control | Title | Class | Basis / note |
|---|---|---|---|
| D001.1 | Config: Groundedness filter | out of scope | prevention |
| D001.2 | Demonstration: User-facing citations & source attributions | out of scope | org |
| D002.1 | Report: Hallucination testing results | out of scope | org |
| D003.1 | Config: Tool authorization & validation | out of scope | prevention · carrier: authority and mandate receipts (SPEC/authority-v1.md, SPEC/mandate-v1.md) make an authorization decision disputable AFTER the fact. The `swarrm-b28/v1` handshake does not authorize here: its favourable PASS is deliberately disabled in the shipping profile (A_BUILD T7), and no tool allow-list is ours |
| D003.2 | Config: Rate limits for tools | out of scope | prevention |
| **D003.3** | Config: Tool call log | **SATISFIED** | the core artifact: `tool.call` receipts (`evd/receipt/v1`, SPEC/receipt-v1.md §`action_type`) carry tool_name, server_name, duration_ms, is_error, arg_keys[] and bounded arg/result projections per SPEC/context-v1.md, emitted by the MCP door (mcpwrap/proxy.py) on each completed `tools/call`; append-only with inclusion proofs and RFC 3161 anchoring (SPEC/log-v1.md), portable via SPEC/certificate-v1.md and SPEC/bundle-v1.md. Parameters are committed as bounded projections and top-level `arg_keys`, not raw values — deliberate, and the honest limit of this row |
| D004.1 | Report: Tool call testing | out of scope | org |

### Pillar E — Accountability

| Control | Title | Class | Basis / note |
|---|---|---|---|
| E001.1 | Documentation: AI failure plan for security breaches | out of scope | org |
| E002.1 | Documentation: AI failure plan for harmful outputs | out of scope | org |
| E003.1 | Documentation: AI failure plan for hallucinations | out of scope | org |
| E004.1 | Documentation: Change approval policy and records | out of scope | org · carrier: `human.approve` + `agent.config_changed` receipts are the sign-off record; the policy itself is the operator's |
| E005.1 | Documentation: Data storage security practices | out of scope | org |
| E006.1 | Documentation: Vendor due diligence | out of scope | org |
| E008.1 | Documentation: Internal review | out of scope | org |
| E009.1 | Config: Third-party access monitoring | out of scope | infra · carrier: agent-mediated third-party interactions are action facts with external_ref carriage; vendor access to infrastructure is the operator's SIEM |
| E010.1 | Documentation: AI acceptable use policy | out of scope | org |
| E010.2 | Config: AUP violation detection | out of scope | prevention · carrier: `guardrail.blocked` |
| E010.3 | Demonstration: User notification for AUP breaches | out of scope | org |
| E011.1 | Documentation: AI processing locations | out of scope | org |
| E012.1 | Documentation: Regulatory compliance reviews | out of scope | org |
| E013.1 | Documentation: Quality objectives and risk management | out of scope | org *(binds on opt-in: requirement E013 is Optional)* |
| E013.2 | Documentation: Change management procedures | out of scope | org *(binds on opt-in: requirement E013 is Optional)* |
| E013.3 | Config: Issue tracking and monitoring | out of scope | org · carrier: dispute and incident surfaces (report/dispute.py, report/incident.py) *(binds on opt-in: requirement E013 is Optional)* |
| **E015.1** | Config: Logging implementation | **SATISFIED** | the flight recorder itself: a captured action is a receipt committing its inputs and outputs with the three times (SPEC/receipt-v1.md, SPEC/action-fact-v1.md §4), append-only under signed checkpoints (SPEC/log-v1.md); example entries are producible from any store. **No capture completeness is claimed or implied** — SPEC/receipt-v1.md §1 and the E1 row of SPEC/log-v1.md refuse it in normative text, and this row inherits that refusal |
| E015.3 | Config: Log storage | out of scope | org · carrier: Swarrm's OWN evidence log is append-only with salted commitments, so payload deletion stays compatible with retained integrity (SPEC/disclosure-v1.md). The retention periods, access controls and masking rules this control asks for govern the operator's AI logs and are the operator's; note the dial deliberately admits some identifiers (`principal`, `principal_display`) as plaintext, so 'no PII in plaintext' would be false as stated |
| E016.1 | Demonstration: Text AI disclosure | out of scope | org |
| E016.2 | Demonstration: Voice AI disclosure | out of scope | org |
| E016.3 | Demonstration: Labelling AI-produced content | out of scope | org |
| E016.4 | Demonstration: Automation AI disclosure | out of scope | org |
| E016.5 | Demonstration: System response to AI inquiry | out of scope | org |
| E017.1 | Documentation: AI system transparency documentation | out of scope | org *(binds on opt-in: requirement E017 is Optional)* |

### Pillar F — Society

| Control | Title | Class | Basis / note |
|---|---|---|---|
| F001.1 | Documentation: Foundation model cyber capabilities | out of scope | org |
| F002.1 | Documentation: Foundation model CBRN capabilities | out of scope | org |

## §3 Nearest misses and divergences by position (for the next recheck)

- **E015.2 (Supplemental) — agent provenance, delegation chains, reasoning
  traces.** Tool calls, approvals, and delegation are receipt-covered;
  **reasoning traces are deliberately not captured** — the flight recorder
  records actions, never chain-of-thought. If AIUC-1 promotes this control
  to Core, the trace clause becomes a documented divergence by position,
  not a gap to close.
- **E015.4 (Supplemental) — log integrity protection.** WORM storage,
  cryptographic hashing, append-only, tamper evidence: this optional-tier
  control is Swarrm's core product. Recorded so a future revision that
  promotes it to Core converts directly into a SATISFIED row.
- **B008.3 (Supplemental) — agentic interface data integrity.** DSSE
  envelopes sign evidence, not the operator's tool I/O; partial by design.

## §4 Quarterly recheck obligation (NORMATIVE)

AIUC-1 refreshes quarterly; the next release is scheduled 2026-10-15.
**This mapping is true only at its pin.** On every AIUC-1 release: re-pull
the standard, re-pin §0, re-measure the shape from the site's own dataset,
re-classify §2 in full, and re-examine §3. Until that recheck lands, the
licensed sentence may cite only the pinned revision by date. A stale
mapping is a false claim, and the claim must be withdrawn rather than
argued. The recheck is a standing obligation of this mapping.

## CHECK (how to verify this document)

1. Every active Core control of the pinned revision appears in §2 exactly
   once: 82 rows, IDs unique, none retired (E007.1/E014.1 absent).
2. Class totals match §1: 2 SATISFIED, 80 out of scope, 0 GAP; every
   SATISFIED row names at least one artifact with a SPEC or module path
   that exists in this tree; every out-of-scope row carries a sub-reason.
5. **Every field a SATISFIED row names is verified to exist in the SPEC it
   cites, not merely plausible from the artifact's name** — the failure
   that cost seven rows in the first draft (§1, correction history). A row
   asserting capture completeness, a preventive property, or a verdict
   value the frozen vocabulary does not define is a defect in this
   document and is corrected here rather than argued.
3. §0's measured shape re-derives from the standard's site (each
   requirement page embeds the full per-control dataset with
   `application: Core | Supplemental`) — **and remains checkable after the
   site moves on.** AIUC-1 refreshes quarterly, so from 2026-10-15 the
   2026-07-15 shape can no longer be re-fetched, which would leave this
   pin permanently unverifiable. The identifier set retrieved at pin time
   is therefore committed as
   `tests/golden/aiuc1_core_controls_2026-07-15.json` — control IDs and
   their Core/Supplemental flag only, plus a SHA-256 over the normalized
   dataset, carrying none of AIUC's prose — and
   `tests/test_aiuc1_mapping.py` asserts that §2's rows equal that set
   exactly, not merely that they count the same.
4. No Swarrm surface renders an AIUC score. Stated precisely, because the
   loose form was false: `banned_schema_fields` in
   `ci/architecture_policy.json` bans exactly `aggregate_rating`,
   `aggregate_score`, `rating`, `reputation_score`, `trust_index`,
   `trust_rating` and `trust_score` **in this tree**. The `risk_index` /
   `risk_rating` / `risk_score` additions are queued on
   `plan/v2-partner-surfaces` (`382e8085`) and are NOT in this tree's list
   yet, so do not cite them as enforced here. A bare `risk_*` glob is not
   the test either — `risk_flags` occurs in customer-simulation fixtures
   (e.g. `tests/customer_live_model_server.py`), where it models a
   THIRD-PARTY model server's response, not a Swarrm scoring surface.
