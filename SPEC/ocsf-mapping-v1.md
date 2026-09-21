<!-- Apache-2.0 -->
# evd/ocsf-mapping v1 — verified facts → OCSF (INFORMATIVE)

Status: INFORMATIVE. A correspondence mapping, not a wire format, not an
exporter, and not a verifier type. OCSF (and ECS-compatible) names already
verified facts; they do not become new evidence. An exporter that needs a
Node door or a new verifier entry point waits on a later train. This
document ships so a SIEM can label Swarrm facts without inventing a second
truth.

## 1. The seam

Swarrm answers, after the fact: did this signed receipt verify, and what
did it commit to? OCSF answers, for a SOC: which event class is this, in
a vocabulary the SIEM already indexes.

Different layers. A mapped OCSF class is a label on a verified fact. It
is never a second verdict, never a population proof, and never a claim
that the SIEM feed is complete.

## 2. Correspondence (verified facts only)

| Swarrm fact (after verify) | OCSF class / field family | Honesty |
|---|---|---|
| `llm.chat` receipt | `gen_ai` / API activity analogue: model call happened | Evidence of a recorded call, not that every call was captured |
| `tool.call` | Process / API activity | Same |
| `human.*` | Authentication / authorization analogue: a named human touched the path | Oversight fired; adequacy is the operator's |
| `payment.execute` + `camt.053` corroboration | Financial transaction | Settlement corroboration, not a payment-network message |
| inclusion / consistency proof | File integrity / detection finding | Tamper-evidence of THIS log |
| `evd.finding.*` / `evd.gap.*` | Detection finding | Explicit gaps stay gaps |
| selective disclosure package | Data disclosure | One field of one receipt, RFC 9942 vocabulary in prose only |

`gen_ai.*` on the receipt itself stays unbound. Mapping a verified
`llm.chat` fact onto an OCSF gen-AI class does not mint a `gen_ai.*`
action type.

## 3. What this document does not license

- No OCSF/ECS exporter in this release.
- No new verifier union member.
- No claim that a SIEM that ingested these labels has a complete agent
  population.
- ECS field names are compatible aliases of the same facts, not a second
  mapping to maintain.
