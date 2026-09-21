<!-- Apache-2.0 -->
# ISO/IEC 27037 alignment — four principles, four mechanisms (INFORMATIVE)

Status: INFORMATIVE. Alignment, not a certification and not a pack.
Swarrm is described here as **forensic readiness** in the ISO/IEC 27043
sense: the capability to use digital evidence when required, built before
the incident. Independent analysis is ISO/IEC 27042. Conformance methods
are ISO/IEC 27041. Electronic discovery is the ISO/IEC 27050 cousin.

## 1. Four principles → four mechanisms

| 27037 principle | Swarrm mechanism |
|---|---|
| Identify | Action types, session lineage, and explicit `evd.gap.*` markers so missing capture is named rather than implied |
| Collect | Fail-open capture: receipts at the instrumented surfaces; capture never blocks the agent |
| Acquire | Salted, domain-separated commitments; payloads stay with the caller (or transit the hosted gateway once) |
| Preserve | RFC 6962 append-only log, inclusion and consistency proofs, RFC 3161 / RFC 5816 timestamps labelled non-qualified |

## 2. Cousin standards (paragraphs, not packs)

- **ISO/IEC 27043 (forensic readiness).** The product is the readiness
  layer: logs, commitments, and offline verification exist before anyone
  asks. It is not a preventative control plane.
- **ISO/IEC 27041 (assurance methods).** The golden / adversarial fixture
  corpus is the conformance method: two independent verifiers must agree
  byte-for-byte. Publishing that corpus as a 17029-shaped artefact waits
  on relying-party lists (direction recorded under `1.3/b45-4-direction`).
- **ISO/IEC 27042 (analysis).** Dual Python and Rust/WASM verifiers that
  agree on the same bytes are independent analysts of the same evidence.
- **ISO/IEC 27050 (eDiscovery).** Same identify/collect/preserve shape
  applied to electronically stored information in a legal hold. Named so
  it is not forgotten. Not a pack, not a legal-hold product, not a claim
  that a bundle is a 27050 production.
