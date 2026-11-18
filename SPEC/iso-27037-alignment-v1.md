<!-- Apache-2.0 -->
# ISO/IEC 27037 alignment (informative)

This note maps Swarrm's evidence mechanisms to
[ISO/IEC 27037](https://www.iso.org/standard/44381.html).
It describes technical alignment, not certification.

## 1. Evidence handling

| Activity | Swarrm mechanism |
|---|---|
| Identify | Action types, session lineage, and explicit `evd.gap.*` markers so missing capture is named rather than implied |
| Collect | Capture-only receipts at the instrumented surfaces |
| Acquire | Salted, domain-separated commitments; payloads stay with the caller (or transit the hosted gateway once) |
| Preserve | RFC 6962 append-only log, inclusion and consistency proofs, RFC 3161 / RFC 5816 timestamps labeled non-qualified |

## 2. Related standards

- **[ISO/IEC 27043](https://www.iso.org/standard/44407.html) (incident investigation).**
  Logs, commitments, and offline verification support preparation before
  an incident and subsequent evidence review.
- **[ISO/IEC 27041](https://www.iso.org/standard/44405.html) (assurance methods).**
  Golden and adversarial fixtures compare Python and Rust/WASM verifier
  results on identical inputs. A formal review packet remains pending
  relying-party arrangements.
- **[ISO/IEC 27042](https://www.iso.org/standard/44406.html) (analysis).**
  Receipts and verification results support an investigator's analysis
  of the captured evidence.
- **[ISO/IEC 27050-1](https://www.iso.org/standard/78647.html) (eDiscovery).**
  Evidence identification, capture, and preservation can support electronic
  discovery. Legal-hold management and evidence production remain external.
