<!-- Apache-2.0 -->
# OWASP ASI01–10 + LLM Top 10 + MITRE ATLAS (INFORMATIVE)

Status: INFORMATIVE. Honest provability after the fact. Swarrm evidences;
it does not prevent. Adjacent threat vocabularies sit on the same table
so a reviewer does not have to guess whether a named risk is in scope.

## 1. ASI01–ASI10

| Id | Risk (OWASP Agentic) | What a receipt log can prove afterwards | What it cannot |
|---|---|---|---|
| ASI01 | Goal hijack / prompt injection | That a named `llm.chat` / `tool.call` sequence ran, with human overrides if any | That injection was blocked |
| ASI02 | Tool misuse | That a tool was invoked, with which action type | That the tool should have been refused |
| ASI03 | Identity / auth abuse | That a principal and session were recorded | That the identity was correct at the IdP |
| ASI04 | Excessive agency | That grants and human decisions exist as receipts | That the grant policy was adequate |
| ASI05 | Supply-chain of tools | That `agent.tool_granted` / revoke events were logged | That the tool binary was the intended one |
| ASI06 | Memory / state poisoning | Commitments to recorded inputs | That memory was unpoisoned |
| ASI07 | Insecure output handling | That outputs were committed | That downstream sanitisation ran |
| ASI08 | Unbounded consumption | Counts and latency on recorded calls | A complete population of calls |
| ASI09 | Insufficient oversight | Presence or **named absence** (`evd.gap.*`) of `human.*` | That oversight was effective |
| ASI10 | Insecure inter-agent | Session parent links among recorded agents | That an uninstrumented agent did nothing |

## 2. Adjacent vocabularies (same honesty)

| Vocabulary | Use here |
|---|---|
| OWASP LLM Top 10 | Application-layer LLM risks. Same split: we can show a recorded call; we cannot show a filter fired. |
| MITRE ATLAS | Adversary techniques against AI systems. Receipts can corroborate that a technique's *observable* ran; they do not detect or prevent the technique. |

No ASI, LLM Top 10, or ATLAS row is a prevention claim.
