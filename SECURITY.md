# Security Policy

## Reporting a vulnerability

Email **proof@swarrm.ai** with the details. Please do **not** open a public issue
for security-sensitive reports.

Include: the affected version (commit hash), a description of the issue, and, where
possible, a minimal bundle or fixture that reproduces it. If your report concerns a
case where `swarrm-verify` returns **VERIFIED for a bundle that should fail** (or
**NOT VERIFIED for a valid bundle**), say so explicitly — soundness of the verdict
is this project's primary security property.

## What to expect

We aim to acknowledge reports within 5 business days and to agree a disclosure
timeline with you. Fixes to verification soundness are prioritized over all other
work.

## Scope

In scope: the correctness and soundness of offline verification — signatures,
RFC 6962 Merkle inclusion/consistency, checkpoint and key-log validation, canonical
(RFC 8785 / JCS) encoding, and hostile-input handling. Out of scope for this
repository: the Swarrm hosted service (report those to proof@swarrm.ai as well, but
they are not part of `swarrm-verify`).
