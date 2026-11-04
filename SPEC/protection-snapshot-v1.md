<!-- SPDX-License-Identifier: Apache-2.0 -->
# Protection snapshot v1

`swarrm/protection-snapshot/v1` binds a read-only GitHub branch-protection
observation to its consumer representation. It grants no merge or policy authority.

The exact fields are `schema`, `representation`, `repository`, `ref`, `base`,
`raw_base64`, `raw_sha256`, and `document`. Repository is an owner/name pair;
ref is the protected branch; base is its exact 40-character lowercase commit ID.
The representation is `github-rest-protection/omitted-off-null/v1`.

`raw_base64` retains the original response bytes, bounded to 1 MiB before parsing;
`raw_sha256` hashes those bytes. Strict JSON decoding rejects duplicate keys and
nonfinite numbers. The consumer adds null only for absent `required_status_checks`,
`required_pull_request_reviews`, and `restrictions`. Every other field, including
unknown controls and value types, is retained. `document` must equal that derived
representation. Unknown envelope fields and incompatible versions refuse.

The existing `land_candidate.py --capture-protection NEW_DIRECTORY` entrypoint
creates an exclusive owned destination, retains `protection.raw` and the adapter's
terminal `transport.json`, and publishes `snapshot.json` after unchanged branch
readback. These are adapter-terminal observations, not an inventory of intermediate
transport retries. Errors remain errors; no merge or protection write occurs.

Retained-file consumption requires all three regular files, matching raw bytes,
a successful integer transport exit, no pending capture member, and safe directory
ownership. Atomic publication failures retain pending originals and refuse reuse.
Landing preflight validates the prepared repository, branch and base against the
actual consumer and freshly observed base; it also compares fresh protection with
the derived document. Omitted/off-null equivalence is the only normalization.
Checks, app bindings, strict/admin flags, unknown controls and types must agree.

This snapshot is preparation evidence. It does not prove PR acceptance, authorize
protection changes, or replace final live identity and merge-result verification.
