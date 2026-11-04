<!-- SPDX-License-Identifier: Apache-2.0 -->
# Disposable merge proof v1

`swarrm/accepted-pr-merge-proof/v1` uses the existing accepted-PR merge caller
and exact plan fields, but proves a disposable exercise, never production
qualification. Production `swarrm/accepted-pr-merge/v1` remains restricted to
`capxholding/swarrm-core` and its immutable repository ID.

The proof target must have a current committed entry in
`ci/disposable_merge_authority.json`. Each entry has exactly `repository`,
`repository_id`, `owner_id`, `created_at`, `valid_from`, `valid_until`, and
`purpose`. Purpose is `1.5/rel14/26`; the repository must be in the
`capxholding/swarrm-proof-merge-` namespace and cannot have the production ID.
IDs are positive JSON integers, excluding booleans. Instants are exact UTC
`YYYY-MM-DDTHH:MM:SSZ`; creation precedes the authorized interval. Duplicate
names/IDs, absent authority, future authority and expired authority refuse.
No target is implicitly admitted by its name or a plan alone. Authority is
not renewed automatically.

Read-only preparation uses the existing entrypoint with
`--capture-protection NEW_DIRECTORY --proof-target OWNER/NAME`. It requires
the isolated admitted interpreter, retains the exact authority and owned
transport outcomes, and creates the existing protection snapshot under
`NEW_DIRECTORY/snapshot/`. The returned capture envelope names that path;
it is not a replacement protection-snapshot representation. The proof-target
option cannot override a merge plan or select a different protected branch.

Fresh GitHub observations must match ID, full name, owner ID, creation time
and `main`, and prove a private, nonfork, nonarchived, enabled, nontemplate
repository with merge commits enabled and administrative custody. Recheck
before preflight, at the lower-level write boundary and during readback.
The inherited host lock and restoration checks remain mandatory. There is
no protection-write mode and no retry of a spent or uncertain merge.
After expiry, a matching spent operation may still be observed and reconciled
without another write. Expired authority cannot start a new preflight or write;
reconciliation keeps the original failed or unknown outcomes unchanged.

Proof acceptance declares `swarrm/disposable-merge-acceptance/v1`, with
`proof_only: true`, `qualification_accepted: false`, exact repository/ID,
source/tested-merge/run/attempt, accepted required checks, original observer
and capture exits zero, and no outstanding host restoration. It must come
from the actual completed proof observation; no release dispatcher outcome
is manufactured for a hosted fixture. Production acceptance remains unchanged.

Proof preflight and results use distinct `swarrm/accepted-pr-merge-proof-`
schemas and retain `proof_only: true`, `qualification_accepted: false` and
the repository ID. Input/helper/protection inventories, complete app-bound
checks, exact parents/tree, original command/capture outcomes and unchanged
protection are still required. A successful proof result cannot replace
production acceptance, native/Linux qualification or release authority.
