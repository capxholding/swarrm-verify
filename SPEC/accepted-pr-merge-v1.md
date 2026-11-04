<!-- SPDX-License-Identifier: Apache-2.0 -->
# Accepted PR merge contract v1

`swarrm/accepted-pr-merge/v1` is the reviewed input to
`land_candidate.py --merge-plan PLAN --output NEW_DIRECTORY`.
Select exactly one of `--check`, `--execute-authorized-merge`, or
`--reconcile-merge`. No mode changes protection or migrates required checks.
General protection-window execution remains unavailable.

The exact plan fields are `schema`, `phase`, `version`, `runtime`, `repository`, `ref`, `source`, `base`,
`tree`, `tested_merge`, `pr`, `run`, `attempt`, `acceptance`,
`acceptance_sha256`, `protection_snapshot`, `protection_sha256`, and `helpers`.
The supported target is `capxholding/swarrm-core`, branch `main`. Phase must be
`merge`; version must match the exact committed project metadata, never a prior
release's hard-coded value.
Commit/tree identities are exact lowercase 40-character hashes. PR, run, and
attempt are positive integers; Boolean values do not qualify. Input paths
are absolute, bounded regular files reached without links or traversal.
Unknown fields or versions refuse.

Runtime binds the invoked/resolved Python binary, exact version, prefixes and
installed YAML-parser tree through the existing matrix-toolchain identities.
The interpreter must run with `-I -B`; a foreign parser prefix or module alias
refuses. These are helper-runtime identities, not a replacement environment
seal or a qualification receipt.

`helpers` is the exact path-to-SHA-256 map declared by the merge consumer.
Acceptance bytes must match their reviewed hash and prove the exact source,
tested merge, run and attempt, accepted status, original dispatcher and observer
exit zero, and verified restoration. Truthy substitutes refuse. The original
acceptance producer remains responsible for qualification and its evidence;
this merge contract does not manufacture or replace that proof.

The protection snapshot uses `swarrm/protection-snapshot/v1`; its complete
retained capture and hash must verify. Preparation and execution consume the
same resolved inputs. The clean local checkout must be the tested merge.
The inherited canonical host lock must already be exclusively held, and no
known restoration journal may remain. The caller does not acquire authority,
stop services, renew policy, or change installed controls.

Fresh reads must confirm the open, nondraft PR, source/base/tested merge,
tested tree and ordered parents, successful exact PR workflow run, complete
app-bound required checks, and unchanged protection. Inputs and custody are
rechecked at the write boundary. Only `PUT pulls/<pr>/merge` with exact source
and merge method `merge` is permitted. A durable, exclusive intent precedes it.
Spent or incomplete intents cannot authorize another write.

Original inputs and helper bytes are retained with a hash inventory before
execution. Command exits, unknown exits, executable identities, stream hashes,
and redacted diagnostic-capture outcomes remain separate. Capture failure
prevents further work and never changes the original command exit.

Credential-valued JSON fields must be redacted before diagnostic persistence or display, including opaque API-issued values, escaped keys and encoded nested streams. Malformed or excessively nested credential values cannot expose their suffix. Retained redacted bytes have their own hash; original stream lengths/hashes and producer exits remain separate. Redacted diagnostics are not original API inputs or merge authority.

`swarrm/accepted-pr-merge-preflight/v1` reports preparation, not merge authority.
`swarrm/accepted-pr-merge-result/v1` binds repository, ref, source, base,
tested merge, run, attempt and plan hash. Success requires exact merge parents,
tree, protected-main readback and unchanged protection and custody.
Reconciliation requires the original matching intent, fresh checks and exact
remote merge proof. It performs no write and leaves original outcomes unchanged;
an unresolved remote operation remains unresolved.

Commands use an owned process group and owner-loss guard with bounded retirement.
Local Git retains the closed probe environment. GitHub requests use the existing
validated credential environment and at most 65,536 stdin bytes; each output stream
is bounded to 4 MiB. Retain launcher, original tool, owner-guard, stdin-delivery,
retirement and capture outcomes separately. A complete pipe write is not remote
acceptance; exact remote readback remains required. Incomplete input, lost
observation, truncation or unproved cleanup cannot admit another phase.

This version admits only the repository and branch specified above. A different
target requires the separately scoped disposable proof contract in
SPEC/disposable-merge-proof-v1.md; changing this plan alone cannot expand the
permitted scope. Proof-only acceptance and results cannot supply production
qualification, even when other identities happen to match.
