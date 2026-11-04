<!-- SPDX-License-Identifier: Apache-2.0 -->
# Rust registry audit evidence v2

The `swarrm/rust-registry-audit/v2` contract binds a registry observation and
its offline replay to an exact candidate, lockfile, existing advisory policy,
recipe closure bytes, scanner and Cargo executables, and operation identity.
The workflow pins the canonical SHA-256 of the path-to-digest map for the
producer, evidence destination, transcript archiver, owned child runner, strict
JSON reader, and collector size declaration. It passes that pin as `--recipe-sha256`; changed helper bytes must
refuse before importing those helpers or launching a scanner. Every recipe file
must also match the exact committed candidate. Registry
package membership is derived from the lockfile, including each source, version
and checksum. A count alone cannot establish coverage.

The producer uses a new private Cargo home without inherited configuration or
credentials. It retains bounded original stdout, stderr, actual producer and
launcher exits, typed observation outcome, closure state, and UTC start/end times
before interpretation. Any lookup diagnostic, incomplete observation, nonzero or
missing exit, unknown output shape, filtered scope, vulnerability, or withdrawn
locked version refuses. The existing explicitly declared Marvin exception is
unchanged. An unavailable registry is incomplete evidence, never a passing skip.

`snapshot.json` names the candidate-bound inputs, original tool identities,
observation time, RustSec commit, exact opaque registry-cache member hashes and
lengths, original capture hashes and lengths, and the archive manifest digest.
The existing gate-transcript archive inventory covers every retained data file.
The v2 transport is `snapshot.tar`, a canonical uncompressed USTAR container
bounded by the actual collector's unchanged 64 MiB member limit, derived from
its bound source declaration. The overall artifact limit remains 128 MiB. It contains `manifest.json` first,
then every original file under `files/` in manifest order. Headers use mode0600,
zero uid/gid/mtime and empty owner names; only regular files are allowed. Every
header, file length/hash, zero padding and complete footer is checked before
materialization. No compression, link, extended header, duplicate or extra member
is accepted. The snapshot binds the container schema, name, length and SHA-256.
This keeps the outer CI artifact below its unchanged member-count bound. Version1
flat-tree records are historical inputs to their original recipe and are refused
by the v2 consumer; they are not translated or resealed.
File-only artifact transports may omit empty directories. The consumer restores
only directory members declared by the original hash-bound archive manifest into
a fresh private copy, then runs the unchanged complete archive verifier. Every
original file and manifest byte must still match; no missing file, changed hash
or undeclared member is repaired. Retained input evidence is never modified.

Only the pinned scanner interprets upstream cache bytes. A consumer verifies
that archive, rechecks original scanner output and terminal evidence, checks the
exact locked registry membership, and executes the pinned scanner on a disposable
copy with `--no-fetch` and Cargo offline mode. The replay must leave its archived
inputs unchanged. Missing or altered members refuse.

`result.json` is published only after both the required original observation and
offline replay have passed, source/tool identities remain unchanged, and the
owned destination still matches its held descriptor. Reused destinations refuse.
A `replay` result has `fresh_observation: false`; replay never refreshes the
original provider-observation time. Consumers retain existing phase freshness
policy; this format grants no new age allowance or publication authority.

The workflow retains the reports, original snapshot archive, snapshot descriptor
and result with exact source/run/attempt artifact naming, including failure
records. Upload success is independent of scanner success. Downloaded evidence
must pass the same consumer with the original operation binding before it can
support acceptance. Native diagnostics alone do not establish sealed-runner,
artifact-transfer or release qualification.

The existing `ci_triage.sh --collect-artifact` and `--verify-artifact` callers
consume `swarrm/ci-rust-artifact-context/v1`. Common repository, source, tested
merge, run, attempt, job, event, branch, workflow and artifact identities remain
mandatory. This context replaces pytest profile fields with `producer_checkout`,
`recipe_sha256`, and `tools` (exact scanner/Cargo paths and SHA-256 values).
The tested checkout is clean at the merge; the producer checkout is clean at
the source. PR topology must prove that source is the merge's second parent.
The committed security job, upload members and recipe must match the actual
consumer. A profile context cannot admit a Rust artifact.

Both callers require `--replay-output` naming a fresh private destination outside
source and retained transport. Complete original API captures, closing steps,
artifact pagination, source/run/attempt membership and ZIP hashes are checked
before interpreting reports. Original online and offline outcomes and their
job intervals must agree. The actual pinned gate then replays the retained
container with the original operation binding. Successful transport output is
`swarrm/ci-artifact-transport/v5`, with `rust_registry` naming original observation
time and result hashes; `fresh_observation` and `release_accepted` remain false.
A failed replay retains the original download and its capture receipts.

Before returning success, the shared verifier rechecks every original capture,
context/layout/diagnostic byte stream and extracted member after semantic replay.
The replay result must preserve the original inputs and observation, use the
expected schema and remain unchanged on disk. Late mutation refuses without
rewriting original scanner, capture or download outcomes.
