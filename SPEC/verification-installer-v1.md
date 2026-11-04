<!-- Apache-2.0 — this file ships with the public verifier repo. -->

# Verification installer evidence, version 1

This contract covers the offline pip version probe, optional target-marker probe,
and hash-checked wheel installation. It does not grant environment, advisory,
workload, or release admission. Runtime creation and other prerequisites retain
their own producer obligations.
The wheelhouse path must be absolute before installer preparation; a relative
path cannot change meaning when the isolated child changes its working directory.

## Capture binding

The environment record names `installer.evidence` as exactly `path` and `sha256`.
`path` is an absolute, private, owned directory without symlink traversal.
`sha256` identifies the exact bytes of `capture.json`. Environment reuse also
requires the recorded interpreter, environment path, export, and installed tree.
A new receipt cannot silently replace an old seal.

`capture.json` has schema `swarrm/verification-installer-capture/v1`,
`inputs`, `helpers`, `stages`, `files`, and `record_sha256`. The last field is
SHA-256 over canonical JSON of all other fields. `helpers` binds the executing
first-party implementation and this format contract. `inputs` binds original requirements, configuration,
wheelhouse content, and original command paths. `files` inventories exact byte
lengths and SHA-256 hashes. Missing, extra, changed, unsafe, or duplicate members
refuse. Unknown schemas and duplicate JSON keys refuse.

## Original members and outcomes

Every capsule retains `requirements.txt`, `pyvenv.cfg`, and the hash-bound
format contract as `contract.md`. Each ordinal retains
`N.stdout`, `N.stderr`, `N.intent.json`, and `N.json`. Streams are bounded by the
existing runner policy. Overflow refuses; omitted bytes are never claimed.

An intent has schema `swarrm/verification-installer-intent/v1`, the exact `argv`,
`inputs`, `helpers`, `producer_exit: null`, a scope identifying it as intent only,
and `record_sha256`. It precedes execution and never becomes terminal proof.

A terminal stage has schema `swarrm/verification-installer-stage/v1`, `argv`,
`inputs`, `context`, original `process`, `streams`, `capture_errors`,
`intent_sha256`, and `record_sha256`. Producer exit, launcher status, observation,
cleanup, and capture are separate. Failed persistence must not replace a known
producer exit. Interruption without a terminal observation remains unknown.
Original streams are persisted during execution, before interpretation.

The Python context has schema `swarrm/owned-python-context/v1` and binds the
creator and invocation bytes, executable and directory identities, configuration,
and closed environment. The invocation keeps its venv path and uses `-I -B`.
Only the explicitly bound creator's loader context can be lent; credentials and
`PYTHONPATH` are excluded. Pip configuration is the null device.

## Completion and readback

Acceptance requires exactly pip version, optional marker probe, then installation.
Installation retains `--no-index`, `--require-hashes`, `--only-binary=:all:`, and
`--no-deps`. Every original process must exit zero with acknowledged ownership,
closed pipes, verified cleanup, unchanged inputs, and successful capture. A later
success cannot erase an earlier failure. Only then may the aggregate receipt and
environment seal be published.

A retained copy verifies with the original receipt hash even after the temporary
runtime and original capture directory are removed. Original command paths remain
historical identities; they are not rewritten. The existing CLI is:

```sh
python -I -B scripts/verification_environment.py verify-installer \
  --path /absolute/owned/capsule --sha256 <original-receipt-sha256>
```

Its JSON uses `swarrm/verification-installer-readback/v1` and identifies the receipt,
stage count, and limited evidence scope. A readback is not live environment reuse.


## Native-client export projection

Original exports keep `swarrm/verification-export/v1`. An explicitly requested
native projection uses `swarrm/verification-export/v2`; v1 cannot carry one.
The existing `export` and `create --requirements` commands take paired
`--native-assembly` and `--native-assembly-sha256` arguments under Python `-I -B`.
A recorded v2 export can subsequently be selected with `create --export-record`.

A v2 record retains the original export and a private, independently verified
copy of every assembly member. `exporter` describes the original export producer.
`native_projection` uses `swarrm/native-client-export/v1` and binds the original
and projected digests, retained and historical assembly bindings, executing recipe,
original filename, and limited scope. Retention failure leaves original evidence
and cannot publish an export record. Neither source nor historical seals change.

The original native package version and complete artifact hash set must match
the bound lock. Projection changes only that package's hash block to the derived
wheel digest, preserves its marker and all other export bytes, and prefixes an
explicit derived-input label and original/assembly digests. The current native
policy and retained assembly must agree. Reuse independently reproduces those
bytes and rejects changed recipes or evidence. A changed recipe needs a distinct
record; it cannot overwrite the predecessor. Creation revalidates v2 inputs before
runtime work and before sealing. The real wheelhouse installer must hold the exact
derived wheel under its declared name; missing or incompatible runtime/platform
inputs refuse before venv creation. Installed members must match the derived wheel
byte for byte, except pip's regenerated RECORD. The installer records
`swarrm/installed-native-client/v1` with assembly/wheel hashes and byte-only scope;
reuse repeats that comparison. This proves dependency-input provenance only;
loaded-native, advisory, workload, and release admission remain mandatory.

## Workflow export production

Release interpreter admission requires a retained `swarrm/workflow-export-production/v1`
archive for the CI `test` job. `dependency_exports.py --prepare-workflow-export`
selects the actual named workflow export from an exact committed candidate;
ambiguous steps require `--export-step`. It rejects changed source/helper bytes
before executing the exporter. The existing toolchain policy admits the exporter.
The producer uses isolated Python, a private source snapshot and offline cache,
and retains the original version probe and two byte-identical exports with
separate original process, capture, observation and cleanup outcomes. Export
stdout uses the existing 8 MiB requirements-artifact bound; version output and
stderr retain the separate 64 KiB diagnostic bound. Oversized streams refuse.

The archive manifest binds every original member, the committed Git snapshot,
resolved/template arguments, input/helper hashes and exporter bytes. Readback
validates this complete contract before temporary originals may be removed.
Failure or interruption retains available originals and never manufactures a
successful terminal record. A new source recipe requires new evidence.

`verification_environment.py create --workflow-job test --candidate <exact-SHA>`
uses that producer directly. The export store retains an independently verified
copy of its complete archive, without changing the original manifest. Exporter
metadata is derived from the original record. Native projection binds that
original output before changing its reviewed native hash block. Creation and
reuse revalidate producer evidence; release interpreter admission also requires
the matching workflow job. Legacy manually recorded exports remain development
inputs and do not satisfy this release prerequisite. Producer evidence establishes
input provenance, not dependency safety, native execution or release acceptance.

## Complete local workflow profiles

`create --workflow-job JOB --candidate SHA --install-project --installer wheelhouse`
requires `--wheelhouse` with a complete absolute, owned wheel set and the existing
runtime-receipt arguments for recipe-managed interpreters. The operator must
already carry the declared marker parser. Unknown or conditional setup commands
refuse; installed target packages cannot equip the preparation interpreter.

The original UV export stays unchanged. A `swarrm/verification-project-inputs/v1`
archive retains committed package/backend source, helper/runtime identities,
build requirements, original builder outcomes/contexts, build wheels, the project
wheel and complete target wheel set. Combined hash-required requirements preserve
original markers/hashes, add build pins and name the exact project wheel;
conflicting pins refuse. The builder uses the workflow's exact hash-bound pip,
not an inherited ensurepip version. Offline binary-only acquisition must resolve
the combined closure. Retain its original reports and selected wheel bytes;
verify exact inventory/hashes before cleanup and again before installation.
Stale, incomplete or incompatible seeds refuse; old project wheels are forbidden.

The installer records the input binding as `installer.workflow_profile` and an
independent `swarrm/verification-project-admission/v1` archive as
`installer.project_admission`. The actual isolated target runs the existing
installed-project reader, including neutral imports and dependency metadata.
Creation and reuse require both receipts to match source, interpreter, original
export, helpers and requirements; missing or changed proof refuses admission.

Both bindings require a separate hash-bound
`swarrm/verification-project-completion/v1` record naming the archive digest,
original owned directory identities and explicit cleanup outcomes. Every archive
member must pass independent readback before originals are removed. Changed
ownership or failed cleanup retains evidence and refuses reuse. Historical
receipts never authorize signaling or removal of their former working paths.

`create --prepare-only --install-project` emits versioned JSON naming the retained
binding file, digest and export record without creating a target. A fresh process
may use `--export-record RECORD --candidate SHA --installer wheelhouse` with
`--prepared-profile FILE --prepared-profile-sha256 DIGEST`. Complete binding,
completion, source/export and requested runtime must agree before creation;
reuse cannot replace a failed producer/capture/cleanup outcome or candidate.

The backend retains bounded original stderr before interpretation or failure.
Only exact committed-manifest exclusions and isolated no-bytecode notices are
classified; unknown, duplicate, altered or actual error diagnostics refuse.
Independent readback repeats classification against the archived manifest.

This sealed local source-wheel derivative does not prove CI's required editable
install or workload, advisory, native-library, CI or publication acceptance.
