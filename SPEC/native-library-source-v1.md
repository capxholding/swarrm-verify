<!-- Apache-2.0 -->

# Native library source material, version 1

`toolchain.py prepare-native-source` prepares complete reviewed library sources.
It performs no build, installation, script execution, or network request. Run
with Python `-I -B`, an exact `--config-sha256`, and a new private `--output`.
`--check` validates the same inputs without creating the destination.

Inputs use `swarrm/native-library-source-inputs/v1`, containing exactly `schema`,
`library`, and `archive`. The archive path is absolute and canonical. The named
profile in committed `ci/native_library_sources.json` binds version, archive
size/hash, root prefix, identity/license members and exact reviewed links.
Acquisition and source authentication retain their own original evidence;
a prepared source receipt does not establish signature or advisory clearance.

The shared source extractor refuses links by default. A reviewed profile may
name exact relative symlinks to original regular files in the same archive.
Preparation materializes their bytes as regular files at the original names,
retaining the original target and resolved member in the inventory. No symlink
is created. Missing or extra links, changed targets, parent traversal, hardlinks,
chains, special files, ambiguous paths and excessive expansion refuse before
destination creation. File modes come from the target; timestamps come from
the original member. For Zstd's two test aliases, the retained script dispatches
by its invoked basename, which is preserved. No tests are removed.

Output contains `evidence/inputs.json`, `evidence/policy.json`,
`evidence/source.tar.gz`, `source/<prefix>/`, and `receipt.json`. The receipt
uses `swarrm/native-library-source-material/v1`, binding library/version,
input/policy/helper hashes, original archive hash and complete normalized
inventory, including sizes, hashes, modes, timestamps and materialized-link
origins. Partial preparation retains its original files without a completed
receipt; the destination is spent even if interrupted.

Helper bindings include first-party modules imported when the shared environment
reader loads: the owned child runner, protected-main identity and attempt-age
readers, and native object reader. Their bytes are required even when preparation
uses only directory checks. Changed bindings require fresh material; original
receipts are never resealed.

`toolchain.py verify-native-source --prefix ... --receipt-sha256 ...` rederives
every member from the retained archive and current reviewed recipe. It checks
the exact file/directory sets, ownership, modes, timestamps and bytes, then
repeats identity/tree observations to detect changes. Original acquisition
paths need not remain available. Changed, extra, missing or unsafe members
refuse. Keep producer, capture and preservation exits separately; successful
source preparation grants no build, ABI, environment or release admission.
