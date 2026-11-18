<!-- Apache-2.0 -->

# Native Python component contract, version 1

This contract records private toolchain provisioning. It grants no SDK,
advisory, workload, or release acceptance.

Inputs use `swarrm/qualification-python-inputs/v5`; plans use
`swarrm/qualification-python-plan/v8`; completed receipts use
`swarrm/qualification-python-component/v8`. Older input, plan, and component
schemas are historical evidence and cannot authorize the current build or
component reuse. Preserve them unchanged rather than rewriting their seals.

On Linux, preparation observes the complete governed APT and unattended-upgrade
unit inventory before reading expensive native inputs. Every unit must be masked
and inactive. The plan binds the boot identity, the exact bounded boot reader,
the exact systemctl executable, the normalized unit states and the original
output digests. Every phase and
receipt readmission repeats that observation. A reboot, unmask, active timer,
changed observer, failed query or automatic package mutation invalidates reuse;
the verifier never stops or masks services to manufacture admission.

The exact configuration digest binds the reviewed, hash-bound prepared source, compiler,
linker, make, shell, archiver, archive indexer, native libraries, CA bundle,
SDK, developer directory, and deployment target. Each executable has an
absolute path and byte digest. Preparation and every phase revalidate these
inputs. The closed environment sets AR, RANLIB, and SHELL explicitly; make
receives those assignments on its command line as well.

The SDK child measures the bound SDK selection only. It validates the exact
configuration and platform overrides, uses a closed environment, retains its
original outcome, and rechecks configuration bytes after measurement. It must
not recursively consume source or ingredient receipts. Preparation, each direct
phase worker, and component reuse still consume the complete input evidence
before invoking it; an SDK observation alone grants no admission. The existing
SDK and phase deadlines remain unchanged, including the thirty-second execute
probe worker limit.

Every library binding contains exactly `path`, `sha256` and `receipt`. The
receipt contains its exact absolute `path` and `sha256`. Matching library bytes
alone cannot authorize a build. The existing provider, static-library or Linux
support consumer must verify the original receipt, its complete evidence and
producer outcomes, target platform, library role and returned prefix. Recheck
both the receipt and prefix after consumption. Preparation, each execution phase
and runtime reuse apply the same contract. No consumer reconstructs missing proof.

`native_library.py verify-ingredient` validates original provider evidence using
the same receipt decoder as `verify`, without admitting or executing the original
build control. The decoder still checks recorded control probes, exact helper,
source/tool/input bytes, SDK evidence and current SDK identity. Its output states
`control_admitted: false`. Execution and ordinary `verify` additionally require
the original live control; ingredient evidence grants no workload admission.

Before configuring Python, the real caller compiles an object, archives and
indexes it, links and executes it, and verifies make startup. Missing tools,
changed bytes, failed commands, or unexplained probe output refuse. Preserve
original producer, supervisor, capture, observation, and cleanup outcomes
separately. Probe success never substitutes for the required build, imports,
upstream tests, installed-tree identity, or subsequent SDK qualification.

The retained capability source is fixed by the helper recipe and revalidated
before execution and receipt reuse. The same compile/archive/link/execute chain
performs an FFI call and zlib/bzip2 round trips before configure. A success marker
from replaced probe source is insufficient. Linux inputs must bind a private
`stdlib` library prefix containing the declared ffi/zlib/bzip2 headers, shared
linker objects and runtime SONAME objects. Its exact tree and explicit include,
link and runtime-search flags are revalidated with the other native inputs; no
ambient library paths are inherited. Import observations must identify the actual
FFI/zlib/bzip2 symbol owners and extensions. Linux consumption requires unchanged
objects under the declared library and constructed interpreter prefixes, with
library bytes matching the declared SONAME objects. On macOS the selected SDK
supplies these interfaces. Configure must also report ctypes enabled on Python 3.12–3.14.
Python 3.11 discovers ctypes in setup.py, so it uses the real FFI capability
probe and required ctypes suite rather than a nonexistent configure field.

Native Python producer records use `swarrm/native-python-phase/v2`; provider
producer records use `swarrm/native-library-producer/v3`. Both retain the original
child exit, first-observed SIGINT/SIGTERM kinds, and any interruption-capture error.
The owning runner terminates its process group; the worker reaps the child and
persists that exit after a handled signal. The bounded, preallocated
`<phase>.interruptions.jsonl` independently retains each first signal observation.
Successful consumption requires the original producer and worker exits, an empty
interruption list, no capture error, and the unchanged regular empty signal stream.
KILL or failed persistence may leave the original exit unknown; missing evidence
refuses and must never be filled from the supervisor's exit.

The receipt retains the original C source, object, archive, executable,
per-phase streams and statuses, configuration and SDK observations, resource
observations, and upstream-test XML. Every declared original has a bounded
length and SHA-256 digest and must survive independent readback. The helper
recipe also binds this contract. Changed inputs or missing originals require
fresh evidence, never reconstructed original receipts.

The plan binds the original helper checkout and the version-specific upstream
module inventory. Execution requires that checkout; readback retains its original
identity. Reconstruct the import probe's original argv from that bound helper
origin, never the current readback checkout. Execution still requires the
admitted origin. This portability rule does not permit changed helper or policy
bytes; those require fresh component evidence.
The inventory includes hashlib and HMAC tests on every supported
version and Zstandard tests on Python 3.14, alongside the existing native-interface
tests. The same declaration owns the actual command and receipt interpretation.

Before upstream tests, the constructed interpreter collects exact case IDs in
isolated, no-bytecode mode. The existing owned runner bounds collection to sixty
seconds within the unchanged 1,800-second self-test phase. Failed imports,
diagnostics, incomplete streams, duplicate or foreign cases, failed producers,
lost observation and changed inputs refuse before tests start. Retain collection
streams, original exit and signal records, control and SDK observations, and the
separate worker outcome. Selection evidence uses `swarrm/native-python-selection/v1`.
The original JUnit must contain every collected case exactly once with a completed
outcome, including named upstream skips. Existing requirements for executed cases
in every selected module and absence of failures/errors remain. No case count can
substitute for those identities. Reuse verifies the same original evidence.
CPython's literal `unittest.loader.ModuleSkipped` case IDs remain in the inventory;
their original JUnit records must identify them as skipped and retain a reason.
Failed-import placeholders, foreign modules and passing module-omission records refuse.

Source preparation recipe `swarrm/python-source-preparation/v2` separately binds
`Lib/test/libregrtest/testresult.py` under local review
`swarrm/cpython-junit-subtests/v1`. This is a qualification exporter correction,
not an upstream security backport. Exact original/postimage hashes and contexts
are mandatory for all four versions. The original source and installed trees
remain unchanged; fresh preparation applies the correction to private copies.
Imports, collection and self-tests refuse a missing, changed or unsafe installed
exporter before executing the constructed interpreter. Recheck after collection.
Environment creation and reuse consume the same complete source inventory.
Historical v1 source preparation cannot authorize current native execution or
managed-runtime admission. A valid current inventory still distinguishes older
unmanaged runtime versions; malformed inventory is never interpreted as unmanaged.
The upstream test command, assertions, parallelism and deadlines are unchanged.

The exporter retains each collected parent once. A skipped subtest cannot consume
its parent's XML slot or hide a later failure. Parent attributes bind the subtest
schema, observed callback count and successful callback count. Successful callbacks
are counted rather than expanded into unbounded XML. Each nonpassing subtest has
its original identity, ordered sequence and original skip reason or failure/error.
Receipts retain these summaries alongside the hash-bound original XML. Unknown
schemas, incomplete counts, changed parents, duplicate/out-of-order sequences and
missing reasons refuse; any failure/error still blocks acceptance. Completion
refusal restores the original output streams. No missing record is reconstructed,
renamed or interpreted as success. Reuse consumes the same evidence contract.

On macOS the compiler and link probe name the native `arm64` or `x86_64`
architecture explicitly. Unknown targets refuse; Linux does not inherit macOS
architecture flags. Capability and build commands use the same target flags.
On Linux, static SQLite dependencies also occupy configure's trailing `LIBS`
slot: older probes put `LIBSQLITE3_LIBS` before the test object and then
link `-lsqlite3` again. Both settings use the same fixed math, loader and thread
dependencies; inherited `LIBS` is excluded. Required-module checks stay mandatory.

## Private Linux support material

`toolchain.py prepare-native-support` prepares the FFI/zlib/bzip2 input prefix
used by the Linux component recipe. Run it with Python `-I -B`, an exact
`--config-sha256`, and a new private `--output`. `--check` validates the same
inputs without creating output. Zstandard package payloads require a Python
3.14 control interpreter with `compression.zstd`.

Inputs use `swarrm/native-support-inputs/v1`, with exactly `schema`, `target`,
and `archives`. The archive map names every package in the committed
`ci/native_support.json` profile and gives its absolute canonical source path.
The reviewed profile binds package names, versions, architecture, sizes and
SHA-256 hashes. Unknown profiles or incomplete input sets refuse.

Preparation decodes bounded package data without installation or script
execution. Links resolve only within the complete input set. The output has
regular private headers, linker/SONAME objects, original package archives,
original input/policy bytes and all applicable copyright files. Its versioned
`swarrm/native-support-material/v1` receipt inventories original archive members,
normalized-file origins, complete output files and helper/policy identities.

`toolchain.py verify-native-support` requires the exact receipt digest and
rederives the output from its retained originals. Extra, missing, changed or
unsafe members refuse. Original acquisition paths need not remain available.
Preparation returns a prefix/tree binding only after that consumer agrees and
the source inputs remain unchanged.

When an older parent consumes Zstandard-compressed support archives, select
the already bound Python 3.14 control from the native configuration. Validate
its declared baseline, binary, prefix, loaded objects and source helpers before
launching the existing complete material consumer in a closed `-I -B` child.
Recheck all identities and material afterward. Missing or incompatible control
refuses before construction. The versioned reader response binds the receipt,
prefix tree and original control observation; malformed output or any failed
producer, capture, owner or cleanup outcome refuses. Retain failed child streams
and actual exits outside sealed inputs. Successful scratch cleanup grants no
new runtime, workload or release admission. Keep the actual command and capture exits
separate: a material receipt does not establish successful process completion.

This prepares input material; it does not qualify ABI compatibility, security,
installed environments or release workloads. Those consumers remain mandatory.

## Offline provider build control

A build control is an explicit binary input, distinct from a qualified runtime.
It breaks the construction cycle in which Python needs a provider while that
provider's build would otherwise require already-qualified Python. Current
runtime, SDK, dependency and release admission remain separate and mandatory.

`native_library.py control-input`, under Python `-I -B`, observes the current
private base interpreter without creating a build destination. It accepts no
execution arguments. Its JSON output uses
`swarrm/native-build-control-observation/v2`, with `schema`, `binding`, `commands` and
`probe_helper`. The binding uses `swarrm/native-build-control/v1`, with exactly
`schema`, `interpreter` and `prefix_tree_sha256`. The interpreter field contains
the existing complete interpreter facts, including binary identity, version,
prefix, Python runtime object and loaded TLS identities. One record supplies
those values; conflicting aliases are not accepted.

The prefix must be canonical and owned, without writable group/other access,
under a private owned parent. The version and TLS version must meet the separate build-control baseline in
`ci/native_control.json`. Target-version changes do not silently change this
baseline; applicable security findings still require refusal and review. Execution checks the declared binary, entire prefix and loaded
objects before another observer starts, then repeats isolated observations and
tree readback. Each observation retains original stdout/stderr, hashes, actual
exit, runner identity, pipe/group cleanup and owner-guard outcome. Missing,
changed, failed or repeated process observations refuse. A failed launch has no
invented producer exit. Refusals retain the observed caller and available
binary, runtime-object, prefix-tree and TLS-object measurements separately from
any original command outcomes.

Provider inputs use `swarrm/native-library-inputs/v2`; their `control` field is
this binding. Plans use `swarrm/native-library-plan/v3`, and completed provider
receipts use `swarrm/native-library-component/v3`. The actual check, build,
phase and receipt readers enforce the same control contract. Preserve initial,
per-phase and final control observations with the original provider evidence.
The reader replays recorded commands through the runtime decoder's own typed
runner interface. It never turns build-control observation into component or
release qualification, or rewrites an older component's seal.

The Python and static-library creators require that same explicit control binding
before source/material/SDK preparation. The initial observation is retained in
admission; every phase and final completion retain their own control observations.
Derived binary aliases must agree with the binding. Direct invocation has the
same requirements. Missing, changed or failed observations cannot authorize a
phase or a completed component; a failure retains its original probe outcomes.
Before observing a direct worker's constructor, validate the plan's complete
helper/policy bindings and capability-source bytes. Refusal must precede new
control, SDK or producer observations.

Control observations version 2 bind `probe_helper.path` and `probe_helper.sha256`.
Recorded arguments must exactly name that historical path, the committed probe
code and isolated/bytecode-disabled flags. The helper bytes must match the trusted
decoder's helper identity. Retained observation decoding uses the same pure decoder
as live admission without accessing historical executable, runtime or TLS paths.
Live admission separately rechecks those actual objects and the complete prefix.
An original observation grants no permission to execute its historical control.
Older observation schemas remain preserved evidence, not current admission.
