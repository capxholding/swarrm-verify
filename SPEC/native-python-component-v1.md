<!-- Apache-2.0 -->

# Native Python component contract, version 1

This contract records private toolchain provisioning. It grants no SDK,
advisory, workload, or release acceptance.

Inputs use `swarrm/qualification-python-inputs/v5`; plans use
`swarrm/qualification-python-plan/v5`; completed receipts use
`swarrm/qualification-python-component/v6`. Older input, plan, and component
schemas are historical evidence and cannot authorize the current build or
component reuse. Preserve them unchanged rather than rewriting their seals.

The exact configuration digest binds the reviewed, hash-bound prepared source, compiler,
linker, make, shell, archiver, archive indexer, native libraries, CA bundle,
SDK, developer directory, and deployment target. Each executable has an
absolute path and byte digest. Preparation and every phase revalidate these
inputs. The closed environment sets AR, RANLIB, and SHELL explicitly; make
receives those assignments on its command line as well.

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

On macOS the compiler and link probe name the native `arm64` or `x86_64`
architecture explicitly. Unknown targets refuse; Linux does not inherit macOS
architecture flags. Capability and build commands use the same target flags.

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
the source inputs remain unchanged. Keep the actual command and capture exits
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
