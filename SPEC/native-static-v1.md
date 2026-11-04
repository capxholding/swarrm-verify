<!-- Apache-2.0 -->

# Private static ingredients, version 1

The existing `scripts/native_library.py` caller provides `check-static`,
`build-static`, `phase-static`, `verify-static` and `preserve-static`, all requiring Python `-I -B`.
This provisions an ingredient; it grants no runtime, advisory, ABI, or release
admission. The recipes support SQLite, XZ and Zstandard. Other libraries refuse until
their own recipes and evidence are implemented.

Inputs use `swarrm/native-static-inputs/v2` with exact keys `schema`, `control`, `library`,
`output`, `source`, `tools`, `sdk`, `developer_dir`, `deployment_target` and
`recipe_sha256`. `source` binds a complete source-material `path` and
`receipt_sha256`. Tools bind absolute `path` and `sha256` for `cc`, `ld`, `ar`,
`ranlib`, `make` and `shell`. The recipe hash covers the current helper and
policy identities. macOS explicitly selects its SDK/developer directory and
deployment target 11.0; Linux requires those fields to be null.

Read-only preparation verifies complete source material, tool identities and
actual SDK observation before output creation. The build then creates a new
private destination, retains original input/source records and archive bytes,
and repeats complete source readback from its private copy. Plans use
`swarrm/native-static-plan/v2`; changed inputs, helpers, tools, control,
functional C source, SDK or output ownership refuse execution.

The shared native phase runner retains original producer, supervisor, capture,
observer and cleanup outcomes separately. Every prior phase must complete
before its successor. `swarrm/native-static-producer/v1` records original exits
and interruptions; missing or interrupted proof refuses. The existing resource
observer must acknowledge startup and remain healthy. Original bounds remain.

SQLite uses the complete reviewed amalgamation, with explicit thread safety
and the committed feature defines. The recipe compiles, archives and indexes
the library, then links and runs a fixed functional program against that exact
archive and its original headers. Version/source ID, thread safety, transaction
rollback, constraints, JSON, FTS and R-tree behavior must pass. There is no
upstream SQLite test-suite claim: the supplied autoconf archive does not contain
that suite, and CPython's required SQLite tests remain mandatory.

Completed `swarrm/native-static-component/v2` receipts bind the plan, every
original phase record/stream, complete retained file inventory and installed
prefix tree. `verify-static` replays the original completion contract without
changing records. A receipt alone is not successful execution. Full downstream
Python consumption, source authentication, dependency checks, supported-platform
and release qualification remain separate requirements.

XZ uses an out-of-tree static build with translations and documentation
installation disabled. Compression formats, threading, scripts, MicroLZMA and
the complete upstream `make check` selection remain enabled. Every declared
test must retain its original PASS report and log; summary counts alone do
not establish completeness. The functional program verifies the exact version,
checksum support and an encoded/decoded round trip against the built archive.

The XZ recipe permits only its exact libtool metadata link,
`build/src/liblzma/.libs/liblzma.la` to `../liblzma.la`. The target must be a
regular file inside the private tree. Other links, devices, FIFOs and unsafe
permissions refuse. The inventory retains the original link target bytes;
it does not follow a link in place of retaining it.

`preserve-static --receipt <absolute-path> --receipt-sha256 <sha256>
--output <new-private-directory>` validates completion before copying. It
preserves every regular file, declared link, executable bit and source timestamp,
then checks the complete copy through the same consumer. Original receipt bytes
remain unchanged. Existing or overlapping destinations refuse. A partial copy
is not successful preservation, and this command never deletes originals.

Zstandard retains a separate work copy of the complete prepared source. Original
source members and the isolated, bytecode-disabled Python launcher must remain
unchanged except for the exact, hash-bound private test overlay declared in the
recipe. The original archive and extracted source remain untouched. The overlay
replaces one six-byte test string initializer with six explicit character
initializers, preserving the buffer type and bytes under the existing warning
policy. Its original/derived identities and readback are retained and verified. The static archive includes multithreading; the functional program
checks version, worker support, round-trip bytes and checksum refusal.

The full vendor contract runs all program variants, the complete tests target
with large-data/fuzzer/stream/pool coverage, and the educational decoder. Nested
make calls remain bounded to two jobs. The original CLI runner selects its own
complete test inventory and preserves each test's original exit/stdout/stderr;
the next consumer checks those identities and original exact/glob expectations.
The full target's separate pool PASS verdict is required once and is not counted
as a CLI node; missing, duplicated or unexplained PASS records refuse.
Known internal CLI aliases retain their original absolute target bytes. During
historical readback, targets are checked against the corresponding retained
regular file, without following an old absolute path or rebinding the link.
These archived links are not admitted for execution in a new location.

The new Zstandard suite phase has a 5 GiB temporary-file ceiling because the
upstream full suite writes a 4,193 MiB regular fixture. Every other phase and
every retained evidence file/stream keeps the 128 MiB bound. Preparation and
phase startup use the existing release-test-surface capacity requirement,
reserve and inode budget against the actual private output filesystem. Runtime
observations must continue to establish that byte headroom. Unknown readings,
insufficient headroom or a lower inherited hard limit refuse before work.
No host-wide limit, storage volume or existing capacity threshold changes.

The initial program-variant outputs are retained before the test target can
rebuild its own driver. Their snapshots, rather than a mutable later executable,
establish the original phase identity. Critical compiler/SDK/linker flags also
remain in the shared make flags when a vendor target replaces CFLAGS.

The measured Darwin/ARM64 variant diagnostics are retained and classified
explicitly: the upstream strip option yields obsolete-strip/no-debug-symbols
messages, and the no-legacy link recipe repeats libz. Only that exact
phase/platform message multiset is reviewed; changed, missing, duplicated or
foreign diagnostics refuse. The compiler warning policy remains intact.

The full-benchmark program can report a failing validation while returning zero.
The consumer therefore also checks its original diagnostics. The single declared
incompressible-input refusal from experimental `compressSequencesAndLiterals`
is retained as an unsupported-operation result, as documented in the original
header. It is not evidence that this operation succeeded. Missing, additional,
changed or duplicated error verdicts and any validation failure refuse. The
separate public-API functional probe must round-trip deterministic incompressible
data through the built multithreaded archive; no test target is omitted.

Five source-declared permission fixtures retain their original modes: the
permission-test output directory is 0777 and its four declared file-stat files
are 0642. The complete producer output remains under an owned 0700 root.
Only these exact paths, kinds and modes are admitted as test data; every member
is still owner-checked, bounded and hash-inventoried. Missing or changed fixtures,
exposed roots and undeclared writable members refuse. Copies preserve the
original modes; these fixtures confer no executable or installation authority.
Domain verdict fields remain separate from original supervisor outcomes and
are independently recomputed by the successor reader.

The `control` input is the existing `swarrm/native-build-control/v1` binding.
Read-only preparation and each direct phase admit the actual constructor under
Python `-I -B` before production. Admission retains the initial observation;
per-phase and final control observations join the original hash inventory.
The plan's command alias derives from this one input and must match it.
Completed receipts require the same original-control decoder as Python components;
historical controls are never executed during retained evidence verification.
Version 1 inputs/plans/receipts remain unchanged historical evidence and cannot
authorize the current recipe.
