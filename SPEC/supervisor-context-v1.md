<!-- Apache-2.0 -->

# Supervised execution context, version 1

The existing surface supervisor records `swarrm/supervisor-context/v1` before
its executor starts. Invocation recipe v7 binds the policy, capability and
runtime helper bytes, exact candidate, interpreter, Git, shell and extractor.

The record identifies the actual supervisor PID and fresh start identity, account home, separate execution
HOME, snapshot cwd, independently owned Git directory and readable candidate
configuration. The account home comes from the operating-system account record,
not an inherited HOME value. Snapshot-identity Git reads use a 30-second command bound; runtime placement
retains the runtime helper’s existing 60-second bound.
Object alternates and common-directory indirection
are refused. Tools retain absolute invoked/resolved paths, content hashes,
filesystem identity, ownership and modes; preparation and execution must agree.

Private directory/file creation, generated executable startup, the GnuPG socket
path and cleanup run from that supervisor in the execution snapshot. The original
v2 filesystem capability and cleanup record is retained with the context result.
Any missing or failed observation refuses admission before the executor starts.

The lower-level executor requires matching unspent admission from its own PID,
candidate and recipe, marks it spent before process creation, and revalidates
process start identity, tools, helper bytes and temporary-directory identity before releasing the gated
child. The existing observer acknowledgment remains mandatory. Context admission
is not a test verdict, future host admission or qualification acceptance.

The private shell executor consumes the same admission through the existing
supervisor's `executor-binding` command. Its bounded, no-follow regular-file
reader rejects ambiguous JSON and retains the original record before identity
interpretation. The recorded executor must be a live child of the recorded
supervisor, with the unique birth identity in the existing ownership ledger;
the reader itself must descend from that executor. Candidate, recipe, spent
admission, supervisor birth identity, tools, helpers, object store and temporary
filesystem are revalidated before any test gate runs. Historical records remain
readable for preservation but cannot authorize new supervised execution.

The existing gate-receipt supervisor retains the reader's original exit, stdout
and stderr separately. A missing or nonterminal receipt refuses before the
binding is parsed. These files and the original input remain in the existing
owned evidence tree for its normal preservation and readback. Unsupervised
diagnostics retain their explicit unsupervised scope.

For recipe v7, the OS account home anchors exclusion, recovery records, retained
evidence and host-lock census under `.swarrm/surface`. Execution `HOME` cannot
relocate that custody state. The recipe binds UID, resolved account home and
state path; changed or unavailable account records refuse before lock acquisition,
context admission or executor release. Earlier recipes retain their recorded
interpretation and cannot authorize new execution.

Source Git and extraction consume the existing protected-main candidate tool
environment as bounded literal data. Caller Git namespaces, replacement objects,
credentials and archive options cannot enter those processes. The declaration,
snapshot producer and direct-executor reader use the same environment contract.
