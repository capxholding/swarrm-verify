<!-- Apache-2.0 -->

# Temporary-filesystem admission, version 2

`scripts/surface_admission.py` emits `evd/admitted-temp-filesystem/v2`.
`probe_verdict` preserves the capability result before cleanup. The final
`verdict` cannot be `SURFACE_ADMITTED` unless the owned probe directory was
removed and its absence verified. A cleanup failure preserves any earlier
failure reason; it cannot replace it with success.

`cleanup` has exactly `path`, `status`, and `error`. Its status is `not-created`,
`unobserved`, `removed`, or `failed`. A failed directory creation that returned
no owned identity remains unobserved. A replaced directory is never removed.
Only `removed` has authority for successful admission; its error is null and
its path matches the original directory. Records retain that directory's device,
inode, owner, mode, and group.

Successful records also retain the base directory's device and inode alongside
its existing owner, group, and mode. Both basetemp creation and environment
selection revalidate that identity. Legacy records and records with missing,
failed, or unobserved cleanup refuse. No record admits a later workload or
replaces that invocation's host, supervisor-context, or qualification checks.

A named base is private by default. A caller may explicitly admit a named
shared base only when it is owned by root or the process and is both sticky and
writable by other users. The record states that decision. A private child must
still be created with mode `0700` and the effective uid; only this explicit
shared-sticky probe may accept the group inherited from that base. Before a
workload uses a private child minted directly under that base, the caller must
bind the already-open directory to the process's effective group and read back
the same device, inode, owner, mode, and final group. The retained identity
states whether the group materialized directly or was normalized from the
shared base. Failure to bind or read back the group removes only the unchanged
empty child and refuses before use. Other named shared directories and
non-sticky writable directories refuse.

Any caller that redirects a governed child to a private basetemp must retain
the exact directory identity and the cleanup outcome with the producer result.
Setup failure after directory creation still performs exact-identity cleanup;
an unadmitted or replaced identity is preserved rather than removed. A passing
producer with failed cleanup is incomplete, while a failed producer remains
failed and retains the cleanup failure independently. The affected-test runner
uses its owned private directory as `TMPDIR` and gives pytest a previously
absent child of that directory as `--basetemp`; this keeps pytest from replacing
the identity that the caller must later verify and remove. A selection that
requires GnuPG separately binds the exact executable bytes and explicitly
probes the platform's short shared-sticky base for its private GnuPG homes. The
runner transfers only those two admitted values, revalidates the executable
after the producer, and retains both bindings in the execution record. Direct
invocation cannot select an unprobed temporary base or an ambient GnuPG from
`PATH`.
