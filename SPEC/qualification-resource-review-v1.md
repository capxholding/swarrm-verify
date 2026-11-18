<!-- Apache-2.0 -->

# Qualification resource review, version 1

This record reviews the resource observations for one completed test surface.
It does not change test results, establish a numerical alert policy, or admit
another workload. Original receipts, observations, and failed attempts remain
unchanged.

The JSON object uses schema `swarrm/qualification-resource-review/v1` and has
exactly these keys: `schema`, `subject`, `decision`, `findings`, `unknowns`,
and `investigation`.

`subject` contains the exact `candidate` and `run`, plus SHA-256 bindings named
`observation_manifest_sha256`, `binding_sha256`, and `measurement_sha256`.
The existing retained surface observation contract, version 2, supplies these
values. The measurement digest covers the UTF-8 encoding of the measurement
object serialized by Python `json.dumps(..., sort_keys=True)`. The candidate
is a full lowercase 40-character Git commit ID; digests are lowercase SHA-256.
Unknown, duplicate, missing, or contradictory fields refuse review.

`decision` is exactly
`qualification-evidence-valid-host-readmission-required`.
`findings` and `unknowns` each contain 1–64 nonempty strings of at most 4,096
characters. Unknown ownership or causation must remain explicit.
`investigation` maps 1–64 distinct file names to their SHA-256 digests. Each
names an original retained supporting file beside the review, with no path
traversal or self-reference. Files must be nonempty, owned by the current user,
private, regular, singly linked, unchanged, and at most 1 MiB. Symlinks,
nonregular files, and changing evidence refuse. The review itself has the
same file constraints and an independently supplied SHA-256 binding.

A consumer revalidates the original terminal, process identities, observer,
complete archive, and investigation before and after review. Missing or failed
producer, supervisor, observer, cleanup, or retention evidence cannot be cleared
by this record. Raw measurements and unknown alert counts remain unchanged.

`suite_receipt.py verify-qualification` also independently verifies the selected
suite receipt and every referenced artifact. Its receipt must be an original
member of both the suite archive and the exact resource-observed surface's
archive, with matching source, run, supervisor, and evidence directory. A passing
resource review cannot accept failed tests or failed capture. The command binds
both mandatory inputs before reporting selected-suite evidence validity.
Ordinary receipt verification continues to describe test evidence only.
The versioned verification output binds the actual receipt entrypoint and
resource consumer SHA-256 values. It is not a reusable release-admission receipt.

The existing status caller revalidates a supplied review on every refresh,
including a fresh session. A missing, changed, or incompatible review remains
visible as unresolved investigation; it never grants release acceptance.
Fresh capacity and custody admission are required for every next workload.

The shared qualification_resource_review.py consumer uses the existing
gate_transcript.py and surface_observer.py readers. suite_receipt.py and
readiness_milestones.py consume its result independently. Changes to the shared
readers also select their declared ci.yml owners before qualification.
