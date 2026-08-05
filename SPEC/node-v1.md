<!-- Apache-2.0 — this file ships with the public verifier repo. -->

# SPEC: node-v1 — Customer Evidence Node

**Status: NORMATIVE (v1).** The Node is ONE private, out-of-path component in
the customer's boundary (A_BUILD B22). It receives agent receipts
asynchronously, independently reads authoritative sources with least
privilege, and never proxies or authorises the business action. Contract
shapes it produces are frozen in SPEC/action-fact-v1.md +
SPEC/cddl/verified-action-v1.cddl; this spec defines the component: package,
config, storage, pipeline, egress, health, integrity, and the receipts it
writes. Fail-open is law: evidence failure never blocks or delays the
customer's action; missing evidence becomes an explicit gap.

## 1. Package, roles, config

- Package `node/` composes the existing pieces (LogStore, local key via the
  recorder's first-boot shape, spool, `core/vault.py`); role picked by
  command: `python -m node.node` / `swarrm node`. Same code ships local,
  Docker and customer-VPC; `node/Dockerfile` mirrors the recorder's
  (non-root, HEALTHCHECK on `/evd/health`).
- **One configuration file**: `EVD_NODE_CONFIG` (JSON). It declares the Node
  identity and the bound sources:
  `{ "deployment_id", "hosted_url"?, "sources": [ {"name", "kind":
  "https_feed"|"signed_webhook"|"emulator", "base_url"?, "auth": {"mode":
  "env"|"token_cmd", "ref", "stdin_ref"?}, "cursor_param"?, "page_size"?,
  "event_key_field", "mapping_version", "correlation_field"?,
  "material_fields": [..], "identity": SourceIdentity } ] }`.
  Config profile `node` (core/config.py) adds: `EVD_NODE_CONFIG` (required),
  `EVD_NODE_KEY_FILE`, `EVD_NODE_MASTER_KEY` / `EVD_NODE_MASTER_KEY_FILE`,
  `EVD_NODE_DATA_DIR`, `EVD_NODE_SCAN_INTERVAL`, `EVD_TENANT`. Local demo may
  default `EVD_TENANT` to `t_dev`; a deployed Node MUST set it explicitly
  before the data directory's first boot.
- **One diagnostic command**: `swarrm node doctor` — effective config,
  master-key mode (dev file-key mode prints a NON-PRODUCTION banner), per
  source: reachability, auth mode, cursor capability, last complete cursor,
  lag, spool depth/age, key/attestation state.

## 2. Customer vault (B22.2)

Two layers, both under customer-held key material, dev mode visibly
non-production:
- **Nonce vault**: `core/vault.py` (per-line AES-256-GCM, `enc1:` framing,
  legacy plaintext lines readable).
- **Evidence store** (`node/evidence_store.py`): content-addressed encrypted
  blobs for raw source artifacts and retained proof material. `put(bytes) ->
  sha256_hex`; file `vault/<d[:2]>/<digest>` holds `env1:` +
  base64(wrapped_data_key || nonce || AESGCM ciphertext); the per-blob data
  key is wrapped (AESGCM) under the master secret (`EVD_NODE_MASTER_KEY`, 64
  hex, or dev key file). `get(digest)` decrypts and VERIFIES the digest over
  plaintext; mismatch or unwrap failure returns nothing and raises a finding
  — never a crash. `SourceProof.material_digest` and
  `SourceEvent.proof_digests` resolve here; proof material is retained
  through certificate generation and export (action-fact-v1 §7). Credentials
  are NEVER stored in either layer (§6).
- **Normalized state is encrypted too.** `node_state.db` is an index and
  recovery journal only: canonical `SourceBatch` and `SourceEvent` documents
  are stored in the Evidence Store and SQLite carries only `evdref1:<digest>`
  references. Plaintext normalized financial/source fields exist only in Node
  memory while mapping/reconciliation runs. A legacy plaintext row is moved
  into the encrypted store and SQLite is securely compacted on open; a
  file-backed NodeState has no plaintext-write fallback.
- **Key continuity is a startup gate.** On first use the vault writes an
  atomically-created, encrypted master-key check. On every later boot the
  configured `EVD_NODE_MASTER_KEY` (or the selected dev key file) MUST open
  that check before the Node creates a key, opens its log/state database, or
  accepts intake. A syntactically valid but wrong key therefore refuses
  startup; a set-but-empty or malformed `EVD_NODE_MASTER_KEY` is an error,
  never a silent switch to dev mode. A legacy vault without a check is adopted
  only after every live digest decrypts; unreadable or quarantined material
  refuses adoption rather than being re-keyed or overwritten.

## 3. Durable intake (B22.3)

Per source batch, strictly in this order — crash anywhere earlier repeats
safely (at-least-once, idempotent):
1. **validate** the batch (schema, declared_count vs events, event-key root);
2. **prepare**: raw encrypted bytes, canonical `SourceEvent`s,
   `SourceBatch`, and an encrypted recovery plan → evidence store; their
   digest references + one PREPARED intake-journal row → the Node store in
   one transaction. Prepared facts are not visible to coverage/reconciliation;
3. **receipt**: one `source.batch.recorded` receipt (context: source name,
   cursor_start/cursor_end, mapping_version, declared_count, event_key_root,
   finality_watermark, gaps, exclusions; commitments: the canonical batch
   document) under the `_node` agent, then every deterministic finding receipt
   for that batch. Receipt/finding retries are idempotent and replay from the
   encrypted plan;
4. **complete**: after every evidence blob and SQLite transaction is fsynced,
   advance `cursors` (source → last_cursor, wall time) and change the journal
   to COMPLETE in one `PRAGMA synchronous=FULL` transaction. That transaction
   is the point at which facts become visible.
Cursor rollback, conflicting reuse, or an inter-range gap at read time is a
FINDING (§8) and forces coverage `GAPPED`; cursors are never reconstructed.
A crash/failure before COMPLETE may leave only encrypted content-addressed
orphans or a PREPARED row, and the identical batch resumes safely. Agent-side
receipts arrive via the recorder's existing spool/ingest path unchanged.
Coverage receipts are revisioned: an exact source/period/document retry
deduplicates, while changed coverage for the same source/period appends a new
`coverage_revision`, names `prev_coverage_receipt`, and links it as a parent.

## 4. Connectors (B22.5) and emulator (B22.7)

`node/connectors.py` implements the frozen interface (A_BUILD B22):
`authenticate() -> SourceIdentity`, `scan(cursor) -> SourceBatch` (events +
per-event and batch proofs), `normalise(raw) -> SourceEvent`,
`verify_source_proof(raw) -> SourceProof | None`, `health() ->
ConnectorHealth`. Vendor auth/pagination/mapping stay in the connector;
reconciliation and verification contain no vendor branch.
- **DeclarativeHttpsConnector** — config-driven paginated full-feed read
  (GET base_url + cursor/page params; `authenticated_read_transcript`
  SourceProof over the response, digest-addressed).
- **SignedWebhookConnector** — inbound deliveries; verifies an asymmetric
  signature or MAC against the pre-bound `SourceIdentity.keys`;
  `SourceProof.proof_type` is `asymmetric_signature` or `mac` accordingly (a
  MAC is possession, never origin — verdict semantics per
  verified-action-v1 §2.2); raw delivery retained encrypted.
  The hostile-input ceilings are fixed and enforced before signature work,
  normalization, evidence writes, or receipt signing: source path 128 bytes;
  request headers 64 / 16 KiB total; body 1 MiB; JSON depth 16; event 64
  fields; any string field 16 KiB; container 1,024 items; pending queue 512
  events / 16 MiB; one intake batch 128 events / 8 MiB. Duplicate JSON keys,
  floats, malformed envelopes, and over-cap input are rejected. Request bodies
  are streamed up to the cap, never buffered unbounded. Every known-source
  refusal raises `webhook_capture_failed`, degrades health and gaps coverage;
  capture failure is never swallowed as merely `verified=false`.
- **Emulator** (`node/emulator.py`) — ships WITH the Node: an in-process
  deterministic fake source (fixed seed; cursor pages; Ed25519-signed or MAC
  modes; injectable gaps/rollbacks/duplicates) so the whole loop runs before
  any real credential exists, and so chaos tests are reproducible.
- **Autodiscovery**: `swarrm node discover <base_url>` probes known feed
  shapes and emits a DRAFT SourceManifest for the reviewer to correct.
  **Pre-flight**: `swarrm node preflight` checks five readiness facts
  (dedicated service identity declared · signing source · cursor-capable
  feed · writable correlation field · no configured secret value detected in
  token argv) and prints an honest report. The fifth check cannot detect a
  hard-coded secret value that the config does not name (§6).
- **Read-only law**: connector config declaring any write/execute
  credential scope fails configuration (mechanical check at load).

## 5. Egress allow-list (B22.4)

All Node outbound goes through one guarded client (`node/egress.py`): the
allow-list is derived from config (source base_urls for reads; `hosted_url`;
opt-in anchor RPC / TSA when set) and any other host raises
`EgressDenied` before a connection is attempted. Only signed commitments,
permitted provenance, health and transparency submissions leave the
boundary. The Node sentinel test (B22.9) drives sentinel bytes through
payloads, nonces AND credentials and asserts none appear in any outbound
request or in hosted storage.

## 6. Credentials never at rest (B22.9)

`auth.mode = "env"`: the credential lives in the named env var, read at scan
time, never written to disk, receipts, logs, config or support bundles.
`auth.mode = "token_cmd"`: a customer-supplied command mints a short-lived
token per scan. The Node data dir and config contain no credential bytes
(test-proven with a credential sentinel). Lost credentials degrade
`ConnectorHealth` (which degrades COVERAGE); they never block execution.

**A token command's argv is world-readable.** The command runs with
`shell=False` and a list argv — that stops shell metacharacters in a config
value being interpreted and removes the extra `sh -c` process, but it does NOT
hide the arguments: every process's arguments are readable by any local user
through `ps auxww` and `/proc/<pid>/cmdline`, and the argv is what process
accounting and container runtimes record. A secret written inline in the
command (`vault-helper --token=hvs.CAESIJ…`) is therefore disclosed on every
scan. Secret material reaches a token command by exactly two channels:

- **environment** — the command inherits the Node's environment and reads its
  own `$VAULT_TOKEN`/`$AWS_*`; nothing extra to configure;
- **stdin** — `auth.stdin_ref` names an env var whose VALUE is written to the
  command's stdin and closed.

Neither appears in argv. A token command whose argv contains the value of a
secret the config names is refused at load, mechanically, like the read-only
credential scope; `swarrm node preflight` reports it as a readiness fact. A
hard-coded literal the config never names is not mechanically detectable, so
the rule above is normative and not merely checked.

`SourceProof.key_identity` names the credential a read ran under. For
`mode: "env"` it is `env:<VAR_NAME>` — a name, already in the config. For
`mode: "token_cmd"` it is the full
`token_cmd:<sha256(JCS({argv, env_ref, stdin_ref}))>`: this binds the executed
argv and both named secret channels without storing their values. Command lines
can carry secrets, and these proofs are retained in the evidence vault and the
encrypted recovery plan, so neither the command text nor a truncated identity
is stored.

## 7. Node identity, heartbeats, fork detection (B22.10–B22.11)

- Node key: first-boot generated like the recorder key (0600, kid printed,
  registered hosted-side before ingest).
- **`node.registered`** receipt (`_node` agent): deployment_id, node kid,
  measured_digest (the running package digest), and the current
  `NodeAttestation` (basics plaintext; the signed attestation document
  committed). Without a valid `ISSUED`, in-window attestation the basis is
  `LOG_WITNESSED_SOFTWARE` — never silently upgraded
  (verified-action-v1 §2.4). Witness-grade claims require
  `HARDWARE_ATTESTED` (B22.10); this spec adds no exception.
- **`node.heartbeat`** receipt each sync interval: `epoch` (increments on
  every restart/upgrade), `beat` (dense within epoch), per-source
  `cursor_digest`, spool depth. The heartbeat chain is what makes a CLONED
  key used concurrently/divergently detectable: two beats at one
  (epoch, beat) with different content, cursor regression against the
  recorded chain, or overlapping epochs raise a FORK finding →
  `fork_findings_open` → coverage `GAPPED`. **Exclusive use of an extracted
  key after the original stops produces no divergence and is NOT
  detectable** — stated here, in the threat model, and in every report.
- **`node.upgraded`** receipt (B22.12): binds release/config digests,
  predecessor kid + final heartbeat hash, per-source cursor digests, vault
  root, successor kid, an explicit handover interval, and the
  org-root detached approval (`root_sig`, authority-v1 §2 rule). Blue-green
  runs separate epochs. Emergency replacement without the old key is
  possible via the Organisation Root but raises a CONTINUITY-GAP finding
  that renders. No silent auto-update, no sequence reuse.

## 8. Findings, gaps, recovery (B22.8, B22.13)

- **`evd.finding.raised`** (`_node` agent) — raised by PUBLISHED
  deterministic rules only, never by a person: `rule_id ∈ {cursor_gap,
  cursor_rollback, cursor_reuse, count_mismatch, event_root_mismatch,
  fork_divergence, continuity_gap, algorithm_family_mismatch,
  credential_expired, source_scan_failed, vault_unreadable, mapping_substituted,
  webhook_capture_failed}` (`mapping_substituted`: a scan under a mapping
  version differing from the bound SourceManifest; `source_scan_failed`: a
  no-advance scan with a retained transport/parser/source gap;
  `webhook_capture_failed`:
  a known-source delivery crossed a published capture bound or capture failed
  before durable intake), scope (source, period), evidence
  digests. `finding_id` = the receipt hash (derived, never declared).
- **`evd.finding.triaged`** — a practitioner's SIGNED factual statement:
  finding_id, new state ∈ `RESOLVED_FACTUAL` | `ACCEPTED_LIMITATION`, the
  statement text, practitioner identity + detached signature. A practitioner
  can never declare coverage closed, invent a finding, or waive a hard
  failure (cryptographic gap, fork, invalid signature, open coverage gap);
  coverage changes only by recomputation (B23 implements the recomputation;
  untriaged findings past their window degrade coverage to `UNKNOWN`).
- **`evd.gap.declared`** — the explicit signed gap: scope, period, what is
  unrecoverable and why. Emitted on restore-without-backup, vault
  unreadability, or any zero-SILENT-loss boundary. Coverage for the window
  is `GAPPED`, never `CLOSED`.
- **Recovery**: the customer-controlled durable Evidence Store/backup (the
  Node data dir: store + evidence vault + cursors + key) is a documented
  deployment prerequisite. Restore from it loses nothing (drill-tested).
  Without it, source effects backfill from the source and everything else
  becomes an explicit `evd.gap.declared` — losing the nonce vault is an
  evidenced capability loss (no disclosure for those items), not a
  confidentiality breach.
- **One volume, one tenant.** At first boot the Node atomically binds
  `EVD_NODE_DATA_DIR` to the exact `EVD_TENANT` and corresponding
  `evd://tenant/<id>` origin before it opens the receipt log, state database,
  Node key, or vault. A later boot with another tenant MUST refuse; it must
  never relabel old receipts under a new origin. A populated legacy directory
  with no binding (including SQLite WAL/SHM sidecars) MUST also refuse rather
  than guess. Preserve that directory and restore it under its original tenant
  or perform an explicit supported migration; do not repoint or hand-edit it.

## 9. Honest health (B22.6)

`/evd/health` (Node role) exposes: role, kid, attestation state/basis, spool
depth and age, per-source `ConnectorHealth` verbatim (last cursor + wall
time, lag, consecutive failures, credential validity remaining, declared vs
observed algorithm family, degradation reason), open findings count,
transparency lag (null until B25). A broken evidence plane is LOUD here and
in `swarrm node doctor`, and never blocks the agent.

## 10. New receipt vocabulary (dial rows land with this spec)

`_node` joins the internal-agent allowlist (both verifiers). New
action types — all ordinary `evd/receipt/v1`, no new envelope (rule 10:
an existing receipt type cannot carry them because each binds a distinct
lifecycle document with its own context keys and finding/gap semantics):
`source.batch.recorded` · `node.registered` · `node.heartbeat` ·
`node.upgraded` · `evd.finding.raised` · `evd.finding.triaged` ·
`evd.gap.declared`. Exact plaintext/committed key sets live in
SPEC/context-v1.md rows added in the same commit as the emitters; no verdict
enum changes (the matrix is untouched — B22 produces evidence, B21 already
derives from it).

## 11. Claim boundary

The Node evidences what it ingested, from where, under which cursor
discipline, key and attestation basis. It does not prove source truth,
completeness beyond the stated basis (`INSUFFICIENT` stays `INSUFFICIENT`
for a software Node), or anything about periods it did not scan. Swarrm
never holds the Node's plaintext, credentials, or master secret.
