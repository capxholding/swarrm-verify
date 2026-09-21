<!-- Apache-2.0 — this file ships with the public verifier repo. -->

# SPEC: node-v1 — Customer Evidence Node

**Status: NORMATIVE (v1).** The Node is ONE private, out-of-path component in
the customer's boundary. It receives agent receipts
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
  "https_feed"|"signed_webhook"|"emulator"|"bulk_file"|"log_stream",
  "base_url"?, "auth": {"mode": "env"|"token_cmd", "ref", "stdin_ref"?},
  "cursor_param"?, "page_size"?, "drop_path"?, "field_map"?,
  "filename_glob"?, "landing"?, "prefix"?, "enumeration"?,
  "event_key_field", "mapping_version", "correlation_field"?,
  "material_fields": [..], "identity": SourceIdentity } ] }`.
  A `bulk_file` source names a local landing `drop_path` plus a declarative
  `field_map` (shipped: `camt053-v1`, which also supplies the event-key /
  mapping / correlation / material defaults when the config omits them); it
  declares NO `auth` — no credential exists for a directory the customer's
  own process drops into, and configuring one is refused at load.
  A `log_stream` source instead declares `landing: {"store": "filesystem",
  "root"}`, `prefix`?, `field_map`, and a REQUIRED `enumeration`; it takes no
  `auth`, no `base_url` and no per-source mapping fields — the field map owns
  the mapping (§4).
  Config profile `node` (core/config.py) adds: `EVD_NODE_CONFIG` (required),
  `EVD_NODE_KEY_FILE`, `EVD_NODE_MASTER_KEY` / `EVD_NODE_MASTER_KEY_FILE`,
  `EVD_NODE_DATA_DIR`, `EVD_NODE_SCAN_INTERVAL`, `EVD_TENANT`. Local demo may
  default `EVD_TENANT` to `t_dev`; a deployed Node MUST set it explicitly
  before the data directory's first boot.
- **One diagnostic command**: `swarrm node doctor` — effective config,
  master-key mode (dev file-key mode prints a NON-PRODUCTION banner), per
  source: reachability, auth mode, cursor capability, last complete cursor,
  lag, spool depth/age, key/attestation state.

## 2. Customer vault

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

## 3. Durable intake

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

## 4. Connectors and emulator

`node/connectors.py` implements the frozen connector interface:
`authenticate() -> SourceIdentity`, `scan(cursor) -> SourceBatch` (events +
per-event and batch proofs), `normalise(raw) -> SourceEvent`,
`verify_source_proof(raw) -> SourceProof | None`, `health() ->
ConnectorHealth`. Vendor auth/pagination/mapping stay in the connector;
reconciliation and verification contain no vendor branch.
- **DeclarativeHttpsConnector** — config-driven paginated full-feed read
  (GET base_url + cursor/page params; `authenticated_read_transcript`
  SourceProof over the response, digest-addressed). It accepts only identity or
  gzip content encoding and streams raw bytes before decoding: one page is at
  most 2 MiB / 1,000 events, one scan at most 16 MiB / 10,000 events, JSON depth
  32 / 20,000 values, any text value 64 KiB and any cursor 4 KiB. Duplicate
  keys, floats, out-of-range integers, concatenated/invalid gzip and a crossing
  of any cumulative limit produce an explicit scan gap; none is retained as a
  valid page.
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
  An inbound source MUST NOT use `auth.mode = "token_cmd"`: verification of
  attacker-selected requests never has authority to launch a credential
  subprocess. HMAC webhooks use an environment-backed secret, resolved at
  delivery time and never stored; asymmetric webhooks use only their
  pre-bound public source key.
  **Replay:** every admitted delivery is bound to three durable
  identities — its raw digest, its canonical-body digest, and its configured
  immutable delivery id — in a bounded per-source seen-set written in the
  same transaction as intake; an exact retry acknowledges idempotently, a
  reused delivery id over different bytes is a `409` conflict, and a
  non-expiring tombstone preserves the id→raw binding after the active cache
  is pruned. **Clock skew:** a source config may name `delivery_time_field`,
  a body field carrying the Z-suffixed RFC 3339 send time of THIS delivery
  attempt; when named, deliveries outside the fixed ±300 s window
  (`MAX_WEBHOOK_CLOCK_SKEW_S`, a protocol ceiling, not a tunable) are refused
  before signature work, and a missing/malformed timestamp is refused too. A
  sender retries by re-signing a fresh timestamp; the immutable delivery id
  keeps the retry idempotent. A config naming no field has NO time bound —
  replay refusal then rests solely on the finite seen-set retention.
  **Enumeration:** a signed_webhook source is bound to
  `enumeration: "PUSH_INDIVIDUAL_EVENTS"` in its validated manifest and a
  config declaring any other value is refused: a push feed of individual
  events cannot prove its own population — a silently dropped delivery is
  indistinguishable from a quiet hour — so webhook-only coverage is
  `GAPPED`/`UNKNOWN` at best and never `CLOSED`. Coverage assembly
  (`node/coverage.py`) copies a declared `enumeration` into the signed
  coverage document, so a manifest that states the bound produces documents
  that state it too; `swarrm node doctor` prints the standing ceiling line. **Ingress boundary:** bind private-only;
  when TLS terminates at one reverse proxy, `EVD_NODE_TRUSTED_PROXY_CIDRS`
  names its narrow CIDRs (1..32, never prefix `/0`) and the proxy must
  overwrite `X-Forwarded-For` with one client IP — a repeated header, a comma
  chain, or a non-address from a trusted proxy is refused with a static
  `webhook_forwarded_chain` 400 that mints no state, while forwarded headers
  from every other peer are ignored (docs/NODE.md).
  subprocess. HMAC webhooks use an environment-backed secret; asymmetric
  webhooks use only their pre-bound public source key.
- **BulkFileConnector** (`node/bulk_file.py`) — a watched local
  landing directory of statement files the customer's existing process
  already delivers (SFTP, an S3 sync, a bank portal export), mapped by a
  declarative field map (shipped: ISO 20022 `camt.053` as `camt053-v1`).
  Ordering is by DECLARED statement period, never arrival; the durable
  cursor is over periods (`<period_end>#<sequence>`), not rows. Per-file
  idempotency: an identical file redelivered inside one scan is excluded by
  content digest, and one redelivered after its period was consumed is
  excluded by the period cursor — never double-counted. The cursor format is
  unchanged and carries no balance: before an advancing scan verifies
  cross-period continuity, it MUST re-derive the unique statement matching
  the stored cursor from the same bounded landing snapshot and compare that
  statement's verified closing balance with the first new opening balance.
  If the cursor statement is absent, ambiguous, lacks a closing balance or
  fails its own statement checks, the batch MUST carry a
  `balance_chain_predecessor_*` gap and `population_proof.verified` MUST be
  false. Existing cursors therefore remain accepted without migration, but
  cannot silently verify continuity after their predecessor was archived.
  The landing path MUST be opened without following symlinks and its directory
  descriptor MUST remain pinned across enumeration and all member opens. Each
  member MUST be a single-link regular file opened relative to that descriptor;
  symlinks and hard links fail closed, while path replacement cannot redirect
  an admitted scan to a different directory inode. Ceilings: one file
  16 MiB, one scan 64 MiB / 256 files / 20,000 entries, XML depth 64 /
  200,000 nodes, any text value 64 KiB; DTD/entity constructs are refused
  outright before parsing. A member that cannot be mapped to a declared
  period (unparseable, over-limit, foreign account) makes the directory
  unorderable: that scan ingests NOTHING, keeps its cursor, retains every
  read byte as evidence and surfaces an explicit gap. Statement structure is
  checked, never repaired: the OPBD→CLBD balance identity, `ElctrncSeqNb`
  continuity and declared entry counts pass through as gaps; the batch
  records `population_proof` (kind `camt053_statement_balance`,
  `source_scope_defined: true`). HONESTY BOUNDS, stated not engineered
  around: a dropped file proves WHAT was read, never FROM WHOM — every
  advancing batch carries an `unauthenticated_file_origin:` gap (coverage
  denies `authenticated_read`; the period renders `GAPPED`, the Node never
  claims it OBSERVED an unauthenticatable source), every SourceProof is
  `verified: false`, and a MISSING LATEST statement is undetectable — a
  directory cannot prove that no newer statement exists.
- **LogStreamConnector** (`node/log_stream.py`) — intake shape (d):
  an object-store landing zone the customer's audit-log stream already
  writes into, read as declarative config plus a per-vendor field map
  (`cloudtrail-v1` ships; a map names `records_path`, the event key, time,
  outcome and material mappings, and its normalisation rule: every mapped
  value is the exact decoded JSON string, verbatim — byte-exact,
  case-sensitive, never trimmed). The durable cursor is the last CONSUMED
  object key in exact S3 ListObjectsV2 order (lexicographic ASCII,
  `start_after` exclusive); `FilesystemObjectStore` implements the two-method
  list/read interface locally, and a native S3 client is a drop-in behind it
  (the `s3` store id is refused at load while no such client exists — a
  mounted bucket satisfies it). ENUMERATION IS DECLARED, NEVER ASSUMED:
  configuration REFUSES a source without `enumeration` and refuses
  `source_proven_population` while no vendor population mechanism
  (e.g. CloudTrail digest-chain validation) exists; the
  batch never carries `population_proof`, so coverage basis stays
  `INSUFFICIENT` and can never reach `CLOSED` from this shape. A consuming
  batch always carries an `unauthenticated_read:` gap and each object proof
  is an `authenticated_read_transcript` with `verified=false` — a
  landing-zone read authenticates nothing about origin. Hostile-input
  ceilings, enforced before parsing or evidence writes: one object 2 MiB
  raw / 8 MiB decoded (single-member gzip only); one scan 64 objects,
  16 MiB, 10,000 records; 1,000 records per object; keys ASCII ≤ 1 KiB with
  no dot/empty segments; JSON limits identical to the declarative feed page.
  Redelivered object bytes are an explicit `duplicate_object:` exclusion
  in-scan; cross-scan redelivery deduplicates by `event_key` at
  reconciliation. An invalid or unreadable object stops the scan BEFORE
  advancing past it — an explicit gap, never a silent skip. A filesystem
  landing source holds no credential and adds no egress authority.
- **Corporate egress records** (`proxy-cef-v1`) arrive through
  that same sink and are a SOURCE, never a fifth door: we do not author them,
  they have no integrity before ingest, and they are reconciled like any
  other book — a connection to a provider with no receipt against it is
  `ORPHAN`, identical in shape to a bank line with no receipt. The map reads
  an ArcSight-CEF connection line (Zscaler-class broker / forward proxy) and
  takes CONNECTION FACTS ONLY: `dhost` → `counterparty`, `dst` →
  `reference`, `rt` → `source_effect_time`, and the broker's verdict `act` →
  `outcome` through a map-declared `outcome_ok_values` closed set (a proxy
  writes a verdict on every line, so absence of an error is not consent, and
  an unrecognised verdict reads as refused). Payload-bearing CEF keys are not
  mapped and never read; octet counts stay in the retained raw object rather
  than on the event, because the only SourceEvent magnitude field (`value`)
  is in the NORMATIVE material floor and a byte count there would make every
  honest match UNCOMPARABLE. **It proves connections, not content** — bounds
  in `docs/THREAT_MODEL.md` under "the agent takes a road with no door",
  not restated here. **Enumeration is the rung**: `enumeration` declares
  which rung of the egress observation ladder produced the book
  (`egress_point_enforced` · `landing_zone_only` · `unknown`); NONE of them
  is a proven population, so every consuming batch carries an
  `egress_enumeration_not_proven:<declared>` gap, and a batch gap derives
  coverage `GAPPED` in both engines — an egress source can therefore never
  reach `CLOSED`, whatever the Node's integrity basis. Egress evidence moves
  no provenance level in either direction; only `linkage`/`outcome` (which
  is this source's whole purpose) and a downward coverage move.
- **Emulator** (`node/emulator.py`) — ships WITH the Node: an in-process
  deterministic fake source (fixed seed; cursor pages; Ed25519-signed or MAC
  modes; injectable gaps/rollbacks/duplicates; a deterministic `camt.053`
  statement writer for `bulk_file` landing directories) so the whole loop
  runs before any real credential exists, and so chaos tests are
  reproducible.
- **Autodiscovery**: `swarrm node discover <base_url>` probes known feed
  shapes, then prompts for exactly the facts nobody can infer — the source
  identity (`source_system`/`account`/`declared_controller`), the declared
  control domain (default `UNKNOWN`, NEVER inferred), the pre-bound signing
  kid and the credential env var — and emits a config that passes preflight
  with no hand-editing (`--out` writes it). Probed fields stay DRAFT guesses
  the reviewer corrects; `--non-interactive` prints the raw DRAFT manifest
  with its `FILL_IN` markers exactly as before.
  **Templates**: `"template": "<name>"` in a source config fills the
  format-determined fields (`event_key_field`, `correlation_field`,
  `material_fields`, `cursor_param`, `page_size`, `mapping_version`,
  `kind`) from a named registry entry (`node/templates.py`; first entry
  `camt053-v1`), leaving only URL, credential ref and identity per
  customer. An explicitly configured key always wins; an unknown template
  name fails configuration.
  **Pre-flight**: `swarrm node preflight` checks five readiness facts
  (dedicated service identity declared · signing source · cursor-capable
  feed · writable correlation field · no configured secret value detected in
  token argv) and prints an honest report in which every FAIL line names the
  exact command or config key that fixes it. The fifth check cannot detect a
  hard-coded secret value that the config does not name (§6).
- **Read-only law**: connector config declaring any write/execute
  credential scope fails configuration (mechanical check at load).

## 5. Egress allow-list

All Node outbound goes through one guarded client (`node/egress.py`): the
allow-list is derived from config (source base_urls for reads; `hosted_url`;
opt-in anchor RPC / TSA when set) and any other host raises
`EgressDenied` before a connection is attempted. Only signed commitments,
permitted provenance, health and transparency submissions leave the
boundary. The Node sentinel test drives sentinel bytes through
payloads, nonces AND credentials and asserts none appear in any outbound
request or in hosted storage.

## 6. Credentials never at rest

`auth.mode = "env"`: the credential lives in the named env var, read at scan
time, never written to disk, receipts, logs, config or support bundles.
`auth.mode = "token_cmd"`: for outbound feed scans only, a customer-supplied
command mints a short-lived token per scan. Signed-webhook sources reject this
mode at configuration load. The Node data dir and config contain no credential
bytes (test-proven with a credential sentinel). Lost credentials degrade
`ConnectorHealth` (which degrades COVERAGE); they never block execution.
The helper receives a scrubbed, explicitly allowed environment and at most
64 KiB on stdin. Its process group is killed after ten seconds or once stdout
crosses 16 KiB; stderr is discarded, output must reduce to one non-empty
visible-ASCII bearer value, and no captured secret bytes enter exceptions.

**A token command's argv is world-readable.** The command runs with
`shell=False` and a list argv — that stops shell metacharacters in a config
value being interpreted and removes the extra `sh -c` process, but it does NOT
hide the arguments: every process's arguments are readable by any local user
through `ps auxww` and `/proc/<pid>/cmdline`, and the argv is what process
accounting and container runtimes record. A secret written inline in the
command (`vault-helper --token=hvs.CAESIJ…`) is therefore disclosed on every
scan. Secret material reaches a token command by exactly two channels:

- **environment** — `auth.env_ref` and `auth.env_allow` explicitly name the
  variables copied into the otherwise scrubbed helper environment;
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

## 7. Node identity, heartbeats, fork detection

- Node key: first-boot generated like the recorder key (0600, kid printed,
  registered hosted-side before ingest).
- **`node.registered`** receipt (`_node` agent): deployment_id, node kid,
  measured_digest (the running package digest), and the current
  `NodeAttestation` (basics plaintext; the signed attestation document
  committed). Without a valid `ISSUED`, in-window attestation the basis is
  `LOG_WITNESSED_SOFTWARE` — never silently upgraded
  (verified-action-v1 §2.4). Witness-grade claims require
  `HARDWARE_ATTESTED` (the Node-integrity measurement basis, §7 above); this
  spec adds no exception.
- **`node.heartbeat`** receipt each sync interval: `epoch` (increments on
  every restart/upgrade), `beat` (dense within epoch), per-source
  `cursor_digest`, spool depth. The heartbeat chain is what makes a CLONED
  key used concurrently/divergently detectable: two beats at one
  (epoch, beat) with different content, cursor regression against the
  recorded chain, or overlapping epochs raise a FORK finding →
  `fork_findings_open` → coverage `GAPPED`. **Exclusive use of an extracted
  key after the original stops produces no divergence and is NOT
  detectable** — stated here, in the threat model, and in every report.
- **`node.upgraded`** receipt (upgrade and key handover): binds
  release/config digests,
  predecessor kid + final heartbeat hash, per-source cursor digests, vault
  root, successor kid, an explicit handover interval, and the
  org-root detached approval (`root_sig`, authority-v1 §2 rule). Blue-green
  runs separate epochs. Emergency replacement without the old key is
  possible via the Organisation Root but raises a CONTINUITY-GAP finding
  that renders. No silent auto-update, no sequence reuse.

## 8. Findings, gaps, recovery

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
  coverage changes only by recomputation (reconciliation implements the
  recomputation, SPEC/reconcile-v1.md;
  untriaged findings past their window degrade coverage to `UNKNOWN`).
- **`evd.gap.declared`** — the explicit signed gap: scope, period, what is
  unrecoverable and why. Emitted on restore-without-backup, vault
  unreadability, or any zero-SILENT-loss boundary. Coverage for the window
  is `GAPPED`, never `CLOSED`.
- **Recovery**: the customer-controlled durable Evidence Store/backup (the
  Node data dir: store + evidence vault + cursors + key) is a documented
  deployment prerequisite. A restore succeeds only when the drill verifies the
  semantic contents of every critical database and retained evidence object;
  partial or skipped restoration is failure. Without a usable backup, source
  effects may be backfilled where the source still exposes them and everything
  else becomes an explicit `evd.gap.declared` — losing the nonce vault is an
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

## 9. Honest health

`/evd/health` (Node role) exposes: role, kid, attestation state/basis, spool
depth and age, per-source `ConnectorHealth` verbatim (last cursor + wall
time, lag, consecutive failures, credential validity remaining, declared vs
observed algorithm family, degradation reason), open findings count,
transparency lag (null until transparency registration ships). A broken evidence plane is LOUD here and
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
enum changes (the matrix is untouched — the Node produces evidence, the
verdict engine already derives from it).

## 11. Claim boundary

The Node evidences what it ingested, from where, under which cursor
discipline, key and attestation basis. It does not prove source truth,
completeness beyond the stated basis (`INSUFFICIENT` stays `INSUFFICIENT`
for a software Node), or anything about periods it did not scan. Swarrm
never holds the Node's plaintext, credentials, or master secret.
