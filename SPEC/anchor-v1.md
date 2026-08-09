<!-- Apache-2.0 -->
# evd/anchor v1 — public-chain anchoring of checkpoints

Status: NORMATIVE wire and verification profile. The Evidence Report's
explicit live profile may derive E2 only from a covering Base (`8453`) or Base
Sepolia (`84532`) anchor re-read through the caller-selected RPC **and** an
RFC 3161 token terminating at a TSA root supplied by the relying party.
Carried anchor/timestamp material alone remains a claim, timestamp-only E2
does not ship, and the word "qualified" remains a separate external claim.

## 1. What is anchored, and why the checkpoint `body_hash`

The worker anchors the **checkpoint `body_hash`**: the SHA-256 of the
checkpoint body's canonical JSON (RFC 8785). Not the raw tree root.

The body covers `{schema, origin, tree_size, root_hash, ts, prev_hash}` — so
one 32-byte digest pins the root, the size, the claimed time, AND the link to
the previous checkpoint. Anchoring the root alone would leave size/time/chain
position unattested; anchoring `body_hash` pins the whole statement.

Anchoring attaches to checkpoints, not receipts. That is what makes anchoring
cost O(checkpoints), independent of receipt volume.

## 2. The contract

`anchor/contract/Anchor.sol` — one function `anchor(bytes32 digest)`, one
event `Anchored(bytes32 indexed digest, address indexed sender, uint256
timestamp)`. No owner, no constructor, no upgradability: the contract carries
zero authority. The EVENT is the anchor; the sender address is incidental
(anyone may pay to anchor a digest — a digest anchored by a stranger is still
an anchored digest).

The wire format can name a chain id. The current operated deployment uses Base
Sepolia staging (chainId 84532); no Base-mainnet production claim is made.

## 3. AnchorRecord (wire format, embedded in bundles)

```json
{
  "checkpoint_body_hash": "<hex, no 0x — must equal a chain checkpoint's body_hash>",
  "chain_id": 84532,
  "tx_hash": "0x…",
  "block_number": 123456,
  "block_ts": "2026-07-17T12:34:56Z",
  "contract": "0x…"
}
```

`block_ts` is the claimed block timestamp, RFC 3339 UTC. It supports an
"existed no later than" conclusion only after the transaction, emitting
contract, chain and timestamp are checked against independently selected live
chain state; the carried string alone has no temporal authority.

Bundles (`evd/bundle/v1`) gain an ADDITIVE field `anchor_records`: a list of
records for every checkpoint in `checkpoint_chain` that has one. The field is
absent when nothing is anchored. Verifiers treating unknown fields as opaque
remain correct.

## 4. Offline verification semantics (normative)

1. If `anchor_records` is absent or empty: the bundle verifies at **E1**
   (signed receipts in a consistent checkpointed log). Their absence never
   fails verification. Reports MUST render "not anchored".
2. If `anchor_records` is present, then for EACH record:
   - all six fields MUST be present, and
   - `checkpoint_body_hash` MUST equal the `body_hash` of some checkpoint in
     the bundle's `checkpoint_chain`.
   Any violation → **NOT VERIFIED**. (A bundle claiming anchors it cannot
   bind to its own chain is lying about its evidence level.)
3. Offline verification proves only that the carried records are *internally
   consistent* with the carried checkpoint chain. It cannot prove the tx exists
   on a public chain and MUST NOT award E2 or consume `block_ts` as independent
   time.

## 5. Live verification (`--live`)

Optional, explicit, loud. For each record that passed offline validation,
re-read the transaction from an RPC endpoint and compare EVERY claim and its
canonical-finality context:

1. `chain_id` — the RPC's chain id must equal the record's;
2. tx existence and success (status 1), with the receipt transaction hash
   equal to `tx_hash`;
3. `block_number` — must equal the receipt's block. The receipt MUST carry a
   block hash; a block fetched by that hash and the canonical block fetched by
   number MUST both have the same hash and number;
4. **emitting contract** — an `Anchored` event decoded from the tx counts
   only if its log's emitting address equals `contract` (decoders match on
   event signature from ANY address; the emitter check is what stops a
   lookalike contract from impersonating the real one);
5. event digest — some event from that contract must carry
   `checkpoint_body_hash`. Its transaction hash, block hash and block number
   MUST equal the receipt's;
6. the transaction destination, zero value and calldata MUST be exactly the
   named contract and `anchor(bytes32)` call for `checkpoint_body_hash`;
7. `block_ts` — the block's consensus timestamp must equal the record's
   `block_ts` (this is the field carrying temporal weight; an unchecked
   `block_ts` would allow backdated anchors); and
8. for Base and Base Sepolia, the canonical inclusion block MUST be at or below
   the RPC's `finalized` head. A `safe` or latest block is not a favourable
   confirmation. The local Anvil development profile uses its explicit
   immediate-finality policy but never contributes to E2.

Any mismatch or any network failure → the live check fails (a live check
that cannot complete is a failed live check, not a skipped one). `--live`
composes with `--json` identically — the JSON report gains a `live` object
and the exit code reflects live failures the same as in text mode.

A successful live result establishes those facts relative to the caller's
chosen RPC and chain. The contract address is a checked member of the record:
the live read proves that address emitted the commitment, not that the contract
has any independent authority. The CLI reports the result separately. The
Evidence Report's explicit live mode may derive E2 for a receipt only when a
successfully re-read checkpoint covers that receipt and `chain_id` is Base
mainnet `8453` or Base Sepolia `84532`. A successful local-development or
unknown-chain read remains E1, and an offline report remains E1. Trust in the
RPC/chain selection is an input, not something the bundle can supply about
itself.

Two non-failures, for symmetry with §4.1: a bundle with NO anchor records
under `--live` has nothing to falsify (still valid E1, reported as such);
records that already failed OFFLINE validation are not live-checked — the
bundle is NOT VERIFIED before the network is ever touched.

The offline verifier makes NO network calls without `--live`. This is a hard
guarantee of the public CLI.

## 6. RFC 3161 timestamp claims (§tsa)

The same checkpoint `body_hash` may be anchored on-chain and submitted to an
RFC 3161 timestamp authority. Either operation can fail without affecting the
other. They are not independent trust roots when the bundle supplies its own
chain endpoint, TSA certificates or labels, and neither currently upgrades an
offline report to E2.

### TstRecord (wire format, embedded in bundles)

```json
{
  "checkpoint_body_hash": "<hex, no 0x — the digest in the token's messageImprint>",
  "token_der_b64": "<TimeStampToken (CMS SignedData), DER, base64>",
  "tsa_url": "https://…",
  "gen_time": "2026-07-17T21:38:25Z",
  "cert_chain_pem": "<TSA cert chain, PEM — pinned at issuance>",
  "qualified": false
}
```

Bundles gain an ADDITIVE `tst_records` field (absent when nothing is
timestamped), mirroring `anchor_records`.

### Normative offline verification (NO network)

For each record: (1) it must reference a checkpoint `body_hash` present in
the bundle's chain; (2) the token must parse as CMS SignedData carrying a
TSTInfo; (3) the messageImprint must be SHA-256 of exactly that digest;
(4) the CMS message-digest attribute must match the eContent; (5) the
signature over the signed attributes must verify with the signer certificate
embedded in the token (RSA PKCS#1 v1.5 and ECDSA); (6) the signer certificate
must chain to a SELF-SIGNED root inside the record's `cert_chain_pem`;
(7) genTime must lie within the signer certificate's validity; (8) the
record's display `gen_time` must equal the token's genTime. Any failure →
**NOT VERIFIED**. Absence of `tst_records` never fails a bundle.

A verifier that does not implement every check above MUST treat that record as
**NOT VERIFIED** and MUST NOT consume its claimed `gen_time` as independent
time for an authority or temporal-binding result. Structural checkpoint binding
alone is not timestamp verification.

Out of scope in v1 (documented limitation, not a hidden gap): CRL/OCSP
revocation checking and ESSCertID binding. The pinned chain is the trust
material used for cryptographic validation, but when that chain travels inside
the same bundle it is not an independently supplied TSA trust root. The token
therefore remains a bound claim rather than an E2 award.

### Trust-rooted time — the E2 time leg (NORMATIVE as of B29)

The verification above is the INTEGRITY GATE: it proves the token binds to
this chain and its cryptography is internally coherent. It proves nothing
independent, because `cert_chain_pem` travels in the same unsigned bundle
member the holder edits — a forger can mint a CA, sign a token over a real
checkpoint digest, and ship both (owner audit 2026-08-03; the committed
`evidence_tst_forged_ca` fixture is the counterexample both engines pin).

A timestamp may therefore contribute to an **E2 award** only when the relying
party supplies TSA root certificate(s) OUT OF BAND (`trust["tsa_roots"]`, PEM
values) and the token's signer chains to one of them:

- The carried `cert_chain_pem` may only INTERMEDIATE. Termination is
  byte-exact: the path must reach a certificate DER-equal to a supplied root,
  or one whose issuer is such a root under a verifying signature.
- At every issuer lookup, supplied roots are preferred over carried
  certificates, so a carried certificate wearing a root's SUBJECT can never
  displace the root's KEY.
- This walk is an UPGRADE check and MUST NOT change the bundle verdict: a
  verified token that fails it stays a claim (E1), and no supplied roots
  means no award — never an error.

Both engines implement the walk identically (`verify/tsa.py`,
`verify-rs/src/tsa.rs`) and agree on the shared fixtures
(`expected_evidence.json`).

The full E2 award additionally requires the anchor leg: a live chain re-read
(§5) of an anchor record on a checkpoint covering the receipt's leaf. Offline
material alone — however verified — never renders E2.

### The "qualified" labeling rule (claims ≤ mechanism)

`qualified: true` is an OPERATOR CLAIM that the issuing TSA is on the EU
trusted list. The offline verifier cannot check trust-list membership, so no
input awards a qualified-timestamp label. It verifies the bound token
cryptography and reports the TSA URL plus the claimed field for explicit
out-of-band review; a renderer MUST NOT turn that producer boolean into a
qualified check or badge. freeTSA/dev/staging output is non-qualified. TSA
outage = skip and retry next cycle; it never blocks checkpointing or anchoring.

## 7. Worker semantics

- Async decoration: ingestion and checkpointing never wait on the chain.
- Idempotent: one anchor row and at most one immutable submission journal per
  checkpoint `body_hash`. An existing row or journal whose exact fields differ
  is a conflict and MUST fail closed; "first write wins" MUST NOT hide it.
- Before any broadcast, the client prepares and signs one transaction and the
  store durably records its canonical raw bytes plus the redundant transaction
  hash, nonce, chain id and checkpoint digest. The journal advances only from
  `PREPARED` to `SIGNING_IN_FLIGHT`; uncertainty never returns it to an
  unprepared state.
- Every retry, process restart and ambiguous provider failure queries or
  rebroadcasts those exact signed bytes. It MUST NOT allocate another nonce,
  rebuild fees, sign a replacement or call the compatibility one-shot send
  while that journal exists.
- `control.db` is the authoritative signer-wide ledger. Its immutable attempt
  core is keyed by `(chain_id, signer_address, nonce)` and binds the scope,
  checkpoint digest, exact raw transaction and transaction hash. Every state
  transition is also appended to an immutable event table; terminal nonce
  history is never deleted. A new nonce is
  `max(RPC pending nonce, durable signer high-water + 1)`, subject to the
  confirmed/pending sanity ceiling. The per-store journal is committed first,
  then the identical central attempt is reserved, and only then may egress
  occur. A crash at either boundary is reconciled from those exact bytes.
  Before the first post-migration send, every store is inspected signer-wide.
  Each legacy row is exactly revalidated to a stable finalized chain view and
  its mined signer, nonce, checkpoint, transaction and block identities are
  imported into an immutable central nonce fence before local promotion. The
  durable high-water includes those fences; any remaining legacy row defers all
  new egress rather than trusting a stale RPC nonce.
- A receipt first creates an internal `OBSERVED` state. The receipt transaction
  hash and block hash, the block fetched both by hash and number, the exact
  transaction and every accepted event are bound as in §5. Base/Base Sepolia
  remain non-exportable until that canonical block is at or below the RPC's
  `finalized` head. A pre-finality reorganisation is an append-only reorg event
  and returns the exact transaction to broadcast recovery; it never creates an
  `AnchorRecord`.
- Only a finalized status-1 exact anchor becomes the six-field wire
  `AnchorRecord`. Persisting that finalized projection and retiring its local
  journal is one local transaction. Historical rows created by the former
  one-receipt policy remain retained with `finalized=0` and MUST NOT count as
  coverage, appear in status, or be exported until exact revalidation promotes
  them.
- A status-0 receipt or status-1 receipt without the exact contract event is
  terminal only after its inclusion is canonical and finalized. The central
  ledger records `REVERTED` or `SUCCEEDED_NO_ANCHOR`, including the observed
  block and finalized-head identities; the local journal is then retired and a
  fresh nonce may retry the checkpoint. A missing transaction, timeout or age
  alone never proves drop or replacement and remains blocking. A foreign
  same-nonce replacement may terminalize only with its finalized canonical
  transaction proof: the explicit operator path verifies its receipt, sender,
  exact nonce, canonical block and stable finalized head. A nonce count alone
  is never proof. Signer recovery from the retained raw transaction permits
  closed-attempt cleanup after key rotation without restoring the old secret;
  an unresolved attempt still requires the configured key to match.
- A concurrency loser reuses the winner's journal and never broadcasts a
  second transaction. In production, only the all-store scheduler may operate
  the shared EVM signer; the legacy single-store command refuses before opening
  state. While holding every configured state-root lock, the scheduler performs
  a bounded read-only prescan of every store before any anchor egress. Exactly
  one retained canonical journal is recovered first regardless of target order;
  multiple or corrupt journals block all anchor egress. If a submission leaves
  an unresolved journal, no later store may prepare a transaction in that cycle.
  TSA processing remains independent. These signer-wide rules, not mere
  sequential iteration, prevent different store journals from allocating the
  same account nonce.
- A successful tx that emits no `Anchored` event from the configured
  contract is an ERROR (wrong `EVD_ANCHOR_CONTRACT`), never silently
  treated as anchored.
- The operated chain is selected from the closed mapping `base` → `8453`,
  `base-sepolia` → `84532`, or explicit local-development `anvil` → `31337`.
  The live RPC chain id MUST equal that mapping before signing or submitting.
- A prepared anchor is an EIP-1559 type-2 transaction with an empty access list
  and the exact `anchor(bytes32)` destination, zero value and calldata. Blob,
  set-code/authorization-list, legacy and extra transaction fields are refused
  both before signing and before every submission. The v1 producer defaults to
  gas `100000`, priority fee `100000000` wei/gas and maximum fee `5000000000`
  wei/gas. Even a configured producer cannot exceed gas `250000`, priority fee
  `10000000000`, maximum fee `100000000000`, or signed execution-fee exposure
  `10000000000000000` wei (`gas * maxFeePerGas`); the active configured values
  are re-applied during journal recovery. The single-purpose signer defaults
  to nonce ceiling `10000000` (hard maximum `1000000000`) and refuses a pending
  nonce more than `32` ahead of confirmed state (hard configurable maximum
  `1024`), in addition to the EVM `0..2^64-2` range. RPC estimates and fee
  suggestions never expand this profile.
- The signing key is a burner holding faucet/dust funds only, supplied via
  env (`EVD_ANCHOR_PRIVATE_KEY`), never a file in the repo.
