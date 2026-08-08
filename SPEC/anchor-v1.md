<!-- Apache-2.0 -->
# evd/anchor v1 — public-chain anchoring of checkpoints

Status: NORMATIVE wire and verification profile. The E2 and qualified-timestamp
assurance labels are withdrawn; carried anchor/timestamp material is rendered
as a claim unless its external trust inputs are supplied independently.

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
re-read the transaction from an RPC endpoint and compare EVERY claim,
normatively all six:

1. `chain_id` — the RPC's chain id must equal the record's;
2. tx existence and success (status 1);
3. `block_number` — must equal the receipt's block;
4. **emitting contract** — an `Anchored` event decoded from the tx counts
   only if its log's emitting address equals `contract` (decoders match on
   event signature from ANY address; the emitter check is what stops a
   lookalike contract from impersonating the real one);
5. event digest — some event from that contract must carry
   `checkpoint_body_hash`;
6. `block_ts` — the block's consensus timestamp must equal the record's
   `block_ts` (this is the field carrying temporal weight; an unchecked
   `block_ts` would allow backdated anchors).

Any mismatch or any network failure → the live check fails (a live check
that cannot complete is a failed live check, not a skipped one). `--live`
composes with `--json` identically — the JSON report gains a `live` object
and the exit code reflects live failures the same as in text mode.

A successful live result establishes those facts relative to the caller's
chosen RPC and configured contract. The CLI reports it separately. The
Evidence Report's explicit live mode may derive E2 for a receipt only when a
successfully re-read checkpoint covers that receipt; an offline report remains
E1. Trust in the RPC/chain selection is an input, not something the bundle can
supply about itself.

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
- Idempotent: one anchor row per checkpoint body_hash (UNIQUE constraint;
  the worker checks before sending, first write wins).
- The anchor row is written only after 1 on-chain confirmation with a
  successful status — no partial rows.
- Bounded retry of the CHAIN SEND only (3 attempts, 1s/4s backoff), then
  exit 0: the cron rerun is the retry loop. A tx that confirmed but whose
  store write failed is never re-sent in the same run (that would burn gas
  re-anchoring the same digest); the next cycle re-anchors.
- A successful tx that emits no `Anchored` event from the configured
  contract is an ERROR (wrong `EVD_ANCHOR_CONTRACT`), never silently
  treated as anchored.
- The signing key is a burner holding faucet/dust funds only, supplied via
  env (`EVD_ANCHOR_PRIVATE_KEY`), never a file in the repo.
