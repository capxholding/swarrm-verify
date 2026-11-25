<!-- Apache-2.0 -->
# RFC 4998 Evidence Record Syntax — comparison (INFORMATIVE)

Status: INFORMATIVE. One page so subsequent maintenance does not re-derive
whether Swarrm is an ERS encoding. It is not. Swarrm now supports an additive,
offline timestamp-renewal chain without changing receipt or checkpoint bytes.

## 1. What ERS is

RFC 4998 Evidence Record Syntax binds a document to a sequence of
archive timestamps so that hash-algorithm ageing can be survived by
*renewing* the timestamp over a new hash of the old evidence record.
The unit is a preserved object plus its timestamp chain.

## 2. What Swarrm is

Swarrm binds **actions** to an RFC 6962 log of salted commitments, with
optional RFC 3161 / RFC 5816 tokens (non-qualified) on checkpoints and
optional SCITT receipts on those checkpoints. The unit is a receipt in
an append-only log, not an ERS archive object.

| ERS idea | Swarrm analogue | Divergence |
|---|---|---|
| Archive timestamp over a data object | RFC 3161 token over a checkpoint `body_hash` | Checkpoint, not document; tokens are non-qualified |
| Hash-tree reduction of many objects | RFC 6962 Merkle tree of receipts | Different tree profile (CT, not ERS) |
| Retained signer status | Offline CRL or direct-issuer OCSP evidence at token `genTime` | Separate relying-party trust material; no network fetch |
| Timestamp renewal when a hash ages | `evd/tsa-renewal-chain/v1` over the exact predecessor evidence | Separate trust input; receipt and checkpoint bytes remain unchanged |
| ERS ASN.1 encoding | Not used | DSSE / COSE / CBOR on the trust path |

## 3. Inherit or diverge

Diverge on encoding (no ERS ASN.1, no new verifier union). Inherit the
*requirement* that long-term verifiability needs renewal when an earlier hash
or signer approaches the end of its useful life. `SPEC/anchor-v1.md` defines
the versioned chain: each new RFC 3161 token hashes the exact prior token,
carried chain and offline status evidence, verifies under independently
supplied roots and has a strictly later `genTime`. This is timestamp renewal,
not a hybrid signature on the wire and not a claim that Swarrm emits ERS.
