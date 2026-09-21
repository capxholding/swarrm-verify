<!-- Apache-2.0 -->
# RFC 4998 Evidence Record Syntax — comparison (INFORMATIVE)

Status: INFORMATIVE. One page so the next session does not re-derive
whether Swarrm is an ERS encoding. It is not. Timestamp **renewal** is
the non-breaking post-quantum story; it is not implemented here.

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
| Timestamp renewal when a hash ages | Not implemented | The written PQ story: renew timestamps without changing the receipt bytes |
| ERS ASN.1 encoding | Not used | DSSE / COSE / CBOR on the trust path |

## 3. Inherit or diverge

Diverge on encoding (no ERS ASN.1, no new verifier union). Inherit the
*requirement* that long-term verifiability needs a renewal story when
SHA-256's calendar changes. That story is timestamp renewal, not a
hybrid signature on the wire, and it waits for a later train.
