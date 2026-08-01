// Apache-2.0 (public verifier repo)
//! RFC 9162 §2.1.3.2 / §2.1.4.2 proof verification (verify-only).

use sha2::{Digest, Sha256};

fn node(l: &[u8], r: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update([0x01u8]);
    h.update(l);
    h.update(r);
    h.finalize().into()
}

fn lsb(n: u64) -> bool {
    n & 1 == 1
}

/// RFC 9162 §2.1.3.2 inclusion proof verification.
pub fn verify_inclusion(
    leaf_hash: &[u8],
    leaf_index: u64,
    tree_size: u64,
    proof: &[[u8; 32]],
    root: &[u8],
) -> bool {
    if leaf_index >= tree_size || leaf_hash.len() != 32 {
        return false;
    }
    let mut fnn = leaf_index;
    let mut sn = tree_size - 1;
    let mut r = [0u8; 32];
    r.copy_from_slice(leaf_hash);
    for p in proof {
        if sn == 0 {
            return false;
        }
        if lsb(fnn) || fnn == sn {
            r = node(p, &r);
            if !lsb(fnn) {
                while !lsb(fnn) && fnn != 0 {
                    fnn >>= 1;
                    sn >>= 1;
                }
            }
        } else {
            r = node(&r, p);
        }
        fnn >>= 1;
        sn >>= 1;
    }
    sn == 0 && r.as_slice() == root
}

/// RFC 9162 §2.1.4.2 consistency proof verification.
pub fn verify_consistency(
    first: u64,
    second: u64,
    first_root: &[u8],
    second_root: &[u8],
    proof: &[[u8; 32]],
) -> bool {
    if first > second || first == 0 {
        return false;
    }
    if first == second {
        return proof.is_empty() && first_root == second_root;
    }
    let mut fnn = first - 1;
    let mut sn = second - 1;
    while lsb(fnn) {
        fnn >>= 1;
        sn >>= 1;
    }
    let mut it = proof.iter();
    let seed = match consistency_seed(fnn, first_root, &mut it) {
        Some(s) => s,
        None => return false,
    };
    let (mut fr, mut sr) = (seed, seed);
    for c in it {
        if !consistency_step(c, &mut fnn, &mut sn, &mut fr, &mut sr) {
            return false;
        }
    }
    fnn == 0 && fr.as_slice() == first_root && sr.as_slice() == second_root
}

fn consistency_seed(
    fnn: u64,
    first_root: &[u8],
    it: &mut std::slice::Iter<'_, [u8; 32]>,
) -> Option<[u8; 32]> {
    if fnn != 0 {
        it.next().copied()
    } else {
        let mut a = [0u8; 32];
        if first_root.len() != 32 {
            return None;
        }
        a.copy_from_slice(first_root);
        Some(a)
    }
}

fn consistency_step(
    c: &[u8; 32],
    fnn: &mut u64,
    sn: &mut u64,
    fr: &mut [u8; 32],
    sr: &mut [u8; 32],
) -> bool {
    if *sn == 0 {
        return false;
    }
    if lsb(*fnn) || *fnn == *sn {
        *fr = node(c, &*fr);
        *sr = node(c, &*sr);
        if !lsb(*fnn) {
            while !lsb(*fnn) && *fnn != 0 {
                *fnn >>= 1;
                *sn >>= 1;
            }
        }
    } else {
        *sr = node(&*sr, c);
    }
    *fnn >>= 1;
    *sn >>= 1;
    true
}
