// Apache-2.0 (public verifier repo)
//! RFC 9162 §2.1.3.2 / §2.1.4.2 bounds and path-length invariants.
//!
//! Two engines, one verdict: every vector below is duplicated verbatim in
//! tests/test_merkle_bounds.py and both engines must return the same answer.
//! `merkle` is pub(crate), so — the house pattern from cose_canonical.rs — the
//! module is compiled directly via `#[path]`.

#[path = "../src/merkle.rs"]
#[allow(dead_code)]
mod merkle;

use merkle::{verify_consistency, verify_inclusion};

/// Same vectors as tests/test_merkle_bounds.py. Both engines must return
/// the same verdict for every tuple here; that is the two-engine contract.
fn h(s: &str) -> [u8; 32] {
    let mut out = [0u8; 32];
    for (i, b) in out.iter_mut().enumerate() {
        *b = u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).unwrap();
    }
    out
}

const ROOT1: &str = "305df59f9590c3c9ac63d2b2743c388e3792449078cebf7fb3dbe6471643b2b7";
const ROOT2: &str = "60a53eed0de87a90c8e59427c59c46253c33a76a09502a51801300927b7e6bdc";
const ROOT3: &str = "cf763a041c81ceef1578a6083f75c61bef2e0014f2a3e683a97fcfca5be7f19a";
const ROOT8: &str = "ca6b7b3e674ac86c1027b59c87c064fc3bc27b313294c75f83bd05fdd13f0dcf";
const P1_3: [&str; 2] = ["3145c409f259b7c53e32036090ff76751025a2498ba9823ef718cac50b4e616f", "fca89f57c9f8c8eb4047a7ff9d333acf9e0f3384b20b255bceab0f216dcca267"];
const P1_8: [&str; 3] = ["3145c409f259b7c53e32036090ff76751025a2498ba9823ef718cac50b4e616f", "bd45ff28796704d88bdac51b1df553fda59837b616d6d1cb2114dbc3b087ff69", "f58aaab46122102d66b00c5eb50b13dd763b5f800139b424fda8b1cacae1408a"];

fn hexes(v: &[&str]) -> Vec<[u8; 32]> {
    v.iter().map(|s| h(s)).collect()
}

/// A truncated consistency path must fail. `first` is a power of two here,
/// so step 3 drives fn to 0 before the loop even starts and the old
/// `fn == 0` terminal test could never fire. Folding only the first hash
/// of the (1,3) proof leaves sr holding the size-2 root, which the forger
/// then presents as the size-3 root.
#[test]
fn truncated_consistency_path_rejected() {
    assert!(!verify_consistency(1, 3, &h(ROOT1), &h(ROOT2), &hexes(&P1_3[..1])));
    assert!(!verify_consistency(1, 8, &h(ROOT1), &h(ROOT2), &hexes(&P1_8[..1])));
    // and the whole path dropped, leaving only the prepended first_root
    assert!(!verify_consistency(1, 3, &h(ROOT1), &h(ROOT1), &[]));
}

/// The honest proofs next door must still verify.
#[test]
fn genuine_consistency_still_accepted() {
    assert!(verify_consistency(1, 3, &h(ROOT1), &h(ROOT3), &hexes(&P1_3)));
    assert!(verify_consistency(1, 8, &h(ROOT1), &h(ROOT8), &hexes(&P1_8)));
    assert!(verify_consistency(7, 8, &h("0b007fb915eb9b2a146f54b1c86ec53b664f8e455b7660b0b6ee13edc0d921c0"), &h(ROOT8), &hexes(&["676f3782f5b3a5fb4370ed49572cedc523f4a66322269c85f2af0509d17b0a4d", "060242692909024231d050c5d4434146ba77da322d450286f577c9f951615d53", "985bb5d36b927800876871da925a7e82abe83a9ddba5882920a007a55ea2b376", "bdd1c5ff55b19cb6b0e7c761bf9a6ccaa27fbbfc07b74f1fabb6e911a0bd2ab3",]),));
    assert!(verify_consistency(4, 8, &h("bdd1c5ff55b19cb6b0e7c761bf9a6ccaa27fbbfc07b74f1fabb6e911a0bd2ab3"), &h(ROOT8), &hexes(&["f58aaab46122102d66b00c5eb50b13dd763b5f800139b424fda8b1cacae1408a"]),));
    assert!(verify_consistency(3, 3, &h(ROOT3), &h(ROOT3), &[]));
}

/// Companion to the Python negative-index guard. A relabelled leaf_index
/// never survives JSON -> u64 in lib.rs (it lands as the u64::MAX
/// sentinel), and no u64 index at or past tree_size is accepted either.
#[test]
fn out_of_range_leaf_index_rejected() {
    let proof = hexes(&P1_8);
    assert!(verify_inclusion(&h(ROOT1), 0, 8, &proof, &h(ROOT8)));
    assert!(!verify_inclusion(&h(ROOT1), u64::MAX, 8, &proof, &h(ROOT8)));
    assert!(!verify_inclusion(&h(ROOT1), 8, 8, &proof, &h(ROOT8)));
    assert!(!verify_inclusion(&h(ROOT1), 0, 0, &proof, &h(ROOT8)));
}
