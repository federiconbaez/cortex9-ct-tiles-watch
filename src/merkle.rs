//! RFC 6962 section 2.1 Merkle Tree Hash.

use sha2::{Digest, Sha256};

pub type Hash = [u8; 32];

/// `SHA-256()` of the empty string: the hash of an empty tree.
pub fn empty() -> Hash {
    Sha256::digest([]).into()
}

/// `MTH({d}) = SHA-256(0x00 || d)`.
pub fn leaf_hash(data: &[u8]) -> Hash {
    let mut h = Sha256::new();
    h.update([0u8]);
    h.update(data);
    h.finalize().into()
}

/// `SHA-256(0x01 || left || right)`.
pub fn node_hash(left: &Hash, right: &Hash) -> Hash {
    let mut h = Sha256::new();
    h.update([1u8]);
    h.update(left);
    h.update(right);
    h.finalize().into()
}

/// Merkle Tree Hash over already-hashed nodes, following the recursive
/// definition of RFC 6962 2.1 (split at the largest power of two < n).
/// With leaf hashes as input this is the MTH of the leaves; with subtree
/// roots of equal, power-of-two size it is the root of their concatenation.
pub fn mth_of_nodes(nodes: &[Hash]) -> Hash {
    match nodes.len() {
        0 => empty(),
        1 => nodes[0],
        n => {
            let k = largest_power_of_two_below(n);
            node_hash(&mth_of_nodes(&nodes[..k]), &mth_of_nodes(&nodes[k..]))
        }
    }
}

/// Largest power of two strictly smaller than `n` (n >= 2).
pub fn largest_power_of_two_below(n: usize) -> usize {
    let mut k = 1;
    while k * 2 < n {
        k *= 2;
    }
    k
}

/// Root from the perfect subtrees of a decomposition, left to right.
pub fn fold_subtrees(subtrees: &[Hash]) -> Hash {
    let mut it = subtrees.iter().rev();
    let Some(last) = it.next() else {
        return empty();
    };
    let mut acc = *last;
    for s in it {
        acc = node_hash(s, &acc);
    }
    acc
}
