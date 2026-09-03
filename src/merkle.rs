//! The MeshCore payload merkle tree.
//!
//! Each payload block (2 KiB by default for new application containers) hashes to a 4-byte leaf
//! (`sha2-256:4`); the root is a Merkle-Mountain-Range:
//! leaves are folded into per-level "peaks" like incrementing a binary counter (carry = combine two equal
//! subtrees), then the leftover peaks are bagged **right-to-left** into the final 4-byte root. This must
//! stay byte-identical to `src/helpers/ota/MerkleTree.cpp` in the firmware — the device recomputes the same
//! root to authenticate a fetch, so [`merkle_root`] is pinned by cross-checks against real `.mota` files.

use crate::crypto::mh;

/// 4-byte leaf of one payload block (the last block may be short — no padding).
pub fn leaf(block: &[u8]) -> [u8; 4] {
    mh::<4>(block)
}

/// Combine a left and right subtree hash into their parent (`sha2-256:4(left ‖ right)`).
fn combine(left: &[u8; 4], right: &[u8; 4]) -> [u8; 4] {
    let mut buf = [0u8; 8];
    buf[..4].copy_from_slice(left);
    buf[4..].copy_from_slice(right);
    mh::<4>(&buf)
}

/// Per-block leaves over `payload`, split into `block_size` chunks (the final chunk is short).
pub fn leaf_hashes(payload: &[u8], block_size: usize) -> Vec<[u8; 4]> {
    payload.chunks(block_size).map(leaf).collect()
}

/// The 4-byte merkle root over the block leaves. Empty → all-zero; a single leaf is its own root.
pub fn root(leaves: &[[u8; 4]]) -> [u8; 4] {
    match leaves {
        [] => [0; 4],
        [only] => *only,
        _ => {
            // peaks[k] = root of a complete 2^k-leaf subtree still awaiting a sibling (None = no peak yet).
            let mut peaks: Vec<Option<[u8; 4]>> = Vec::new();
            for &leaf in leaves {
                let mut cur = leaf;
                let mut level = 0;
                while matches!(peaks.get(level), Some(Some(_))) {
                    // carry: the pending peak is the earlier (left) subtree, `cur` the right one.
                    cur = combine(&peaks[level].take().unwrap(), &cur);
                    level += 1;
                }
                if level == peaks.len() {
                    peaks.push(Some(cur));
                } else {
                    peaks[level] = Some(cur);
                }
            }
            // Bag remaining peaks right-to-left: start at the lowest set level (rightmost peak); each higher
            // peak is a larger, further-left subtree, so it joins as the LEFT child of the accumulator.
            let mut peaks = peaks.into_iter().flatten();
            let mut acc = peaks.next().expect("≥2 leaves leaves at least one peak");
            for higher in peaks {
                acc = combine(&higher, &acc);
            }
            acc
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_and_single() {
        assert_eq!(root(&[]), [0; 4]);
        assert_eq!(root(&[[1, 2, 3, 4]]), [1, 2, 3, 4]);
    }

    #[test]
    fn two_leaves_is_a_single_combine() {
        let a = [0xAA; 4];
        let b = [0xBB; 4];
        assert_eq!(root(&[a, b]), combine(&a, &b));
    }

    #[test]
    fn three_leaves_bags_right_to_left() {
        // peaks after folding [a,b,c]: level1 = combine(a,b), level0 = c.
        // bag: acc = c (rightmost), then combine(level1, acc) = combine(combine(a,b), c).
        let (a, b, c) = ([1; 4], [2; 4], [3; 4]);
        assert_eq!(root(&[a, b, c]), combine(&combine(&a, &b), &c));
    }

    #[test]
    fn four_leaves_is_balanced() {
        let (a, b, c, d) = ([1; 4], [2; 4], [3; 4], [4; 4]);
        assert_eq!(
            root(&[a, b, c, d]),
            combine(&combine(&a, &b), &combine(&c, &d))
        );
    }

    #[test]
    fn leaf_hashes_last_block_is_short() {
        let payload = vec![0u8; 1024 + 10];
        let leaves = leaf_hashes(&payload, 1024);
        assert_eq!(leaves.len(), 2);
        assert_eq!(leaves[0], leaf(&payload[..1024]));
        assert_eq!(leaves[1], leaf(&payload[1024..])); // 10 bytes, no padding
    }
}
