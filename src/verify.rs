//! Content-integrity verification of a `.mota` container.
//!
//! Recomputes the per-block leaves from the payload, the merkle root, the full-image hash, and (if signed)
//! the Ed25519 signature over the embedded signer key. Returns a list of problems — empty means valid. A
//! delta's `image_hash` is not checked here (it needs the base image); `verify --base` does that separately.

use crate::crypto::{ed25519_verify, sha256};
use crate::format::*;
use crate::merkle;

/// Verify a container's integrity. Returns every problem found (empty ⇒ valid).
pub fn verify(blob: &[u8]) -> Vec<String> {
    let m = match Manifest::parse(blob) {
        Ok(m) => m,
        Err(e) => return vec![e.to_string()], // unparseable: one fatal problem
    };
    let mut problems = Vec::new();

    let stored_leaves = &blob[m.leaves_off()..m.payload_off()];
    let payload = &blob[m.payload_off()..m.payload_off() + m.payload_size as usize];

    // 1) recompute leaves[] from the payload → catches payload corruption.
    let recomputed: Vec<u8> = merkle::leaf_hashes(payload, m.block_size() as usize)
        .into_iter()
        .flatten()
        .collect();
    if recomputed != stored_leaves {
        problems.push("leaves[] do not match the payload (corruption)".into());
    }

    // 2) merkle root over the STORED leaves must equal the manifest root.
    let leaves: Vec<[u8; 4]> = stored_leaves
        .chunks_exact(4)
        .map(|c| c.try_into().unwrap())
        .collect();
    if merkle::root(&leaves) != m.merkle_root {
        problems.push("merkle_root mismatch".into());
    }

    // 3) full image: the payload IS the image, so its hash must match.
    if m.is_full() && sha256(payload) != m.image_hash {
        problems.push("image_hash mismatch (full image)".into());
    }

    // 4) signed: Ed25519 signature over manifest[0, 129) against the embedded signer key.
    if m.is_signed()
        && !ed25519_verify(
            &m.signer,
            &blob[HEADER_LEN..HEADER_LEN + SIGNED_LEN],
            &m.signature,
        )
    {
        problems.push("Ed25519 signature INVALID".into());
    }

    // 5) every distributed-container approval byte must remain erased. `APRV` is the complete local
    // consent marker, but a torn/partial write is also not safe to redistribute.
    if m.approval != APPROVAL_NONE {
        problems
            .push("approval is not FF FF FF FF (distributed container must be unapproved)".into());
    }

    problems
}
