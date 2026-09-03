//! Delta (`build --base`) end-to-end: the full `.mota` assembly + the apply-equivalence guarantee.
//!
//! Complements `tests/encode.rs` (which drives the raw encoders): here we build a real signed-layout delta
//! container and check the manifest wiring (codec, base_hash, image_size/hash) plus that the payload — the
//! detools patch — reconstructs the target byte-for-byte under the real detools decoder, for both patch
//! types. Gated on the dev detools oracle; skips cleanly without it.

mod common;

use motatool::endf::ensure_endf;
use motatool::{build, verify, BuildOpts, Codec, FwIdent, Manifest, PatchType};

const MEM: u32 = 0x8000; // in-place window for the tiny test images (> base+target)
const SEG: u32 = 0x1000;

fn ident() -> FwIdent {
    FwIdent {
        fw_version: 0x0111_0000,
        target_id: 0x04D4_13FD,
        hw_id: "RAK4631".into(),
    }
}

/// A base body and a "version-bump" target body: mostly identical, a few scattered edits + a small tail.
fn base_and_target() -> (Vec<u8>, Vec<u8>) {
    let base: Vec<u8> = (0..4000u32)
        .map(|i| (i.wrapping_mul(2654435761) >> 13) as u8)
        .collect();
    let mut tgt = base.clone();
    for off in [7usize, 8, 9, 1500, 2600, 3999] {
        tgt[off] ^= 0x5A;
    }
    tgt.extend((0..200u32).map(|i| (i.wrapping_mul(40503) >> 3) as u8));
    (base, tgt)
}

fn opts(new_fw: Vec<u8>, base_fw: Vec<u8>, ptype: PatchType) -> BuildOpts {
    BuildOpts {
        fw: new_fw,
        base: Some(base_fw),
        patch_type: ptype,
        inplace_memory: Some(MEM),
        segment_size: SEG,
        target_id: Some(0x04D4_13FD),
        fw_version: Some(0x0111_0000),
        hw_id: Some("RAK4631".into()),
        sign_seed: None,
        block_size: 1024,
        force: false,
    }
}

/// Core assertions shared by both patch types: the built `.mota` verifies, is a delta with the right
/// codec/base_hash, and — the key property — its payload, applied to the base by the real detools decoder,
/// reconstructs exactly the target image the manifest describes.
fn assert_delta_roundtrips(ptype: PatchType, expect_codec: Codec) {
    let (base_body, tgt_body) = base_and_target();
    let (base_image, base_body_hash) = ensure_endf(&base_body, &ident());
    let (target_image, _) = ensure_endf(&tgt_body, &ident());

    let built = build(&opts(tgt_body, base_image.clone(), ptype)).expect("delta build");
    assert!(verify(&built.bytes).is_empty(), "delta .mota must verify");

    let m = Manifest::parse(&built.bytes).unwrap();
    assert!(!m.is_full(), "must be flagged as a delta");
    assert_eq!(m.codec(), Some(expect_codec));
    assert_eq!(
        &m.base_hash, &base_body_hash,
        "base_hash == base EndF body hash"
    );
    assert_eq!(m.image_size as usize, target_image.len());

    // The payload is the detools patch; the leaves/root cover it (fetched+verified over the air).
    let payload = &built.bytes[m.payload_off()..m.payload_off() + m.payload_size as usize];

    // APPLY-EQUIVALENCE: real detools decoder over (base, our payload) == the target image, byte-for-byte.
    let rebuilt = common::apply(&base_image, payload, ptype, MEM, target_image.len() as u32);
    assert_eq!(rebuilt, target_image, "decoded image must equal the target");

    // ...and equal to what detools reconstructs from ITS OWN patch (decoder-output equality, independent of
    // how the patch was produced — the invariant the pure-Rust encoder must satisfy).
    let ref_patch = common::encode(&base_image, &target_image, ptype, MEM, SEG);
    let ref_rebuilt = common::apply(
        &base_image,
        &ref_patch,
        ptype,
        MEM,
        target_image.len() as u32,
    );
    assert_eq!(
        rebuilt, ref_rebuilt,
        "our patch and detools' patch must decode identically"
    );

    // And the reconstructed image matches the manifest's full-image hash (what the device checks post-apply).
    assert_eq!(
        motatool::crypto::sha256(&rebuilt).as_slice(),
        &m.image_hash[..],
        "image_hash must match the decoded target",
    );
}

#[test]
fn sequential_delta_applies_to_target() {
    if !common::available() {
        eprintln!("SKIP: detools backend unavailable (run `make dev-setup`)");
        return;
    }
    assert_delta_roundtrips(PatchType::Sequential, Codec::DetoolsSequential);
}

#[test]
fn in_place_delta_applies_to_target() {
    if !common::available() {
        eprintln!("SKIP: detools backend unavailable");
        return;
    }
    assert_delta_roundtrips(PatchType::InPlace, Codec::DetoolsInplace);
}

#[test]
fn delta_suggested_name_tags_the_codec() {
    if !common::available() {
        eprintln!("SKIP: detools backend unavailable");
        return;
    }
    let (base_body, tgt_body) = base_and_target();
    let (base_image, _) = ensure_endf(&base_body, &ident());
    let seq = build(&opts(
        tgt_body.clone(),
        base_image.clone(),
        PatchType::Sequential,
    ))
    .unwrap();
    assert!(
        seq.suggested_name.contains("_seqdelta_"),
        "{}",
        seq.suggested_name
    );
    let ip = build(&opts(tgt_body, base_image, PatchType::InPlace)).unwrap();
    assert!(
        ip.suggested_name.contains("_ipdelta_"),
        "{}",
        ip.suggested_name
    );
}
