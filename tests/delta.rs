//! Delta (`build --base`) end-to-end: the full `.mota` assembly + the apply-equivalence guarantee.
//!
//! Complements `tests/encode.rs` (which drives the raw encoders): here we build a real signed-layout delta
//! container and check the manifest wiring (codec, base_hash, image_size/hash) plus that the payload — the
//! detools patch — reconstructs the target byte-for-byte under the real detools decoder, for both patch
//! types. Gated on the dev detools oracle; skips cleanly without it.

mod common;

use motatool::endf::ensure_endf;
use motatool::format::{
    NRF52_APP_BASE_S140_V6, NRF52_APP_BASE_S140_V7, NRF52_APP_END, NRF52_EXTRAFS_START,
    NRF52_FALLBACK_INPLACE_MEMORY, NRF52_FLASH_PAGE, NRF52_LAYOUT_FLAG_BOOTLOADER_SCRATCH,
    NRF52_LAYOUT_FLAG_QSPI, NRF52_LAYOUT_LEN, NRF52_LAYOUT_MAGIC, NRF52_LAYOUT_VERSION,
    NRF52_QSPI_LINKED_APP_END,
};
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

fn with_layout(body: Vec<u8>, app_base: u32, linked_end: u32, ceiling: u32) -> Vec<u8> {
    with_layout_flags(body, app_base, linked_end, ceiling, 0)
}

fn with_layout_flags(
    mut body: Vec<u8>,
    app_base: u32,
    linked_end: u32,
    ceiling: u32,
    flags: u8,
) -> Vec<u8> {
    body.extend_from_slice(&NRF52_LAYOUT_MAGIC);
    body.push(NRF52_LAYOUT_VERSION);
    body.push(flags);
    body.extend_from_slice(&(NRF52_LAYOUT_LEN as u16).to_le_bytes());
    body.extend_from_slice(&app_base.to_le_bytes());
    body.extend_from_slice(&linked_end.to_le_bytes());
    body.extend_from_slice(&ceiling.to_le_bytes());
    body
}

fn patch_memory(blob: &[u8]) -> u32 {
    let m = Manifest::parse(blob).unwrap();
    let payload = &blob[m.payload_off()..m.payload_off() + m.payload_size as usize];
    assert_eq!((payload[0] >> 4) & 7, 1);
    let mut pos = 1;
    let first = payload[pos];
    pos += 1;
    assert_eq!(first & 0x40, 0);
    let mut value = (first & 0x3f) as u32;
    let mut shift = 6;
    let mut byte = first;
    while byte & 0x80 != 0 {
        byte = payload[pos];
        pos += 1;
        value |= ((byte & 0x7f) as u32) << shift;
        shift += 7;
    }
    value
}

fn assert_auto_patch_fits(blob: &[u8], app_base: u32, ceiling: u32) {
    let stage_start = (ceiling - blob.len() as u32) & !(NRF52_FLASH_PAGE - 1);
    assert!(stage_start > app_base);
    assert!(patch_memory(blob) <= stage_start - app_base);
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

#[test]
fn auto_memory_uses_embedded_layout_and_legacy_fallback() {
    let (base_body, tgt_body) = base_and_target();
    let (base_image, _) = ensure_endf(&base_body, &ident());

    let mut legacy = opts(
        with_layout(
            tgt_body.clone(),
            NRF52_APP_BASE_S140_V6,
            NRF52_EXTRAFS_START,
            NRF52_EXTRAFS_START,
        ),
        base_image.clone(),
        PatchType::InPlace,
    );
    legacy.inplace_memory = None;
    let legacy_built = build(&legacy).unwrap();
    let legacy_memory = patch_memory(&legacy_built.bytes);
    assert_auto_patch_fits(
        &legacy_built.bytes,
        NRF52_APP_BASE_S140_V6,
        NRF52_EXTRAFS_START,
    );

    let mut expanded = opts(
        with_layout(
            tgt_body.clone(),
            NRF52_APP_BASE_S140_V7,
            NRF52_EXTRAFS_START,
            NRF52_APP_END,
        ),
        base_image.clone(),
        PatchType::InPlace,
    );
    expanded.inplace_memory = None;
    let expanded_built = build(&expanded).unwrap();
    let expanded_memory = patch_memory(&expanded_built.bytes);
    assert_auto_patch_fits(&expanded_built.bytes, NRF52_APP_BASE_S140_V7, NRF52_APP_END);

    assert!(legacy_memory < NRF52_EXTRAFS_START - NRF52_APP_BASE_S140_V6);
    assert!(expanded_memory < NRF52_APP_END - NRF52_APP_BASE_S140_V7);
    assert!(expanded_memory > legacy_memory);

    let mut old = opts(tgt_body, base_image, PatchType::InPlace);
    old.inplace_memory = None;
    assert_eq!(
        patch_memory(&build(&old).unwrap().bytes),
        NRF52_FALLBACK_INPLACE_MEMORY
    );
}

#[test]
fn qspi_auto_memory_uses_linker_bounded_external_workspace() {
    let (base_body, tgt_body) = base_and_target();
    let (base_image, _) = ensure_endf(&base_body, &ident());
    for linked_end in [
        NRF52_APP_END,
        NRF52_QSPI_LINKED_APP_END,
        NRF52_EXTRAFS_START,
    ] {
        let flags = NRF52_LAYOUT_FLAG_QSPI
            | if linked_end == NRF52_QSPI_LINKED_APP_END {
                NRF52_LAYOUT_FLAG_BOOTLOADER_SCRATCH
            } else {
                0
            };
        let mut qspi = opts(
            with_layout_flags(
                tgt_body.clone(),
                NRF52_APP_BASE_S140_V7,
                linked_end,
                NRF52_APP_END,
                flags,
            ),
            base_image.clone(),
            PatchType::InPlace,
        );
        qspi.inplace_memory = None;

        let built = build(&qspi).unwrap();
        assert_eq!(
            patch_memory(&built.bytes),
            linked_end - NRF52_APP_BASE_S140_V7,
        );
        if linked_end == NRF52_QSPI_LINKED_APP_END {
            assert_eq!(flags, 0x0C, "real XIAO scratch layout flags");
        }
    }
}
