//! Assemble a `.mota` container from a firmware image.
//!
//! Full images and both delta codecs are 100% Rust. A **delta** (`--base`) diffs the base against the target:
//! the container is identical except the payload is a detools-compatible patch, `codec_id` marks the patch
//! type, and `base_hash` pins the image the delta must be applied to.

use crate::crypto::{ed25519_public_from_seed, ed25519_sign, sha256};
use crate::encode::PatchType;
use crate::endf::{
    ensure_endf, has_endf, parse_ident, parse_nrf52_layout, version_str, Nrf52Layout,
};
use crate::format::*;
use crate::merkle;
use anyhow::{bail, Result};

pub struct BuildOpts {
    pub fw: Vec<u8>,
    pub base: Option<Vec<u8>>,
    pub patch_type: PatchType, // delta layout; used iff base.is_some()
    pub inplace_memory: Option<u32>, // explicit window; None derives from embedded layout or legacy fallback
    pub segment_size: u32,           // in-place segment; used iff patch_type == InPlace
    pub target_id: Option<u32>,      // overrides the EndF identity
    pub fw_version: Option<u32>,     // overrides the EndF identity
    pub hw_id: Option<String>,       // overrides the EndF identity
    pub sign_seed: Option<[u8; 32]>,
    pub block_size: u32,
    pub force: bool,
}

pub struct Built {
    pub bytes: Vec<u8>,
    pub suggested_name: String,
    pub manifest: Manifest,
}

pub fn build(o: &BuildOpts) -> Result<Built> {
    // Resolve identity: explicit flags win over the firmware's self-describing EndF trailer.
    let from_fw = parse_ident(&o.fw);
    let ident = FwIdent {
        fw_version: o.fw_version.unwrap_or(from_fw.fw_version),
        target_id: o.target_id.unwrap_or(from_fw.target_id),
        hw_id: o.hw_id.clone().unwrap_or(from_fw.hw_id),
    };

    // The target image (EndF-trailed) is what image_size/image_hash always describe.
    let (image, _body_hash) = ensure_endf(&o.fw, &ident);

    // Full: the payload IS the image. Delta: the payload is a detools patch base_image -> image, and
    // base_hash pins the running image it applies to (the device checks it against its EndF body_hash).
    let (codec, payload, base_hash) = match &o.base {
        None => (Codec::Full, image.clone(), [0u8; 8]),
        Some(base_fw) => build_delta(o, &ident, &image, base_fw)?,
    };
    let is_full = codec == Codec::Full;

    let leaves = merkle::leaf_hashes(&payload, o.block_size as usize);
    let block_count = leaves.len();
    if !(1..=0xFFFF).contains(&block_count) {
        bail!("payload yields an invalid block count ({block_count})");
    }
    let root = merkle::root(&leaves);
    let image_hash = sha256(&image);
    let signed = o.sign_seed.is_some();

    // ---- assemble the fixed 197-byte manifest ----
    let mut mf = [0u8; MFL];
    mf[off::FORMAT_VER] = FORMAT_VER;
    mf[off::FLAGS] = if is_full { MFLAG_FULL } else { 0 } | if signed { MFLAG_SIGNED } else { 0 };
    mf[off::HASH_ALGO] = HASH_ALGO_SHA256;
    wr_u32(&mut mf, off::TARGET_ID, ident.target_id);
    wr_u32(&mut mf, off::FW_VERSION, ident.fw_version);
    wr_u32(&mut mf, off::IMAGE_SIZE, image.len() as u32);
    wr_u32(&mut mf, off::PAYLOAD_SIZE, payload.len() as u32);
    mf[off::BLOCK_SIZE_LOG2] = block_size_log2(o.block_size);
    mf[off::MERKLE_ROOT..off::MERKLE_ROOT + 4].copy_from_slice(&root);
    mf[off::IMAGE_HASH..off::IMAGE_HASH + 32].copy_from_slice(&image_hash);
    mf[off::CODEC_ID] = codec as u8;
    let hw = ident.hw_id.as_bytes();
    mf[off::HW_ID..off::HW_ID + hw.len().min(HW_ID_LEN)]
        .copy_from_slice(&hw[..hw.len().min(HW_ID_LEN)]);
    mf[off::BASE_HASH..off::BASE_HASH + 8].copy_from_slice(&base_hash); // zero for a full image
    if let Some(seed) = &o.sign_seed {
        mf[off::SIGNER..off::SIGNER + 32].copy_from_slice(&ed25519_public_from_seed(seed));
        let sig = ed25519_sign(seed, &mf[..SIGNED_LEN]);
        mf[off::SIGNATURE..off::SIGNATURE + 64].copy_from_slice(&sig);
    }
    mf[off::APPROVAL..off::APPROVAL + 4].copy_from_slice(&APPROVAL_NONE);

    // ---- container = MAGIC ‖ total(4) ‖ manifest ‖ leaves[] ‖ payload ‖ TRAILER ----
    let leaves_bytes: Vec<u8> = leaves.into_iter().flatten().collect();
    let total = HEADER_LEN + MFL + leaves_bytes.len() + payload.len() + TRAILER_LEN;
    let mut bytes = Vec::with_capacity(total);
    bytes.extend_from_slice(&MAGIC);
    bytes.extend_from_slice(&(total as u32).to_le_bytes());
    bytes.extend_from_slice(&mf);
    bytes.extend_from_slice(&leaves_bytes);
    bytes.extend_from_slice(&payload);
    bytes.extend_from_slice(&TRAILER);

    let manifest = Manifest::parse(&bytes)?; // our own output must parse
    let suggested_name = suggested_name(&ident, codec, &root);
    Ok(Built {
        bytes,
        suggested_name,
        manifest,
    })
}

/// Diff `base_fw` against the target `image` into a detools patch (the delta payload), returning the codec,
/// that patch, and the 8-byte `base_hash` the device matches against its running image's EndF body hash.
fn build_delta(
    o: &BuildOpts,
    ident: &FwIdent,
    image: &[u8],
    base_fw: &[u8],
) -> Result<(Codec, Vec<u8>, [u8; 8])> {
    // The delta must apply to the device's *actual* running image, which carries its own EndF trailer.
    // Requiring one here stops a silently-wrong patch built against a re-stamped base (it would fail the
    // on-device base_hash check anyway, but failing early is clearer).
    if !has_endf(base_fw) {
        bail!(
            "--base must be a real firmware image with its EndF trailer (the device's running image); \
             this one has none"
        );
    }
    let base_ident = parse_ident(base_fw);
    if !o.force && base_ident.hw_id != ident.hw_id {
        bail!(
            "base hardware {:?} != target hardware {:?}; a cross-hardware delta will not apply (use --force to override)",
            base_ident.hw_id,
            ident.hw_id
        );
    }
    let (base_image, base_hash) = ensure_endf(base_fw, &base_ident);

    // Both patch types are the pure-Rust encoder now — no detools/Python at runtime.
    let (codec, patch) = match o.patch_type {
        PatchType::Sequential => (
            Codec::DetoolsSequential,
            crate::encode::encode_sequential(&base_image, image),
        ),
        PatchType::InPlace => {
            let layout = parse_nrf52_layout(image);
            let patch = match o.inplace_memory {
                Some(memory) => {
                    validate_inplace_memory(&base_image, image, memory, o.segment_size)?;
                    if let Some(layout) = layout {
                        validate_layout_target(image, layout)?;
                    }
                    let patch =
                        crate::encode::encode_in_place(&base_image, image, memory, o.segment_size);
                    if let Some(layout) = layout {
                        validate_explicit_inplace_layout(
                            &patch,
                            memory,
                            layout,
                            o.segment_size,
                            o.block_size,
                        )?;
                    }
                    patch
                }
                None => match layout {
                    Some(layout) => auto_inplace_patch(
                        &base_image,
                        image,
                        layout,
                        o.segment_size,
                        o.block_size,
                    )?,
                    None => {
                        let memory = NRF52_FALLBACK_INPLACE_MEMORY;
                        validate_inplace_memory(&base_image, image, memory, o.segment_size)?;
                        crate::encode::encode_in_place(&base_image, image, memory, o.segment_size)
                    }
                },
            };
            (Codec::DetoolsInplace, patch)
        }
    };
    Ok((codec, patch, base_hash))
}

fn validate_inplace_memory(from: &[u8], to: &[u8], memory: u32, segment: u32) -> Result<()> {
    if segment == 0 || !segment.is_power_of_two() || memory == 0 || memory % segment != 0 {
        bail!(
            "in-place: --inplace-memory ({memory}) must be a non-zero multiple of power-of-two --segment-size ({segment})"
        );
    }
    let minimum = (from.len() as u64)
        .saturating_add(2 * segment as u64)
        .max(to.len() as u64);
    if minimum > memory as u64 {
        bail!(
            "in-place: apply window {memory} B is too small for base {} B, target {} B, and two-segment shift",
            from.len(),
            to.len()
        );
    }
    Ok(())
}

fn patch_container_total(patch_len: usize, block_size: u32) -> Result<u32> {
    if block_size == 0 || !block_size.is_power_of_two() {
        bail!("in-place: block size must be a non-zero power of two");
    }
    let blocks = patch_len.div_ceil(block_size as usize);
    let total = HEADER_LEN
        .checked_add(MFL)
        .and_then(|n| n.checked_add(blocks.checked_mul(4)?))
        .and_then(|n| n.checked_add(patch_len))
        .and_then(|n| n.checked_add(TRAILER_LEN))
        .ok_or_else(|| anyhow::anyhow!("in-place container size overflow"))?;
    u32::try_from(total).map_err(|_| anyhow::anyhow!("in-place container exceeds 32-bit format"))
}

fn align_down(value: u32, unit: u32) -> u32 {
    value & !(unit - 1)
}

fn validate_layout_target(to: &[u8], layout: Nrf52Layout) -> Result<u32> {
    if layout.stage_ceiling <= layout.app_base || layout.linked_app_end <= layout.app_base {
        bail!("in-place: invalid embedded nRF52 layout");
    }
    let linked_span = layout.linked_app_end - layout.app_base;
    if to.len() as u64 > linked_span as u64 {
        bail!(
            "in-place: target image {} B exceeds embedded application region {} B",
            to.len(),
            linked_span
        );
    }
    Ok(linked_span)
}

/// Return the page-aligned address where the application will bottom-stage an internal container.
/// The live device additionally checks that this address is at or above its exact running EndF.
fn internal_stage_start(patch_len: usize, block_size: u32, layout: Nrf52Layout) -> Result<u32> {
    let total = patch_container_total(patch_len, block_size)?;
    let span = layout
        .stage_ceiling
        .checked_sub(layout.app_base)
        .ok_or_else(|| anyhow::anyhow!("in-place: invalid embedded nRF52 staging span"))?;
    if total >= span {
        bail!(
            "in-place: package {total} B does not fit below staging ceiling 0x{:X}",
            layout.stage_ceiling
        );
    }
    let start = align_down(layout.stage_ceiling - total, NRF52_FLASH_PAGE);
    if start <= layout.app_base {
        bail!("in-place: package leaves no apply workspace");
    }
    Ok(start)
}

/// An explicit memory override still has to fit the target firmware's authenticated layout. For an
/// internal store, encode first because the complete container size determines its physical source
/// address. For an external SD/QSPI store, the source is off-chip and the linker end is the hard bound.
fn validate_explicit_inplace_layout(
    patch: &[u8],
    memory: u32,
    layout: Nrf52Layout,
    segment: u32,
    block_size: u32,
) -> Result<()> {
    let allowed = if layout.external_staging() {
        align_down(layout.linked_app_end - layout.app_base, segment)
    } else {
        let source = internal_stage_start(patch.len(), block_size, layout)?;
        align_down(source - layout.app_base, segment)
    };
    if memory > allowed {
        bail!(
            "in-place: explicit apply window {memory} B exceeds the embedded layout/source bound {allowed} B"
        );
    }
    Ok(())
}

/// Encode using the largest monotonically safe workspace below the package's eventual page-aligned
/// staging address. Re-encoding can change patch size, so candidates only move downward until the
/// actual container fits. Externally staged SD/QSPI packages need no internal reservation and use the
/// full linked application region.
fn auto_inplace_patch(
    from: &[u8],
    to: &[u8],
    layout: Nrf52Layout,
    segment: u32,
    block_size: u32,
) -> Result<Vec<u8>> {
    if segment == 0 || !segment.is_power_of_two() {
        bail!("in-place: --segment-size must be a non-zero power of two");
    }
    validate_layout_target(to, layout)?;

    if layout.external_staging() {
        let memory = align_down(layout.linked_app_end - layout.app_base, segment);
        validate_inplace_memory(from, to, memory, segment)?;
        return Ok(crate::encode::encode_in_place(from, to, memory, segment));
    }

    // Every non-empty internal package consumes at least the highest 4 KiB flash page below its ceiling.
    let span = layout.stage_ceiling - layout.app_base;
    if span <= NRF52_FLASH_PAGE {
        bail!("in-place: nRF52 layout leaves no internal staging page");
    }
    let mut memory = align_down(span - NRF52_FLASH_PAGE, segment);
    loop {
        validate_inplace_memory(from, to, memory, segment)?;
        let patch = crate::encode::encode_in_place(from, to, memory, segment);
        let stage_start = internal_stage_start(patch.len(), block_size, layout)?;
        let allowed = align_down(stage_start - layout.app_base, segment);
        if memory <= allowed {
            return Ok(patch);
        }
        memory = allowed;
    }
}

/// log2 of a power-of-two block size (1024 → 10).
fn block_size_log2(bs: u32) -> u8 {
    (u32::BITS - 1 - bs.max(1).leading_zeros()) as u8
}

/// `<hw|fw>_<target8>_v<version>_<full|seqdelta|ipdelta>_<mid8>.mota`
fn suggested_name(ident: &FwIdent, codec: Codec, root: &[u8; 4]) -> String {
    let hw = if ident.hw_id.is_empty() {
        "fw"
    } else {
        ident.hw_id.as_str()
    };
    format!(
        "{hw}_{:08X}_v{}_{}_{}.mota",
        ident.target_id,
        version_str(ident.fw_version),
        codec.name_tag(),
        hex::encode_upper(root)
    )
}
