//! Assemble a `.mota` container from a firmware image.
//!
//! Full images are 100% Rust. A **delta** (`--base`) diffs the base against the target with detools (see
//! [`crate::delta`] — a dev-only dependency until a pure-Rust encoder lands): the container is identical
//! except the payload is the detools patch, `codec_id` marks the patch type, and `base_hash` pins the
//! image the delta must be applied to.

use crate::crypto::{ed25519_public_from_seed, ed25519_sign, sha256};
use crate::encode::PatchType;
use crate::endf::{
    ensure_endf, has_endf, parse_ident, parse_nrf52_layout, version_str, Nrf52Layout,
};
use crate::format::*;
use crate::merkle;
use anyhow::{bail, ensure, Context, Result};

pub struct BuildOpts {
    pub fw: Vec<u8>,
    pub base: Option<Vec<u8>>,
    pub patch_type: PatchType, // delta layout; used iff base.is_some()
    /// Explicit in-place apply window. `None` derives it from authenticated nRF52 layout records, with
    /// the conservative legacy fallback only when either image predates that record.
    pub inplace_memory: Option<u32>,
    pub segment_size: u32, // in-place segment; used iff patch_type == InPlace
    pub target_id: Option<u32>, // overrides the EndF identity
    pub fw_version: Option<u32>, // overrides the EndF identity
    pub hw_id: Option<String>, // overrides the EndF identity
    pub sign_seed: Option<[u8; 32]>,
    pub block_size: u32,
    pub force: bool,
}

pub struct Built {
    pub bytes: Vec<u8>,
    pub suggested_name: String,
    pub manifest: Manifest,
    /// Actual detools in-place memory encoded in the payload (`None` for full/sequential packages).
    pub inplace_memory: Option<u32>,
}

#[derive(Clone, Copy)]
struct InplacePlan {
    memory: u32,
    /// The running/base firmware determines where this update will be staged and applied.
    base_layout: Option<Nrf52Layout>,
    /// True only when neither authenticated layout pair nor an explicit override was available.
    legacy_auto: bool,
}

struct DeltaBuilt {
    codec: Codec,
    payload: Vec<u8>,
    base_hash: [u8; 8],
    inplace: Option<InplacePlan>,
}

pub fn build(o: &BuildOpts) -> Result<Built> {
    ensure!(
        o.block_size > 1
            && o.block_size <= MAX_APPLICATION_BLOCK_SIZE
            && o.block_size.is_power_of_two(),
        "application block size must be a power of two between 2 and {MAX_APPLICATION_BLOCK_SIZE} bytes"
    );

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
    let DeltaBuilt {
        codec,
        payload,
        base_hash,
        inplace,
    } = match &o.base {
        None => DeltaBuilt {
            codec: Codec::Full,
            payload: image.clone(),
            base_hash: [0u8; 8],
            inplace: None,
        },
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
    ensure!(total <= u32::MAX as usize, ".mota container is too large");
    if let Some(plan) = inplace {
        validate_staging_fit(plan, total)?;
    }
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
        inplace_memory: inplace.map(|p| p.memory),
    })
}

/// Diff `base_fw` against the target `image` into a detools patch (the delta payload), returning the codec,
/// that patch, and the 8-byte `base_hash` the device matches against its running image's EndF body hash.
fn build_delta(o: &BuildOpts, ident: &FwIdent, image: &[u8], base_fw: &[u8]) -> Result<DeltaBuilt> {
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
    let delta = match o.patch_type {
        PatchType::Sequential => DeltaBuilt {
            codec: Codec::DetoolsSequential,
            payload: crate::encode::encode_sequential(&base_image, image),
            base_hash,
            inplace: None,
        },
        PatchType::InPlace => {
            let plan = plan_inplace(o, &base_image, image)?;
            DeltaBuilt {
                codec: Codec::DetoolsInplace,
                payload: crate::encode::encode_in_place(
                    &base_image,
                    image,
                    plan.memory,
                    o.segment_size,
                ),
                base_hash,
                inplace: Some(plan),
            }
        }
    };
    Ok(delta)
}

/// Smallest detools window that satisfies the decoder's destructive-write geometry:
///
/// - the complete target must fit in `memory`, and
/// - the complete base must fit below `memory - shift`, where detools requires at least a two-segment
///   shift.  Rounding the base up to a segment before adding those two segments proves that bound.
fn minimum_inplace_memory(base_len: usize, target_len: usize, segment: u32) -> Result<u32> {
    ensure!(segment != 0, "in-place: --segment-size must be non-zero");
    let seg = u64::from(segment);
    let align = |n: usize| -> Result<u64> {
        let n = u64::try_from(n).context("firmware image length does not fit u64")?;
        n.checked_add(seg - 1)
            .map(|v| v / seg * seg)
            .context("in-place memory calculation overflow")
    };
    let base = align(base_len)?
        .checked_add(2 * seg)
        .context("in-place base/shift memory calculation overflow")?;
    let target = align(target_len)?;
    u32::try_from(base.max(target)).context("required in-place memory exceeds 32 bits")
}

fn image_fits_layout(which: &str, image_len: usize, layout: Nrf52Layout) -> Result<()> {
    let ceiling = layout.linked_app_end.min(layout.stage_ceiling);
    let capacity = ceiling
        .checked_sub(layout.app_base)
        .context("invalid nRF52 image layout")?;
    ensure!(
        image_len <= capacity as usize,
        "{which} image is {image_len} bytes but its authenticated nRF52 layout permits only {capacity} bytes"
    );
    Ok(())
}

fn plan_inplace(o: &BuildOpts, base_image: &[u8], target_image: &[u8]) -> Result<InplacePlan> {
    ensure!(
        o.segment_size != 0,
        "in-place: --segment-size must be non-zero"
    );
    let base_layout = parse_nrf52_layout(base_image).context("base nRF52 layout record")?;
    let target_layout = parse_nrf52_layout(target_image).context("target nRF52 layout record")?;

    if let Some(layout) = base_layout {
        image_fits_layout("base", base_image.len(), layout)?;
    }
    if let Some(layout) = target_layout {
        image_fits_layout("target", target_image.len(), layout)?;
    }
    if let (Some(base), Some(target)) = (base_layout, target_layout) {
        ensure!(
            base.app_base == target.app_base,
            "in-place: base app address 0x{:X} != target app address 0x{:X}; refusing a cross-SoftDevice layout",
            base.app_base,
            target.app_base
        );
    }
    if base_layout.is_some() {
        ensure!(
            o.segment_size == NRF52_INPLACE_SEGMENT,
            "in-place: an authenticated nRF52 base layout requires --segment-size {}",
            NRF52_INPLACE_SEGMENT
        );
    }

    let minimum = minimum_inplace_memory(base_image.len(), target_image.len(), o.segment_size)?;
    let layout_auto = base_layout.is_some() && target_layout.is_some();
    let (memory, legacy_auto) = match o.inplace_memory {
        Some(memory) => (memory, false),
        None if layout_auto => (minimum, false),
        None => (NRF52_FALLBACK_INPLACE_MEMORY, true),
    };
    ensure!(
        memory != 0 && memory % o.segment_size == 0,
        "in-place: --inplace-memory ({memory}) must be a non-zero multiple of --segment-size ({})",
        o.segment_size
    );
    if memory < minimum {
        if legacy_auto {
            bail!(
                "in-place: legacy default memory 0x{memory:X} is too small for base={}B target={}B; \
                 at least 0x{minimum:X} is required. Build both images with an authenticated mOTALay1 \
                 record for automatic sizing, or pass --inplace-memory 0x{minimum:X} only after \
                 verifying the installed bootloader/storage ceiling",
                base_image.len(),
                target_image.len()
            );
        }
        bail!(
            "in-place: --inplace-memory 0x{memory:X} is too small for base={}B target={}B; at least 0x{minimum:X} is required",
            base_image.len(),
            target_image.len()
        );
    }

    if legacy_auto {
        ensure!(
            o.segment_size == NRF52_INPLACE_SEGMENT,
            "in-place: legacy automatic sizing requires --segment-size {}; use an explicit \
             --inplace-memory only for a separately verified custom layout",
            NRF52_INPLACE_SEGMENT
        );
    }

    if let Some(layout) = base_layout {
        let apply_span = layout
            .application_ceiling()
            .checked_sub(layout.app_base)
            .context("invalid nRF52 application workspace")?;
        let workspace_span = if layout.external_backed() {
            apply_span
        } else {
            layout
                .stage_ceiling
                .checked_sub(layout.app_base)
                .context("invalid nRF52 internal staging workspace")?
        };
        ensure!(
            memory <= workspace_span,
            "in-place: memory 0x{memory:X} exceeds authenticated nRF52 workspace 0x{workspace_span:X}"
        );
        ensure!(
            target_image.len() <= apply_span as usize,
            "in-place: target image is {} bytes but the running layout's application workspace is {} bytes",
            target_image.len(),
            apply_span
        );
    }

    Ok(InplacePlan {
        memory,
        base_layout,
        legacy_auto,
    })
}

fn validate_staging_fit(plan: InplacePlan, total: usize) -> Result<()> {
    let span = match plan.base_layout {
        Some(layout) if layout.external_backed() => return Ok(()),
        Some(layout) => layout
            .stage_ceiling
            .checked_sub(layout.app_base)
            .context("invalid nRF52 staging span")?,
        None if plan.legacy_auto => NRF52_FALLBACK_FLASH_SPAN,
        None => return Ok(()), // an explicit legacy override has no authenticated physical ceiling
    };
    let page = u64::from(NRF52_INPLACE_SEGMENT);
    let total = u64::try_from(total).context(".mota length does not fit u64")?;
    let page_round_up = |value: u64| -> Result<u64> {
        value
            .checked_add(page - 1)
            .map(|v| v / page * page)
            .context("staged container size overflow")
    };
    let staged = if plan.base_layout.is_some_and(Nrf52Layout::hybrid_ram) {
        // MeshCore keeps at least the first flash page (header, manifest and
        // APRV) internal, then places at most 64 KiB of the logical tail in
        // reset-retained SRAM.  Rounding the flash charge, rather than the
        // whole container, exactly matches its deterministic split planner.
        let overflow = total.saturating_sub(u64::from(NRF52_HYBRID_RAM_SIZE));
        let flash_charge = page_round_up(overflow)?.max(page);
        // A small package may still fit wholly in flash.  The layout flag is
        // a capability, not a requirement that every transfer use SRAM.
        if flash_charge < total {
            ensure!(
                total - flash_charge <= u64::from(NRF52_HYBRID_RAM_SIZE),
                "in-place: hybrid RAM suffix exceeds {} bytes",
                NRF52_HYBRID_RAM_SIZE
            );
        }
        flash_charge
    } else {
        page_round_up(total)?
    };
    let used = u64::from(plan.memory)
        .checked_add(staged)
        .context("in-place workspace calculation overflow")?;
    ensure!(
        used <= u64::from(span),
        "in-place: memory 0x{:X} plus the {}-byte container ({} bytes page-rounded) exceeds the authenticated staging span 0x{:X}",
        plan.memory,
        total,
        staged,
        span
    );
    Ok(())
}

/// log2 of a power-of-two block size (2048 → 11).
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn minimum_memory_reserves_two_segments_after_rounded_base() {
        assert_eq!(
            minimum_inplace_memory(707_348, 707_396, 4096).unwrap(),
            0xAF000
        );
        assert_eq!(minimum_inplace_memory(1, 0x6001, 4096).unwrap(), 0x7000);
    }

    #[test]
    fn internal_layout_accounts_for_page_rounded_container() {
        let layout = Nrf52Layout {
            app_base: NRF52_APP_BASE_S140_V6,
            linked_app_end: NRF52_APP_END,
            stage_ceiling: NRF52_APP_END,
            flags: 0,
        };
        let span = layout.stage_ceiling - layout.app_base;
        let plan = InplacePlan {
            memory: span - 0x1000,
            base_layout: Some(layout),
            legacy_auto: false,
        };
        assert!(validate_staging_fit(plan, 4096).is_ok());
        let err = validate_staging_fit(plan, 4097).unwrap_err().to_string();
        assert!(err.contains("page-rounded"), "unexpected error: {err}");
    }

    #[test]
    fn external_layout_does_not_charge_container_against_internal_workspace() {
        let layout = Nrf52Layout {
            app_base: NRF52_APP_BASE_S140_V7,
            linked_app_end: NRF52_APP_END,
            stage_ceiling: NRF52_APP_END,
            flags: NRF52_LAYOUT_FLAG_QSPI,
        };
        let plan = InplacePlan {
            memory: layout.application_ceiling() - layout.app_base,
            base_layout: Some(layout),
            legacy_auto: false,
        };
        assert!(validate_staging_fit(plan, 1_000_000).is_ok());
    }

    #[test]
    fn hybrid_layout_charges_only_deterministic_flash_prefix() {
        let layout = Nrf52Layout {
            app_base: NRF52_APP_BASE_S140_V6,
            linked_app_end: NRF52_APP_END,
            stage_ceiling: NRF52_APP_END,
            flags: NRF52_LAYOUT_FLAG_HYBRID_RAM,
        };
        let span = layout.stage_ceiling - layout.app_base;
        let plan = InplacePlan {
            memory: span - 0x2000,
            base_layout: Some(layout),
            legacy_auto: false,
        };

        // An overflow just beyond one page needs a two-page flash prefix.
        assert!(validate_staging_fit(plan, NRF52_HYBRID_RAM_SIZE as usize + 0x1001).is_ok());
        // One byte beyond that two-page band charges a third page and no
        // longer fits beside the selected detools workspace.
        let err = validate_staging_fit(plan, NRF52_HYBRID_RAM_SIZE as usize + 0x2001)
            .unwrap_err()
            .to_string();
        assert!(err.contains("page-rounded"), "unexpected error: {err}");
    }

    #[test]
    fn hybrid_layout_keeps_small_pure_flash_packages_buildable() {
        let layout = Nrf52Layout {
            app_base: NRF52_APP_BASE_S140_V6,
            linked_app_end: NRF52_APP_END,
            stage_ceiling: NRF52_APP_END,
            flags: NRF52_LAYOUT_FLAG_HYBRID_RAM,
        };
        let plan = InplacePlan {
            memory: layout.stage_ceiling - layout.app_base - 0x1000,
            base_layout: Some(layout),
            legacy_auto: false,
        };
        assert!(validate_staging_fit(plan, 0x1000).is_ok());
    }
}
