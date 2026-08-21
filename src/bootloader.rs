//! XIAO nRF52840 OTAFIX bootloader-package support.
//!
//! A bootloader package is deliberately narrower than an application package: it is format v3,
//! always full and signed, and its payload is the exact padded 40 KiB flash region copied by the
//! Nordic MBR. The payload's embedded OTAFIX manifest provides a second, board-bound integrity gate.

use crate::build::Built;
use crate::crypto::{ed25519_public_from_seed, ed25519_sign, sha256};
use crate::endf::version_str;
use crate::format::*;
use crate::merkle;
use anyhow::{bail, ensure, Context, Result};
use ihex::Record;

pub const BOOTLOADER_IMAGE_START: u32 = 0x000F_4000;
pub const BOOTLOADER_IMAGE_SIZE: usize = 0x0000_A000;
pub const BOOTLOADER_IMAGE_END: u32 = BOOTLOADER_IMAGE_START + BOOTLOADER_IMAGE_SIZE as u32;
pub const BOOTLOADER_BLOCK_SIZE: u32 = 1024;
pub const BOOTLOADER_BLOCK_COUNT: u32 = 40;
pub const NRF52840_RAM_START: u32 = 0x2000_0000;
pub const NRF52840_RAM_END: u32 = 0x2004_0000;

pub const UPDATE_MANIFEST_MAGIC0: u32 = 0x464D_4C42;
pub const UPDATE_MANIFEST_MAGIC1: u32 = 0x3143_5243;
pub const UPDATE_MANIFEST_VERSION: u16 = 1;
pub const UPDATE_MANIFEST_SIZE: usize = 44;
pub const UPDATE_MANIFEST_DEVICE_NAME_SIZE: usize = 16;
pub const UPDATE_MANIFEST_CRC_OFFSET: usize = 40;

pub const XIAO_NRF52840_BLE_BOARD_ID: u32 = 0x2886_0044;
pub const XIAO_NRF52840_BLE_SENSE_BOARD_ID: u32 = 0x2886_0045;

pub const BOOTLOADER_CAPS_MAGIC: [u8; 8] = *b"MOTABLDR";
pub const BOOTLOADER_CAPS_SIZE: usize = 16;
pub const BOOTLOADER_MIN_APPLY_ABI: u16 = 3;
pub const BOOTLOADER_CODEC_FULL: u16 = 1 << (Codec::Full as u8);
pub const BOOTLOADER_STORAGE_QSPI: u8 = 0x04;
pub const BOOTLOADER_STORAGE_BOOT_UPDATE: u8 = 0x08;
pub const BOOTLOADER_REQUIRED_STORAGE: u8 =
    BOOTLOADER_STORAGE_QSPI | BOOTLOADER_STORAGE_BOOT_UPDATE;

const XIAO_DEVICE_NAME: &str = "XIAO_DFU";
const BOOTLOADER_FLAGS: u8 = MFLAG_FULL | MFLAG_SIGNED | MFLAG_BOOTLOADER;

/// The two intentionally supported OTAFIX bootloader identities.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BootloaderBoard {
    XiaoNrf52840Ble,
    XiaoNrf52840BleSense,
}

impl BootloaderBoard {
    pub const fn board_id(self) -> u32 {
        match self {
            Self::XiaoNrf52840Ble => XIAO_NRF52840_BLE_BOARD_ID,
            Self::XiaoNrf52840BleSense => XIAO_NRF52840_BLE_SENSE_BOARD_ID,
        }
    }

    pub const fn name(self) -> &'static str {
        match self {
            Self::XiaoNrf52840Ble => "xiao_nrf52840_ble",
            Self::XiaoNrf52840BleSense => "xiao_nrf52840_ble_sense",
        }
    }

    pub const fn hw_id(self) -> &'static str {
        match self {
            Self::XiaoNrf52840Ble => "XIAO_BL_28860044",
            Self::XiaoNrf52840BleSense => "XIAO_BL_28860045",
        }
    }

    pub const fn device_name(self) -> &'static str {
        XIAO_DEVICE_NAME
    }

    pub const fn from_board_id(board_id: u32) -> Option<Self> {
        match board_id {
            XIAO_NRF52840_BLE_BOARD_ID => Some(Self::XiaoNrf52840Ble),
            XIAO_NRF52840_BLE_SENSE_BOARD_ID => Some(Self::XiaoNrf52840BleSense),
            _ => None,
        }
    }

    fn padded_hw_id(self) -> [u8; HW_ID_LEN] {
        let mut out = [0u8; HW_ID_LEN];
        let value = self.hw_id().as_bytes();
        out[..value.len()].copy_from_slice(value);
        out
    }

    fn padded_device_name(self) -> [u8; UPDATE_MANIFEST_DEVICE_NAME_SIZE] {
        let mut out = [0u8; UPDATE_MANIFEST_DEVICE_NAME_SIZE];
        let value = self.device_name().as_bytes();
        out[..value.len()].copy_from_slice(value);
        out
    }
}

/// The embedded 44-byte OTAFIX bootloader update manifest after validation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BootloaderUpdateManifest {
    pub offset: usize,
    pub image_start: u32,
    pub image_size: u32,
    pub board_id: u32,
    pub device_name: [u8; UPDATE_MANIFEST_DEVICE_NAME_SIZE],
    pub crc32: u32,
}

/// The continuity marker read by the running application before it stages a future update.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BootloaderCapabilities {
    pub offset: usize,
    pub apply_abi: u16,
    pub codec_mask: u16,
    pub storage_flags: u8,
}

impl BootloaderUpdateManifest {
    pub fn device_name_str(&self) -> String {
        cstr(&self.device_name)
    }
}

pub struct BootloaderBuildOpts {
    /// Exact padded bytes for [`BOOTLOADER_IMAGE_START`]..[`BOOTLOADER_IMAGE_END`].
    pub image: Vec<u8>,
    pub board: BootloaderBoard,
    pub fw_version: u32,
    /// Bootloader packages are never allowed to be unsigned, so this is not optional.
    pub sign_seed: [u8; 32],
}

/// Extract the exact MBR-copy region from an OTAFIX Intel HEX, filling holes with erased-flash `0xFF`.
/// Records outside the bootloader region (for example MBR, SoftDevice, and UICR records) are ignored.
pub fn extract_bootloader_region_from_hex(bytes: &[u8]) -> Result<Vec<u8>> {
    let text = std::str::from_utf8(bytes).context("Intel HEX is not valid UTF-8")?;
    let mut image = vec![0xFF; BOOTLOADER_IMAGE_SIZE];
    let mut written = vec![false; BOOTLOADER_IMAGE_SIZE];
    let mut base = 0u32;
    let mut saw_region_data = false;
    let mut saw_eof = false;

    for record in ihex::Reader::new(text) {
        match record.context("malformed Intel HEX record")? {
            Record::Data { offset, value } => {
                let address = base
                    .checked_add(offset as u32)
                    .context("Intel HEX data address overflow")?;
                let end = address
                    .checked_add(value.len() as u32)
                    .context("Intel HEX data range overflow")?;
                let copy_start = address.max(BOOTLOADER_IMAGE_START);
                let copy_end = end.min(BOOTLOADER_IMAGE_END);
                if copy_start < copy_end {
                    saw_region_data = true;
                    let src = (copy_start - address) as usize;
                    let dst = (copy_start - BOOTLOADER_IMAGE_START) as usize;
                    let len = (copy_end - copy_start) as usize;
                    for i in 0..len {
                        let value = value[src + i];
                        if written[dst + i] && image[dst + i] != value {
                            bail!(
                                "conflicting Intel HEX data at address 0x{:08X}",
                                copy_start + i as u32
                            );
                        }
                        image[dst + i] = value;
                        written[dst + i] = true;
                    }
                }
            }
            Record::ExtendedLinearAddress(upper) => base = (upper as u32) << 16,
            Record::ExtendedSegmentAddress(segment) => base = (segment as u32) << 4,
            Record::EndOfFile => {
                saw_eof = true;
                break;
            }
            _ => {}
        }
    }

    ensure!(saw_eof, "Intel HEX missing EOF record");
    ensure!(
        saw_region_data,
        "Intel HEX contains no data in bootloader region 0x{BOOTLOADER_IMAGE_START:08X}..0x{BOOTLOADER_IMAGE_END:08X}"
    );
    Ok(image)
}

/// IEEE CRC-32 over the whole padded image while treating the embedded CRC field as four zero bytes.
pub fn bootloader_image_crc32(image: &[u8], crc_offset: usize) -> u32 {
    let mut crc = u32::MAX;
    for (i, &byte) in image.iter().enumerate() {
        let value = if (crc_offset..crc_offset + 4).contains(&i) {
            0
        } else {
            byte
        };
        crc ^= value as u32;
        for _ in 0..8 {
            crc = (crc >> 1) ^ (0xEDB8_8320 & 0u32.wrapping_sub(crc & 1));
        }
    }
    !crc
}

/// Locate the sole fully valid v1 OTAFIX manifest. Magic/version constants can also occur in literal
/// pools, so an invalid candidate must not shadow a valid manifest later in the image.
pub fn parse_bootloader_update_manifest(image: &[u8]) -> Result<BootloaderUpdateManifest> {
    ensure!(
        image.len() == BOOTLOADER_IMAGE_SIZE,
        "bootloader image must be exactly 0x{BOOTLOADER_IMAGE_SIZE:X} bytes (got 0x{:X})",
        image.len()
    );
    validate_bootloader_vectors(image)?;
    parse_bootloader_capabilities(image)?;

    // Only candidates whose complete identity, geometry, and whole-image CRC validate count. Retain the
    // last rejection solely to make a lone corrupt real manifest easier to diagnose.
    let mut candidates = Vec::new();
    let mut last_rejection = None;
    let expected_device = BootloaderBoard::XiaoNrf52840Ble.padded_device_name();
    for offset in (0..=image.len() - UPDATE_MANIFEST_SIZE).step_by(4) {
        if rd_u32(image, offset) != UPDATE_MANIFEST_MAGIC0
            || rd_u32(image, offset + 4) != UPDATE_MANIFEST_MAGIC1
        {
            continue;
        }
        if rd_u16(image, offset + 8) != UPDATE_MANIFEST_VERSION {
            last_rejection = Some("version mismatch".to_owned());
            continue;
        }
        if rd_u16(image, offset + 10) as usize != UPDATE_MANIFEST_SIZE {
            last_rejection = Some("header_size mismatch".to_owned());
            continue;
        }

        let manifest = BootloaderUpdateManifest {
            offset,
            image_start: rd_u32(image, offset + 12),
            image_size: rd_u32(image, offset + 16),
            board_id: rd_u32(image, offset + 20),
            device_name: arr(image, offset + 24),
            crc32: rd_u32(image, offset + UPDATE_MANIFEST_CRC_OFFSET),
        };
        if manifest.image_start != BOOTLOADER_IMAGE_START {
            last_rejection = Some(format!(
                "image_start mismatch (got 0x{:08X})",
                manifest.image_start
            ));
            continue;
        }
        if manifest.image_size != BOOTLOADER_IMAGE_SIZE as u32 {
            last_rejection = Some(format!(
                "image_size mismatch (got 0x{:X})",
                manifest.image_size
            ));
            continue;
        }
        if BootloaderBoard::from_board_id(manifest.board_id).is_none() {
            last_rejection = Some(format!("unsupported board_id 0x{:08X}", manifest.board_id));
            continue;
        }
        if manifest.device_name != expected_device {
            last_rejection = Some("device_name is not exact NUL-padded XIAO_DFU".to_owned());
            continue;
        }
        let computed = bootloader_image_crc32(image, offset + UPDATE_MANIFEST_CRC_OFFSET);
        if manifest.crc32 != computed {
            last_rejection = Some(format!(
                "CRC32 mismatch (stored 0x{:08X}, computed 0x{computed:08X})",
                manifest.crc32
            ));
            continue;
        }
        candidates.push(manifest);
    }
    match candidates.len() {
        1 => Ok(candidates.pop().unwrap()),
        0 => bail!(
            "no fully valid bootloader update manifest{}",
            last_rejection
                .map(|reason| format!(": {reason}"))
                .unwrap_or_default()
        ),
        count => {
            bail!("expected exactly one fully valid bootloader update manifest, found {count}")
        }
    }
}

/// Locate and validate the marker that makes the installed image capable of accepting its successor.
pub fn parse_bootloader_capabilities(image: &[u8]) -> Result<BootloaderCapabilities> {
    let mut matches = 0usize;
    for (offset, window) in image.windows(BOOTLOADER_CAPS_MAGIC.len()).enumerate() {
        if window != BOOTLOADER_CAPS_MAGIC {
            continue;
        }
        matches += 1;
        if offset % 4 != 0 || offset + BOOTLOADER_CAPS_SIZE > image.len() {
            continue;
        }
        let capabilities = BootloaderCapabilities {
            offset,
            apply_abi: rd_u16(image, offset + 8),
            codec_mask: rd_u16(image, offset + 10),
            storage_flags: image[offset + 12],
        };
        if capabilities.apply_abi >= BOOTLOADER_MIN_APPLY_ABI
            && capabilities.apply_abi != u16::MAX
            && capabilities.codec_mask & BOOTLOADER_CODEC_FULL != 0
            && capabilities.storage_flags & !0x0F == 0
            && capabilities.storage_flags & BOOTLOADER_REQUIRED_STORAGE
                == BOOTLOADER_REQUIRED_STORAGE
            && image[offset + 13..offset + 16] == [0, 0, 0]
        {
            return Ok(capabilities);
        }
    }
    if matches == 0 {
        bail!("bootloader image has no MOTABLDR capability marker");
    }
    bail!(
        "found {matches} MOTABLDR marker candidate(s), but none are aligned, structurally valid, and advertise finite apply_abi >= {BOOTLOADER_MIN_APPLY_ABI}, CODEC_FULL, and QSPI|BOOT_UPDATE storage flags (0x{BOOTLOADER_REQUIRED_STORAGE:02X})"
    )
}

/// Validate the vector-table invariants the MBR needs before transferring control to the image.
pub fn validate_bootloader_vectors(image: &[u8]) -> Result<()> {
    ensure!(
        image.len() == BOOTLOADER_IMAGE_SIZE,
        "bootloader image must be exactly 0x{BOOTLOADER_IMAGE_SIZE:X} bytes"
    );
    ensure!(
        !image.iter().all(|&byte| byte == 0xFF),
        "bootloader image is entirely erased (all 0xFF)"
    );
    let initial_sp = rd_u32(image, 0);
    ensure!(
        initial_sp % 8 == 0 && (NRF52840_RAM_START..=NRF52840_RAM_END).contains(&initial_sp),
        "initial stack pointer 0x{initial_sp:08X} is not 8-byte aligned nRF52840 RAM"
    );
    let reset_vector = rd_u32(image, 4);
    let reset_address = reset_vector & !1;
    ensure!(
        reset_vector & 1 == 1
            && (BOOTLOADER_IMAGE_START..BOOTLOADER_IMAGE_END).contains(&reset_address),
        "reset vector 0x{reset_vector:08X} is not a Thumb address in the bootloader region"
    );
    Ok(())
}

/// Validate the embedded manifest against the explicitly selected XIAO variant.
pub fn validate_bootloader_image(
    image: &[u8],
    expected: BootloaderBoard,
) -> Result<BootloaderUpdateManifest> {
    let manifest = parse_bootloader_update_manifest(image)?;
    ensure!(
        manifest.board_id == expected.board_id(),
        "embedded manifest board_id 0x{:08X} does not match {} (0x{:08X})",
        manifest.board_id,
        expected.name(),
        expected.board_id()
    );
    ensure!(
        manifest.device_name == expected.padded_device_name(),
        "embedded manifest DEVICE_NAME {:?} does not exactly match {:?}",
        manifest.device_name_str(),
        expected.device_name()
    );
    Ok(manifest)
}

/// Validate the bootloader-specific portion of a parsed `.mota` contract.
pub fn validate_bootloader_package(
    manifest: &Manifest,
    payload: &[u8],
) -> Result<BootloaderUpdateManifest> {
    ensure!(
        manifest.format_ver == BOOTLOADER_FORMAT_VER,
        "bootloader package must use format_ver {BOOTLOADER_FORMAT_VER}"
    );
    ensure!(
        manifest.flags == BOOTLOADER_FLAGS,
        "bootloader flags must be exactly FULL|SIGNED|BOOTLOADER (0x{BOOTLOADER_FLAGS:02X})"
    );
    ensure!(
        manifest.hash_algo == HASH_ALGO_SHA256,
        "bootloader package must use SHA-256"
    );
    ensure!(
        manifest.fw_version != 0,
        "bootloader package fw_version must be nonzero"
    );
    ensure!(
        manifest.codec() == Some(Codec::Full),
        "bootloader package must use CODEC_FULL"
    );
    ensure!(
        manifest.image_size == BOOTLOADER_IMAGE_SIZE as u32
            && manifest.payload_size == BOOTLOADER_IMAGE_SIZE as u32
            && payload.len() == BOOTLOADER_IMAGE_SIZE,
        "bootloader package image and payload must both be exactly 0x{BOOTLOADER_IMAGE_SIZE:X} bytes"
    );
    ensure!(
        manifest.block_size() == BOOTLOADER_BLOCK_SIZE
            && manifest.block_count == BOOTLOADER_BLOCK_COUNT,
        "bootloader package must use {BOOTLOADER_BLOCK_COUNT} blocks of {BOOTLOADER_BLOCK_SIZE} bytes"
    );
    ensure!(
        manifest.base_hash == [0u8; 8],
        "bootloader package base_hash must be zero"
    );
    let board = BootloaderBoard::from_board_id(manifest.target_id).with_context(|| {
        format!(
            "unsupported bootloader target_id 0x{:08X}",
            manifest.target_id
        )
    })?;
    ensure!(
        manifest.hw_id == board.padded_hw_id(),
        "bootloader hw_id must be canonical NUL-padded {:?}",
        board.hw_id()
    );
    validate_bootloader_image(payload, board)
}

/// Build a signed, exact-board bootloader package from an already extracted 40 KiB region.
pub fn build_bootloader(options: &BootloaderBuildOpts) -> Result<Built> {
    validate_bootloader_image(&options.image, options.board)?;
    ensure!(
        options.fw_version != 0,
        "bootloader package fw_version must be nonzero"
    );
    let leaves = merkle::leaf_hashes(&options.image, BOOTLOADER_BLOCK_SIZE as usize);
    ensure!(
        leaves.len() == BOOTLOADER_BLOCK_COUNT as usize,
        "bootloader payload must yield exactly {BOOTLOADER_BLOCK_COUNT} blocks (got {})",
        leaves.len()
    );
    let root = merkle::root(&leaves);
    let image_hash = sha256(&options.image);

    let mut mf = [0u8; MFL];
    mf[off::FORMAT_VER] = BOOTLOADER_FORMAT_VER;
    mf[off::FLAGS] = BOOTLOADER_FLAGS;
    mf[off::HASH_ALGO] = HASH_ALGO_SHA256;
    wr_u32(&mut mf, off::TARGET_ID, options.board.board_id());
    wr_u32(&mut mf, off::FW_VERSION, options.fw_version);
    wr_u32(&mut mf, off::IMAGE_SIZE, BOOTLOADER_IMAGE_SIZE as u32);
    wr_u32(&mut mf, off::PAYLOAD_SIZE, BOOTLOADER_IMAGE_SIZE as u32);
    mf[off::BLOCK_SIZE_LOG2] = 10;
    mf[off::MERKLE_ROOT..off::MERKLE_ROOT + 4].copy_from_slice(&root);
    mf[off::IMAGE_HASH..off::IMAGE_HASH + 32].copy_from_slice(&image_hash);
    mf[off::CODEC_ID] = Codec::Full as u8;
    mf[off::HW_ID..off::HW_ID + HW_ID_LEN].copy_from_slice(&options.board.padded_hw_id());
    mf[off::SIGNER..off::SIGNER + 32]
        .copy_from_slice(&ed25519_public_from_seed(&options.sign_seed));
    let signature = ed25519_sign(&options.sign_seed, &mf[..SIGNED_LEN]);
    mf[off::SIGNATURE..off::SIGNATURE + 64].copy_from_slice(&signature);
    mf[off::APPROVAL..off::APPROVAL + 4].copy_from_slice(&APPROVAL_NONE);

    let leaves_bytes: Vec<u8> = leaves.into_iter().flatten().collect();
    let total = HEADER_LEN + MFL + leaves_bytes.len() + options.image.len() + TRAILER_LEN;
    let mut bytes = Vec::with_capacity(total);
    bytes.extend_from_slice(&MAGIC);
    bytes.extend_from_slice(&(total as u32).to_le_bytes());
    bytes.extend_from_slice(&mf);
    bytes.extend_from_slice(&leaves_bytes);
    bytes.extend_from_slice(&options.image);
    bytes.extend_from_slice(&TRAILER);

    let manifest = Manifest::parse(&bytes)?;
    let suggested_name = format!(
        "{}_v{}_bootloader_{}.mota",
        options.board.hw_id(),
        version_str(options.fw_version),
        hex::encode_upper(root)
    );
    Ok(Built {
        bytes,
        suggested_name,
        manifest,
    })
}

fn rd_u16(bytes: &[u8], offset: usize) -> u16 {
    u16::from_le_bytes(bytes[offset..offset + 2].try_into().unwrap())
}
