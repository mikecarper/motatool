//! Validation of MeshCore's privileged format-3 nRF52840 bootloader payload.
//!
//! Format 3 deliberately has the same outer byte layout as an application `.mota`, but it is not a
//! general-purpose new format version.  It is one exact, fail-closed profile for a signed 40 KiB OTAFIX
//! bootloader image.  These checks mirror MeshCore's `tools/mota/motalib.py` package parser so `verify`
//! and folder serving cannot turn an arbitrary signed blob into a bootloader offer.

use crate::crypto::sha256;
use anyhow::{ensure, Context, Result};

pub const IMAGE_START: u32 = 0x000F_4000;
pub const IMAGE_SIZE: usize = 0x0000_A000;
pub const MANIFEST_MAGIC: [u8; 8] = *b"BLMFCRC1";
pub const MANIFEST_VERSION: u16 = 1;
pub const MANIFEST_SIZE: usize = 44;
pub const CONTINUITY_MAGIC: [u8; 8] = *b"BLM2SOFT";
pub const CONTINUITY_VERSION: u16 = 2;
pub const CONTINUITY_SIZE: usize = 32;
pub const ENVELOPE_SIZE: usize = MANIFEST_SIZE + CONTINUITY_SIZE;
pub const CANDIDATE_MANIFEST_OFFSET: usize = IMAGE_SIZE - ENVELOPE_SIZE;
pub const CAPS_MAGIC: [u8; 8] = *b"MOTABLDR";

pub const STORAGE_SD: u8 = 0x01;
pub const STORAGE_STAGE_CEILING: u8 = 0x02;
pub const STORAGE_QSPI: u8 = 0x04;
pub const STORAGE_UPDATE: u8 = 0x08;
pub const STORAGE_KNOWN: u8 = 0x0F;
pub const STORAGE_SD_UPDATE: u8 = STORAGE_SD | STORAGE_UPDATE;
pub const STORAGE_QSPI_UPDATE: u8 = STORAGE_STAGE_CEILING | STORAGE_QSPI | STORAGE_UPDATE;
pub const STORAGE_INTERNAL_UPDATE: u8 = STORAGE_STAGE_CEILING | STORAGE_UPDATE;

const REQUIRED_FORMAT_ABI: u16 = 3;
const REQUIRED_APP_CODEC_MASK: u16 = (1 << 0) | (1 << 2); // FULL | DETOOLS_INPLACE
const FAMILY_S140: u16 = 140;
const S140_V6_FWID: u16 = 0x00B6;
const S140_V7_FWID: u16 = 0x0123;
const APP_BASE_S140_V6: u32 = 0x0002_6000;
const APP_BASE_S140_V7: u32 = 0x0002_7000;
const LAYOUT_ABI: u16 = 1;
const XIAO_BASE: u32 = 0x2886_0044;
const XIAO_SENSE: u32 = 0x2886_0045;

const INTERNAL_IDENTITIES: &[(u32, &str)] = &[
    (0x239A_0071, "TOWER_V2_OTA"),
    (0x239A_0071, "T096_DFU"),
    (0x239A_0071, "T1_DFU"),
    (0x239A_0071, "T114_DFU"),
    (0x239A_0071, "MESH_POCKET_OTA"),
    (0x239A_00B3, "KeepteenLT1_OTA"),
    (0x239A_0029, "MX25_DFU"),
    (0x239A_00B3, "PROM_DFU"),
    (0x2886_0057, "T1KE_DFU"),
    (0x239A_00DA, "TNM3_DFU"),
    (0x239A_0029, "3401_DFU"),
    (0x239A_0029, "4631_DFU"),
    (0x239A_0029, "RTAG_DFU"),
];
const S140_V7_IDENTITIES: &[(u32, &str)] = &[
    (XIAO_BASE, "XIAO_DFU"),
    (XIAO_SENSE, "XIAO_DFU"),
    (0x239A_0029, "MX25_DFU"),
    (0x2886_0057, "T1KE_DFU"),
];

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BootloaderIdentity {
    pub manifest_offset: usize,
    pub board_id: u32,
    pub device_name: String,
    pub boot_version: u32,
    pub softdevice_family: u16,
    pub softdevice_fwid: u16,
    pub app_base: u32,
    pub layout_abi: u16,
    pub storage_flags: u8,
}

pub fn version_valid(version: u32) -> bool {
    version != 0 && version != u32::MAX && version & 0xFF != 0
}

pub fn bootloader_hw_id(board_id: u32, device_name: &str) -> Result<[u8; 32]> {
    let name_raw = device_name.as_bytes();
    ensure!(
        name_raw.len() <= 15
            && valid_device_name(board_id, &padded_name(name_raw)?)
                .is_some_and(|parsed| parsed == device_name),
        "invalid embedded bootloader board/name identity"
    );
    let text = match board_id {
        XIAO_BASE => "XIAO_BL_28860044".to_owned(),
        XIAO_SENSE => "XIAO_BL_28860045".to_owned(),
        _ => format!("NRF_BL_{board_id:08X}_{device_name}"),
    };
    ensure!(
        text.len() <= 32,
        "canonical bootloader hw_id exceeds 32 bytes"
    );
    let mut out = [0u8; 32];
    out[..text.len()].copy_from_slice(text.as_bytes());
    Ok(out)
}

pub fn bootloader_target_id(board_id: u32, device_name: &str) -> Result<u32> {
    if matches!(board_id, XIAO_BASE | XIAO_SENSE) {
        return Ok(board_id);
    }
    let hw = bootloader_hw_id(board_id, device_name)?;
    Ok(u32::from_le_bytes(sha256(&hw)[..4].try_into().unwrap()))
}

/// Validate the complete payload contract and bind its embedded identity to the signed outer manifest.
pub fn validate_bootloader_image(
    image: &[u8],
    target_id: u32,
    signed_hw_id: &[u8; 32],
    outer_version: u32,
) -> Result<BootloaderIdentity> {
    ensure!(
        image.len() == IMAGE_SIZE,
        "bootloader image must be exactly {IMAGE_SIZE} bytes"
    );
    validate_vector(image)?;
    let embedded = parse_identity(image)?;
    ensure!(
        embedded.manifest_offset == CANDIDATE_MANIFEST_OFFSET,
        "bootloader continuity envelope must be at exact offset 0x{CANDIDATE_MANIFEST_OFFSET:04X}"
    );
    ensure!(
        outer_version == embedded.boot_version,
        "outer bootloader version does not match BLM2 metadata"
    );
    ensure!(
        target_id == bootloader_target_id(embedded.board_id, &embedded.device_name)?,
        "bootloader target ID does not match embedded identity"
    );
    ensure!(
        signed_hw_id == &bootloader_hw_id(embedded.board_id, &embedded.device_name)?,
        "bootloader signed hw_id does not match embedded identity"
    );

    let storage = capability_storage(image)
        .context("bootloader lacks one unambiguous ABI 3 self-update capability marker")?;
    let allowed = qualified_storage(embedded.board_id, &embedded.device_name);
    ensure!(
        allowed.contains(&storage),
        "bootloader self-update storage profile 0x{storage:02X} is not valid for its identity"
    );

    if let Some(expected) = qualified_platform(embedded.board_id, &embedded.device_name) {
        let actual = (
            embedded.softdevice_family,
            embedded.softdevice_fwid,
            embedded.app_base,
            embedded.layout_abi,
        );
        ensure!(
            actual == expected,
            "bootloader continuity platform does not match its qualified profile"
        );
    }

    Ok(BootloaderIdentity {
        storage_flags: storage,
        ..embedded
    })
}

fn padded_name(name: &[u8]) -> Result<[u8; 16]> {
    ensure!(name.len() <= 15, "bootloader device name exceeds 15 bytes");
    let mut out = [0u8; 16];
    out[..name.len()].copy_from_slice(name);
    Ok(out)
}

fn valid_device_name(board_id: u32, raw: &[u8; 16]) -> Option<&str> {
    if matches!(board_id, 0 | u32::MAX) {
        return None;
    }
    if matches!(board_id, XIAO_BASE | XIAO_SENSE) {
        return (raw == b"XIAO_DFU\0\0\0\0\0\0\0\0").then_some("XIAO_DFU");
    }
    let end = raw.iter().position(|&b| b == 0)?;
    if end == 0
        || raw[end..].iter().any(|&b| b != 0)
        || raw[..end].iter().any(|&b| !(0x21..=0x7E).contains(&b))
    {
        return None;
    }
    std::str::from_utf8(&raw[..end]).ok()
}

fn validate_vector(image: &[u8]) -> Result<()> {
    let sp = rd_u32(image, 0);
    let reset = rd_u32(image, 4);
    let entry = reset & !1;
    ensure!(
        sp & 7 == 0
            && (0x2000_0000..=0x2004_0000).contains(&sp)
            && reset & 1 != 0
            && (IMAGE_START..IMAGE_START + IMAGE_SIZE as u32).contains(&entry),
        "bootloader vector table is invalid"
    );
    Ok(())
}

fn parse_identity(image: &[u8]) -> Result<BootloaderIdentity> {
    let mut found: Option<(usize, u32, String)> = None;
    for off in (0..=image.len() - MANIFEST_SIZE).step_by(4) {
        if image[off..off + 8] != MANIFEST_MAGIC {
            continue;
        }
        let version = rd_u16(image, off + 8);
        let size = rd_u16(image, off + 10) as usize;
        let start = rd_u32(image, off + 12);
        let image_size = rd_u32(image, off + 16) as usize;
        let board_id = rd_u32(image, off + 20);
        let name_raw: &[u8; 16] = image[off + 24..off + 40].try_into().unwrap();
        let Some(device_name) = valid_device_name(board_id, name_raw) else {
            continue;
        };
        let stored_crc = rd_u32(image, off + 40);
        if version != MANIFEST_VERSION
            || size != MANIFEST_SIZE
            || start != IMAGE_START
            || image_size != IMAGE_SIZE
            || crc32_with_zeroed(image, off + 40..off + 44) != stored_crc
        {
            continue;
        }
        ensure!(
            found.is_none(),
            "bootloader embedded manifest/CRC is ambiguous"
        );
        found = Some((off, board_id, device_name.to_owned()));
    }
    let (off, board_id, device_name) =
        found.context("bootloader embedded manifest/CRC is invalid")?;

    let ext = image
        .get(off + MANIFEST_SIZE..off + ENVELOPE_SIZE)
        .context("bootloader continuity extension is truncated")?;
    ensure!(
        ext[..8] == CONTINUITY_MAGIC,
        "bootloader lacks the BLM2/SOFT continuity extension"
    );
    ensure!(
        rd_u16(ext, 8) == CONTINUITY_VERSION && rd_u16(ext, 10) as usize == CONTINUITY_SIZE,
        "bootloader continuity extension has an invalid version/size"
    );
    let boot_version = rd_u32(ext, 12);
    let family = rd_u16(ext, 16);
    let fwid = rd_u16(ext, 18);
    let app_base = rd_u32(ext, 20);
    let layout_abi = rd_u16(ext, 24);
    let compat = rd_u16(ext, 26);
    let reserved = rd_u32(ext, 28);
    ensure!(
        version_valid(boot_version)
            && family != 0
            && fwid != 0
            && app_base != 0
            && layout_abi != 0
            && compat == 0
            && reserved == 0,
        "bootloader continuity metadata is invalid"
    );
    Ok(BootloaderIdentity {
        manifest_offset: off,
        board_id,
        device_name,
        boot_version,
        softdevice_family: family,
        softdevice_fwid: fwid,
        app_base,
        layout_abi,
        storage_flags: 0,
    })
}

fn capability_storage(image: &[u8]) -> Option<u8> {
    let mut found = None;
    let mut valid_count = 0u8;
    for off in (0..=image.len() - 16).step_by(4) {
        if image[off..off + 8] != CAPS_MAGIC {
            continue;
        }
        let abi = rd_u16(image, off + 8);
        let codecs = rd_u16(image, off + 10);
        let storage = image[off + 12];
        if abi < REQUIRED_FORMAT_ABI
            || abi == u16::MAX
            || codecs & REQUIRED_APP_CODEC_MASK != REQUIRED_APP_CODEC_MASK
            || storage & !STORAGE_KNOWN != 0
            || storage & STORAGE_UPDATE == 0
            || image[off + 13..off + 16] != [0, 0, 0]
        {
            continue;
        }
        valid_count = valid_count.saturating_add(1);
        if valid_count != 1 {
            return None;
        }
        if matches!(
            storage,
            STORAGE_SD_UPDATE | STORAGE_QSPI_UPDATE | STORAGE_INTERNAL_UPDATE
        ) {
            found = Some(storage);
        }
    }
    (valid_count == 1).then_some(found).flatten()
}

fn qualified_storage(board_id: u32, name: &str) -> &'static [u8] {
    const INTERNAL: &[u8] = &[STORAGE_INTERNAL_UPDATE];
    const QSPI: &[u8] = &[STORAGE_QSPI_UPDATE];
    const TOWER: &[u8] = &[STORAGE_INTERNAL_UPDATE, STORAGE_SD_UPDATE];
    if matches!(board_id, XIAO_BASE | XIAO_SENSE) && name == "XIAO_DFU" {
        QSPI
    } else if board_id == 0x239A_0071 && name == "TOWER_V2_OTA" {
        TOWER
    } else {
        // Generic, future canonical identities are inspectable, but—as in MeshCore's reference parser—
        // they do not silently acquire SD/QSPI privileges outside the qualified inventory.
        INTERNAL
    }
}

fn qualified_platform(board_id: u32, name: &str) -> Option<(u16, u16, u32, u16)> {
    let qualified = matches!(board_id, XIAO_BASE | XIAO_SENSE) && name == "XIAO_DFU"
        || INTERNAL_IDENTITIES.contains(&(board_id, name));
    if !qualified {
        return None;
    }
    let v7 = S140_V7_IDENTITIES.contains(&(board_id, name));
    Some(if v7 {
        (FAMILY_S140, S140_V7_FWID, APP_BASE_S140_V7, LAYOUT_ABI)
    } else {
        (FAMILY_S140, S140_V6_FWID, APP_BASE_S140_V6, LAYOUT_ABI)
    })
}

fn crc32_with_zeroed(bytes: &[u8], zero: std::ops::Range<usize>) -> u32 {
    let mut crc = u32::MAX;
    for (i, &stored) in bytes.iter().enumerate() {
        let byte = if zero.contains(&i) { 0 } else { stored };
        crc ^= u32::from(byte);
        for _ in 0..8 {
            crc = (crc >> 1) ^ (0xEDB8_8320 & 0u32.wrapping_sub(crc & 1));
        }
    }
    !crc
}

fn rd_u16(buf: &[u8], off: usize) -> u16 {
    u16::from_le_bytes(buf[off..off + 2].try_into().unwrap())
}

fn rd_u32(buf: &[u8], off: usize) -> u32 {
    u32::from_le_bytes(buf[off..off + 4].try_into().unwrap())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn t096_wire_identity_is_stable() {
        let hw = bootloader_hw_id(0x239A_0071, "T096_DFU").unwrap();
        assert_eq!(&hw[..24], b"NRF_BL_239A0071_T096_DFU");
        assert_eq!(
            bootloader_target_id(0x239A_0071, "T096_DFU").unwrap(),
            0x4235_4C85
        );
    }

    #[test]
    fn version_rejects_sentinels_and_release_marker() {
        assert!(!version_valid(0));
        assert!(!version_valid(u32::MAX));
        assert!(!version_valid(0x0204_0400));
        assert!(version_valid(0x0204_0401));
    }
}
