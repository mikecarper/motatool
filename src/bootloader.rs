//! Validation of MeshCore's privileged format-3 nRF52840 bootloader payload.
//!
//! Format 3 deliberately has the same outer byte layout as an application `.mota`, but it is not a
//! general-purpose new format version.  It is one exact, fail-closed profile for a signed 40 KiB OTAFIX
//! bootloader image.  These checks mirror MeshCore's `tools/mota/motalib.py` package parser so `verify`
//! and folder serving cannot turn an arbitrary signed blob into a bootloader offer.

use crate::build::Built;
use crate::crypto::{ed25519_public_from_seed, ed25519_sign, sha256};
use crate::format::{
    off, wr_u32, Codec, Manifest, APPROVAL_NONE, BOOTLOADER_BLOCK_SIZE, BOOT_FORMAT_VER,
    HASH_ALGO_SHA256, HEADER_LEN, HW_ID_LEN, MAGIC, MFL, MFLAG_BOOTLOADER, MFLAG_FULL,
    MFLAG_SIGNED, SIGNED_LEN, TRAILER, TRAILER_LEN,
};
use crate::merkle;
use anyhow::{bail, ensure, Context, Result};

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
pub const BLOCK_COUNT: usize = IMAGE_SIZE / BOOTLOADER_BLOCK_SIZE as usize;
pub const PACKAGE_SIZE: usize = HEADER_LEN + MFL + BLOCK_COUNT * 4 + IMAGE_SIZE + TRAILER_LEN;

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

/// Exact OTAFIX bootloader identities qualified for package creation.
///
/// Board ID alone is not an identity because several boards share a vendor ID.
/// Every selection is bound to the complete embedded device name as well.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BootloaderBoard {
    XiaoNrf52840Ble,
    XiaoNrf52840BleSense,
    Gat562,
    HeltecMeshTowerV2,
    HeltecMeshPocket,
    HeltecT096,
    HeltecT1,
    HeltecT114,
    KeepteenLt1,
    MinewsemiMx25le01,
    PromicroNrf52840,
    T1000E,
    ThinknodeM3,
    WiscoreRak3401,
    WiscoreRak4631Board,
    WismeshTag,
}

pub const BOOTLOADER_BOARDS: [BootloaderBoard; 16] = [
    BootloaderBoard::XiaoNrf52840Ble,
    BootloaderBoard::XiaoNrf52840BleSense,
    BootloaderBoard::Gat562,
    BootloaderBoard::HeltecMeshTowerV2,
    BootloaderBoard::HeltecMeshPocket,
    BootloaderBoard::HeltecT096,
    BootloaderBoard::HeltecT1,
    BootloaderBoard::HeltecT114,
    BootloaderBoard::KeepteenLt1,
    BootloaderBoard::MinewsemiMx25le01,
    BootloaderBoard::PromicroNrf52840,
    BootloaderBoard::T1000E,
    BootloaderBoard::ThinknodeM3,
    BootloaderBoard::WiscoreRak3401,
    BootloaderBoard::WiscoreRak4631Board,
    BootloaderBoard::WismeshTag,
];

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BootloaderCompatibility {
    pub softdevice_family: u16,
    pub softdevice_fwid: u16,
    pub app_base: u32,
    pub layout_abi: u16,
}

impl BootloaderBoard {
    pub const fn board_id(self) -> u32 {
        match self {
            Self::XiaoNrf52840Ble => XIAO_BASE,
            Self::XiaoNrf52840BleSense => XIAO_SENSE,
            Self::HeltecMeshTowerV2
            | Self::HeltecMeshPocket
            | Self::HeltecT096
            | Self::HeltecT1
            | Self::HeltecT114 => 0x239A_0071,
            Self::KeepteenLt1 | Self::PromicroNrf52840 => 0x239A_00B3,
            Self::Gat562
            | Self::MinewsemiMx25le01
            | Self::WiscoreRak3401
            | Self::WiscoreRak4631Board
            | Self::WismeshTag => 0x239A_0029,
            Self::T1000E => 0x2886_0057,
            Self::ThinknodeM3 => 0x239A_00DA,
        }
    }

    pub const fn name(self) -> &'static str {
        match self {
            Self::XiaoNrf52840Ble => "xiao_nrf52840_ble",
            Self::XiaoNrf52840BleSense => "xiao_nrf52840_ble_sense",
            Self::Gat562 => "gat562",
            Self::HeltecMeshTowerV2 => "heltec_mesh_tower_v2",
            Self::HeltecMeshPocket => "heltec_mesh_pocket",
            Self::HeltecT096 => "heltec_t096",
            Self::HeltecT1 => "heltec_t1",
            Self::HeltecT114 => "heltec_t114",
            Self::KeepteenLt1 => "keepteen_lt1",
            Self::MinewsemiMx25le01 => "minewsemi_mx25le01",
            Self::PromicroNrf52840 => "promicro_nrf52840",
            Self::T1000E => "t1000_e",
            Self::ThinknodeM3 => "thinknode_m3",
            Self::WiscoreRak3401 => "wiscore_rak3401",
            Self::WiscoreRak4631Board => "wiscore_rak4631_board",
            Self::WismeshTag => "wismesh_tag",
        }
    }

    pub const fn device_name(self) -> &'static str {
        match self {
            Self::XiaoNrf52840Ble | Self::XiaoNrf52840BleSense => "XIAO_DFU",
            Self::Gat562 => "GAT562_DFU",
            Self::HeltecMeshTowerV2 => "TOWER_V2_OTA",
            Self::HeltecMeshPocket => "MESH_POCKET_OTA",
            Self::HeltecT096 => "T096_DFU",
            Self::HeltecT1 => "T1_DFU",
            Self::HeltecT114 => "T114_DFU",
            Self::KeepteenLt1 => "KeepteenLT1_OTA",
            Self::MinewsemiMx25le01 => "MX25_DFU",
            Self::PromicroNrf52840 => "PROM_DFU",
            Self::T1000E => "T1KE_DFU",
            Self::ThinknodeM3 => "TNM3_DFU",
            Self::WiscoreRak3401 => "3401_DFU",
            Self::WiscoreRak4631Board => "4631_DFU",
            Self::WismeshTag => "RTAG_DFU",
        }
    }

    pub const fn storage_profile(self) -> u8 {
        match self {
            Self::XiaoNrf52840Ble | Self::XiaoNrf52840BleSense => STORAGE_QSPI_UPDATE,
            _ => STORAGE_INTERNAL_UPDATE,
        }
    }

    pub const fn accepts_storage_profile(self, profile: u8) -> bool {
        match self {
            Self::HeltecMeshTowerV2 => {
                profile == STORAGE_INTERNAL_UPDATE || profile == STORAGE_SD_UPDATE
            }
            _ => profile == self.storage_profile(),
        }
    }

    pub const fn profile_name(self, profile: u8) -> Option<&'static str> {
        match (self, profile) {
            (Self::HeltecMeshTowerV2, STORAGE_SD_UPDATE) => Some("heltec_mesh_tower_v2_sdcard"),
            _ if profile == self.storage_profile() => Some(self.name()),
            _ => None,
        }
    }

    pub const fn compatibility(self) -> BootloaderCompatibility {
        match self {
            Self::XiaoNrf52840Ble
            | Self::XiaoNrf52840BleSense
            | Self::MinewsemiMx25le01
            | Self::T1000E => BootloaderCompatibility {
                softdevice_family: FAMILY_S140,
                softdevice_fwid: S140_V7_FWID,
                app_base: APP_BASE_S140_V7,
                layout_abi: LAYOUT_ABI,
            },
            _ => BootloaderCompatibility {
                softdevice_family: FAMILY_S140,
                softdevice_fwid: S140_V6_FWID,
                app_base: APP_BASE_S140_V6,
                layout_abi: LAYOUT_ABI,
            },
        }
    }

    pub fn hw_id(self) -> [u8; HW_ID_LEN] {
        bootloader_hw_id(self.board_id(), self.device_name())
            .expect("qualified bootloader identity must have a canonical hw_id")
    }

    pub fn hw_id_str(self) -> String {
        let value = self.hw_id();
        let end = value
            .iter()
            .position(|byte| *byte == 0)
            .unwrap_or(value.len());
        std::str::from_utf8(&value[..end])
            .expect("qualified bootloader hw_id must be ASCII")
            .to_owned()
    }

    pub fn target_id(self) -> u32 {
        bootloader_target_id(self.board_id(), self.device_name())
            .expect("qualified bootloader identity must have a target ID")
    }

    pub fn from_identity(board_id: u32, device_name: &str) -> Option<Self> {
        BOOTLOADER_BOARDS
            .into_iter()
            .find(|board| board.board_id() == board_id && board.device_name() == device_name)
    }
}

/// Validate the checked-in builder inventory before trusting its derived routes.
pub fn validate_bootloader_inventory() -> Result<()> {
    for (index, board) in BOOTLOADER_BOARDS.iter().copied().enumerate() {
        let hw_id = board.hw_id();
        let target_id = board.target_id();
        ensure!(
            !matches!(target_id, 0 | u32::MAX),
            "invalid bootloader target ID for {}",
            board.name()
        );
        ensure!(
            qualified_storage(board.board_id(), board.device_name())
                .contains(&board.storage_profile()),
            "invalid bootloader storage inventory for {}",
            board.name()
        );
        let compatibility = board.compatibility();
        ensure!(
            qualified_platform(board.board_id(), board.device_name())
                == Some((
                    compatibility.softdevice_family,
                    compatibility.softdevice_fwid,
                    compatibility.app_base,
                    compatibility.layout_abi,
                )),
            "invalid bootloader platform inventory for {}",
            board.name()
        );
        if let Some(application) = crate::targets::env_name(target_id) {
            bail!(
                "bootloader target ID 0x{target_id:08X} for {} collides with application target {application}",
                board.name()
            );
        }
        for other in BOOTLOADER_BOARDS[index + 1..].iter().copied() {
            ensure!(
                (board.board_id(), board.device_name()) != (other.board_id(), other.device_name()),
                "duplicate bootloader identity: {} and {}",
                board.name(),
                other.name()
            );
            ensure!(
                hw_id != other.hw_id(),
                "bootloader hw_id collision: {} and {}",
                board.name(),
                other.name()
            );
            ensure!(
                target_id != other.target_id(),
                "bootloader target ID collision: {} and {}",
                board.name(),
                other.name()
            );
        }
    }
    Ok(())
}

/// Render the OTAFIX version encoded in BLM2 continuity metadata.
pub fn bootloader_version_str(version: u32) -> String {
    let base = format!(
        "{}.{}.{}",
        (version >> 24) & 0xFF,
        (version >> 16) & 0xFF,
        (version >> 8) & 0xFF
    );
    match version & 0xFF {
        0xFF => base,
        preview => format!("{base}-preview.{preview}"),
    }
}

const INTERNAL_IDENTITIES: &[(u32, &str)] = &[
    (0x239A_0029, "GAT562_DFU"),
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

pub struct BootloaderBuildOpts {
    /// Exact padded bytes for IMAGE_START through IMAGE_START + IMAGE_SIZE.
    pub image: Vec<u8>,
    pub board: BootloaderBoard,
    /// Exact successor storage profile selected by the operator.
    pub storage_profile: u8,
    /// Bootloader packages must always be signed.
    pub sign_seed: [u8; 32],
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

/// Validate an image against an explicitly selected release profile.
pub fn validate_bootloader_image_for_profile(
    image: &[u8],
    board: BootloaderBoard,
    storage_profile: u8,
) -> Result<BootloaderIdentity> {
    validate_bootloader_inventory()?;
    ensure!(
        board.accepts_storage_profile(storage_profile),
        "storage profile 0x{storage_profile:02X} is not valid for {}",
        board.name()
    );
    ensure!(
        image.len() == IMAGE_SIZE,
        "bootloader image must be exactly {IMAGE_SIZE} bytes"
    );
    validate_vector(image)?;
    let parsed = parse_identity(image)?;
    ensure!(
        parsed.board_id == board.board_id() && parsed.device_name == board.device_name(),
        "embedded bootloader identity does not match selected board {}",
        board.name()
    );
    let identity = validate_bootloader_image(
        image,
        board.target_id(),
        &board.hw_id(),
        parsed.boot_version,
    )?;
    ensure!(
        identity.storage_flags == storage_profile,
        "embedded storage profile 0x{:02X} does not match selected profile 0x{storage_profile:02X}",
        identity.storage_flags
    );
    let compatibility = board.compatibility();
    ensure!(
        (
            identity.softdevice_family,
            identity.softdevice_fwid,
            identity.app_base,
            identity.layout_abi,
        ) == (
            compatibility.softdevice_family,
            compatibility.softdevice_fwid,
            compatibility.app_base,
            compatibility.layout_abi,
        ),
        "embedded continuity metadata does not match selected board {}",
        board.name()
    );
    Ok(identity)
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

/// Extract the exact bootloader-copy region from an OTAFIX Intel HEX file.
/// Data outside the region is ignored and holes are filled with erased bytes.
pub fn extract_bootloader_region_from_hex(bytes: &[u8]) -> Result<Vec<u8>> {
    use ihex::Record;

    let text = std::str::from_utf8(bytes).context("Intel HEX is not valid UTF-8")?;
    let mut image = vec![0xFF; IMAGE_SIZE];
    let mut written = vec![false; IMAGE_SIZE];
    let mut base = 0u32;
    let mut saw_region_data = false;
    let mut saw_eof = false;

    for record in ihex::Reader::new(text) {
        match record.context("malformed Intel HEX record")? {
            Record::Data { offset, value } => {
                let address = base
                    .checked_add(u32::from(offset))
                    .context("Intel HEX data address overflow")?;
                let end = address
                    .checked_add(value.len() as u32)
                    .context("Intel HEX data range overflow")?;
                let copy_start = address.max(IMAGE_START);
                let copy_end = end.min(IMAGE_START + IMAGE_SIZE as u32);
                if copy_start < copy_end {
                    saw_region_data = true;
                    let source = (copy_start - address) as usize;
                    let destination = (copy_start - IMAGE_START) as usize;
                    let length = (copy_end - copy_start) as usize;
                    for index in 0..length {
                        let byte = value[source + index];
                        if written[destination + index] && image[destination + index] != byte {
                            bail!(
                                "conflicting Intel HEX data at address 0x{:08X}",
                                copy_start + index as u32
                            );
                        }
                        image[destination + index] = byte;
                        written[destination + index] = true;
                    }
                }
            }
            Record::ExtendedLinearAddress(upper) => base = u32::from(upper) << 16,
            Record::ExtendedSegmentAddress(segment) => base = u32::from(segment) << 4,
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
        "Intel HEX contains no data in bootloader region 0x{IMAGE_START:08X}..0x{:08X}",
        IMAGE_START + IMAGE_SIZE as u32
    );
    Ok(image)
}

/// Calculate the embedded bootloader CRC with its four-byte field zeroed.
pub fn bootloader_image_crc32(image: &[u8], crc_offset: usize) -> u32 {
    crc32_with_zeroed(image, crc_offset..crc_offset.saturating_add(4))
}

/// Build a signed, exact-board format-3 bootloader package.
pub fn build_bootloader(options: &BootloaderBuildOpts) -> Result<Built> {
    let identity = validate_bootloader_image_for_profile(
        &options.image,
        options.board,
        options.storage_profile,
    )?;
    let leaves = merkle::leaf_hashes(&options.image, BOOTLOADER_BLOCK_SIZE as usize);
    ensure!(
        leaves.len() == BLOCK_COUNT,
        "bootloader payload must yield exactly {BLOCK_COUNT} blocks"
    );
    let root = merkle::root(&leaves);
    let image_hash = sha256(&options.image);

    let mut manifest_bytes = [0u8; MFL];
    manifest_bytes[off::FORMAT_VER] = BOOT_FORMAT_VER;
    manifest_bytes[off::FLAGS] = MFLAG_FULL | MFLAG_SIGNED | MFLAG_BOOTLOADER;
    manifest_bytes[off::HASH_ALGO] = HASH_ALGO_SHA256;
    wr_u32(
        &mut manifest_bytes,
        off::TARGET_ID,
        options.board.target_id(),
    );
    wr_u32(&mut manifest_bytes, off::FW_VERSION, identity.boot_version);
    wr_u32(&mut manifest_bytes, off::IMAGE_SIZE, IMAGE_SIZE as u32);
    wr_u32(&mut manifest_bytes, off::PAYLOAD_SIZE, IMAGE_SIZE as u32);
    manifest_bytes[off::BLOCK_SIZE_LOG2] = BOOTLOADER_BLOCK_SIZE.ilog2() as u8;
    manifest_bytes[off::MERKLE_ROOT..off::MERKLE_ROOT + root.len()].copy_from_slice(&root);
    manifest_bytes[off::IMAGE_HASH..off::IMAGE_HASH + image_hash.len()]
        .copy_from_slice(&image_hash);
    manifest_bytes[off::CODEC_ID] = Codec::Full as u8;
    manifest_bytes[off::HW_ID..off::HW_ID + HW_ID_LEN].copy_from_slice(&options.board.hw_id());
    manifest_bytes[off::SIGNER..off::SIGNER + 32]
        .copy_from_slice(&ed25519_public_from_seed(&options.sign_seed));
    let signature = ed25519_sign(&options.sign_seed, &manifest_bytes[..SIGNED_LEN]);
    manifest_bytes[off::SIGNATURE..off::SIGNATURE + signature.len()].copy_from_slice(&signature);
    manifest_bytes[off::APPROVAL..off::APPROVAL + APPROVAL_NONE.len()]
        .copy_from_slice(&APPROVAL_NONE);

    let leaves_bytes: Vec<u8> = leaves.into_iter().flatten().collect();
    let mut bytes = Vec::with_capacity(PACKAGE_SIZE);
    bytes.extend_from_slice(&MAGIC);
    bytes.extend_from_slice(&(PACKAGE_SIZE as u32).to_le_bytes());
    bytes.extend_from_slice(&manifest_bytes);
    bytes.extend_from_slice(&leaves_bytes);
    bytes.extend_from_slice(&options.image);
    bytes.extend_from_slice(&TRAILER);
    ensure!(
        bytes.len() == PACKAGE_SIZE,
        "bootloader package geometry drifted from {PACKAGE_SIZE} bytes"
    );

    let manifest = Manifest::parse(&bytes)?;
    let suggested_name = format!(
        "{}_v{}_bootloader_{}.mota",
        options.board.hw_id_str(),
        bootloader_version_str(identity.boot_version),
        hex::encode_upper(root)
    );
    Ok(Built {
        bytes,
        suggested_name,
        manifest,
        inplace_memory: None,
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
