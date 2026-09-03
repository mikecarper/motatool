use motatool::bootloader::{
    bootloader_image_crc32, bootloader_version_str, build_bootloader,
    extract_bootloader_region_from_hex, validate_bootloader_image_for_profile,
    validate_bootloader_inventory, BootloaderBoard, BootloaderBuildOpts, BOOTLOADER_BOARDS,
    CANDIDATE_MANIFEST_OFFSET, CAPS_MAGIC, CONTINUITY_MAGIC, IMAGE_SIZE, IMAGE_START,
    MANIFEST_MAGIC, PACKAGE_SIZE, STORAGE_INTERNAL_UPDATE, STORAGE_SD_UPDATE,
};
use motatool::crypto::ed25519_public_from_seed;
use motatool::format::{wr_u32, BOOT_FORMAT_VER, MFLAG_BOOTLOADER, MFLAG_FULL, MFLAG_SIGNED};
use motatool::{verify, Manifest};
use std::fmt::Write as _;
use std::process::Command;

const BOOT_VERSION: u32 = 0x0204_03FF;
const CAPS_OFFSET: usize = 0x80;
const TEST_SEED: [u8; 32] = [0x42; 32];

fn wr_u16(bytes: &mut [u8], offset: usize, value: u16) {
    bytes[offset..offset + 2].copy_from_slice(&value.to_le_bytes());
}

fn synthetic_image(board: BootloaderBoard, storage: u8) -> Vec<u8> {
    let mut image = vec![0xFF; IMAGE_SIZE];
    wr_u32(&mut image, 0, 0x2004_0000);
    wr_u32(&mut image, 4, IMAGE_START + 0x101);

    image[CAPS_OFFSET..CAPS_OFFSET + 8].copy_from_slice(&CAPS_MAGIC);
    wr_u16(&mut image, CAPS_OFFSET + 8, 3);
    wr_u16(&mut image, CAPS_OFFSET + 10, 0x0005);
    image[CAPS_OFFSET + 12] = storage;
    image[CAPS_OFFSET + 13..CAPS_OFFSET + 16].fill(0);

    let manifest = CANDIDATE_MANIFEST_OFFSET;
    image[manifest..manifest + 8].copy_from_slice(&MANIFEST_MAGIC);
    wr_u16(&mut image, manifest + 8, 1);
    wr_u16(&mut image, manifest + 10, 44);
    wr_u32(&mut image, manifest + 12, IMAGE_START);
    wr_u32(&mut image, manifest + 16, IMAGE_SIZE as u32);
    wr_u32(&mut image, manifest + 20, board.board_id());
    image[manifest + 24..manifest + 40].fill(0);
    let name = board.device_name().as_bytes();
    image[manifest + 24..manifest + 24 + name.len()].copy_from_slice(name);

    let continuity = manifest + 44;
    image[continuity..continuity + 8].copy_from_slice(&CONTINUITY_MAGIC);
    wr_u16(&mut image, continuity + 8, 2);
    wr_u16(&mut image, continuity + 10, 32);
    wr_u32(&mut image, continuity + 12, BOOT_VERSION);
    let compatibility = board.compatibility();
    wr_u16(&mut image, continuity + 16, compatibility.softdevice_family);
    wr_u16(&mut image, continuity + 18, compatibility.softdevice_fwid);
    wr_u32(&mut image, continuity + 20, compatibility.app_base);
    wr_u16(&mut image, continuity + 24, compatibility.layout_abi);
    wr_u16(&mut image, continuity + 26, 0);
    wr_u32(&mut image, continuity + 28, 0);

    let crc_offset = manifest + 40;
    image[crc_offset..crc_offset + 4].fill(0);
    let crc = bootloader_image_crc32(&image, crc_offset);
    wr_u32(&mut image, crc_offset, crc);
    image
}

fn build_for(board: BootloaderBoard, storage: u8) -> motatool::Built {
    build_bootloader(&BootloaderBuildOpts {
        image: synthetic_image(board, storage),
        board,
        storage_profile: storage,
        sign_seed: TEST_SEED,
    })
    .unwrap()
}

#[test]
fn qualified_inventory_builds_exact_v3_packages() {
    validate_bootloader_inventory().unwrap();
    for board in BOOTLOADER_BOARDS {
        let built = build_for(board, board.storage_profile());
        assert_eq!(built.bytes.len(), PACKAGE_SIZE, "{}", board.name());
        assert_eq!(built.manifest.format_ver, BOOT_FORMAT_VER);
        assert_eq!(
            built.manifest.flags,
            MFLAG_FULL | MFLAG_SIGNED | MFLAG_BOOTLOADER
        );
        assert_eq!(built.manifest.target_id, board.target_id());
        assert_eq!(built.manifest.hw_id, board.hw_id());
        assert_eq!(built.manifest.fw_version, BOOT_VERSION);
        assert_eq!(built.manifest.block_count, 40);
        assert!(built.inplace_memory.is_none());
        assert!(verify(&built.bytes).is_empty(), "{}", board.name());
    }

    let sd = build_for(BootloaderBoard::HeltecMeshTowerV2, STORAGE_SD_UPDATE);
    assert!(verify(&sd.bytes).is_empty());
}

#[test]
fn selected_board_and_storage_profile_are_enforced() {
    let t096 = synthetic_image(BootloaderBoard::HeltecT096, STORAGE_INTERNAL_UPDATE);
    assert!(validate_bootloader_image_for_profile(
        &t096,
        BootloaderBoard::HeltecT1,
        STORAGE_INTERNAL_UPDATE
    )
    .is_err());

    let tower_sd = synthetic_image(BootloaderBoard::HeltecMeshTowerV2, STORAGE_SD_UPDATE);
    assert!(validate_bootloader_image_for_profile(
        &tower_sd,
        BootloaderBoard::HeltecMeshTowerV2,
        STORAGE_INTERNAL_UPDATE
    )
    .is_err());
}

#[test]
fn bootloader_version_labels_stable_and_preview_builds() {
    assert_eq!(bootloader_version_str(0x0204_03FF), "2.4.3");
    assert_eq!(bootloader_version_str(0x0204_030D), "2.4.3-preview.13");
}

#[test]
fn qualified_inventory_matches_release_contract() {
    let expected = [
        (
            BootloaderBoard::XiaoNrf52840Ble,
            0x2886_0044,
            "XIAO_BL_28860044",
            0x0123,
            0x0002_7000,
            0x0E,
        ),
        (
            BootloaderBoard::XiaoNrf52840BleSense,
            0x2886_0045,
            "XIAO_BL_28860045",
            0x0123,
            0x0002_7000,
            0x0E,
        ),
        (
            BootloaderBoard::HeltecMeshTowerV2,
            0x1150_F50E,
            "NRF_BL_239A0071_TOWER_V2_OTA",
            0x00B6,
            0x0002_6000,
            0x0A,
        ),
        (
            BootloaderBoard::HeltecMeshPocket,
            0x0592_77F4,
            "NRF_BL_239A0071_MESH_POCKET_OTA",
            0x00B6,
            0x0002_6000,
            0x0A,
        ),
        (
            BootloaderBoard::HeltecT096,
            0x4235_4C85,
            "NRF_BL_239A0071_T096_DFU",
            0x00B6,
            0x0002_6000,
            0x0A,
        ),
        (
            BootloaderBoard::HeltecT1,
            0xFC55_6FFC,
            "NRF_BL_239A0071_T1_DFU",
            0x00B6,
            0x0002_6000,
            0x0A,
        ),
        (
            BootloaderBoard::HeltecT114,
            0x0C3F_2902,
            "NRF_BL_239A0071_T114_DFU",
            0x00B6,
            0x0002_6000,
            0x0A,
        ),
        (
            BootloaderBoard::KeepteenLt1,
            0xDB2E_7B51,
            "NRF_BL_239A00B3_KeepteenLT1_OTA",
            0x00B6,
            0x0002_6000,
            0x0A,
        ),
        (
            BootloaderBoard::MinewsemiMx25le01,
            0x026A_A982,
            "NRF_BL_239A0029_MX25_DFU",
            0x0123,
            0x0002_7000,
            0x0A,
        ),
        (
            BootloaderBoard::PromicroNrf52840,
            0xAF79_E8CC,
            "NRF_BL_239A00B3_PROM_DFU",
            0x00B6,
            0x0002_6000,
            0x0A,
        ),
        (
            BootloaderBoard::T1000E,
            0xE6F5_F03F,
            "NRF_BL_28860057_T1KE_DFU",
            0x0123,
            0x0002_7000,
            0x0A,
        ),
        (
            BootloaderBoard::ThinknodeM3,
            0x0CA4_1DB2,
            "NRF_BL_239A00DA_TNM3_DFU",
            0x00B6,
            0x0002_6000,
            0x0A,
        ),
        (
            BootloaderBoard::WiscoreRak3401,
            0x2381_8A80,
            "NRF_BL_239A0029_3401_DFU",
            0x00B6,
            0x0002_6000,
            0x0A,
        ),
        (
            BootloaderBoard::WiscoreRak4631Board,
            0x2D0D_F000,
            "NRF_BL_239A0029_4631_DFU",
            0x00B6,
            0x0002_6000,
            0x0A,
        ),
        (
            BootloaderBoard::WismeshTag,
            0xC72E_9C9C,
            "NRF_BL_239A0029_RTAG_DFU",
            0x00B6,
            0x0002_6000,
            0x0A,
        ),
    ];

    for ((board, target_id, hw_id, fwid, app_base, storage), listed) in
        expected.into_iter().zip(BOOTLOADER_BOARDS)
    {
        assert_eq!(board, listed);
        assert_eq!(board.target_id(), target_id, "{}", board.name());
        assert_eq!(board.hw_id_str(), hw_id, "{}", board.name());
        assert_eq!(board.compatibility().softdevice_family, 140);
        assert_eq!(board.compatibility().softdevice_fwid, fwid);
        assert_eq!(board.compatibility().app_base, app_base);
        assert_eq!(board.compatibility().layout_abi, 1);
        assert_eq!(board.storage_profile(), storage);
    }
    assert_eq!(
        BootloaderBoard::HeltecMeshTowerV2.profile_name(STORAGE_SD_UPDATE),
        Some("heltec_mesh_tower_v2_sdcard")
    );
}

fn hex_record(address: u16, record_type: u8, data: &[u8]) -> String {
    let mut bytes = Vec::with_capacity(data.len() + 4);
    bytes.push(data.len() as u8);
    bytes.extend_from_slice(&address.to_be_bytes());
    bytes.push(record_type);
    bytes.extend_from_slice(data);
    let checksum = 0u8.wrapping_sub(bytes.iter().fold(0u8, |sum, byte| sum.wrapping_add(*byte)));
    let mut line = String::from(":");
    for byte in bytes {
        write!(&mut line, "{byte:02X}").unwrap();
    }
    writeln!(&mut line, "{checksum:02X}").unwrap();
    line
}

fn image_as_intel_hex(image: &[u8]) -> String {
    let mut output = hex_record(0, 4, &[0x00, 0x0F]);
    for (offset, chunk) in image.chunks(16).enumerate() {
        output.push_str(&hex_record(0x4000 + (offset * 16) as u16, 0, chunk));
    }
    output.push_str(":00000001FF\n");
    output
}

#[test]
fn hex_extraction_clips_outside_region_and_fills_holes() {
    let lower = (0x10..0x20).collect::<Vec<u8>>();
    let upper = (0x80..0x90).collect::<Vec<u8>>();
    let mut encoded = hex_record(0, 4, &[0x00, 0x0F]);
    encoded.push_str(&hex_record(0x3FF8, 0, &lower));
    encoded.push_str(&hex_record(0xDFF8, 0, &upper));
    encoded.push_str(":00000001FF\n");

    let image = extract_bootloader_region_from_hex(encoded.as_bytes()).unwrap();
    assert_eq!(&image[..8], &lower[8..]);
    assert!(image[8..IMAGE_SIZE - 8].iter().all(|byte| *byte == 0xFF));
    assert_eq!(&image[IMAGE_SIZE - 8..], &upper[..8]);

    let mut conflicting = hex_record(0, 4, &[0x00, 0x0F]);
    conflicting.push_str(&hex_record(0x4000, 0, &[0xAA]));
    conflicting.push_str(&hex_record(0x4000, 0, &[0xBB]));
    conflicting.push_str(":00000001FF\n");
    let error = extract_bootloader_region_from_hex(conflicting.as_bytes())
        .unwrap_err()
        .to_string();
    assert!(error.contains("conflicting Intel HEX data"), "{error}");
}

#[test]
fn cli_build_bootloader_matches_release_interface() {
    let board = BootloaderBoard::HeltecT096;
    let image = synthetic_image(board, STORAGE_INTERNAL_UPDATE);
    let encoded = image_as_intel_hex(&image);
    assert_eq!(
        extract_bootloader_region_from_hex(encoded.as_bytes()).unwrap(),
        image
    );

    let dir = tempfile::tempdir().unwrap();
    let input = dir.path().join("heltec_t096_bootloader.hex");
    let key = dir.path().join("signing.key");
    let output = dir.path().join("update-heltec_t096.mota");
    std::fs::write(&input, encoded).unwrap();
    std::fs::write(&key, hex::encode_upper(TEST_SEED)).unwrap();

    let result = Command::new(env!("CARGO_BIN_EXE_motatool"))
        .arg("build-bootloader")
        .arg("--fw")
        .arg(&input)
        .arg("--board")
        .arg("heltec_t096")
        .arg("--sign")
        .arg(&key)
        .arg("--fw-version")
        .arg("2.4.3.255")
        .arg("--out")
        .arg(&output)
        .output()
        .unwrap();
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    let stdout = String::from_utf8(result.stdout).unwrap();
    assert!(stdout.contains("board=heltec_t096"), "{stdout}");

    let blob = std::fs::read(output).unwrap();
    assert_eq!(blob.len(), PACKAGE_SIZE);
    assert!(verify(&blob).is_empty());
    let manifest = Manifest::parse(&blob).unwrap();
    assert_eq!(manifest.signer, ed25519_public_from_seed(&TEST_SEED));
}

#[test]
fn serve_help_keeps_otafix_companion_compatibility_flag() {
    let result = Command::new(env!("CARGO_BIN_EXE_motatool"))
        .arg("serve")
        .arg("--help")
        .output()
        .unwrap();
    assert!(result.status.success());
    let stdout = String::from_utf8(result.stdout).unwrap();
    assert!(stdout.contains("--companion-terminal"), "{stdout}");
    assert!(stdout.contains("compatibility no-op"), "{stdout}");
}
