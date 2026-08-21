//! Signed, exact-board OTAFIX bootloader package contract.

use motatool::bootloader::*;
use motatool::crypto::{ed25519_public_from_seed, ed25519_sign, sha256};
use motatool::format::{
    off, rd_u32, BOOTLOADER_FORMAT_VER, HEADER_LEN, HW_ID_LEN, MFLAG_BOOTLOADER, MFLAG_FULL,
    MFLAG_SIGNED, NRF52_APP_END, NRF52_FLASH_PAGE, SIGNED_LEN,
};
use motatool::merkle;
use motatool::{build_bootloader, verify, BootloaderBuildOpts, Manifest};
use std::process::Command;

const MANIFEST_OFFSET: usize = 0x8000;
const CAPS_OFFSET: usize = 0x0100;
const FALSE_CAPS_OFFSET: usize = 0x0080;
const FALSE_MANIFEST_OFFSET: usize = 0x0200;
const SEED: [u8; 32] = [0x5A; 32];

fn wr_u16(bytes: &mut [u8], offset: usize, value: u16) {
    bytes[offset..offset + 2].copy_from_slice(&value.to_le_bytes());
}

fn wr_u32(bytes: &mut [u8], offset: usize, value: u32) {
    bytes[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
}

fn make_image(board: BootloaderBoard) -> Vec<u8> {
    let mut image = vec![0xFF; BOOTLOADER_IMAGE_SIZE];

    // Plausible nRF52840 vector table at the beginning of the copied region.
    wr_u32(&mut image, 0, NRF52840_RAM_END);
    wr_u32(&mut image, 4, BOOTLOADER_IMAGE_START + 0x101); // Thumb bit set.
    image[8..32].fill(0x00);

    // A literal-pool occurrence precedes the real capability marker; the scanner must skip it.
    image[FALSE_CAPS_OFFSET..FALSE_CAPS_OFFSET + 8].copy_from_slice(&BOOTLOADER_CAPS_MAGIC);
    image[CAPS_OFFSET..CAPS_OFFSET + 8].copy_from_slice(&BOOTLOADER_CAPS_MAGIC);
    wr_u16(&mut image, CAPS_OFFSET + 8, BOOTLOADER_MIN_APPLY_ABI);
    wr_u16(&mut image, CAPS_OFFSET + 10, 0x0005); // full + in-place codecs
    image[CAPS_OFFSET + 12] = board.storage_profile();
    image[CAPS_OFFSET + 13..CAPS_OFFSET + 16].fill(0);

    // Likewise, a bare magic pair is not a complete embedded update manifest.
    wr_u32(&mut image, FALSE_MANIFEST_OFFSET, UPDATE_MANIFEST_MAGIC0);
    wr_u32(
        &mut image,
        FALSE_MANIFEST_OFFSET + 4,
        UPDATE_MANIFEST_MAGIC1,
    );
    wr_u16(
        &mut image,
        FALSE_MANIFEST_OFFSET + 8,
        UPDATE_MANIFEST_VERSION,
    );
    wr_u16(
        &mut image,
        FALSE_MANIFEST_OFFSET + 10,
        UPDATE_MANIFEST_SIZE as u16,
    );

    wr_u32(&mut image, MANIFEST_OFFSET, UPDATE_MANIFEST_MAGIC0);
    wr_u32(&mut image, MANIFEST_OFFSET + 4, UPDATE_MANIFEST_MAGIC1);
    wr_u16(&mut image, MANIFEST_OFFSET + 8, UPDATE_MANIFEST_VERSION);
    wr_u16(
        &mut image,
        MANIFEST_OFFSET + 10,
        UPDATE_MANIFEST_SIZE as u16,
    );
    wr_u32(&mut image, MANIFEST_OFFSET + 12, BOOTLOADER_IMAGE_START);
    wr_u32(
        &mut image,
        MANIFEST_OFFSET + 16,
        BOOTLOADER_IMAGE_SIZE as u32,
    );
    wr_u32(&mut image, MANIFEST_OFFSET + 20, board.board_id());
    image[MANIFEST_OFFSET + 24..MANIFEST_OFFSET + 40].fill(0);
    let name = board.device_name().as_bytes();
    image[MANIFEST_OFFSET + 24..MANIFEST_OFFSET + 24 + name.len()].copy_from_slice(name);
    rewrite_image_crc(&mut image);
    image
}

fn rewrite_image_crc(image: &mut [u8]) {
    let crc_offset = MANIFEST_OFFSET + UPDATE_MANIFEST_CRC_OFFSET;
    let crc = bootloader_image_crc32(image, crc_offset);
    wr_u32(image, crc_offset, crc);
}

fn write_manifest_header(image: &mut [u8], offset: usize, board: BootloaderBoard) {
    wr_u32(image, offset, UPDATE_MANIFEST_MAGIC0);
    wr_u32(image, offset + 4, UPDATE_MANIFEST_MAGIC1);
    wr_u16(image, offset + 8, UPDATE_MANIFEST_VERSION);
    wr_u16(image, offset + 10, UPDATE_MANIFEST_SIZE as u16);
    wr_u32(image, offset + 12, BOOTLOADER_IMAGE_START);
    wr_u32(image, offset + 16, BOOTLOADER_IMAGE_SIZE as u32);
    wr_u32(image, offset + 20, board.board_id());
    image[offset + 24..offset + 40].fill(0);
    let name = board.device_name().as_bytes();
    image[offset + 24..offset + 24 + name.len()].copy_from_slice(name);
    wr_u32(image, offset + UPDATE_MANIFEST_CRC_OFFSET, 0);
}

/// Solve the two coupled CRC fields so both otherwise identical embedded manifests validate against the
/// same complete image. CRC32 is affine over GF(2); reducing the resulting 64 equations makes the duplicate
/// identity rejection exercise two genuinely valid candidates rather than two merely plausible headers.
fn make_both_manifest_crcs_valid(image: &mut [u8], first: usize, second: usize) {
    let first_crc = first + UPDATE_MANIFEST_CRC_OFFSET;
    let second_crc = second + UPDATE_MANIFEST_CRC_OFFSET;
    wr_u32(image, first_crc, 0);
    wr_u32(image, second_crc, 0);

    let residual = |value: u64| {
        let mut trial = image.to_vec();
        wr_u32(&mut trial, first_crc, value as u32);
        wr_u32(&mut trial, second_crc, (value >> 32) as u32);
        let first_error = rd_u32(&trial, first_crc) ^ bootloader_image_crc32(&trial, first_crc);
        let second_error = rd_u32(&trial, second_crc) ^ bootloader_image_crc32(&trial, second_crc);
        first_error as u64 | ((second_error as u64) << 32)
    };

    let affine = residual(0);
    let mut columns = [0u64; 64];
    for (bit, column) in columns.iter_mut().enumerate() {
        *column = residual(1u64 << bit) ^ affine;
    }
    let mut rows = [0u128; 64];
    for (out_bit, row) in rows.iter_mut().enumerate() {
        for (in_bit, column) in columns.iter().enumerate() {
            if (column >> out_bit) & 1 != 0 {
                *row |= 1u128 << in_bit;
            }
        }
        if (affine >> out_bit) & 1 != 0 {
            *row |= 1u128 << 64;
        }
    }

    let mut pivot_columns = [usize::MAX; 64];
    let mut pivot_row = 0usize;
    for column in 0..64 {
        let Some(found) = (pivot_row..64).find(|&row| (rows[row] >> column) & 1 != 0) else {
            continue;
        };
        rows.swap(pivot_row, found);
        for row in 0..64 {
            if row != pivot_row && (rows[row] >> column) & 1 != 0 {
                rows[row] ^= rows[pivot_row];
            }
        }
        pivot_columns[pivot_row] = column;
        pivot_row += 1;
    }
    for row in &rows[pivot_row..] {
        assert!(
            *row != 1u128 << 64,
            "duplicate-manifest CRC equations are inconsistent"
        );
    }
    let mut solution = 0u64;
    for row in 0..pivot_row {
        if (rows[row] >> 64) & 1 != 0 {
            solution |= 1u64 << pivot_columns[row];
        }
    }
    assert_eq!(
        residual(solution),
        0,
        "failed to solve duplicate-manifest CRC fields"
    );
    wr_u32(image, first_crc, solution as u32);
    wr_u32(image, second_crc, (solution >> 32) as u32);
}

fn opts(image: Vec<u8>, board: BootloaderBoard) -> BootloaderBuildOpts {
    BootloaderBuildOpts {
        image,
        board,
        fw_version: 0x0102_0300,
        sign_seed: SEED,
    }
}

fn resign(blob: &mut [u8]) {
    blob[HEADER_LEN + off::SIGNER..HEADER_LEN + off::SIGNER + 32]
        .copy_from_slice(&ed25519_public_from_seed(&SEED));
    let signature = ed25519_sign(&SEED, &blob[HEADER_LEN..HEADER_LEN + SIGNED_LEN]);
    blob[HEADER_LEN + off::SIGNATURE..HEADER_LEN + off::SIGNATURE + 64].copy_from_slice(&signature);
}

fn refresh_payload_integrity(blob: &mut [u8]) {
    let manifest = Manifest::parse(blob).unwrap();
    let payload_start = manifest.payload_off();
    let payload_end = payload_start + manifest.payload_size as usize;
    let embedded_crc_offset = MANIFEST_OFFSET + UPDATE_MANIFEST_CRC_OFFSET;
    let embedded_crc =
        bootloader_image_crc32(&blob[payload_start..payload_end], embedded_crc_offset);
    wr_u32(blob, payload_start + embedded_crc_offset, embedded_crc);

    let payload = &blob[payload_start..payload_end];
    let leaves = merkle::leaf_hashes(payload, manifest.block_size() as usize);
    let leaves_bytes: Vec<u8> = leaves.iter().flatten().copied().collect();
    blob[manifest.leaves_off()..payload_start].copy_from_slice(&leaves_bytes);
    blob[HEADER_LEN + off::MERKLE_ROOT..HEADER_LEN + off::MERKLE_ROOT + 4]
        .copy_from_slice(&merkle::root(&leaves));
    let image_hash = sha256(&blob[payload_start..payload_end]);
    blob[HEADER_LEN + off::IMAGE_HASH..HEADER_LEN + off::IMAGE_HASH + 32]
        .copy_from_slice(&image_hash);
    resign(blob);
}

#[test]
fn signed_exact_board_package_roundtrips() {
    validate_bootloader_inventory().unwrap();
    for board in BOOTLOADER_BOARDS {
        let image = make_image(board);
        let built = build_bootloader(&opts(image.clone(), board)).unwrap();
        assert!(verify(&built.bytes).is_empty());

        let manifest = Manifest::parse(&built.bytes).unwrap();
        assert_eq!(manifest.format_ver, BOOTLOADER_FORMAT_VER);
        assert_eq!(manifest.flags, MFLAG_FULL | MFLAG_SIGNED | MFLAG_BOOTLOADER);
        assert!(manifest.is_full() && manifest.is_signed() && manifest.is_bootloader());
        assert_eq!(manifest.target_id, board.target_id());
        assert_eq!(manifest.hw_id_str(), board.hw_id());
        assert_eq!(manifest.image_size, BOOTLOADER_IMAGE_SIZE as u32);
        assert_eq!(manifest.payload_size, BOOTLOADER_IMAGE_SIZE as u32);
        assert_eq!(manifest.block_size(), BOOTLOADER_BLOCK_SIZE);
        assert_eq!(manifest.block_count, BOOTLOADER_BLOCK_COUNT);
        assert_eq!(built.bytes.len(), BOOTLOADER_PACKAGE_SIZE);
        assert_eq!(BOOTLOADER_PACKAGE_SIZE, 41_330);
        let payload = &built.bytes
            [manifest.payload_off()..manifest.payload_off() + manifest.payload_size as usize];
        assert_eq!(payload, image);
        assert_eq!(
            validate_bootloader_package(&manifest, payload)
                .unwrap()
                .board_id,
            board.board_id()
        );
        assert!(built.suggested_name.contains("_bootloader_"));
    }
}

#[test]
fn shared_internal_boot_package_geometry_is_pinned() {
    let stage_start = (NRF52_APP_END - BOOTLOADER_PACKAGE_SIZE as u32) & !(NRF52_FLASH_PAGE - 1);
    assert_eq!(stage_start, 0x000E_2000);
    assert_eq!(stage_start + BOOTLOADER_IMAGE_SIZE as u32, 0x000E_C000);
    assert!(stage_start + BOOTLOADER_PACKAGE_SIZE as u32 <= NRF52_APP_END);
    assert!(BOOTLOADER_BOARDS
        .into_iter()
        .filter(|board| board.storage_profile() == BOOTLOADER_INTERNAL_STORAGE)
        .all(|board| board.storage_profile() == 0x0A));
}

#[test]
fn shared_vid_pid_identities_route_without_collisions() {
    let shared = [
        BootloaderBoard::MinewsemiMx25le01,
        BootloaderBoard::WiscoreRak3401,
        BootloaderBoard::WiscoreRak4631Board,
        BootloaderBoard::WismeshTag,
    ];
    assert!(shared.iter().all(|board| board.board_id() == 0x239A_0029));
    let mut targets: Vec<u32> = shared.iter().map(|board| board.target_id()).collect();
    targets.sort_unstable();
    targets.dedup();
    assert_eq!(targets.len(), shared.len());
    assert_eq!(BootloaderBoard::WiscoreRak3401.target_id(), 0x2381_8A80);
    assert_eq!(
        BootloaderBoard::WiscoreRak3401.hw_id(),
        "NRF_BL_239A0029_3401_DFU"
    );
    assert_eq!(BootloaderBoard::XiaoNrf52840Ble.target_id(), 0x2886_0044);
    assert_eq!(BootloaderBoard::XiaoNrf52840Ble.hw_id(), "XIAO_BL_28860044");
}

#[test]
fn generic_target_ids_are_pinned_to_the_canonical_hw_hash() {
    for (board, expected) in [
        (BootloaderBoard::HeltecMeshTowerV2, 0x1150_F50E),
        (BootloaderBoard::HeltecMeshPocket, 0x0592_77F4),
        (BootloaderBoard::HeltecT096, 0x4235_4C85),
        (BootloaderBoard::HeltecT1, 0xFC55_6FFC),
        (BootloaderBoard::HeltecT114, 0x0C3F_2902),
        (BootloaderBoard::KeepteenLt1, 0xDB2E_7B51),
        (BootloaderBoard::MinewsemiMx25le01, 0x026A_A982),
        (BootloaderBoard::PromicroNrf52840, 0xAF79_E8CC),
        (BootloaderBoard::T1000E, 0xE6F5_F03F),
        (BootloaderBoard::ThinknodeM3, 0x0CA4_1DB2),
        (BootloaderBoard::WiscoreRak3401, 0x2381_8A80),
        (BootloaderBoard::WiscoreRak4631Board, 0x2D0D_F000),
        (BootloaderBoard::WismeshTag, 0xC72E_9C9C),
    ] {
        assert_eq!(board.target_id(), expected, "{}", board.name());
        assert_eq!(BootloaderBoard::from_target_id(expected), Some(board));
    }
}

#[test]
fn qualified_application_targets_cannot_collide_with_bootloader_routes() {
    let applications = motatool::targets::BOOTLOADER_RELEVANT_APPLICATION_TARGETS;
    assert_eq!(applications.len(), 21);
    let mut application_ids = Vec::with_capacity(applications.len());
    for &(target, name) in applications {
        let derived = u32::from_le_bytes(sha256(name.as_bytes())[..4].try_into().unwrap());
        assert_eq!(target, derived, "stale application target ID for {name}");
        assert_eq!(motatool::targets::env_name(target), Some(name));
        application_ids.push(target);
    }
    application_ids.sort_unstable();
    application_ids.dedup();
    assert_eq!(application_ids.len(), applications.len());
    for board in BOOTLOADER_BOARDS {
        assert!(
            !application_ids.contains(&board.target_id()),
            "{} boot target collides with an application route",
            board.name()
        );
    }
}

#[test]
fn wrong_base_vs_sense_selection_is_rejected() {
    let error = build_bootloader(&opts(
        make_image(BootloaderBoard::XiaoNrf52840BleSense),
        BootloaderBoard::XiaoNrf52840Ble,
    ))
    .err()
    .unwrap()
    .to_string();
    assert!(error.contains("board_id"), "{error}");

    let error = build_bootloader(&opts(
        make_image(BootloaderBoard::XiaoNrf52840Ble),
        BootloaderBoard::XiaoNrf52840BleSense,
    ))
    .err()
    .unwrap()
    .to_string();
    assert!(error.contains("board_id"), "{error}");
}

#[test]
fn embedded_crc_and_geometry_are_rejected() {
    let mut corrupt = make_image(BootloaderBoard::XiaoNrf52840Ble);
    corrupt[0x1234] ^= 0x80;
    let error = build_bootloader(&opts(corrupt, BootloaderBoard::XiaoNrf52840Ble))
        .err()
        .unwrap()
        .to_string();
    assert!(error.contains("CRC32 mismatch"), "{error}");

    let mut bad_geometry = make_image(BootloaderBoard::XiaoNrf52840Ble);
    wr_u32(
        &mut bad_geometry,
        MANIFEST_OFFSET + 16,
        BOOTLOADER_IMAGE_SIZE as u32 - 4,
    );
    rewrite_image_crc(&mut bad_geometry);
    let error = build_bootloader(&opts(bad_geometry, BootloaderBoard::XiaoNrf52840Ble))
        .err()
        .unwrap()
        .to_string();
    assert!(error.contains("image_size"), "{error}");

    let short = vec![0xFF; BOOTLOADER_IMAGE_SIZE - 4];
    let error = build_bootloader(&opts(short, BootloaderBoard::XiaoNrf52840Ble))
        .err()
        .unwrap()
        .to_string();
    assert!(error.contains("exactly 0xA000"), "{error}");

    let mut wrong_device = make_image(BootloaderBoard::XiaoNrf52840Ble);
    wrong_device[MANIFEST_OFFSET + 24] = b'Y';
    rewrite_image_crc(&mut wrong_device);
    let error = build_bootloader(&opts(wrong_device, BootloaderBoard::XiaoNrf52840Ble))
        .err()
        .unwrap()
        .to_string();
    assert!(error.contains("bootloader update manifest"), "{error}");

    let mut noncanonical_padding = make_image(BootloaderBoard::WiscoreRak3401);
    noncanonical_padding[MANIFEST_OFFSET + 24 + "3401_DFU".len() + 1] = b'X';
    rewrite_image_crc(&mut noncanonical_padding);
    let error = build_bootloader(&opts(noncanonical_padding, BootloaderBoard::WiscoreRak3401))
        .err()
        .unwrap()
        .to_string();
    assert!(error.contains("trailing NUL padding"), "{error}");

    let mut unterminated_name = make_image(BootloaderBoard::WiscoreRak3401);
    unterminated_name[MANIFEST_OFFSET + 24..MANIFEST_OFFSET + 40].fill(b'A');
    rewrite_image_crc(&mut unterminated_name);
    let error = parse_bootloader_update_manifest(&unterminated_name)
        .err()
        .unwrap()
        .to_string();
    assert!(error.contains("at most 15"), "{error}");
}

#[test]
fn invalid_manifest_candidate_does_not_shadow_later_valid_manifest() {
    let board = BootloaderBoard::XiaoNrf52840Ble;
    let mut image = make_image(board);
    write_manifest_header(&mut image, FALSE_MANIFEST_OFFSET, board);
    wr_u32(
        &mut image,
        FALSE_MANIFEST_OFFSET + 16,
        BOOTLOADER_IMAGE_SIZE as u32 - 4,
    );
    rewrite_image_crc(&mut image);

    let parsed = parse_bootloader_update_manifest(&image).unwrap();
    assert_eq!(parsed.offset, MANIFEST_OFFSET);
}

#[test]
fn duplicate_fully_valid_manifests_are_rejected() {
    let board = BootloaderBoard::XiaoNrf52840Ble;
    let mut image = make_image(board);
    write_manifest_header(&mut image, FALSE_MANIFEST_OFFSET, board);
    make_both_manifest_crcs_valid(&mut image, FALSE_MANIFEST_OFFSET, MANIFEST_OFFSET);

    let error = parse_bootloader_update_manifest(&image)
        .err()
        .unwrap()
        .to_string();
    assert!(error.contains("found 2"), "{error}");
}

#[test]
fn unsigned_and_noncanonical_packages_are_rejected_by_verify() {
    let built = build_bootloader(&opts(
        make_image(BootloaderBoard::XiaoNrf52840Ble),
        BootloaderBoard::XiaoNrf52840Ble,
    ))
    .unwrap();

    let mut unsigned = built.bytes.clone();
    unsigned[HEADER_LEN + off::FLAGS] = MFLAG_FULL | MFLAG_BOOTLOADER;
    let problems = verify(&unsigned);
    assert!(
        problems.iter().any(|problem| problem.contains("SIGNED")),
        "{problems:?}"
    );

    let mut v2_unknown = built.bytes.clone();
    v2_unknown[HEADER_LEN + off::FORMAT_VER] = 2;
    v2_unknown[HEADER_LEN + off::FLAGS] = MFLAG_FULL | MFLAG_SIGNED | 0x08;
    let error = Manifest::parse(&v2_unknown).err().unwrap().to_string();
    assert!(error.contains("format_ver 2 flags"), "{error}");

    let mut wrong_hw = built.bytes.clone();
    wrong_hw[HEADER_LEN + off::HW_ID..HEADER_LEN + off::HW_ID + HW_ID_LEN].fill(0);
    wrong_hw[HEADER_LEN + off::HW_ID..HEADER_LEN + off::HW_ID + 6].copy_from_slice(b"WRONG!");
    resign(&mut wrong_hw);
    let problems = verify(&wrong_hw);
    assert!(
        problems
            .iter()
            .any(|problem| problem.contains("canonical NUL-padded")),
        "{problems:?}"
    );

    // Route a base-board image as Sense, including a self-consistent canonical Sense hw_id and signature.
    let mut wrong_board = built.bytes.clone();
    wrong_board[HEADER_LEN + off::TARGET_ID..HEADER_LEN + off::TARGET_ID + 4]
        .copy_from_slice(&XIAO_NRF52840_BLE_SENSE_BOARD_ID.to_le_bytes());
    wrong_board[HEADER_LEN + off::HW_ID..HEADER_LEN + off::HW_ID + HW_ID_LEN].fill(0);
    let sense_hw_id = BootloaderBoard::XiaoNrf52840BleSense.hw_id();
    let sense_hw = sense_hw_id.as_bytes();
    wrong_board[HEADER_LEN + off::HW_ID..HEADER_LEN + off::HW_ID + sense_hw.len()]
        .copy_from_slice(sense_hw);
    resign(&mut wrong_board);
    let problems = verify(&wrong_board);
    assert!(
        problems.iter().any(|problem| problem.contains("target_id")),
        "{problems:?}"
    );

    let mut zero_version = built.bytes.clone();
    zero_version[HEADER_LEN + off::FW_VERSION..HEADER_LEN + off::FW_VERSION + 4].fill(0);
    resign(&mut zero_version);
    let problems = verify(&zero_version);
    assert!(
        problems.iter().any(|problem| problem.contains("nonzero")),
        "{problems:?}"
    );

    let manifest = Manifest::parse(&built.bytes).unwrap();
    let payload = &built.bytes
        [manifest.payload_off()..manifest.payload_off() + manifest.payload_size as usize];
    let mut wrong_blocks = manifest.clone();
    wrong_blocks.block_size_log2 = 11;
    wrong_blocks.block_count = 20;
    let error = validate_bootloader_package(&wrong_blocks, payload)
        .err()
        .unwrap()
        .to_string();
    assert!(error.contains("40 blocks of 1024 bytes"), "{error}");

    let rak = BootloaderBoard::WiscoreRak3401;
    let mut raw_vid_pid_target = build_bootloader(&opts(make_image(rak), rak)).unwrap().bytes;
    raw_vid_pid_target[HEADER_LEN + off::TARGET_ID..HEADER_LEN + off::TARGET_ID + 4]
        .copy_from_slice(&rak.board_id().to_le_bytes());
    resign(&mut raw_vid_pid_target);
    let problems = verify(&raw_vid_pid_target);
    assert!(
        problems
            .iter()
            .any(|problem| problem.contains("canonical target")),
        "{problems:?}"
    );
}

#[test]
fn vectors_and_successor_capability_are_required() {
    let board = BootloaderBoard::XiaoNrf52840Ble;

    let mut bad_sp = make_image(board);
    wr_u32(&mut bad_sp, 0, 0x1000_0000);
    rewrite_image_crc(&mut bad_sp);
    let error = build_bootloader(&opts(bad_sp, board))
        .err()
        .unwrap()
        .to_string();
    assert!(error.contains("stack pointer"), "{error}");

    let mut bad_reset = make_image(board);
    wr_u32(&mut bad_reset, 4, BOOTLOADER_IMAGE_START + 0x100); // no Thumb bit
    rewrite_image_crc(&mut bad_reset);
    let error = build_bootloader(&opts(bad_reset, board))
        .err()
        .unwrap()
        .to_string();
    assert!(error.contains("reset vector"), "{error}");

    let erased = vec![0xFF; BOOTLOADER_IMAGE_SIZE];
    let error = build_bootloader(&opts(erased, board))
        .err()
        .unwrap()
        .to_string();
    assert!(error.contains("entirely erased"), "{error}");

    let mut old_abi = make_image(board);
    wr_u16(&mut old_abi, CAPS_OFFSET + 8, 2);
    rewrite_image_crc(&mut old_abi);
    let error = build_bootloader(&opts(old_abi, board))
        .err()
        .unwrap()
        .to_string();
    assert!(error.contains("apply_abi"), "{error}");

    let mut erased_abi = make_image(board);
    wr_u16(&mut erased_abi, CAPS_OFFSET + 8, u16::MAX);
    rewrite_image_crc(&mut erased_abi);
    let error = build_bootloader(&opts(erased_abi, board))
        .err()
        .unwrap()
        .to_string();
    assert!(error.contains("finite apply_abi"), "{error}");

    let mut no_full_codec = make_image(board);
    wr_u16(&mut no_full_codec, CAPS_OFFSET + 10, 1 << 2);
    rewrite_image_crc(&mut no_full_codec);
    let error = build_bootloader(&opts(no_full_codec, board))
        .err()
        .unwrap()
        .to_string();
    assert!(error.contains("CODEC_FULL"), "{error}");

    let mut no_boot_update = make_image(board);
    no_boot_update[CAPS_OFFSET + 12] = BOOTLOADER_STORAGE_QSPI;
    rewrite_image_crc(&mut no_boot_update);
    let error = build_bootloader(&opts(no_boot_update, board))
        .err()
        .unwrap()
        .to_string();
    assert!(error.contains("exact QSPI"), "{error}");

    let mut unknown_storage = make_image(board);
    unknown_storage[CAPS_OFFSET + 12] = BOOTLOADER_REQUIRED_STORAGE | 0x80;
    rewrite_image_crc(&mut unknown_storage);
    let error = build_bootloader(&opts(unknown_storage, board))
        .err()
        .unwrap()
        .to_string();
    assert!(error.contains("structurally valid"), "{error}");

    let internal = BootloaderBoard::WiscoreRak3401;
    let mut wrong_profile = make_image(internal);
    wrong_profile[CAPS_OFFSET + 12] = BOOTLOADER_QSPI_STORAGE;
    rewrite_image_crc(&mut wrong_profile);
    let error = build_bootloader(&opts(wrong_profile, internal))
        .err()
        .unwrap()
        .to_string();
    assert!(error.contains("does not match wiscore_rak3401"), "{error}");

    let mut nonzero_reserved = make_image(board);
    nonzero_reserved[CAPS_OFFSET + 13] = 1;
    rewrite_image_crc(&mut nonzero_reserved);
    let error = build_bootloader(&opts(nonzero_reserved, board))
        .err()
        .unwrap()
        .to_string();
    assert!(error.contains("structurally valid"), "{error}");

    let mut unaligned = make_image(board);
    let marker: [u8; BOOTLOADER_CAPS_SIZE] = unaligned
        [CAPS_OFFSET..CAPS_OFFSET + BOOTLOADER_CAPS_SIZE]
        .try_into()
        .unwrap();
    unaligned[CAPS_OFFSET..CAPS_OFFSET + BOOTLOADER_CAPS_SIZE].fill(0xFF);
    unaligned[CAPS_OFFSET + 1..CAPS_OFFSET + 1 + BOOTLOADER_CAPS_SIZE].copy_from_slice(&marker);
    rewrite_image_crc(&mut unaligned);
    let error = build_bootloader(&opts(unaligned, board))
        .err()
        .unwrap()
        .to_string();
    assert!(error.contains("aligned"), "{error}");

    let mut duplicate_caps = make_image(board);
    let marker: [u8; BOOTLOADER_CAPS_SIZE] = duplicate_caps
        [CAPS_OFFSET..CAPS_OFFSET + BOOTLOADER_CAPS_SIZE]
        .try_into()
        .unwrap();
    duplicate_caps[CAPS_OFFSET + 0x80..CAPS_OFFSET + 0x80 + BOOTLOADER_CAPS_SIZE]
        .copy_from_slice(&marker);
    rewrite_image_crc(&mut duplicate_caps);
    let error = build_bootloader(&opts(duplicate_caps, board))
        .err()
        .unwrap()
        .to_string();
    assert!(error.contains("found 2"), "{error}");

    let mut zero_version = opts(make_image(board), board);
    zero_version.fw_version = 0;
    let error = build_bootloader(&zero_version).err().unwrap().to_string();
    assert!(error.contains("fw_version must be nonzero"), "{error}");

    // Verification repeats the vector gate even for an otherwise self-consistent, freshly signed package.
    let mut bad_vector_package = build_bootloader(&opts(make_image(board), board))
        .unwrap()
        .bytes;
    let payload_start = Manifest::parse(&bad_vector_package).unwrap().payload_off();
    wr_u32(&mut bad_vector_package, payload_start, 0x1000_0000);
    refresh_payload_integrity(&mut bad_vector_package);
    let problems = verify(&bad_vector_package);
    assert!(
        problems
            .iter()
            .any(|problem| problem.contains("stack pointer")),
        "{problems:?}"
    );
}

#[test]
fn crc_matches_standard_ieee_vector() {
    assert_eq!(bootloader_image_crc32(b"123456789", 9), 0xCBF4_3926);
}

#[test]
fn cli_builds_from_hex_and_labels_bootloader_packages() {
    let board = BootloaderBoard::XiaoNrf52840Ble;
    let image = make_image(board);
    let dir = tempfile::tempdir().unwrap();
    let hex_path = dir.path().join("xiao_bootloader.hex");
    let key_path = dir.path().join("sign.key");
    let out_path = dir.path().join("xiao.mota");
    std::fs::write(&hex_path, image_as_intel_hex(&image)).unwrap();
    std::fs::write(&key_path, hex::encode_upper(SEED)).unwrap();

    let missing_key = Command::new(env!("CARGO_BIN_EXE_motatool"))
        .args([
            "build-bootloader",
            "--fw",
            hex_path.to_str().unwrap(),
            "--board",
            board.name(),
            "--fw-version",
            "1.2.3",
        ])
        .output()
        .unwrap();
    assert!(!missing_key.status.success(), "--sign must be required");

    let output = Command::new(env!("CARGO_BIN_EXE_motatool"))
        .args([
            "build-bootloader",
            "--fw",
            hex_path.to_str().unwrap(),
            "--board",
            board.name(),
            "--sign",
            key_path.to_str().unwrap(),
            "--fw-version",
            "1.2.3",
            "--out",
            out_path.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(String::from_utf8_lossy(&output.stdout).contains("bootloader"));

    let blob = std::fs::read(&out_path).unwrap();
    assert!(verify(&blob).is_empty());
    let manifest = Manifest::parse(&blob).unwrap();
    assert_eq!(
        &blob[manifest.payload_off()..manifest.payload_off() + BOOTLOADER_IMAGE_SIZE],
        image
    );

    let verify_output = Command::new(env!("CARGO_BIN_EXE_motatool"))
        .args(["verify", out_path.to_str().unwrap()])
        .output()
        .unwrap();
    assert!(verify_output.status.success());
    assert!(String::from_utf8_lossy(&verify_output.stdout).contains("bootloader"));

    let inspect_output = Command::new(env!("CARGO_BIN_EXE_motatool"))
        .args(["inspect", out_path.to_str().unwrap()])
        .output()
        .unwrap();
    assert!(inspect_output.status.success());
    let stdout = String::from_utf8_lossy(&inspect_output.stdout);
    assert!(stdout.contains("package_kind   : bootloader"), "{stdout}");
    assert!(stdout.contains("BOOTLOADER=true"), "{stdout}");
    assert!(stdout.contains("xiao_nrf52840_ble"), "{stdout}");
    assert!(stdout.contains("caps_apply_abi  : 3"), "{stdout}");

    let rak = BootloaderBoard::WiscoreRak3401;
    let rak_hex = dir.path().join("rak3401_bootloader.hex");
    let rak_out = dir.path().join("rak3401.mota");
    std::fs::write(&rak_hex, image_as_intel_hex(&make_image(rak))).unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_motatool"))
        .args([
            "build-bootloader",
            "--fw",
            rak_hex.to_str().unwrap(),
            "--board",
            rak.name(),
            "--sign",
            key_path.to_str().unwrap(),
            "--fw-version",
            "1.2.3",
            "--out",
            rak_out.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let blob = std::fs::read(&rak_out).unwrap();
    assert!(verify(&blob).is_empty());
    let manifest = Manifest::parse(&blob).unwrap();
    assert_eq!(manifest.target_id, 0x2381_8A80);
    assert_eq!(manifest.hw_id_str(), "NRF_BL_239A0029_3401_DFU");
    let inspect = Command::new(env!("CARGO_BIN_EXE_motatool"))
        .args(["inspect", rak_out.to_str().unwrap()])
        .output()
        .unwrap();
    assert!(inspect.status.success());
    let stdout = String::from_utf8_lossy(&inspect.stdout);
    assert!(
        stdout.contains("bootloader_board: wiscore_rak3401"),
        "{stdout}"
    );
    assert!(stdout.contains("caps_storage    : 0x0a"), "{stdout}");
    assert!(stdout.contains("caps_stage_kind : internal"), "{stdout}");
}

fn image_as_intel_hex(image: &[u8]) -> String {
    let mut text = String::new();
    text.push_str(&hex_record(0, 0x04, &[0x00, 0x0F]));
    for (index, chunk) in image.chunks(16).enumerate() {
        text.push_str(&hex_record((0x4000 + index * 16) as u16, 0x00, chunk));
    }
    text.push_str(&hex_record(0, 0x01, &[]));
    text
}

fn hex_record(address: u16, record_type: u8, data: &[u8]) -> String {
    let mut bytes = Vec::with_capacity(data.len() + 5);
    bytes.push(data.len() as u8);
    bytes.extend_from_slice(&address.to_be_bytes());
    bytes.push(record_type);
    bytes.extend_from_slice(data);
    let checksum = 0u8.wrapping_sub(bytes.iter().fold(0u8, |sum, byte| sum.wrapping_add(*byte)));
    let mut line = String::from(":");
    for byte in bytes {
        line.push_str(&format!("{byte:02X}"));
    }
    line.push_str(&format!("{checksum:02X}\n"));
    line
}
