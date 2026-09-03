//! Format-3 bootloader fixtures are generated in memory from public wire constants. No release image or
//! signing key is stored in the repository; each test uses a fresh ephemeral Ed25519 key.

use motatool::bootloader::{
    bootloader_hw_id, bootloader_target_id, CANDIDATE_MANIFEST_OFFSET, CAPS_MAGIC,
    CONTINUITY_MAGIC, IMAGE_SIZE, IMAGE_START, MANIFEST_MAGIC, STORAGE_INTERNAL_UPDATE,
};
use motatool::crypto::{ed25519_keygen, ed25519_sign, sha256};
use motatool::format::{
    off, seeder, wr_u32, APPROVAL_NONE, APP_FORMAT_VER, BOOTLOADER_BLOCK_SIZE, BOOT_FORMAT_VER,
    HASH_ALGO_SHA256, HEADER_LEN, MAGIC, MFL, MFLAG_BOOTLOADER, MFLAG_FULL, MFLAG_SIGNED,
    SIGNED_LEN, TRAILER,
};
use motatool::merkle;
use motatool::serve::{Folder, SeederCore};
use motatool::{verify, Manifest};
use std::process::Command;

const BOARD_ID: u32 = 0x239A_0071;
const DEVICE_NAME: &str = "T096_DFU";
const BOOT_VERSION: u32 = 0x0204_0401;
const CAPS_OFF: usize = 0x80;
type ManifestMutation = fn(&mut [u8]);

fn wr_u16(buf: &mut [u8], off: usize, value: u16) {
    buf[off..off + 2].copy_from_slice(&value.to_le_bytes());
}

fn synthetic_t096_bootloader() -> Vec<u8> {
    let mut image = vec![0xFF; IMAGE_SIZE];
    wr_u32(&mut image, 0, 0x2004_0000);
    wr_u32(&mut image, 4, IMAGE_START + 0x101); // Thumb reset vector inside the image

    image[CAPS_OFF..CAPS_OFF + 8].copy_from_slice(&CAPS_MAGIC);
    wr_u16(&mut image, CAPS_OFF + 8, 3);
    wr_u16(&mut image, CAPS_OFF + 10, 0x0005); // FULL | DETOOLS_INPLACE
    image[CAPS_OFF + 12] = STORAGE_INTERNAL_UPDATE;
    image[CAPS_OFF + 13..CAPS_OFF + 16].fill(0);

    let base = CANDIDATE_MANIFEST_OFFSET;
    image[base..base + 8].copy_from_slice(&MANIFEST_MAGIC);
    wr_u16(&mut image, base + 8, 1);
    wr_u16(&mut image, base + 10, 44);
    wr_u32(&mut image, base + 12, IMAGE_START);
    wr_u32(&mut image, base + 16, IMAGE_SIZE as u32);
    wr_u32(&mut image, base + 20, BOARD_ID);
    image[base + 24..base + 40].fill(0);
    image[base + 24..base + 24 + DEVICE_NAME.len()].copy_from_slice(DEVICE_NAME.as_bytes());
    image[base + 40..base + 44].fill(0);

    let ext = base + 44;
    image[ext..ext + 8].copy_from_slice(&CONTINUITY_MAGIC);
    wr_u16(&mut image, ext + 8, 2);
    wr_u16(&mut image, ext + 10, 32);
    wr_u32(&mut image, ext + 12, BOOT_VERSION);
    wr_u16(&mut image, ext + 16, 140);
    wr_u16(&mut image, ext + 18, 0x00B6);
    wr_u32(&mut image, ext + 20, 0x0002_6000);
    wr_u16(&mut image, ext + 24, 1);
    wr_u16(&mut image, ext + 26, 0);
    wr_u32(&mut image, ext + 28, 0);
    repair_embedded_crc(&mut image);
    image
}

fn repair_embedded_crc(image: &mut [u8]) {
    let crc_off = CANDIDATE_MANIFEST_OFFSET + 40;
    image[crc_off..crc_off + 4].fill(0);
    let crc = ieee_crc32(image);
    wr_u32(image, crc_off, crc);
}

fn ieee_crc32(bytes: &[u8]) -> u32 {
    let mut crc = u32::MAX;
    for &byte in bytes {
        crc ^= u32::from(byte);
        for _ in 0..8 {
            crc = (crc >> 1) ^ (0xEDB8_8320 & 0u32.wrapping_sub(crc & 1));
        }
    }
    !crc
}

fn noop(_: &mut [u8]) {}

fn bootloader_container(image: &[u8], mutate_manifest: fn(&mut [u8])) -> Vec<u8> {
    let leaves = merkle::leaf_hashes(image, BOOTLOADER_BLOCK_SIZE as usize);
    assert_eq!(leaves.len(), 40);
    let mut manifest = [0u8; MFL];
    manifest[off::FORMAT_VER] = BOOT_FORMAT_VER;
    manifest[off::FLAGS] = MFLAG_FULL | MFLAG_SIGNED | MFLAG_BOOTLOADER;
    manifest[off::HASH_ALGO] = HASH_ALGO_SHA256;
    wr_u32(
        &mut manifest,
        off::TARGET_ID,
        bootloader_target_id(BOARD_ID, DEVICE_NAME).unwrap(),
    );
    wr_u32(&mut manifest, off::FW_VERSION, BOOT_VERSION);
    wr_u32(&mut manifest, off::IMAGE_SIZE, IMAGE_SIZE as u32);
    wr_u32(&mut manifest, off::PAYLOAD_SIZE, IMAGE_SIZE as u32);
    manifest[off::BLOCK_SIZE_LOG2] = BOOTLOADER_BLOCK_SIZE.ilog2() as u8;
    manifest[off::MERKLE_ROOT..off::MERKLE_ROOT + 4].copy_from_slice(&merkle::root(&leaves));
    manifest[off::IMAGE_HASH..off::IMAGE_HASH + 32].copy_from_slice(&sha256(image));
    manifest[off::CODEC_ID] = 0;
    manifest[off::HW_ID..off::HW_ID + 32]
        .copy_from_slice(&bootloader_hw_id(BOARD_ID, DEVICE_NAME).unwrap());
    manifest[off::BASE_HASH..off::BASE_HASH + 8].fill(0);
    manifest[off::APPROVAL..off::APPROVAL + 4].copy_from_slice(&APPROVAL_NONE);

    // Fresh test-only key material exists only in this process and is never written or printed.
    let (seed, public) = ed25519_keygen();
    manifest[off::SIGNER..off::SIGNER + 32].copy_from_slice(&public);
    mutate_manifest(&mut manifest);
    let signature = ed25519_sign(&seed, &manifest[..SIGNED_LEN]);
    manifest[off::SIGNATURE..off::SIGNATURE + 64].copy_from_slice(&signature);

    let total = HEADER_LEN + MFL + leaves.len() * 4 + image.len() + TRAILER.len();
    let mut blob = Vec::with_capacity(total);
    blob.extend_from_slice(&MAGIC);
    blob.extend_from_slice(&(total as u32).to_le_bytes());
    blob.extend_from_slice(&manifest);
    for leaf in leaves {
        blob.extend_from_slice(&leaf);
    }
    blob.extend_from_slice(image);
    blob.extend_from_slice(&TRAILER);
    blob
}

#[test]
fn signed_t096_v3_parses_verifies_inspects_and_serves() {
    let blob = bootloader_container(&synthetic_t096_bootloader(), noop);
    assert_eq!(blob.len(), 41_330);
    let manifest = Manifest::parse(&blob).unwrap();
    assert!(manifest.is_full() && manifest.is_signed() && manifest.is_bootloader());
    assert_eq!(manifest.target_id, 0x4235_4C85);
    assert_eq!(manifest.payload_off(), 365);
    assert!(verify(&blob).is_empty());

    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("t096-bootloader.mota");
    std::fs::write(&path, &blob).unwrap();
    let mut warnings = Vec::new();
    let folder = Folder::scan(dir.path(), false, |_, why| warnings.push(why.to_owned()));
    assert!(
        warnings.is_empty(),
        "unexpected folder warning: {warnings:?}"
    );
    assert_eq!(folder.count(), 1);
    let core = SeederCore::new(folder, None);
    let (status, desc) = core.handle(seeder::OP_DESCRIBE, &[0]).unwrap();
    assert_eq!(status, seeder::STATUS_OK);
    assert_eq!(desc[13], 0x07);
    assert_eq!(desc[34], 10);

    let output = Command::new(env!("CARGO_BIN_EXE_motatool"))
        .arg("inspect")
        .arg(&path)
        .output()
        .unwrap();
    assert!(output.status.success());
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(stdout.contains("BOOTLOADER=true"), "{stdout}");
    assert!(stdout.contains("bootloader_board: 0x239a0071"), "{stdout}");
    assert!(stdout.contains("bootloader_name : T096_DFU"), "{stdout}");
    assert!(stdout.contains("bootloader_store: 0x0a"), "{stdout}");
}

fn v2_with_bootloader_flag(m: &mut [u8]) {
    m[off::FORMAT_VER] = APP_FORMAT_VER;
}
fn v3_without_exact_flags(m: &mut [u8]) {
    m[off::FLAGS] = MFLAG_FULL | MFLAG_SIGNED;
}
fn v3_wrong_hash(m: &mut [u8]) {
    m[off::HASH_ALGO] = 0x13;
}
fn v3_wrong_codec(m: &mut [u8]) {
    m[off::CODEC_ID] = 2;
}
fn v3_wrong_block_size(m: &mut [u8]) {
    m[off::BLOCK_SIZE_LOG2] = 11;
}
fn v3_nonzero_base(m: &mut [u8]) {
    m[off::BASE_HASH] = 1;
}
fn v3_bad_version(m: &mut [u8]) {
    wr_u32(m, off::FW_VERSION, 0x0204_0400);
}
fn v3_wrong_target(m: &mut [u8]) {
    let value = u32::from_le_bytes(m[off::TARGET_ID..off::TARGET_ID + 4].try_into().unwrap());
    wr_u32(m, off::TARGET_ID, value ^ 1);
}
fn v3_wrong_hw(m: &mut [u8]) {
    m[off::HW_ID] ^= 1;
}

#[test]
fn v3_outer_profile_is_exact_and_identity_bound() {
    let image = synthetic_t096_bootloader();
    let cases: &[(&str, ManifestMutation)] = &[
        ("v2+bootloader", v2_with_bootloader_flag),
        ("non-exact flags", v3_without_exact_flags),
        ("hash algorithm", v3_wrong_hash),
        ("codec", v3_wrong_codec),
        ("2 KiB block size", v3_wrong_block_size),
        ("base hash", v3_nonzero_base),
        ("version sentinel", v3_bad_version),
        ("target binding", v3_wrong_target),
        ("hardware binding", v3_wrong_hw),
    ];
    for (name, mutate) in cases {
        let blob = bootloader_container(&image, *mutate);
        assert!(Manifest::parse(&blob).is_err(), "accepted malformed {name}");
        assert!(!verify(&blob).is_empty(), "verified malformed {name}");
    }
}

#[test]
fn v3_rejects_malformed_embedded_contract_and_wire_integrity() {
    let mut bad_vector = synthetic_t096_bootloader();
    wr_u32(&mut bad_vector, 0, 0x2004_0001);
    repair_embedded_crc(&mut bad_vector);
    assert!(Manifest::parse(&bootloader_container(&bad_vector, noop)).is_err());

    let mut bad_caps = synthetic_t096_bootloader();
    bad_caps[CAPS_OFF + 12] = 0x02; // stage ceiling without BOOT_UPDATE
    repair_embedded_crc(&mut bad_caps);
    assert!(Manifest::parse(&bootloader_container(&bad_caps, noop)).is_err());

    let mut bad_continuity = synthetic_t096_bootloader();
    let ext = CANDIDATE_MANIFEST_OFFSET + 44;
    wr_u16(&mut bad_continuity, ext + 18, 0x0123); // T096 is qualified for S140 v6
    repair_embedded_crc(&mut bad_continuity);
    assert!(Manifest::parse(&bootloader_container(&bad_continuity, noop)).is_err());

    let mut bad_signature = bootloader_container(&synthetic_t096_bootloader(), noop);
    bad_signature[HEADER_LEN + off::SIGNATURE] ^= 1;
    assert!(Manifest::parse(&bad_signature).is_ok());
    assert!(verify(&bad_signature)
        .iter()
        .any(|problem| problem.contains("signature INVALID")));

    let mut partial_approval = bootloader_container(&synthetic_t096_bootloader(), noop);
    partial_approval[HEADER_LEN + off::APPROVAL] = 0xFE;
    assert!(Manifest::parse(&partial_approval).is_ok());
    assert!(verify(&partial_approval)
        .iter()
        .any(|problem| problem.contains("approval is not")));
}
