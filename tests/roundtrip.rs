//! End-to-end checks that a built container verifies, round-trips, and catches tampering.
//! (Byte-exact equivalence with the reference C++ `motatool` is validated out-of-band by building the same
//! firmware with both tools and comparing — see the README.)

use motatool::crypto::ed25519_public_from_seed;
use motatool::{build, verify, BuildOpts, Manifest, PatchType};

fn synthetic_fw(n: usize) -> Vec<u8> {
    (0..n)
        .map(|i| (i.wrapping_mul(7).wrapping_add(3)) as u8)
        .collect()
}

fn opts(fw: Vec<u8>) -> BuildOpts {
    BuildOpts {
        fw,
        base: None,
        patch_type: PatchType::Sequential,
        inplace_memory: None,
        segment_size: 0,
        target_id: Some(0x04D4_13FD),
        fw_version: Some(0x0111_0000),
        hw_id: Some("RAK4631".into()),
        sign_seed: None,
        block_size: 1024,
        force: false,
    }
}

#[test]
fn full_build_verifies_and_roundtrips() {
    let built = build(&opts(synthetic_fw(2500))).unwrap();
    assert!(
        verify(&built.bytes).is_empty(),
        "a freshly built container must verify"
    );

    let m = Manifest::parse(&built.bytes).unwrap();
    assert!(m.is_full() && !m.is_signed());
    assert_eq!(m.target_id, 0x04D4_13FD);
    assert_eq!(m.fw_version, 0x0111_0000);
    assert_eq!(m.hw_id_str(), "RAK4631");
    assert_eq!(m.block_count, 3); // 2500 + 56-byte EndF = 2556 → ceil(/1024) = 3
    assert!(built
        .suggested_name
        .starts_with("RAK4631_04D413FD_v1.17.0_full_"));
    assert!(built.suggested_name.ends_with(".mota"));
}

#[test]
fn signed_build_verifies_with_embedded_key() {
    let seed = [7u8; 32];
    let mut o = opts(synthetic_fw(1500));
    o.sign_seed = Some(seed);
    let built = build(&o).unwrap();

    assert!(verify(&built.bytes).is_empty());
    let m = Manifest::parse(&built.bytes).unwrap();
    assert!(m.is_signed());
    assert_eq!(m.signer, ed25519_public_from_seed(&seed));
}

#[test]
fn payload_tamper_is_detected() {
    let built = build(&opts(synthetic_fw(2500))).unwrap();
    let mut bad = built.bytes.clone();
    let payload_off = Manifest::parse(&bad).unwrap().payload_off();
    bad[payload_off] ^= 0xFF;
    let problems = verify(&bad);
    assert!(
        problems.iter().any(|p| p.contains("leaves")),
        "tamper must be caught: {problems:?}"
    );
}

#[test]
fn delta_base_without_endf_is_rejected() {
    // A delta must be built against the device's real running image, which carries an EndF trailer.
    // A raw base with no trailer is refused rather than producing a patch that could never apply.
    // (The full delta apply-equivalence round-trip lives in tests/delta.rs, gated on the dev detools.)
    let mut o = opts(synthetic_fw(2500));
    o.base = Some(synthetic_fw(2400)); // no EndF trailer
    let err = build(&o).err().expect("delta must error").to_string();
    assert!(
        err.contains("EndF"),
        "expected an EndF-base error, got: {err}"
    );
}
