use motatool::endf::{build_nrf52_layout, ensure_endf, Nrf52Layout};
use motatool::format::{
    NRF52_APP_BASE_S140_V6, NRF52_APP_BASE_S140_V7, NRF52_APP_END, NRF52_INPLACE_SEGMENT,
};
use motatool::{build, BuildOpts, FwIdent, PatchType};

fn ident() -> FwIdent {
    FwIdent {
        fw_version: 0x0111_0100,
        target_id: 0x9841_1AC6,
        hw_id: "Heltec_t096".into(),
    }
}

fn image_with_layout(len: usize, layout: Nrf52Layout, salt: u8) -> Vec<u8> {
    let mut body: Vec<u8> = (0..len)
        .map(|i| (i as u8).wrapping_mul(29).wrapping_add(salt))
        .collect();
    body.extend_from_slice(&build_nrf52_layout(layout).unwrap());
    ensure_endf(&body, &ident()).0
}

fn opts(fw: Vec<u8>, base: Vec<u8>) -> BuildOpts {
    BuildOpts {
        fw,
        base: Some(base),
        patch_type: PatchType::InPlace,
        inplace_memory: None,
        segment_size: NRF52_INPLACE_SEGMENT,
        target_id: None,
        fw_version: None,
        hw_id: None,
        sign_seed: None,
        block_size: 1024,
        force: false,
    }
}

#[test]
fn layout_auto_sizes_from_complete_base_plus_two_pages() {
    let layout = Nrf52Layout {
        app_base: NRF52_APP_BASE_S140_V6,
        linked_app_end: NRF52_APP_END,
        stage_ceiling: NRF52_APP_END,
        flags: 0,
    };
    let base = image_with_layout(0x2500, layout, 3);
    let target = image_with_layout(0x2600, layout, 3);
    let expected = (((base.len() as u32 + 0xFFF) & !0xFFF) + 0x2000)
        .max((target.len() as u32 + 0xFFF) & !0xFFF);

    let built = build(&opts(target, base)).expect("layout-aware in-place build");
    assert_eq!(built.inplace_memory, Some(expected));
}

#[test]
fn legacy_default_fails_early_when_images_need_more_than_0x98000() {
    // No mOTALay1 records: the tool may not infer extra flash from the hardware name.  The EndF-trailed
    // base is large enough that base + detools' mandatory two-page shift exceeds the legacy window.
    let (base, _) = ensure_endf(&vec![0x11; 0x96000], &ident());
    let (target, _) = ensure_endf(&vec![0x22; 0x96020], &ident());
    let err = build(&opts(target, base))
        .err()
        .expect("oversized legacy build must fail")
        .to_string();
    assert!(
        err.contains("legacy default memory"),
        "unexpected error: {err}"
    );
    assert!(err.contains("at least 0x99000"), "unexpected error: {err}");
}

#[test]
fn layout_auto_sizing_rejects_cross_softdevice_app_addresses() {
    let v6 = Nrf52Layout {
        app_base: NRF52_APP_BASE_S140_V6,
        linked_app_end: NRF52_APP_END,
        stage_ceiling: NRF52_APP_END,
        flags: 0,
    };
    let v7 = Nrf52Layout {
        app_base: NRF52_APP_BASE_S140_V7,
        ..v6
    };
    let base = image_with_layout(4096, v6, 7);
    let target = image_with_layout(4096, v7, 7);
    let err = build(&opts(target, base))
        .err()
        .expect("cross-layout build must fail")
        .to_string();
    assert!(err.contains("cross-SoftDevice"), "unexpected error: {err}");
}
