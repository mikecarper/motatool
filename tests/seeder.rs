//! Exercise the transport-agnostic `SeederCore` directly (no wire): the serve ops (COUNT/DESCRIBE/READ)
//! and the pull-to-folder storage ops (STAT/BEGIN/WRITE/SREAD/FIN), including the warm-start seed overlay.

use motatool::format::seeder::*;
use motatool::format::{HEADER_LEN, MAGIC, MFL};
use motatool::serve::{Folder, SeederCore};
use motatool::{build, BuildOpts};

fn a_mota() -> Vec<u8> {
    build(&BuildOpts {
        fw: (0..3000u32).map(|i| i as u8).collect(),
        base: None,
        patch_type: motatool::PatchType::Sequential,
        inplace_memory: None,
        segment_size: 0,
        target_id: Some(0x04D4_13FD),
        fw_version: Some(0x0111_0000),
        hw_id: Some("RAK4631".into()),
        sign_seed: None,
        block_size: 1024,
        force: false,
    })
    .unwrap()
    .bytes
}

fn req(mid: &[u8; 4], off: u32, len: u16, data: &[u8]) -> Vec<u8> {
    let mut v = mid.to_vec();
    v.extend_from_slice(&off.to_le_bytes());
    v.extend_from_slice(&len.to_le_bytes());
    v.extend_from_slice(data);
    v
}

#[test]
fn serve_ops_count_describe_read() {
    let dir = tempfile::tempdir().unwrap();
    let mota = a_mota();
    std::fs::write(dir.path().join("fw.mota"), &mota).unwrap();
    let folder = Folder::scan(dir.path(), true, |_, _| {
        panic!("valid mota must not be skipped")
    });
    let core = SeederCore::new(folder, None);

    assert_eq!(core.handle(OP_COUNT, &[]), Some((STATUS_OK, vec![1])));

    let (st, desc) = core.handle(OP_DESCRIBE, &[0]).unwrap();
    assert_eq!(st, STATUS_OK);
    assert_eq!(desc.len(), DESC_WIRE);
    assert_eq!(&desc[0..4], &mota[HEADER_LEN + 20..HEADER_LEN + 24]); // mid == manifest merkle_root

    assert_eq!(core.handle(OP_DESCRIBE, &[9]).unwrap().0, STATUS_ERR); // out of range

    // READ idx=0 off=0 len=4 → the container MAGIC. (READ args = idx(1) off(4) len(2).)
    let mut read_args = vec![0u8]; // idx 0
    read_args.extend_from_slice(&0u32.to_le_bytes());
    read_args.extend_from_slice(&4u16.to_le_bytes());
    assert_eq!(
        core.handle(OP_READ, &read_args),
        Some((STATUS_OK, MAGIC.to_vec()))
    );
}

#[test]
fn storage_capture_roundtrip_and_publish() {
    let dir = tempfile::tempdir().unwrap();
    let folder = Folder::scan(dir.path(), true, |_, _| {});
    let core = SeederCore::new(folder, Some(dir.path().to_path_buf()));

    let mota = a_mota();
    let mid: [u8; 4] = mota[HEADER_LEN + 20..HEADER_LEN + 24].try_into().unwrap();

    // STAT before begin → not present.
    assert_eq!(
        core.handle(OP_STAT, &mid).unwrap(),
        (STATUS_OK, {
            let mut p = vec![0u8];
            p.extend_from_slice(&0u32.to_le_bytes());
            p
        })
    );

    // BEGIN a .part of the full size, WRITE the whole container in ≤WRITE_MAX chunks, FIN.
    let mut begin = mid.to_vec();
    begin.extend_from_slice(&(mota.len() as u32).to_le_bytes());
    assert_eq!(core.handle(OP_BEGIN, &begin).unwrap(), (STATUS_OK, vec![]));

    for (i, chunk) in mota.chunks(WRITE_MAX).enumerate() {
        let off = (i * WRITE_MAX) as u32;
        assert_eq!(
            core.handle(OP_WRITE, &req(&mid, off, chunk.len() as u16, chunk))
                .unwrap()
                .0,
            STATUS_OK
        );
    }

    // SREAD a slice back → matches what we wrote.
    let (st, got) = core.handle(OP_SREAD, &req(&mid, 8, 64, &[])).unwrap();
    assert_eq!(st, STATUS_OK);
    assert_eq!(got, &mota[8..72]);

    assert_eq!(core.handle(OP_FIN, &mid).unwrap(), (STATUS_OK, vec![]));

    // Published as <mid-lowercase>.mota, byte-for-byte what we streamed.
    let published = dir.path().join(format!("{}.mota", hex::encode(mid)));
    assert_eq!(std::fs::read(&published).unwrap(), mota);
    assert!(!dir
        .path()
        .join(format!("{}.mota.part", hex::encode(mid)))
        .exists());
}

#[test]
fn begin_overlays_seed_payload_leaving_header_and_leaves_blank() {
    let dir = tempfile::tempdir().unwrap();
    let folder = Folder::scan(dir.path(), true, |_, _| {});
    let mut core = SeederCore::new(folder, Some(dir.path().to_path_buf()));

    let block_count = 3u32;
    let seed_payload = vec![0x5Au8; 2048];
    core.set_seed(seed_payload.clone(), block_count);

    let mid = [0xDE, 0xAD, 0xBE, 0xEF];
    let total = 8 + MFL + block_count as usize * 4 + seed_payload.len() + 5;
    let mut begin = mid.to_vec();
    begin.extend_from_slice(&(total as u32).to_le_bytes());
    assert_eq!(core.handle(OP_BEGIN, &begin).unwrap(), (STATUS_OK, vec![]));

    let part = std::fs::read(dir.path().join(format!("{}.mota.part", hex::encode(mid)))).unwrap();
    assert_eq!(part.len(), total);
    let payload_off = HEADER_LEN + MFL + block_count as usize * 4;
    assert!(
        part[..payload_off].iter().all(|&b| b == 0xFF),
        "header + leaves stay 0xFF"
    );
    assert_eq!(
        &part[payload_off..payload_off + seed_payload.len()],
        &seed_payload[..]
    );
}
