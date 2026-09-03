use motatool::transport::deflate_transport_size;

#[test]
fn selects_independent_smaller_streams_and_counts_171_byte_packets() {
    let mut payload = vec![0u8; 2048];
    // The short final block cannot benefit from DEFLATE, so this also checks
    // that raw fallback is included in wire bytes and gets its own packet.
    payload.extend_from_slice(b"short");

    let size = deflate_transport_size(&payload, 2048).unwrap();
    assert_eq!(size.payload_bytes, 2053);
    assert_eq!(size.block_count, 2);
    assert_eq!(size.deflate_blocks, 1);
    assert!(size.deflate_bytes < 2048);
    assert_eq!(size.wire_bytes, size.deflate_bytes + 5);
    assert_eq!(size.data_packets, size.deflate_bytes.div_ceil(171) + 1);
}

#[test]
fn rejects_sizes_no_manifest_can_encode() {
    for block_size in [0, 1, 3, 1000, 1025, 2047, 2049, 4096] {
        assert_eq!(
            deflate_transport_size(b"payload", block_size).unwrap_err(),
            "block size must be a power of two between 2 and 2048 bytes",
            "unexpected result for block size {block_size}"
        );
    }
    assert_eq!(
        deflate_transport_size(&[], 2048).unwrap_err(),
        "payload is empty"
    );
}

#[test]
fn incompressible_blocks_fall_back_without_cross_block_coalescing() {
    // A short block always expands because a raw stream still needs framing.
    let size = deflate_transport_size(b"abcdefgh", 4).unwrap();
    assert_eq!(size.block_count, 2);
    assert_eq!(size.deflate_blocks, 0);
    assert_eq!(size.deflate_bytes, 0);
    assert_eq!(size.wire_bytes, 8);
    assert_eq!(size.data_packets, 2);
}
