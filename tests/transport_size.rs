use motatool::transport::deflate_transport_size;

#[test]
fn selects_independent_smaller_streams_and_counts_171_byte_packets() {
    let mut payload = vec![0u8; 1024];
    // The short final block cannot benefit from DEFLATE, so this also checks
    // that raw fallback is included in wire bytes and gets its own packet.
    payload.extend_from_slice(b"short");

    let size = deflate_transport_size(&payload, 1024).unwrap();
    assert_eq!(size.payload_bytes, 1029);
    assert_eq!(size.block_count, 2);
    assert_eq!(size.deflate_blocks, 1);
    assert!(size.deflate_bytes < 1024);
    assert_eq!(size.wire_bytes, size.deflate_bytes + 5);
    assert_eq!(size.data_packets, size.deflate_bytes.div_ceil(171) + 1);
}

#[test]
fn rejects_sizes_the_meshcore_radio_contract_cannot_accept() {
    assert_eq!(
        deflate_transport_size(b"payload", 0).unwrap_err(),
        "block size must be between 1 and 1024 bytes"
    );
    assert_eq!(
        deflate_transport_size(b"payload", 1025).unwrap_err(),
        "block size must be between 1 and 1024 bytes"
    );
    assert_eq!(
        deflate_transport_size(&[], 1024).unwrap_err(),
        "payload is empty"
    );
}

#[test]
fn incompressible_blocks_fall_back_without_cross_block_coalescing() {
    // A short block always expands because a raw stream still needs framing.
    let size = deflate_transport_size(b"abcdef", 3).unwrap();
    assert_eq!(size.block_count, 2);
    assert_eq!(size.deflate_blocks, 0);
    assert_eq!(size.deflate_bytes, 0);
    assert_eq!(size.wire_bytes, 6);
    assert_eq!(size.data_packets, 2);
}
