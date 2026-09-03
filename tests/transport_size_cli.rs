use motatool::transport::deflate_transport_size;
use std::process::Command;

#[test]
fn transport_size_cli_reports_the_shared_live_encoder_measurement() {
    let directory = tempfile::tempdir().unwrap();
    let payload_path = directory.path().join("payload.patch");
    let mut payload = vec![0u8; 2048];
    payload.extend_from_slice(b"short");
    std::fs::write(&payload_path, &payload).unwrap();

    let expected = deflate_transport_size(&payload, 2048).unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_motatool"))
        .args([
            "transport-size",
            "--payload",
            payload_path.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(output.status.success(), "{:?}", output);

    let expected_json = format!(
        "{{\"schema\":1,\"payload_bytes\":{},\"block_size\":{},\"block_count\":{},\"wire_bytes\":{},\"deflate_bytes\":{},\"deflate_blocks\":{},\"data_packets\":{}}}",
        expected.payload_bytes,
        expected.block_size,
        expected.block_count,
        expected.wire_bytes,
        expected.deflate_bytes,
        expected.deflate_blocks,
        expected.data_packets,
    );
    assert_eq!(
        String::from_utf8(output.stdout).unwrap().trim(),
        expected_json
    );
}

#[test]
fn transport_size_help_documents_the_2k_default() {
    let output = Command::new(env!("CARGO_BIN_EXE_motatool"))
        .args(["transport-size", "--help"])
        .output()
        .unwrap();
    assert!(output.status.success(), "{output:?}");
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(stdout.contains("at most 2048"), "{stdout}");
    assert!(stdout.contains("[default: 2048]"), "{stdout}");
}
