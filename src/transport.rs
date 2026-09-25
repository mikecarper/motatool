//! Exact transport-DEFLATE sizing using the same encoder as the folder seeder.

use crate::format::MAX_APPLICATION_BLOCK_SIZE;
use flate2::{write::DeflateEncoder, Compression};
use std::io::Write;
use std::num::NonZeroU64;

/// Match the host-side MeshCore mOTA sender's maximum-search DEFLATE setting.
pub const ZOPFLI_ITERATIONS: u64 = 1000;

/// Largest logical application block supported by MeshCore's radio OTA transport.
pub const MAX_TRANSPORT_BLOCK_SIZE: usize = MAX_APPLICATION_BLOCK_SIZE as usize;

/// Statistics needed by MeshCore's route planner. Each logical block is an
/// independent raw RFC 1951 stream, matching `OP_DEFLATE_BLOCK` exactly.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DeflateTransportSize {
    pub payload_bytes: usize,
    pub block_size: usize,
    pub block_count: usize,
    /// Bytes carried in DATA after choosing compressed bytes only when smaller.
    pub wire_bytes: usize,
    /// Compressed-stream bytes for blocks which actually use DEFLATE.
    pub deflate_bytes: usize,
    pub deflate_blocks: usize,
    /// Number of 171-byte radio DATA slices after making the per-block choice.
    pub data_packets: usize,
}

/// Compress one independent raw RFC 1951 stream exactly as the live seeder does.
fn zopfli_raw(input: &[u8], iterations: u64) -> Option<Vec<u8>> {
    let options = zopfli::Options {
        iteration_count: NonZeroU64::new(iterations)?,
        ..zopfli::Options::default()
    };
    let mut encoded = Vec::new();
    zopfli::compress(options, zopfli::Format::Deflate, input, &mut encoded).ok()?;
    Some(encoded)
}

fn zlib_best_raw(input: &[u8]) -> Option<Vec<u8>> {
    let mut encoder = DeflateEncoder::new(Vec::new(), Compression::best());
    encoder.write_all(input).ok()?;
    encoder.finish().ok()
}

/// Search several valid independent representations. Zopfli's 1,000-pass
/// result is the primary candidate, but its heuristic is not guaranteed to
/// beat every earlier pass or zlib on every 2 KiB block. The shortest stream
/// also minimizes the number of 171-byte radio DATA slices; no bytes are ever
/// dropped from a partially filled final slice.
pub(crate) fn deflate_raw(input: &[u8]) -> Option<Vec<u8>> {
    let mut best = zopfli_raw(input, ZOPFLI_ITERATIONS)?;
    for iterations in [15, 100] {
        if let Some(candidate) = zopfli_raw(input, iterations) {
            if candidate.len() < best.len() {
                best = candidate;
            }
        }
    }
    if let Some(candidate) = zlib_best_raw(input) {
        if candidate.len() < best.len() {
            best = candidate;
        }
    }
    Some(best)
}

/// Measure the v2 representation selected by the live folder seeder.
pub fn deflate_transport_size(
    payload: &[u8],
    block_size: usize,
) -> Result<DeflateTransportSize, &'static str> {
    if payload.is_empty() {
        return Err("payload is empty");
    }
    if !(2..=MAX_TRANSPORT_BLOCK_SIZE).contains(&block_size) || !block_size.is_power_of_two() {
        return Err("block size must be a power of two between 2 and 2048 bytes");
    }

    let mut wire_bytes = 0usize;
    let mut deflate_bytes = 0usize;
    let mut deflate_blocks = 0usize;
    let mut data_packets = 0usize;
    for block in payload.chunks(block_size) {
        let encoded = deflate_raw(block).ok_or("raw DEFLATE encoder failed")?;
        let selected_len = if !encoded.is_empty() && encoded.len() < block.len() {
            deflate_bytes = deflate_bytes
                .checked_add(encoded.len())
                .ok_or("transport size overflow")?;
            deflate_blocks += 1;
            encoded.len()
        } else {
            block.len()
        };
        wire_bytes = wire_bytes
            .checked_add(selected_len)
            .ok_or("transport size overflow")?;
        data_packets = data_packets
            .checked_add(selected_len.div_ceil(171))
            .ok_or("transport size overflow")?;
    }

    Ok(DeflateTransportSize {
        payload_bytes: payload.len(),
        block_size,
        block_count: payload.len().div_ceil(block_size),
        wire_bytes,
        deflate_bytes,
        deflate_blocks,
        data_packets,
    })
}
