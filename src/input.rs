//! Reading a firmware image from a file, an `http(s)` URL, or an Intel-HEX file.

use anyhow::{bail, Context, Result};
use std::io::Read;

pub fn is_url(s: &str) -> bool {
    s.starts_with("http://") || s.starts_with("https://")
}

/// Read a firmware image from a local path or an `http(s)` URL. A `.hex` file (nRF52/STM32 build) is parsed
/// from Intel HEX into its flat binary; anything else is used verbatim. The nRF52 `firmware.hex` already
/// carries the EndF trailer, so the flat image IS the OTA image.
pub fn read_input(src: &str) -> Result<Vec<u8>> {
    let raw = read_raw_input(src)?;
    if src.to_ascii_lowercase().ends_with(".hex") {
        parse_intel_hex(&raw).with_context(|| format!("parsing Intel HEX: {src}"))
    } else {
        Ok(raw)
    }
}

/// Read an OTAFIX Intel HEX and extract its exact padded bootloader region.
pub fn read_bootloader_hex(src: &str) -> Result<Vec<u8>> {
    let raw = read_raw_input(src)?;
    crate::bootloader::extract_bootloader_region_from_hex(&raw)
        .with_context(|| format!("extracting OTAFIX bootloader region from Intel HEX: {src}"))
}

fn read_raw_input(src: &str) -> Result<Vec<u8>> {
    let raw = if is_url(src) {
        fetch_url(src).with_context(|| format!("downloading {src}"))?
    } else {
        std::fs::read(src).with_context(|| format!("cannot read file: {src}"))?
    };
    if raw.is_empty() {
        bail!("input is empty: {src}");
    }
    Ok(raw)
}

fn fetch_url(url: &str) -> Result<Vec<u8>> {
    let mut buf = Vec::new();
    ureq::get(url).call()?.into_reader().read_to_end(&mut buf)?;
    Ok(buf)
}

/// Parse Intel HEX into the flat image it represents: `min..max` address span with gaps filled `0xFF`.
fn parse_intel_hex(bytes: &[u8]) -> Result<Vec<u8>> {
    use ihex::Record;
    let text = std::str::from_utf8(bytes).context("Intel HEX is not valid UTF-8")?;

    let mut base: u32 = 0;
    let mut segments: Vec<(u32, Vec<u8>)> = Vec::new();
    let (mut lo, mut hi) = (u32::MAX, 0u32);
    let mut saw_eof = false;

    for record in ihex::Reader::new(text) {
        match record.context("malformed Intel HEX record")? {
            Record::Data { offset, value } => {
                let addr = base + offset as u32;
                lo = lo.min(addr);
                hi = hi.max(addr + value.len() as u32);
                segments.push((addr, value));
            }
            Record::ExtendedLinearAddress(upper) => base = (upper as u32) << 16,
            Record::ExtendedSegmentAddress(seg) => base = (seg as u32) << 4,
            Record::EndOfFile => {
                saw_eof = true;
                break;
            }
            _ => {} // start-address records: ignored
        }
    }

    if segments.is_empty() {
        bail!("no data records in Intel HEX");
    }
    if !saw_eof {
        bail!("Intel HEX missing EOF record");
    }
    let mut out = vec![0xFFu8; (hi - lo) as usize];
    for (addr, data) in segments {
        let at = (addr - lo) as usize;
        out[at..at + data.len()].copy_from_slice(&data);
    }
    Ok(out)
}
