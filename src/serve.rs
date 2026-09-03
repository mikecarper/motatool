//! Serve a folder of `.mota` to a MeshCore node over the seeder link (USB serial or WiFi TCP), and capture
//! a "pull to folder" `.mota` the node is fetching off-mesh.
//!
//! Split into a transport-agnostic [`SeederCore`] (turns a `(op, args)` request into a `(status, payload)`
//! reply — a future BLE/GATT path would call it directly) and a byte-stream [`serve_loop`] that frames it.

use crate::format::{rd_u32, seeder, Manifest, HEADER_LEN, MAGIC, MFL};
use crate::verify::verify;
use anyhow::{Context, Result};
use flate2::{write::DeflateEncoder, Compression};
use std::io::{ErrorKind, Read, Seek, SeekFrom, Write};
use std::net::TcpStream;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

const LINK_TIMEOUT: Duration = Duration::from_millis(500);

// ---- served folder -------------------------------------------------------------------------------

pub struct ServedMota {
    pub path: PathBuf,
    pub bytes: Vec<u8>,
    pub manifest: Manifest,
}

/// Every valid `*.mota` under a folder, in a stable order (indices are how the node addresses them).
pub struct Folder {
    motas: Vec<ServedMota>,
}

impl Folder {
    /// Scan `dir` for `.mota` files, validating each; invalid ones are reported via `warn` and skipped so
    /// one bad file never sinks the rest.
    pub fn scan(dir: &Path, recursive: bool, mut warn: impl FnMut(&Path, &str)) -> Folder {
        let mut motas = Vec::new();
        let depth = if recursive { usize::MAX } else { 1 };
        for entry in walkdir::WalkDir::new(dir)
            .max_depth(depth)
            .sort_by_file_name()
            .into_iter()
            .flatten()
        {
            let path = entry.path();
            if !entry.file_type().is_file()
                || path.extension().and_then(|e| e.to_str()) != Some("mota")
            {
                continue;
            }
            let Ok(bytes) = std::fs::read(path) else {
                warn(path, "cannot read");
                continue;
            };
            let problems = verify(&bytes);
            if !problems.is_empty() {
                warn(path, &problems.join("; "));
                continue;
            }
            let manifest = Manifest::parse(&bytes).expect("verified above");
            motas.push(ServedMota {
                path: path.to_path_buf(),
                bytes,
                manifest,
            });
        }
        motas.sort_by(|a, b| a.path.cmp(&b.path)); // deterministic catalog order
        Folder { motas }
    }

    pub fn count(&self) -> usize {
        self.motas.len()
    }
    pub fn at(&self, i: usize) -> Option<&ServedMota> {
        self.motas.get(i)
    }
    pub fn all(&self) -> &[ServedMota] {
        &self.motas
    }
}

// ---- transport-agnostic seeder core --------------------------------------------------------------

pub struct SeederCore {
    folder: Folder,
    store_dir: Option<PathBuf>,
    seed: Option<(Vec<u8>, u32)>, // (payload, block_count) injected into a fresh capture on OP_BEGIN
}

impl SeederCore {
    pub fn new(folder: Folder, store_dir: Option<PathBuf>) -> Self {
        SeederCore {
            folder,
            store_dir,
            seed: None,
        }
    }

    /// Stage a *similar* build's payload into each captured `.part` so `ota pull … validate` on the node
    /// diffs it against the target's merkle leaves and pulls only the differing blocks.
    pub fn set_seed(&mut self, payload: Vec<u8>, block_count: u32) {
        self.seed = Some((payload, block_count));
    }

    pub fn folder(&self) -> &Folder {
        &self.folder
    }

    /// Handle one request. `None` means ignore an unknown/short op (the node retries); `Some((status,
    /// payload))` is a reply to frame back.
    pub fn handle(&self, op: u8, args: &[u8]) -> Option<(u8, Vec<u8>)> {
        use seeder::*;
        match op {
            OP_COUNT => Some((STATUS_OK, vec![self.folder.count().min(255) as u8])),
            OP_DESCRIBE => Some(match self.folder.at(*args.first()? as usize) {
                Some(s) => (STATUS_OK, describe(s).to_vec()),
                None => (STATUS_ERR, vec![]),
            }),
            OP_READ => {
                let off = rd_u32(args, 1) as usize;
                let len = u16::from_le_bytes([args[5], args[6]]) as usize;
                Some(match self.folder.at(args[0] as usize) {
                    Some(s) if off + len <= s.bytes.len() => {
                        (STATUS_OK, s.bytes[off..off + len].to_vec())
                    }
                    _ => (STATUS_ERR, vec![]),
                })
            }
            OP_DEFLATE_BLOCK => Some(self.deflate_block(args)),
            OP_STAT | OP_BEGIN | OP_WRITE | OP_SREAD | OP_FIN => {
                Some(self.handle_storage(op, args))
            }
            _ => None,
        }
    }

    /// Return a slice of one independently raw-DEFLATE-compressed logical payload block. A zero-length
    /// request queries only the encoded length. Firmware asks in bounded slices so the serial/TCP reply
    /// remains below the node's fixed receive buffer. Blocks which do not shrink return STATUS_ERR and the
    /// radio source transparently falls back to the negotiated 171-byte raw representation.
    fn deflate_block(&self, args: &[u8]) -> (u8, Vec<u8>) {
        use seeder::{DEFLATE_READ_MAX, STATUS_ERR, STATUS_OK};

        if args.len() != 7 {
            return (STATUS_ERR, vec![]);
        }
        let index = args[0] as usize;
        let block = u16::from_le_bytes([args[1], args[2]]) as u32;
        let off = u16::from_le_bytes([args[3], args[4]]) as usize;
        let len = u16::from_le_bytes([args[5], args[6]]) as usize;
        if len > DEFLATE_READ_MAX || (len == 0 && off != 0) {
            return (STATUS_ERR, vec![]);
        }

        let Some(served) = self.folder.at(index) else {
            return (STATUS_ERR, vec![]);
        };
        if block >= served.manifest.block_count {
            return (STATUS_ERR, vec![]);
        }
        let block_size = served.manifest.block_size() as usize;
        // MeshCore's radio descriptor and receiver accept logical blocks only through 1 KiB. Reject a
        // syntactically valid larger-container geometry before allocating/compressing attacker-sized input.
        if block_size == 0 || block_size > 1024 {
            return (STATUS_ERR, vec![]);
        }
        let payload_start = served.manifest.payload_off();
        let start = match payload_start.checked_add(block as usize * block_size) {
            Some(v) => v,
            None => return (STATUS_ERR, vec![]),
        };
        let payload_end = payload_start + served.manifest.payload_size as usize;
        let end = start.saturating_add(block_size).min(payload_end);
        if start >= end || end > served.bytes.len() {
            return (STATUS_ERR, vec![]);
        }

        let Some(encoded) = deflate_raw(&served.bytes[start..end]) else {
            return (STATUS_ERR, vec![]);
        };
        if encoded.is_empty() || encoded.len() >= end - start || encoded.len() > u16::MAX as usize {
            return (STATUS_ERR, vec![]);
        }
        let Some(slice_end) = off.checked_add(len) else {
            return (STATUS_ERR, vec![]);
        };
        if off > encoded.len() || slice_end > encoded.len() {
            return (STATUS_ERR, vec![]);
        }

        let mut payload = Vec::with_capacity(2 + len);
        payload.extend_from_slice(&(encoded.len() as u16).to_le_bytes());
        payload.extend_from_slice(&encoded[off..slice_end]);
        (STATUS_OK, payload)
    }

    /// "Pull to folder" storage ops — capture a `.mota` the node is fetching off-mesh, keyed by `mid[4]`:
    /// a partial pull is `<mid>.mota.part`, published to `<mid>.mota` on `OP_FIN`.
    fn handle_storage(&self, op: u8, args: &[u8]) -> (u8, Vec<u8>) {
        use seeder::{STATUS_ERR, STATUS_OK};
        let Some(store) = &self.store_dir else {
            return (STATUS_ERR, vec![]); // serve-only: storage refused
        };
        let mid: [u8; 4] = args[..4].try_into().unwrap();
        let part = store_path(store, &mid, true);
        let done = store_path(store, &mid, false);
        let ok = |r: std::io::Result<()>| {
            if r.is_ok() {
                (STATUS_OK, vec![])
            } else {
                (STATUS_ERR, vec![])
            }
        };

        match op {
            seeder::OP_STAT => {
                let (present, total) = std::fs::metadata(&done)
                    .or_else(|_| std::fs::metadata(&part))
                    .map(|m| (1u8, m.len() as u32))
                    .unwrap_or((0, 0));
                let mut payload = vec![present];
                payload.extend_from_slice(&total.to_le_bytes());
                (STATUS_OK, payload)
            }
            seeder::OP_BEGIN => ok(self.begin_part(&part, rd_u32(args, 4))),
            seeder::OP_WRITE => {
                let off = rd_u32(args, 4) as u64;
                let len = u16::from_le_bytes([args[8], args[9]]) as usize;
                match args.get(10..10 + len) {
                    Some(data) => ok(write_at(&part, off, data)),
                    None => (STATUS_ERR, vec![]),
                }
            }
            seeder::OP_SREAD => {
                let off = rd_u32(args, 4) as u64;
                let len = u16::from_le_bytes([args[8], args[9]]) as usize;
                let src = if part.exists() { &part } else { &done };
                match read_at(src, off, len) {
                    Ok(buf) => (STATUS_OK, buf),
                    Err(_) => (STATUS_ERR, vec![]),
                }
            }
            seeder::OP_FIN => ok(self.publish(&part, &done)),
            _ => (STATUS_ERR, vec![]),
        }
    }

    /// Create a fresh `total`-byte `.part` filled with `0xFF`, then (if a seed is configured) overlay the
    /// seed payload at the payload region. Header + leaves stay `0xFF` — the node writes those as it fetches.
    fn begin_part(&self, part: &Path, total: u32) -> std::io::Result<()> {
        let mut buf = vec![0xFFu8; total as usize];
        if let Some((payload, block_count)) = &self.seed {
            let off = HEADER_LEN + MFL + *block_count as usize * 4;
            if off < buf.len() {
                let n = payload.len().min(buf.len() - off);
                buf[off..off + n].copy_from_slice(&payload[..n]);
            }
        }
        std::fs::write(part, &buf)
    }

    /// Light-validate a finished `.part` (MAGIC + declared size) and publish it as `<mid>.mota`.
    fn publish(&self, part: &Path, done: &Path) -> std::io::Result<()> {
        let size = std::fs::metadata(part)?.len();
        let mut head = [0u8; 8];
        std::fs::File::open(part)?.read_exact(&mut head)?;
        if head[..4] != MAGIC || rd_u32(&head, 4) as u64 != size {
            return Err(std::io::Error::new(
                ErrorKind::InvalidData,
                "incomplete/invalid .part",
            ));
        }
        std::fs::rename(part, done)
    }
}

/// One independently compressed raw RFC 1951 stream. The receiver's full decoder accepts every
/// standard DEFLATE block type; wrapper-level raw fallback is used when this does not save bytes.
fn deflate_raw(input: &[u8]) -> Option<Vec<u8>> {
    let mut encoder = DeflateEncoder::new(Vec::new(), Compression::best());
    encoder.write_all(input).ok()?;
    encoder.finish().ok()
}

/// MotaDesc wire (38 B): mid[4] target(4) fwver(4) codec(1) flags(1) total(4) leaves_off(4) block_count(4)
/// payload_off(4) payload_size(4) block_log2(1) source_caps(1) reserved(2).
fn describe(s: &ServedMota) -> [u8; seeder::DESC_WIRE] {
    let m = &s.manifest;
    let mut w = [0u8; seeder::DESC_WIRE];
    w[0..4].copy_from_slice(&m.merkle_root); // mid
    w[4..8].copy_from_slice(&m.target_id.to_le_bytes());
    w[8..12].copy_from_slice(&m.fw_version.to_le_bytes());
    w[12] = m.codec_id;
    w[13] = m.flags;
    w[14..18].copy_from_slice(&(s.bytes.len() as u32).to_le_bytes());
    w[18..22].copy_from_slice(&(m.leaves_off() as u32).to_le_bytes());
    w[22..26].copy_from_slice(&m.block_count.to_le_bytes());
    w[26..30].copy_from_slice(&(m.payload_off() as u32).to_le_bytes());
    w[30..34].copy_from_slice(&m.payload_size.to_le_bytes());
    w[34] = m.block_size_log2;
    w[35] = seeder::SOURCE_CAP_DEFLATE_BLOCK;
    w
}

/// `<store_dir>/<mid-hex-lowercase>.mota[.part]`.
fn store_path(store_dir: &Path, mid: &[u8; 4], part: bool) -> PathBuf {
    let suffix = if part { ".mota.part" } else { ".mota" };
    store_dir.join(format!("{}{suffix}", hex::encode(mid)))
}

fn write_at(path: &Path, off: u64, data: &[u8]) -> std::io::Result<()> {
    let mut file = std::fs::OpenOptions::new().write(true).open(path)?;
    file.seek(SeekFrom::Start(off))?;
    file.write_all(data)
}

fn read_at(path: &Path, off: u64, len: usize) -> std::io::Result<Vec<u8>> {
    let mut buf = vec![0u8; len];
    let mut file = std::fs::File::open(path)?;
    file.seek(SeekFrom::Start(off))?;
    file.read_exact(&mut buf)?;
    Ok(buf)
}

// ---- transports ----------------------------------------------------------------------------------

/// A bidirectional byte link with a read timeout configured (serial or TCP).
pub trait Link: Read + Write {}
impl<T: Read + Write> Link for T {}

/// Open the node's USB serial port at `baud` (raw, no flow control), with a read timeout.
pub fn open_serial(dev: &str, baud: u32) -> Result<Box<dyn Link>> {
    let port = serialport::new(dev, baud)
        .timeout(LINK_TIMEOUT)
        .open()
        .with_context(|| format!("cannot open serial device: {dev}"))?;
    Ok(Box::new(port))
}

/// Connect to the node's WiFi seeder port (`host[:port]`, default 5001) — a dedicated port, separate from
/// the companion port, so serving doesn't disturb a phone app.
pub fn open_tcp(host: &str, port: u16) -> Result<Box<dyn Link>> {
    let stream = TcpStream::connect((host, port))
        .with_context(|| format!("cannot connect to {host}:{port}"))?;
    stream.set_read_timeout(Some(LINK_TIMEOUT))?;
    Ok(Box::new(stream))
}

// ---- framed byte-stream loop ---------------------------------------------------------------------

enum Byte {
    Got(u8),
    Timeout,
    Closed,
}

fn read_byte(link: &mut dyn Link) -> Byte {
    let mut b = [0u8; 1];
    match link.read(&mut b) {
        Ok(1) => Byte::Got(b[0]),
        Ok(_) => Byte::Closed, // 0 = EOF/peer closed
        Err(e) if matches!(e.kind(), ErrorKind::TimedOut | ErrorKind::WouldBlock) => Byte::Timeout,
        Err(_) => Byte::Closed,
    }
}

/// Read exactly `n` bytes, or `None` if a byte times out / the link closes mid-frame (discard + resync).
fn read_frame_bytes(link: &mut dyn Link, n: usize) -> Option<Vec<u8>> {
    let mut buf = vec![0u8; n];
    for slot in &mut buf {
        match read_byte(link) {
            Byte::Got(b) => *slot = b,
            _ => return None,
        }
    }
    Some(buf)
}

fn xor(bytes: &[u8], seed: u8) -> u8 {
    bytes.iter().fold(seed, |x, &b| x ^ b)
}

/// Read one full request (`op` + fixed header + optional WRITE data + checksum), validating the checksum.
fn read_request(link: &mut dyn Link) -> Option<(u8, Vec<u8>)> {
    let op = read_frame_bytes(link, 1)?[0];
    let hdr = seeder::request_header_len(op)?;
    let mut args = if hdr > 0 {
        read_frame_bytes(link, hdr)?
    } else {
        Vec::new()
    };
    if op == seeder::OP_WRITE {
        let dlen = u16::from_le_bytes([args[8], args[9]]) as usize;
        if dlen > seeder::WRITE_MAX {
            return None; // guard a runaway frame
        }
        if dlen > 0 {
            args.extend(read_frame_bytes(link, dlen)?);
        }
    }
    let xsum = read_frame_bytes(link, 1)?[0];
    (xsum == xor(&args, op)).then_some((op, args))
}

fn send_response(link: &mut dyn Link, op: u8, status: u8, payload: &[u8]) {
    let mut frame = Vec::with_capacity(5 + payload.len());
    frame.extend_from_slice(&seeder::RSP_MAGIC);
    frame.push(op);
    frame.push(status);
    frame.extend_from_slice(payload);
    frame.push(xor(&frame, 0)); // xsum over all prior bytes (incl. magic)
    let _ = link.write_all(&frame);
}

/// Run the seeder framing loop until `stop` is set: resync on `M S`, verify the request, dispatch to
/// `core`, frame the reply. Interleaved device text/log lines (serial only) are surfaced via `devline`.
pub fn serve_loop(
    link: &mut dyn Link,
    core: &SeederCore,
    verbose: bool,
    mut devline: impl FnMut(&str),
    stop: &AtomicBool,
) {
    let mut prev: Option<u8> = None;
    let mut line = String::new();

    while !stop.load(Ordering::Relaxed) {
        let b = match read_byte(link) {
            Byte::Got(b) => b,
            Byte::Timeout => continue,
            Byte::Closed => break,
        };

        if prev == Some(seeder::REQ_MAGIC[0]) && b == seeder::REQ_MAGIC[1] {
            prev = None;
            if let Some((op, args)) = read_request(link) {
                if let Some((status, payload)) = core.handle(op, &args) {
                    send_response(link, op, status, &payload);
                    if verbose {
                        log_request(&mut devline, op, &args, status, &payload);
                    }
                }
            }
            continue;
        }

        // Not a frame start: this is device text sharing the wire (serial console).
        if let Some(p) = prev {
            line.push(p as char);
            if p == b'\n' || line.len() > 512 {
                flush_line(&mut line, &mut devline);
            }
        }
        prev = Some(b);
    }
}

fn flush_line(line: &mut String, devline: &mut impl FnMut(&str)) {
    let trimmed = line.trim_end_matches(['\r', '\n']);
    if !trimmed.is_empty() {
        devline(trimmed);
    }
    line.clear();
}

fn log_request(devline: &mut impl FnMut(&str), op: u8, args: &[u8], status: u8, payload: &[u8]) {
    let ok = if status == seeder::STATUS_OK {
        "OK"
    } else {
        "ERR"
    };
    let msg = match op {
        seeder::OP_COUNT => format!("COUNT -> {}", payload.first().copied().unwrap_or(0)),
        seeder::OP_DESCRIBE => format!("DESCRIBE {} {ok}", args[0]),
        seeder::OP_READ => format!("READ {} @{} {ok}", args[0], rd_u32(args, 1)),
        seeder::OP_DEFLATE_BLOCK => format!(
            "DEFLATE {} block={} @{} {ok}",
            args[0],
            u16::from_le_bytes([args[1], args[2]]),
            u16::from_le_bytes([args[3], args[4]])
        ),
        _ => return, // storage ops: quiet unless it matters
    };
    devline(&msg);
}
