//! Serve a folder of `.mota` to a MeshCore node over the seeder link (USB serial or WiFi TCP), and capture
//! a "pull to folder" `.mota` the node is fetching off-mesh.
//!
//! Split into a transport-agnostic [`SeederCore`] (turns a `(op, args)` request into a `(status, payload)`
//! reply — a future BLE/GATT path would call it directly) and a byte-stream [`serve_loop`] that frames it.

use crate::format::{rd_u32, seeder, Manifest, HEADER_LEN, MAGIC, MFL};
use crate::verify::verify;
use anyhow::{bail, Context, Result};
use flate2::{write::DeflateEncoder, Compression};
use std::io::{ErrorKind, Read, Seek, SeekFrom, Write};
use std::net::TcpStream;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread;
use std::time::{Duration, Instant};

const LINK_TIMEOUT: Duration = Duration::from_millis(500);
const SERIAL_OPEN_SETTLE: Duration = Duration::from_millis(750);
const ATTACH_RETRY_AFTER: Duration = Duration::from_secs(2);
const ATTACH_TIMEOUT: Duration = Duration::from_secs(12);
const ATTACH_MAX_ATTEMPTS: usize = 3;
const FOLDER_ON: &[u8] = b"ota folder on\r\n";

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
        let mut file = std::fs::File::open(part)?;
        file.seek(SeekFrom::Start(0))?;
        file.read_exact(&mut head)?;
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
/// payload_off(4) payload_size(4) block_size_log2(1) source_caps(1) reserved(2).
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
    let mut port = serialport::new(dev, baud)
        .timeout(LINK_TIMEOUT)
        // Windows preserves DTR low by default. MeshCore's native USB CDC console does not reliably
        // consume the first command until the host has asserted its terminal-control lines.
        .dtr_on_open(true)
        .open()
        .with_context(|| format!("cannot open serial device: {dev}"))?;
    // The builder applies DTR best-effort, so assert both lines once more and surface a real failure.
    // RTS is held (not pulsed); this matches normal terminal clients and does not enable flow control.
    port.write_data_terminal_ready(true)
        .with_context(|| format!("cannot assert DTR on serial device: {dev}"))?;
    port.write_request_to_send(true)
        .with_context(|| format!("cannot assert RTS on serial device: {dev}"))?;
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

#[derive(Default)]
struct StreamState {
    // Only an `M` needs delaying: it may be the first byte of the binary `MS` request magic.
    pending_m: bool,
    deferred: Option<u8>,
    line: String,
}

enum PumpEvent {
    Activity,
    Timeout,
    Closed,
    SeederFrame(Option<String>),
    DeviceLine(String),
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

enum RequestRead {
    Valid(u8, Vec<u8>),
    MalformedKnown,
    Unknown(u8),
}

/// Read one full request (`op` + fixed header + optional WRITE data + checksum), validating the checksum.
fn read_request(link: &mut dyn Link) -> RequestRead {
    let Some(op) = read_frame_bytes(link, 1).map(|b| b[0]) else {
        return RequestRead::MalformedKnown;
    };
    let Some(hdr) = seeder::request_header_len(op) else {
        return RequestRead::Unknown(op);
    };
    let mut args = if hdr > 0 {
        let Some(args) = read_frame_bytes(link, hdr) else {
            return RequestRead::MalformedKnown;
        };
        args
    } else {
        Vec::new()
    };
    if op == seeder::OP_WRITE {
        let dlen = u16::from_le_bytes([args[8], args[9]]) as usize;
        if dlen > seeder::WRITE_MAX {
            return RequestRead::MalformedKnown; // guard a runaway frame
        }
        if dlen > 0 {
            let Some(data) = read_frame_bytes(link, dlen) else {
                return RequestRead::MalformedKnown;
            };
            args.extend(data);
        }
    }
    let Some(xsum) = read_frame_bytes(link, 1).map(|b| b[0]) else {
        return RequestRead::MalformedKnown;
    };
    if xsum == xor(&args, op) {
        RequestRead::Valid(op, args)
    } else {
        RequestRead::MalformedKnown
    }
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

impl StreamState {
    /// Consume one byte-stream event while continuing to answer seeder requests. Text and binary
    /// frames share the serial wire, including while `ota folder on` is still refreshing sources.
    fn pump(&mut self, link: &mut dyn Link, core: &SeederCore, verbose: bool) -> PumpEvent {
        let b = match self.deferred.take() {
            Some(b) => b,
            None => match read_byte(link) {
                Byte::Got(b) => b,
                Byte::Timeout => return PumpEvent::Timeout,
                Byte::Closed => return PumpEvent::Closed,
            },
        };

        if self.pending_m {
            self.pending_m = false;
            if b == seeder::REQ_MAGIC[1] {
                let log = match read_request(link) {
                    RequestRead::Valid(op, args) => {
                        // A binary frame is a hard boundary. Do not let an unterminated console
                        // fragment become a prefix of the acknowledgement that follows the frame.
                        self.line.clear();
                        if let Some((status, payload)) = core.handle(op, &args) {
                            send_response(link, op, status, &payload);
                            verbose
                                .then(|| request_log(op, &args, status, &payload))
                                .flatten()
                        } else {
                            None
                        }
                    }
                    RequestRead::MalformedKnown => {
                        self.line.clear();
                        None
                    }
                    RequestRead::Unknown(op) => {
                        // `MS` is common in ordinary console text (`CHANNEL MSG`, for example).
                        // An undefined opcode proves this was not one of our seeder frames. Replay
                        // `MS` as text, then feed the opcode through normal candidate handling so an
                        // overlapping `MSMS<op>` still finds the second, valid frame.
                        if let Some(line) = self.push_literal(&seeder::REQ_MAGIC) {
                            self.deferred = Some(op);
                            return PumpEvent::DeviceLine(line);
                        }
                        return self.accept_unframed(op);
                    }
                };
                // Report the magic even when the rest of the frame was damaged. Once a device has
                // entered binary seeder framing, another ASCII enable command could corrupt it.
                return PumpEvent::SeederFrame(log);
            }
            if let Some(line) = self.push_text(seeder::REQ_MAGIC[0]) {
                // Retain the current byte if the defensive 512-byte flush happened on the pending M.
                self.deferred = Some(b);
                return PumpEvent::DeviceLine(line);
            }
        }

        self.accept_unframed(b)
    }

    fn accept_unframed(&mut self, b: u8) -> PumpEvent {
        if b == seeder::REQ_MAGIC[0] {
            self.pending_m = true;
            PumpEvent::Activity
        } else if let Some(line) = self.push_text(b) {
            PumpEvent::DeviceLine(line)
        } else {
            PumpEvent::Activity
        }
    }

    fn push_text(&mut self, b: u8) -> Option<String> {
        self.line.push(b as char);
        if b != b'\n' && self.line.len() <= 512 {
            return None;
        }
        let line = std::mem::take(&mut self.line);
        let trimmed = line.trim_end_matches(['\r', '\n']);
        (!trimmed.is_empty()).then(|| trimmed.to_owned())
    }

    fn push_literal(&mut self, bytes: &[u8]) -> Option<String> {
        let mut emitted = None;
        for &b in bytes {
            if let Some(line) = self.push_text(b) {
                emitted.get_or_insert(line);
            }
        }
        emitted
    }
}

#[derive(Clone, Copy)]
struct AttachPolicy {
    settle: Duration,
    retry_after: Duration,
    timeout: Duration,
    max_attempts: usize,
}

impl Default for AttachPolicy {
    fn default() -> Self {
        Self {
            settle: SERIAL_OPEN_SETTLE,
            retry_after: ATTACH_RETRY_AFTER,
            timeout: ATTACH_TIMEOUT,
            max_attempts: ATTACH_MAX_ATTEMPTS,
        }
    }
}

/// Enable the serial folder source and wait for the node's positive acknowledgement.
///
/// Source refresh is synchronous on the node, so it may issue COUNT/DESCRIBE/READ requests before
/// printing `OK folder attached`. Those requests must be served during the handshake. A lost first
/// command is retried only until binary framing appears, after which sending ASCII would be unsafe.
pub fn attach_serial_folder(
    link: &mut dyn Link,
    core: &SeederCore,
    verbose: bool,
    mut devline: impl FnMut(&str),
    stop: &AtomicBool,
) -> Result<()> {
    attach_serial_folder_with_policy(
        link,
        core,
        verbose,
        &mut devline,
        stop,
        AttachPolicy::default(),
    )
}

fn attach_serial_folder_with_policy(
    link: &mut dyn Link,
    core: &SeederCore,
    verbose: bool,
    devline: &mut impl FnMut(&str),
    stop: &AtomicBool,
    policy: AttachPolicy,
) -> Result<()> {
    if !policy.settle.is_zero() {
        thread::sleep(policy.settle);
    }
    if stop.load(Ordering::Relaxed) {
        bail!("interrupted before enabling the serial folder source");
    }

    send_folder_on(link)?;
    let mut attempts = 1usize;
    let started = Instant::now();
    let mut retry_at = started + policy.retry_after;
    let deadline = started + policy.timeout;
    let mut protocol_seen = false;
    let mut stream = StreamState::default();

    loop {
        if stop.load(Ordering::Relaxed) {
            bail!("interrupted while enabling the serial folder source");
        }
        if Instant::now() >= deadline {
            bail!(
                "timed out waiting for `OK folder attached` after {attempts} enable attempt{}",
                if attempts == 1 { "" } else { "s" }
            );
        }

        match stream.pump(link, core, verbose) {
            PumpEvent::Closed => bail!("serial link closed while enabling the folder source"),
            PumpEvent::SeederFrame(log) => {
                protocol_seen = true;
                if let Some(log) = log {
                    devline(&log);
                }
            }
            PumpEvent::DeviceLine(line) => {
                devline(&line);
                let reply = normalize_console_reply(&line);
                if is_attach_ok(reply) {
                    return Ok(());
                }
                if reply == "ERR" || reply.starts_with("ERR ") || reply.starts_with("ERR:") {
                    bail!("node rejected `ota folder on`: {reply}");
                }
            }
            PumpEvent::Activity | PumpEvent::Timeout => {}
        }

        let now = Instant::now();
        if !protocol_seen && !stream.pending_m && attempts < policy.max_attempts && now >= retry_at
        {
            send_folder_on(link)?;
            attempts += 1;
            retry_at = now + policy.retry_after;
        }
    }
}

fn send_folder_on(link: &mut dyn Link) -> Result<()> {
    link.write_all(FOLDER_ON)
        .context("sending `ota folder on`")?;
    link.flush().context("flushing `ota folder on`")
}

fn is_attach_ok(line: &str) -> bool {
    has_reply_prefix(line, "OK folder attached") || has_reply_prefix(line, "OK folder refreshed")
}

/// Dedicated MeshCore OTA consoles render command replies with this exact marker. Full Companion's
/// USB mOTA mode emits the reply bare, so accept either representation without substring matching.
fn normalize_console_reply(line: &str) -> &str {
    line.strip_prefix("  -> ").unwrap_or(line)
}

fn has_reply_prefix(line: &str, prefix: &str) -> bool {
    line.strip_prefix(prefix)
        .is_some_and(|rest| rest.is_empty() || rest.starts_with(' ') || rest.starts_with(':'))
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
    let mut stream = StreamState::default();

    while !stop.load(Ordering::Relaxed) {
        match stream.pump(link, core, verbose) {
            PumpEvent::Closed => break,
            PumpEvent::DeviceLine(line) => devline(&line),
            PumpEvent::SeederFrame(Some(log)) => devline(&log),
            PumpEvent::Activity | PumpEvent::Timeout | PumpEvent::SeederFrame(None) => {}
        }
    }
}

fn request_log(op: u8, args: &[u8], status: u8, payload: &[u8]) -> Option<String> {
    let ok = if status == seeder::STATUS_OK {
        "OK"
    } else {
        "ERR"
    };
    match op {
        seeder::OP_COUNT => Some(format!(
            "COUNT -> {}",
            payload.first().copied().unwrap_or(0)
        )),
        seeder::OP_DESCRIBE => Some(format!("DESCRIBE {} {ok}", args[0])),
        seeder::OP_READ => Some(format!("READ {} @{} {ok}", args[0], rd_u32(args, 1))),
        seeder::OP_DEFLATE_BLOCK => Some(format!(
            "DEFLATE {} block={} @{} {ok}",
            args[0],
            u16::from_le_bytes([args[1], args[2]]),
            u16::from_le_bytes([args[3], args[4]])
        )),
        _ => None, // storage ops: quiet unless it matters
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::VecDeque;
    use std::io;

    enum ReadStep {
        Byte(u8),
        Timeout(Duration),
        Closed,
    }

    struct ScriptedLink {
        reads: VecDeque<ReadStep>,
        writes: Vec<u8>,
    }

    impl ScriptedLink {
        fn new(reads: impl IntoIterator<Item = ReadStep>) -> Self {
            Self {
                reads: reads.into_iter().collect(),
                writes: Vec::new(),
            }
        }
    }

    impl Read for ScriptedLink {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            match self.reads.pop_front().unwrap_or(ReadStep::Closed) {
                ReadStep::Byte(b) => {
                    buf[0] = b;
                    Ok(1)
                }
                ReadStep::Timeout(delay) => {
                    thread::sleep(delay);
                    Err(io::Error::new(ErrorKind::TimedOut, "scripted timeout"))
                }
                ReadStep::Closed => Ok(0),
            }
        }
    }

    impl Write for ScriptedLink {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            self.writes.extend_from_slice(buf);
            Ok(buf.len())
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    fn byte_steps(bytes: &[u8]) -> Vec<ReadStep> {
        bytes.iter().copied().map(ReadStep::Byte).collect()
    }

    fn count_request() -> Vec<u8> {
        vec![
            seeder::REQ_MAGIC[0],
            seeder::REQ_MAGIC[1],
            seeder::OP_COUNT,
            seeder::OP_COUNT,
        ]
    }

    fn test_core() -> SeederCore {
        SeederCore::new(Folder { motas: Vec::new() }, None)
    }

    fn test_policy() -> AttachPolicy {
        AttachPolicy {
            settle: Duration::ZERO,
            retry_after: Duration::from_millis(2),
            timeout: Duration::from_millis(100),
            max_attempts: 3,
        }
    }

    fn occurrences(haystack: &[u8], needle: &[u8]) -> usize {
        haystack
            .windows(needle.len())
            .filter(|w| *w == needle)
            .count()
    }

    #[test]
    fn attach_retries_a_lost_first_command_and_serves_count_before_ack() {
        let mut reads = vec![ReadStep::Timeout(Duration::from_millis(3))];
        reads.extend(byte_steps(&count_request()));
        reads.extend(byte_steps(
            b"\r\n  -> OK folder attached (serial): advertising 1/1 host mOTAs\r\n",
        ));
        let mut link = ScriptedLink::new(reads);
        let mut lines = Vec::new();

        attach_serial_folder_with_policy(
            &mut link,
            &test_core(),
            true,
            &mut |line| lines.push(line.to_owned()),
            &AtomicBool::new(false),
            test_policy(),
        )
        .unwrap();

        assert_eq!(occurrences(&link.writes, FOLDER_ON), 2);
        assert!(link.writes.windows(2).any(|w| w == seeder::RSP_MAGIC));
        assert!(lines.iter().any(|line| line == "COUNT -> 0"));
        assert!(lines
            .iter()
            .any(|line| line == "  -> OK folder attached (serial): advertising 1/1 host mOTAs"));
    }

    #[test]
    fn attach_never_retries_ascii_after_binary_framing_begins() {
        let mut reads = byte_steps(&count_request());
        reads.extend([
            ReadStep::Timeout(Duration::from_millis(3)),
            ReadStep::Timeout(Duration::from_millis(3)),
        ]);
        reads.extend(byte_steps(
            b"OK folder refreshed (serial): advertising 0/0 host mOTAs\r\n",
        ));
        let mut link = ScriptedLink::new(reads);

        attach_serial_folder_with_policy(
            &mut link,
            &test_core(),
            false,
            &mut |_| {},
            &AtomicBool::new(false),
            test_policy(),
        )
        .unwrap();

        assert_eq!(occurrences(&link.writes, FOLDER_ON), 1);
    }

    #[test]
    fn attach_does_not_retry_between_split_magic_bytes() {
        let mut reads = vec![
            ReadStep::Byte(seeder::REQ_MAGIC[0]),
            ReadStep::Timeout(Duration::from_millis(3)),
            ReadStep::Byte(seeder::REQ_MAGIC[1]),
            ReadStep::Byte(seeder::OP_COUNT),
            ReadStep::Byte(seeder::OP_COUNT),
        ];
        reads.extend(byte_steps(
            b"OK folder attached (serial): advertising 0/0 host mOTAs\r\n",
        ));
        let mut link = ScriptedLink::new(reads);

        attach_serial_folder_with_policy(
            &mut link,
            &test_core(),
            false,
            &mut |_| {},
            &AtomicBool::new(false),
            test_policy(),
        )
        .unwrap();

        assert_eq!(occurrences(&link.writes, FOLDER_ON), 1);
    }

    #[test]
    fn console_msg_text_does_not_suppress_a_lost_command_retry() {
        let mut reads = byte_steps(b"CHANNEL MSG -> unrelated console text\r\n");
        reads.push(ReadStep::Timeout(Duration::from_millis(3)));
        reads.extend(byte_steps(&count_request()));
        reads.extend(byte_steps(
            b"  -> OK folder attached (serial): advertising 1/1 host mOTAs\r\n",
        ));
        let mut link = ScriptedLink::new(reads);
        let mut lines = Vec::new();

        attach_serial_folder_with_policy(
            &mut link,
            &test_core(),
            false,
            &mut |line| lines.push(line.to_owned()),
            &AtomicBool::new(false),
            test_policy(),
        )
        .unwrap();

        assert_eq!(occurrences(&link.writes, FOLDER_ON), 2);
        assert!(lines
            .iter()
            .any(|line| line == "CHANNEL MSG -> unrelated console text"));
    }

    #[test]
    fn unknown_magic_candidate_preserves_an_overlapping_valid_frame() {
        let mut reads = vec![
            ReadStep::Byte(b'M'),
            ReadStep::Byte(b'S'),
            ReadStep::Byte(b'M'),
            ReadStep::Byte(b'S'),
            ReadStep::Byte(seeder::OP_COUNT),
            ReadStep::Byte(seeder::OP_COUNT),
        ];
        reads.extend(byte_steps(
            b"OK folder attached (serial): advertising 0/0 host mOTAs\r\n",
        ));
        let mut link = ScriptedLink::new(reads);

        attach_serial_folder_with_policy(
            &mut link,
            &test_core(),
            false,
            &mut |_| {},
            &AtomicBool::new(false),
            test_policy(),
        )
        .unwrap();

        assert_eq!(occurrences(&link.writes, FOLDER_ON), 1);
        assert!(link.writes.windows(2).any(|w| w == seeder::RSP_MAGIC));
    }

    #[test]
    fn attach_requires_positive_reply() {
        let mut reads = byte_steps(b"ERR folder source unavailable\r\n");
        reads.push(ReadStep::Closed);
        let mut link = ScriptedLink::new(reads);

        let err = attach_serial_folder_with_policy(
            &mut link,
            &test_core(),
            false,
            &mut |_| {},
            &AtomicBool::new(false),
            test_policy(),
        )
        .unwrap_err();

        assert!(err.to_string().contains("node rejected"));
    }

    #[test]
    fn attach_retries_and_wait_are_bounded() {
        let reads = (0..4).map(|_| ReadStep::Timeout(Duration::from_millis(3)));
        let mut link = ScriptedLink::new(reads);
        let policy = AttachPolicy {
            settle: Duration::ZERO,
            retry_after: Duration::from_millis(2),
            timeout: Duration::from_millis(8),
            max_attempts: 2,
        };

        let err = attach_serial_folder_with_policy(
            &mut link,
            &test_core(),
            false,
            &mut |_| {},
            &AtomicBool::new(false),
            policy,
        )
        .unwrap_err();

        assert!(err.to_string().contains("timed out"));
        assert_eq!(occurrences(&link.writes, FOLDER_ON), 2);
    }
}
