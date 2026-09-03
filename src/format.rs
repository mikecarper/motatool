//! The `.mota` container format and its fixed manifest layout.
//!
//! A container is `MAGIC(4) ‖ total_size(4,LE) ‖ manifest(197) ‖ leaves[](block_count·4) ‖ payload ‖
//! TRAILER(5)`. The manifest is **fixed-layout**: every field sits at a constant offset and is always
//! present (base_hash / signer / signature are zero-filled when unused); only `leaves[]` and `payload`
//! vary. This mirrors `src/helpers/ota/OtaFormat.h` and `docs/ota_protocol.md` — keep it byte-identical.

use anyhow::{ensure, Result};

// ---- container framing ----
pub const MAGIC: [u8; 4] = *b"mOTA";
pub const TRAILER: [u8; 5] = *b"vk496";
pub const HEADER_LEN: usize = 8; // MAGIC(4) + total_size(4)
pub const TRAILER_LEN: usize = 5;

// ---- manifest constants ----
pub const FORMAT_VER: u8 = 0x02;
pub const HASH_ALGO_SHA256: u8 = 0x12;
pub const MFLAG_FULL: u8 = 0x01;
pub const MFLAG_SIGNED: u8 = 0x02;
pub const APPROVAL_NONE: [u8; 4] = [0xFF; 4]; // required on the wire
pub const APPROVAL_YES: [u8; 4] = *b"APRV";
pub const MFL: usize = 197; // manifest-minus-leaves length (constant)
pub const SIGNED_LEN: usize = 129; // the Ed25519 signature covers manifest[0, 129)
pub const HW_ID_LEN: usize = 32;
pub const DEFAULT_BLOCK_SIZE: u32 = 1024;

/// Manifest field offsets, relative to the manifest start (= [`HEADER_LEN`]).
pub mod off {
    pub const FORMAT_VER: usize = 0;
    pub const FLAGS: usize = 1;
    pub const HASH_ALGO: usize = 2;
    pub const TARGET_ID: usize = 3;
    pub const FW_VERSION: usize = 7;
    pub const IMAGE_SIZE: usize = 11;
    pub const PAYLOAD_SIZE: usize = 15;
    pub const BLOCK_SIZE_LOG2: usize = 19;
    pub const MERKLE_ROOT: usize = 20; // 4
    pub const IMAGE_HASH: usize = 24; // 32
    pub const CODEC_ID: usize = 56; // 1
    pub const HW_ID: usize = 57; // 32
    pub const BASE_HASH: usize = 89; // 8  (zero if full)
    pub const SIGNER: usize = 97; // 32 (zero if unsigned)
    pub const SIGNATURE: usize = 129; // 64 (zero if unsigned)
    pub const APPROVAL: usize = 193; // 4
}

// ---- EndF trailer (fixed 56 bytes) ----
pub const ENDF_MAGIC: [u8; 4] = *b"EndF";
pub const ENDF_LEN: usize = 56; // marker(4) body_len(4) body_hash8(8) fw_version(4) target_id(4) hw_id(32)
pub const ENDF_OFF_FWVER: usize = 16;
pub const ENDF_OFF_TARGET: usize = 20;
pub const ENDF_OFF_HWID: usize = 24;

// ---- nRF52 in-place apply limits (mirror OtaFlashLayout_nrf52.h); used to warn on oversized deltas ----
pub const NRF52_INPLACE_MEMORY: u32 = 0x0009_8000;
pub const NRF52_INPLACE_SEGMENT: u32 = 4096;
pub const NRF52_FLASH_SPAN: u32 = 0x000D_4000 - 0x0002_6000; // 0xAE000
pub const NRF52_MAX_INPLACE_MOTA: u32 = NRF52_FLASH_SPAN - NRF52_INPLACE_MEMORY; // ~90 KB

/// The mota-seeder link protocol (host ⇄ node), mirroring `src/helpers/ota/MotaSeederProto.h`.
///
/// Request  (host→node): `M S  op(1)  args…               xsum(1 = XOR of op‖args)`
/// Response (node→host): `m s  op(1)  status(1)  payload…  xsum(1 = XOR of all prior)`
pub mod seeder {
    pub const REQ_MAGIC: [u8; 2] = [b'M', b'S'];
    pub const RSP_MAGIC: [u8; 2] = [b'm', b's'];
    pub const OP_COUNT: u8 = 0x01; // → count(1)
    pub const OP_DESCRIBE: u8 = 0x02; // idx(1) → MotaDesc(38)
    pub const OP_READ: u8 = 0x03; // idx(1) off(4) len(2) → bytes
    pub const OP_STAT: u8 = 0x04; // mid(4) → present(1) total(4)
    pub const OP_BEGIN: u8 = 0x05; // mid(4) total(4) → OK (create 0xFF-filled)
    pub const OP_WRITE: u8 = 0x06; // mid(4) off(4) len(2) data(len) → OK
    pub const OP_SREAD: u8 = 0x07; // mid(4) off(4) len(2) → bytes (0xFF = unwritten)
    pub const OP_FIN: u8 = 0x08; // mid(4) → OK (validate + publish)
    pub const OP_DEFLATE_BLOCK: u8 = 0x09; // idx(1) block(2) off(2) len(2) → total(2) + bytes
    pub const STATUS_OK: u8 = 0x00;
    pub const STATUS_ERR: u8 = 0x01;
    pub const DESC_WIRE: usize = 38; // MotaDesc wire size
    pub const SOURCE_CAP_DEFLATE_BLOCK: u8 = 0x01;
    pub const WRITE_MAX: usize = 512; // max data bytes per WRITE/SREAD
    pub const DEFLATE_READ_MAX: usize = 190; // response adds total(2), keeping the payload <= 192 bytes

    /// Fixed header length (bytes after `op`) for a request, or `None` for an unknown op. `OP_WRITE`
    /// additionally carries `len` data bytes after its 10-byte header.
    pub fn request_header_len(op: u8) -> Option<usize> {
        Some(match op {
            OP_COUNT => 0,
            OP_DESCRIBE => 1,
            OP_READ | OP_DEFLATE_BLOCK => 7,
            OP_STAT | OP_FIN => 4,
            OP_BEGIN => 8,
            OP_SREAD | OP_WRITE => 10,
            _ => return None,
        })
    }
}

/// Delta/full codec (`codec_id` in the manifest).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Codec {
    Full = 0,
    DetoolsSequential = 1, // ESP32 A/B
    DetoolsInplace = 2,    // nRF52 single-slot
}

impl Codec {
    pub fn from_u8(v: u8) -> Option<Codec> {
        match v {
            0 => Some(Codec::Full),
            1 => Some(Codec::DetoolsSequential),
            2 => Some(Codec::DetoolsInplace),
            _ => None,
        }
    }
    /// Human label as used in `inspect`.
    pub fn label(self) -> &'static str {
        match self {
            Codec::Full => "full",
            Codec::DetoolsSequential => "detools-sequential",
            Codec::DetoolsInplace => "detools-in-place",
        }
    }
    /// Short tag as used in auto-generated filenames.
    pub fn name_tag(self) -> &'static str {
        match self {
            Codec::Full => "full",
            Codec::DetoolsSequential => "seqdelta",
            Codec::DetoolsInplace => "ipdelta",
        }
    }
}

/// Self-describing firmware identity carried in the EndF trailer (and overridable on `build`).
#[derive(Clone, Default, Debug)]
pub struct FwIdent {
    pub fw_version: u32,
    pub target_id: u32,
    pub hw_id: String, // NUL-trimmed
}

impl FwIdent {
    pub fn any(&self) -> bool {
        self.fw_version != 0 || self.target_id != 0 || !self.hw_id.is_empty()
    }
}

/// A parsed `.mota` manifest (the fixed 197-byte header block), with derived geometry.
#[derive(Clone, Debug)]
pub struct Manifest {
    pub format_ver: u8,
    pub flags: u8,
    pub hash_algo: u8,
    pub target_id: u32,
    pub fw_version: u32,
    pub image_size: u32,
    pub payload_size: u32,
    pub block_size_log2: u8,
    pub block_count: u32,
    pub merkle_root: [u8; 4],
    pub image_hash: [u8; 32],
    pub codec_id: u8,
    pub hw_id: [u8; 32],
    pub base_hash: [u8; 8],
    pub signer: [u8; 32],
    pub signature: [u8; 64],
    pub approval: [u8; 4],
}

impl Manifest {
    pub fn is_full(&self) -> bool {
        self.flags & MFLAG_FULL != 0
    }
    pub fn is_signed(&self) -> bool {
        self.flags & MFLAG_SIGNED != 0
    }
    pub fn is_approved(&self) -> bool {
        self.approval == APPROVAL_YES
    }
    pub fn block_size(&self) -> u32 {
        1u32 << self.block_size_log2
    }
    pub fn codec(&self) -> Option<Codec> {
        Codec::from_u8(self.codec_id)
    }
    pub fn leaves_off(&self) -> usize {
        HEADER_LEN + MFL
    }
    pub fn payload_off(&self) -> usize {
        self.leaves_off() + self.block_count as usize * 4
    }
    pub fn total_size(&self) -> usize {
        self.payload_off() + self.payload_size as usize + TRAILER_LEN
    }
    /// The NUL-trimmed hardware tag.
    pub fn hw_id_str(&self) -> String {
        cstr(&self.hw_id)
    }

    /// Parse and validate a whole container: framing, format version, and that the declared geometry
    /// matches the file length. Does *not* recompute hashes — that is [`crate::verify`].
    pub fn parse(blob: &[u8]) -> Result<Manifest> {
        ensure!(
            blob.len() >= HEADER_LEN + MFL + TRAILER_LEN,
            "too small for a .mota"
        );
        ensure!(blob[..4] == MAGIC, "bad MAGIC (not a .mota)");
        let total = rd_u32(blob, 4);
        ensure!(
            total as usize == blob.len(),
            "MOTA_TOTAL_SIZE != file length"
        );
        ensure!(blob[blob.len() - TRAILER_LEN..] == TRAILER, "bad TRAILER");

        let mf = &blob[HEADER_LEN..];
        let format_ver = mf[off::FORMAT_VER];
        ensure!(
            format_ver == FORMAT_VER,
            "unsupported format_ver {format_ver}"
        );

        let block_size_log2 = mf[off::BLOCK_SIZE_LOG2];
        let payload_size = rd_u32(mf, off::PAYLOAD_SIZE);
        ensure!(
            (1..=24).contains(&block_size_log2) && payload_size != 0,
            "bad block_size/payload"
        );
        let block_size = 1u32 << block_size_log2;
        let block_count = payload_size.div_ceil(block_size);
        ensure!(
            (1..=0xFFFF).contains(&block_count),
            "block_count out of range"
        );

        let m = Manifest {
            format_ver,
            flags: mf[off::FLAGS],
            hash_algo: mf[off::HASH_ALGO],
            target_id: rd_u32(mf, off::TARGET_ID),
            fw_version: rd_u32(mf, off::FW_VERSION),
            image_size: rd_u32(mf, off::IMAGE_SIZE),
            payload_size,
            block_size_log2,
            block_count,
            merkle_root: arr(mf, off::MERKLE_ROOT),
            image_hash: arr(mf, off::IMAGE_HASH),
            codec_id: mf[off::CODEC_ID],
            hw_id: arr(mf, off::HW_ID),
            base_hash: arr(mf, off::BASE_HASH),
            signer: arr(mf, off::SIGNER),
            signature: arr(mf, off::SIGNATURE),
            approval: arr(mf, off::APPROVAL),
        };
        ensure!(
            m.total_size() == blob.len(),
            "geometry (leaves+payload) != file length"
        );
        Ok(m)
    }
}

// ---- little-endian helpers ----
pub fn rd_u32(buf: &[u8], off: usize) -> u32 {
    u32::from_le_bytes(buf[off..off + 4].try_into().unwrap())
}
pub fn wr_u32(buf: &mut [u8], off: usize, v: u32) {
    buf[off..off + 4].copy_from_slice(&v.to_le_bytes());
}
/// Read a fixed-size byte array at `off`.
pub fn arr<const N: usize>(buf: &[u8], off: usize) -> [u8; N] {
    buf[off..off + N].try_into().unwrap()
}
/// Interpret a NUL-padded byte field as a string (stops at the first NUL).
pub fn cstr(bytes: &[u8]) -> String {
    let end = bytes.iter().position(|&b| b == 0).unwrap_or(bytes.len());
    String::from_utf8_lossy(&bytes[..end]).into_owned()
}
