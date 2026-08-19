//! The `EndF` firmware-identity trailer and version/target helpers.
//!
//! A firmware image self-describes via a fixed 56-byte trailer the build appends: `EndF ‖ body_len(4) ‖
//! body_hash8(8) ‖ fw_version(4) ‖ target_id(4) ‖ hw_id(32)`. `build` reads identity from here (overridable
//! by flags) so a `.mota` inherits the firmware's own target/version/hardware without a filename convention.

use crate::crypto::mh;
use crate::format::*;
use anyhow::{bail, Result};

/// True if `image` already ends with a valid EndF trailer (magic + correct body length + body hash).
pub fn has_endf(image: &[u8]) -> bool {
    if image.len() < ENDF_LEN {
        return false;
    }
    let (body, t) = image.split_at(image.len() - ENDF_LEN);
    t[..4] == ENDF_MAGIC && rd_u32(t, 4) as usize == body.len() && mh::<8>(body) == arr::<8>(t, 8)
}

/// Read the firmware identity from an image's EndF trailer (all-zero/empty if there is none).
pub fn parse_ident(image: &[u8]) -> FwIdent {
    if !has_endf(image) {
        return FwIdent::default();
    }
    let t = &image[image.len() - ENDF_LEN..];
    FwIdent {
        fw_version: rd_u32(t, ENDF_OFF_FWVER),
        target_id: rd_u32(t, ENDF_OFF_TARGET),
        hw_id: cstr(&t[ENDF_OFF_HWID..ENDF_OFF_HWID + HW_ID_LEN]),
    }
}

/// Resolved nRF52 flash geometry appended by MeshCore immediately before EndF.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Nrf52Layout {
    pub app_base: u32,
    pub linked_app_end: u32,
    pub stage_ceiling: u32,
    pub flags: u8,
}

impl Nrf52Layout {
    pub fn sd_backed(self) -> bool {
        self.flags & NRF52_LAYOUT_FLAG_SD != 0
    }
}

/// Read a validated layout record. Firmware predating the record returns `None` and keeps the legacy
/// 0x98000 packaging default; no target-name or board-name guessing is used.
pub fn parse_nrf52_layout(image: &[u8]) -> Option<Nrf52Layout> {
    if !has_endf(image) || image.len() < ENDF_LEN + NRF52_LAYOUT_LEN {
        return None;
    }
    let r = &image[image.len() - ENDF_LEN - NRF52_LAYOUT_LEN..image.len() - ENDF_LEN];
    if r[..8] != NRF52_LAYOUT_MAGIC
        || r[8] != NRF52_LAYOUT_VERSION
        || u16::from_le_bytes([r[10], r[11]]) as usize != NRF52_LAYOUT_LEN
    {
        return None;
    }
    let layout = Nrf52Layout {
        flags: r[9],
        app_base: rd_u32(r, 12),
        linked_app_end: rd_u32(r, 16),
        stage_ceiling: rd_u32(r, 20),
    };
    let known_flags = NRF52_LAYOUT_FLAG_SD | NRF52_LAYOUT_FLAG_INTERNAL_EXTRAFS;
    if layout.flags & !known_flags != 0
        || !matches!(
            layout.app_base,
            NRF52_APP_BASE_S140_V6 | NRF52_APP_BASE_S140_V7
        )
        || !matches!(layout.linked_app_end, NRF52_EXTRAFS_START | NRF52_APP_END)
        || !matches!(layout.stage_ceiling, NRF52_EXTRAFS_START | NRF52_APP_END)
        || layout.app_base >= layout.linked_app_end
        || layout.linked_app_end > NRF52_APP_END
    {
        return None;
    }
    let expected_ceiling = if layout.sd_backed() {
        NRF52_APP_END
    } else if layout.flags & NRF52_LAYOUT_FLAG_INTERNAL_EXTRAFS != 0 {
        NRF52_EXTRAFS_START
    } else {
        NRF52_APP_END
    };
    if layout.stage_ceiling != expected_ceiling {
        return None;
    }
    Some(layout)
}

/// Append a 56-byte EndF trailer carrying `ident` if `image` has none (idempotent — a trailed image is
/// returned unchanged). Returns the image and its 8-byte body hash.
pub fn ensure_endf(image: &[u8], ident: &FwIdent) -> (Vec<u8>, [u8; 8]) {
    if has_endf(image) {
        let t = &image[image.len() - ENDF_LEN..];
        return (image.to_vec(), arr::<8>(t, 8));
    }
    let body_hash = mh::<8>(image);
    let hw = ident.hw_id.as_bytes();
    let mut out = Vec::with_capacity(image.len() + ENDF_LEN);
    out.extend_from_slice(image);
    out.extend_from_slice(&ENDF_MAGIC);
    out.extend_from_slice(&(image.len() as u32).to_le_bytes());
    out.extend_from_slice(&body_hash);
    out.extend_from_slice(&ident.fw_version.to_le_bytes());
    out.extend_from_slice(&ident.target_id.to_le_bytes());
    let mut hw_field = [0u8; HW_ID_LEN];
    let n = hw.len().min(HW_ID_LEN);
    hw_field[..n].copy_from_slice(&hw[..n]);
    out.extend_from_slice(&hw_field);
    (out, body_hash)
}

/// `target_id = sha2-256:4(env_name)` read as a little-endian u32.
pub fn target_id_for_env(env: &str) -> u32 {
    rd_u32(&mh::<4>(env.as_bytes()), 0)
}

/// Pack `"a.b.c[.d]"` into a u32 (each dotted part clamped to a byte: `a<<24 | b<<16 | c<<8 | d`).
pub fn pack_version(s: &str) -> Result<u32> {
    let mut parts = [0u32; 4];
    let mut n = 0;
    for tok in s.split('.').take(4) {
        if tok.is_empty() || !tok.bytes().all(|b| b.is_ascii_digit()) {
            bail!("bad version: {s:?}");
        }
        parts[n] = tok
            .parse()
            .map_err(|_| anyhow::anyhow!("version component too large: {s:?}"))?;
        n += 1;
    }
    if n == 0 {
        bail!("bad version: {s:?}");
    }
    Ok(((parts[0] & 0xFF) << 24)
        | ((parts[1] & 0xFF) << 16)
        | ((parts[2] & 0xFF) << 8)
        | (parts[3] & 0xFF))
}

/// Render the packed version as `"major.minor.patch"` (the prerelease byte is not shown).
pub fn version_str(v: u32) -> String {
    format!(
        "{}.{}.{}",
        (v >> 24) & 0xFF,
        (v >> 16) & 0xFF,
        (v >> 8) & 0xFF
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn version_roundtrip() {
        assert_eq!(pack_version("1.17.0").unwrap(), 0x0111_0000);
        assert_eq!(version_str(0x0111_0000), "1.17.0");
        assert!(pack_version("1..2").is_err());
        assert!(pack_version("").is_err());
        assert!(pack_version("1.2.x").is_err());
    }

    #[test]
    fn ensure_endf_is_idempotent() {
        let img = vec![0xABu8; 200];
        let id = FwIdent {
            fw_version: 0x0111_0000,
            target_id: 0x04D4_13FD,
            hw_id: "RAK4631".into(),
        };
        let (trailed, h1) = ensure_endf(&img, &id);
        assert!(has_endf(&trailed));
        let (again, h2) = ensure_endf(&trailed, &id);
        assert_eq!(trailed, again); // no double trailer
        assert_eq!(h1, h2);
        let back = parse_ident(&trailed);
        assert_eq!(back.target_id, id.target_id);
        assert_eq!(back.hw_id, "RAK4631");
    }

    #[test]
    fn parses_embedded_nrf52_layout_and_old_firmware_falls_back() {
        let mut body = vec![0xA5u8; 200];
        body.extend_from_slice(&NRF52_LAYOUT_MAGIC);
        body.push(NRF52_LAYOUT_VERSION);
        body.push(0);
        body.extend_from_slice(&(NRF52_LAYOUT_LEN as u16).to_le_bytes());
        body.extend_from_slice(&NRF52_APP_BASE_S140_V7.to_le_bytes());
        body.extend_from_slice(&NRF52_EXTRAFS_START.to_le_bytes());
        body.extend_from_slice(&NRF52_APP_END.to_le_bytes());
        let image = ensure_endf(&body, &FwIdent::default()).0;
        assert_eq!(
            parse_nrf52_layout(&image),
            Some(Nrf52Layout {
                app_base: NRF52_APP_BASE_S140_V7,
                linked_app_end: NRF52_EXTRAFS_START,
                stage_ceiling: NRF52_APP_END,
                flags: 0,
            })
        );

        let mut inconsistent = body.clone();
        let ceiling = inconsistent.len() - 4;
        inconsistent[ceiling..].copy_from_slice(&NRF52_EXTRAFS_START.to_le_bytes());
        assert_eq!(
            parse_nrf52_layout(&ensure_endf(&inconsistent, &FwIdent::default()).0),
            None
        );

        let mut internal = body.clone();
        let record = internal.len() - NRF52_LAYOUT_LEN;
        internal[record + 9] = NRF52_LAYOUT_FLAG_INTERNAL_EXTRAFS;
        internal[ceiling..].copy_from_slice(&NRF52_EXTRAFS_START.to_le_bytes());
        assert_eq!(
            parse_nrf52_layout(&ensure_endf(&internal, &FwIdent::default()).0),
            Some(Nrf52Layout {
                app_base: NRF52_APP_BASE_S140_V7,
                linked_app_end: NRF52_EXTRAFS_START,
                stage_ceiling: NRF52_EXTRAFS_START,
                flags: NRF52_LAYOUT_FLAG_INTERNAL_EXTRAFS,
            })
        );
        assert_eq!(
            parse_nrf52_layout(&ensure_endf(b"old", &FwIdent::default()).0),
            None
        );
    }
}
