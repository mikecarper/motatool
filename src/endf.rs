//! The `EndF` firmware-identity trailer and version/target helpers.
//!
//! A firmware image self-describes via a fixed 56-byte trailer the build appends: `EndF ‖ body_len(4) ‖
//! body_hash8(8) ‖ fw_version(4) ‖ target_id(4) ‖ hw_id(32)`. `build` reads identity from here (overridable
//! by flags) so a `.mota` inherits the firmware's own target/version/hardware without a filename convention.

use crate::crypto::mh;
use crate::format::*;
use anyhow::{bail, ensure, Result};

/// Authenticated nRF52840 flash geometry embedded immediately before an image's EndF trailer.
///
/// This is a layout ABI, not a target lookup: PlatformIO resolves it from the actual linker region and
/// storage configuration for each build.  Because the record is part of the EndF-hashed body, a valid
/// record cannot be changed without invalidating the firmware identity trailer.
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

    pub fn qspi_backed(self) -> bool {
        self.flags & NRF52_LAYOUT_FLAG_QSPI != 0
    }

    pub fn external_backed(self) -> bool {
        self.sd_backed() || self.qspi_backed()
    }

    pub fn uses_internal_extrafs(self) -> bool {
        self.flags & NRF52_LAYOUT_FLAG_INTERNAL_EXTRAFS != 0
    }

    pub fn bootloader_scratch(self) -> bool {
        self.flags & NRF52_LAYOUT_FLAG_BOOTLOADER_SCRATCH != 0
    }

    /// Internal application workspace available to the currently running image.  QSPI bootloader-update
    /// builds reserve the final 0xA000 below APP_END as scratch; all other supported layouts may apply an
    /// application through APP_END (internal staging is bounded separately by `stage_ceiling`).
    pub fn application_ceiling(self) -> u32 {
        if self.bootloader_scratch() {
            self.linked_app_end
        } else {
            NRF52_APP_END
        }
    }

    pub fn validate(self) -> Result<()> {
        ensure!(
            matches!(
                self.app_base,
                NRF52_APP_BASE_S140_V6 | NRF52_APP_BASE_S140_V7
            ),
            "unsupported nRF52 app base 0x{:X}",
            self.app_base
        );
        ensure!(
            matches!(
                self.linked_app_end,
                NRF52_EXTRAFS_START | NRF52_BOOT_SCRATCH_START | NRF52_APP_END
            ),
            "unsupported nRF52 linked app end 0x{:X}",
            self.linked_app_end
        );
        ensure!(
            matches!(self.stage_ceiling, NRF52_EXTRAFS_START | NRF52_APP_END),
            "unsupported nRF52 staging ceiling 0x{:X}",
            self.stage_ceiling
        );
        ensure!(
            self.app_base < self.linked_app_end && self.linked_app_end <= NRF52_APP_END,
            "invalid nRF52 app region 0x{:X}..0x{:X}",
            self.app_base,
            self.linked_app_end
        );
        ensure!(
            self.flags & !NRF52_LAYOUT_FLAGS_KNOWN == 0,
            "unsupported nRF52 layout flags 0x{:X}",
            self.flags
        );
        ensure!(
            !(self.sd_backed() && self.qspi_backed()),
            "nRF52 layout cannot use both SD and QSPI staging"
        );
        ensure!(
            !(self.external_backed() && self.uses_internal_extrafs()),
            "nRF52 external staging cannot also reserve internal ExtraFS"
        );
        if self.bootloader_scratch() {
            ensure!(
                self.qspi_backed()
                    && !self.sd_backed()
                    && self.linked_app_end == NRF52_BOOT_SCRATCH_START,
                "nRF52 bootloader scratch requires the QSPI scratch layout"
            );
        } else {
            ensure!(
                self.linked_app_end != NRF52_BOOT_SCRATCH_START,
                "reserved bootloader geometry requires the bootloader-scratch flag"
            );
        }

        let expected_ceiling = if self.external_backed() {
            NRF52_APP_END
        } else if self.uses_internal_extrafs() {
            NRF52_EXTRAFS_START
        } else {
            // Every version-1 linked region is a known supported layout and may reclaim the unused
            // InternalFS range.  Unknown future geometry is rejected above rather than guessed here.
            NRF52_APP_END
        };
        ensure!(
            self.stage_ceiling == expected_ceiling,
            "nRF52 staging ceiling 0x{:X} is inconsistent with layout flags",
            self.stage_ceiling
        );
        Ok(())
    }
}

/// Serialize one validated version-1 nRF52 layout record.
pub fn build_nrf52_layout(layout: Nrf52Layout) -> Result<[u8; NRF52_LAYOUT_LEN]> {
    layout.validate()?;
    let mut out = [0u8; NRF52_LAYOUT_LEN];
    out[..8].copy_from_slice(&NRF52_LAYOUT_MAGIC);
    out[8] = NRF52_LAYOUT_VERSION;
    out[9] = layout.flags;
    out[10..12].copy_from_slice(&(NRF52_LAYOUT_LEN as u16).to_le_bytes());
    out[12..16].copy_from_slice(&layout.app_base.to_le_bytes());
    out[16..20].copy_from_slice(&layout.linked_app_end.to_le_bytes());
    out[20..24].copy_from_slice(&layout.stage_ceiling.to_le_bytes());
    Ok(out)
}

/// Parse the authenticated layout record immediately before EndF.
///
/// `Ok(None)` means an older image with no record.  If the marker is present but its version, length, or
/// geometry is invalid, this fails closed instead of silently treating corrupted layout metadata as legacy.
pub fn parse_nrf52_layout(image: &[u8]) -> Result<Option<Nrf52Layout>> {
    if !has_endf(image) || image.len() < ENDF_LEN + NRF52_LAYOUT_LEN {
        return Ok(None);
    }
    let start = image.len() - ENDF_LEN - NRF52_LAYOUT_LEN;
    let record = &image[start..start + NRF52_LAYOUT_LEN];
    if record[..8] != NRF52_LAYOUT_MAGIC {
        return Ok(None);
    }
    ensure!(
        record[8] == NRF52_LAYOUT_VERSION,
        "unsupported nRF52 layout version {}",
        record[8]
    );
    ensure!(
        u16::from_le_bytes([record[10], record[11]]) as usize == NRF52_LAYOUT_LEN,
        "invalid nRF52 layout record length {}",
        u16::from_le_bytes([record[10], record[11]])
    );
    let layout = Nrf52Layout {
        flags: record[9],
        app_base: rd_u32(record, 12),
        linked_app_end: rd_u32(record, 16),
        stage_ceiling: rd_u32(record, 20),
    };
    layout.validate()?;
    Ok(Some(layout))
}

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
    fn nrf52_layout_roundtrips_inside_endf_body() {
        let layout = Nrf52Layout {
            app_base: NRF52_APP_BASE_S140_V6,
            linked_app_end: NRF52_APP_END,
            stage_ceiling: NRF52_APP_END,
            flags: 0,
        };
        let mut body = vec![0xA5; 1234];
        body.extend_from_slice(&build_nrf52_layout(layout).unwrap());
        let (image, _) = ensure_endf(&body, &FwIdent::default());
        assert_eq!(parse_nrf52_layout(&image).unwrap(), Some(layout));

        let (legacy, _) = ensure_endf(&body[..1234], &FwIdent::default());
        assert_eq!(parse_nrf52_layout(&legacy).unwrap(), None);
    }

    #[test]
    fn nrf52_layout_marker_fails_closed_when_invalid() {
        let layout = Nrf52Layout {
            app_base: NRF52_APP_BASE_S140_V7,
            linked_app_end: NRF52_APP_END,
            stage_ceiling: NRF52_APP_END,
            flags: NRF52_LAYOUT_FLAG_QSPI,
        };
        let mut record = build_nrf52_layout(layout).unwrap();
        record[8] = NRF52_LAYOUT_VERSION + 1;
        let (image, _) = ensure_endf(&record, &FwIdent::default());
        let err = parse_nrf52_layout(&image).unwrap_err().to_string();
        assert!(err.contains("version"), "unexpected error: {err}");
    }

    #[test]
    fn nrf52_layout_rejects_conflicting_storage_geometry() {
        for layout in [
            Nrf52Layout {
                app_base: NRF52_APP_BASE_S140_V7,
                linked_app_end: NRF52_APP_END,
                stage_ceiling: NRF52_APP_END,
                flags: NRF52_LAYOUT_FLAG_SD | NRF52_LAYOUT_FLAG_QSPI,
            },
            Nrf52Layout {
                app_base: NRF52_APP_BASE_S140_V7,
                linked_app_end: NRF52_EXTRAFS_START,
                stage_ceiling: NRF52_EXTRAFS_START,
                flags: 0,
            },
        ] {
            assert!(build_nrf52_layout(layout).is_err());
        }
    }
}
