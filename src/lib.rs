//! motatool — build, verify, inspect, and serve MeshCore `.mota` firmware-update containers.
//!
//! The `.mota` on-wire format, merkle tree, EndF trailer, and hash truncation are kept **byte-identical**
//! to the MeshCore firmware (see `format`, `merkle`, `endf`, `crypto`); the byte layout is pinned by tests
//! and cross-checked against real containers. Everything else is idiomatic Rust over well-known crates.

pub mod bootloader;
pub mod build;
pub mod crypto;
pub mod encode;
pub mod endf;
pub mod format;
pub mod input;
pub mod merkle;
pub mod serve;
pub mod targets;
pub mod verify;

pub use bootloader::{
    bootloader_version_str, build_bootloader, validate_bootloader_image_for_profile,
    validate_bootloader_inventory, BootloaderBoard, BootloaderBuildOpts, BootloaderCompatibility,
    BootloaderUpdateManifest, BOOTLOADER_BOARDS,
};
pub use build::{build, BuildOpts, Built};
pub use encode::PatchType;
pub use format::{Codec, FwIdent, Manifest};
pub use verify::verify;
