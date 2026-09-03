//! motatool CLI.

use anyhow::{bail, Context, Result};
use clap::{Args, Parser, Subcommand, ValueEnum};
use motatool::bootloader::{
    bootloader_version_str, validate_bootloader_image, BootloaderBoard, BootloaderBuildOpts,
    STORAGE_SD_UPDATE,
};
use motatool::crypto::{ed25519_keygen, load_key32};
use motatool::endf::{pack_version, target_id_for_env, version_str};
use motatool::format::DEFAULT_BLOCK_SIZE;
use motatool::input::{read_bootloader_hex, read_input};
use motatool::serve::{
    attach_serial_folder, detach_serial_folder, open_serial, open_tcp, serve_loop, Folder,
    SeederCore,
};
use motatool::transport::deflate_transport_size;
use motatool::{build, build_bootloader, targets, verify, BuildOpts, Codec, Manifest, PatchType};

#[derive(Clone, Copy, ValueEnum)]
enum CliPatchType {
    Sequential,
    #[value(name = "in-place")]
    InPlace,
}

impl From<CliPatchType> for PatchType {
    fn from(c: CliPatchType) -> Self {
        match c {
            CliPatchType::Sequential => PatchType::Sequential,
            CliPatchType::InPlace => PatchType::InPlace,
        }
    }
}

#[derive(Clone, Copy, ValueEnum)]
enum CliBootloaderBoard {
    #[value(name = "xiao_nrf52840_ble", alias = "xiao-nrf52840-ble")]
    XiaoNrf52840Ble,
    #[value(name = "xiao_nrf52840_ble_sense", alias = "xiao-nrf52840-ble-sense")]
    XiaoNrf52840BleSense,
    #[value(name = "heltec_mesh_tower_v2")]
    HeltecMeshTowerV2,
    #[value(name = "heltec_mesh_tower_v2_sdcard")]
    HeltecMeshTowerV2Sdcard,
    #[value(name = "heltec_mesh_pocket")]
    HeltecMeshPocket,
    #[value(name = "heltec_t096")]
    HeltecT096,
    #[value(name = "heltec_t1")]
    HeltecT1,
    #[value(name = "heltec_t114")]
    HeltecT114,
    #[value(name = "keepteen_lt1")]
    KeepteenLt1,
    #[value(name = "minewsemi_mx25le01")]
    MinewsemiMx25le01,
    #[value(name = "promicro_nrf52840")]
    PromicroNrf52840,
    #[value(name = "t1000_e")]
    T1000E,
    #[value(name = "thinknode_m3")]
    ThinknodeM3,
    #[value(name = "wiscore_rak3401")]
    WiscoreRak3401,
    #[value(name = "wiscore_rak4631_board")]
    WiscoreRak4631Board,
    #[value(name = "wismesh_tag")]
    WismeshTag,
}

impl CliBootloaderBoard {
    fn profile(self) -> (BootloaderBoard, u8) {
        let board = match self {
            Self::XiaoNrf52840Ble => BootloaderBoard::XiaoNrf52840Ble,
            Self::XiaoNrf52840BleSense => BootloaderBoard::XiaoNrf52840BleSense,
            Self::HeltecMeshTowerV2 | Self::HeltecMeshTowerV2Sdcard => {
                BootloaderBoard::HeltecMeshTowerV2
            }
            Self::HeltecMeshPocket => BootloaderBoard::HeltecMeshPocket,
            Self::HeltecT096 => BootloaderBoard::HeltecT096,
            Self::HeltecT1 => BootloaderBoard::HeltecT1,
            Self::HeltecT114 => BootloaderBoard::HeltecT114,
            Self::KeepteenLt1 => BootloaderBoard::KeepteenLt1,
            Self::MinewsemiMx25le01 => BootloaderBoard::MinewsemiMx25le01,
            Self::PromicroNrf52840 => BootloaderBoard::PromicroNrf52840,
            Self::T1000E => BootloaderBoard::T1000E,
            Self::ThinknodeM3 => BootloaderBoard::ThinknodeM3,
            Self::WiscoreRak3401 => BootloaderBoard::WiscoreRak3401,
            Self::WiscoreRak4631Board => BootloaderBoard::WiscoreRak4631Board,
            Self::WismeshTag => BootloaderBoard::WismeshTag,
        };
        let storage = match self {
            Self::HeltecMeshTowerV2Sdcard => STORAGE_SD_UPDATE,
            _ => board.storage_profile(),
        };
        (board, storage)
    }
}
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::sync::atomic::AtomicBool;
use std::sync::Arc;

#[derive(Parser)]
#[command(
    name = "motatool",
    version,
    about = "Build, verify, inspect, and serve MeshCore .mota firmware-update containers.",
    long_about = "A .mota is a self-verifying firmware-update package that MeshCore nodes fetch over \
                  LoRa, block by block. This tool builds full and delta application packages plus signed \
                  OTAFIX bootloader packages, verifies and inspects them, and serves a folder to a node."
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Package firmware as a full or delta application .mota.
    Build(BuildArgs),
    /// Package an exact-board OTAFIX nRF52840 bootloader as a signed v3 .mota.
    BuildBootloader(BuildBootloaderArgs),
    /// Validate .mota files (block hashes, merkle root, image hash, signature).
    Verify(VerifyArgs),
    /// Print every field of a .mota's manifest.
    Inspect(InspectArgs),
    /// Generate an Ed25519 signing keypair.
    Keygen(KeygenArgs),
    /// Serve a folder of .mota to a node over USB serial or WiFi, and capture pull-to-folder downloads.
    Serve(ServeArgs),
    /// Measure exact per-block transport-DEFLATE sizes for a raw mOTA payload.
    TransportSize(TransportSizeArgs),
}

#[derive(Args)]
struct BuildBootloaderArgs {
    /// OTAFIX Intel HEX input. Only the 0xF4000..0xFE000 bootloader region is used.
    #[arg(long)]
    fw: String,
    /// Exact OTAFIX board and storage profile.
    #[arg(long, value_enum)]
    board: CliBootloaderBoard,
    /// Ed25519 private signing key. Bootloader packages cannot be unsigned.
    #[arg(long)]
    sign: String,
    /// Optional four-byte version assertion. The embedded BLM2 version remains authoritative.
    #[arg(long = "fw-version")]
    fw_version: Option<String>,
    /// Output directory used when --out is omitted.
    #[arg(long = "out-dir", default_value = ".")]
    out_dir: String,
    /// Exact output path.
    #[arg(long)]
    out: Option<String>,
}

#[derive(Args)]
struct BuildArgs {
    /// NEW firmware: a file path or an http(s):// URL. A .hex is parsed to its flat image.
    #[arg(long)]
    fw: String,
    /// Previous firmware to diff against → a delta patch (omit for a full image). Must be a real image
    /// with its EndF trailer — the device applies the delta to exactly this running image.
    #[arg(long)]
    base: Option<String>,
    /// Delta patch layout (with --base): `sequential` (ESP32 A/B) or `in-place` (nRF52 single-slot).
    #[arg(long = "patch-type", default_value = "sequential")]
    patch_type: CliPatchType,
    /// Override the in-place apply window. By default it is derived from authenticated nRF52 layout
    /// records; old images without those records use the conservative 0x98000 legacy window.
    #[arg(long = "inplace-memory")]
    inplace_memory: Option<String>,
    /// In-place segment size in bytes (default one nRF52 flash page).
    #[arg(long = "segment-size", default_value_t = 4096)]
    segment_size: u32,
    /// PlatformIO env name, hashed into the target id (overrides the firmware's EndF).
    #[arg(long = "target-env", conflicts_with = "target_id")]
    target_env: Option<String>,
    /// Raw target id, e.g. 0x04D413FD (overrides the EndF).
    #[arg(long = "target-id")]
    target_id: Option<String>,
    /// Firmware version, e.g. 1.17.0 (overrides the EndF).
    #[arg(long = "fw-version")]
    fw_version: Option<String>,
    /// Hardware tag, e.g. RAK4631 or Heltec_v3 (overrides the EndF).
    #[arg(long = "hw-id")]
    hw_id: Option<String>,
    /// Ed25519 private key (hex or raw 32 bytes, from `keygen`) to sign the container.
    #[arg(long)]
    sign: Option<String>,
    /// Application payload/Merkle block size (default 2048; legacy 1024 remains supported).
    #[arg(long = "block-size", default_value_t = DEFAULT_BLOCK_SIZE)]
    block_size: u32,
    /// Build the delta even across differing hardware identity (delta only).
    #[arg(long)]
    force: bool,
    /// Output directory; the file is auto-named. Default: current directory.
    #[arg(long = "out-dir", default_value = ".")]
    out_dir: String,
    /// Exact output path (overrides --out-dir and the auto-name).
    #[arg(long)]
    out: Option<String>,
}

#[derive(Args)]
struct VerifyArgs {
    /// .mota files to check.
    #[arg(required = true)]
    files: Vec<String>,
    /// Require the container to be signed by THIS public key (hex or raw 32 bytes).
    #[arg(long = "pub")]
    pub_key: Option<String>,
}

#[derive(Args)]
struct InspectArgs {
    /// The .mota file to dump.
    file: String,
}

#[derive(Args)]
struct KeygenArgs {
    /// Write the private key to <file> and the public key to <file>.pub (hex).
    #[arg(long)]
    out: Option<String>,
}

#[derive(Args)]
struct ServeArgs {
    /// Folder of .mota to serve (also the capture destination for pull-to-folder).
    #[arg(long)]
    dir: String,
    /// The node's USB serial port (e.g. /dev/ttyUSB0).
    #[arg(long, required_unless_present = "tcp", conflicts_with = "tcp")]
    serial: Option<String>,
    /// The node's WiFi seeder address host[:port] (default port 5001).
    #[arg(long)]
    tcp: Option<String>,
    /// Serial speed (--serial only).
    #[arg(long, default_value_t = 115200)]
    baud: u32,
    /// Serve only the top folder; don't descend into sub-folders.
    #[arg(long = "no-recursive")]
    no_recursive: bool,
    /// (serial only) don't auto-send `ota folder on`/`off` on the node's console.
    #[arg(long = "no-enable")]
    no_enable: bool,
    /// Deprecated compatibility no-op; terminal entry is now automatic.
    #[arg(long = "companion-terminal", requires = "serial")]
    _companion_terminal: bool,
    /// Warm-start: stage this similar build's payload into each captured .part (for `ota pull … validate`).
    #[arg(long)]
    seed: Option<String>,
    /// Log each request the node makes.
    #[arg(short, long)]
    verbose: bool,
}

#[derive(Args)]
struct TransportSizeArgs {
    /// Raw mOTA payload (for a delta, the generated patch bytes).
    #[arg(long)]
    payload: PathBuf,
    /// Logical payload block size; MeshCore application radio OTA supports at most 2048.
    #[arg(long = "block-size", default_value_t = DEFAULT_BLOCK_SIZE as usize)]
    block_size: usize,
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    let result = match cli.command {
        Command::Build(a) => cmd_build(a),
        Command::BuildBootloader(a) => cmd_build_bootloader(a),
        Command::Verify(a) => return cmd_verify(a),
        Command::Inspect(a) => cmd_inspect(a),
        Command::Keygen(a) => cmd_keygen(a),
        Command::Serve(a) => cmd_serve(a),
        Command::TransportSize(a) => cmd_transport_size(a),
    };
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("error: {e:#}");
            ExitCode::FAILURE
        }
    }
}

fn cmd_transport_size(a: TransportSizeArgs) -> Result<()> {
    let payload = std::fs::read(&a.payload)
        .with_context(|| format!("cannot read payload: {}", a.payload.display()))?;
    if payload.is_empty() {
        bail!("payload is empty: {}", a.payload.display());
    }
    let size = deflate_transport_size(&payload, a.block_size).map_err(anyhow::Error::msg)?;
    println!(
        "{{\"schema\":1,\"payload_bytes\":{},\"block_size\":{},\"block_count\":{},\"wire_bytes\":{},\"deflate_bytes\":{},\"deflate_blocks\":{},\"data_packets\":{}}}",
        size.payload_bytes,
        size.block_size,
        size.block_count,
        size.wire_bytes,
        size.deflate_bytes,
        size.deflate_blocks,
        size.data_packets,
    );
    Ok(())
}

fn parse_u32_auto(s: &str) -> Result<u32> {
    let s = s.trim();
    let v = if let Some(hex) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
        u32::from_str_radix(hex, 16)
    } else {
        s.parse()
    };
    v.with_context(|| format!("not a valid number: {s:?}"))
}

fn cmd_build(a: BuildArgs) -> Result<()> {
    let fw = read_input(&a.fw)?;
    let base = a.base.as_deref().map(read_input).transpose()?;

    let target_id = match (&a.target_id, &a.target_env) {
        (Some(id), _) => Some(parse_u32_auto(id).context("--target-id")?),
        (None, Some(env)) => Some(target_id_for_env(env)),
        (None, None) => None,
    };
    let fw_version = a.fw_version.as_deref().map(pack_version).transpose()?;
    let sign_seed = a.sign.as_deref().map(load_key32).transpose()?;

    let built = build(&BuildOpts {
        fw,
        base,
        patch_type: a.patch_type.into(),
        inplace_memory: a
            .inplace_memory
            .as_deref()
            .map(parse_u32_auto)
            .transpose()
            .context("--inplace-memory")?,
        segment_size: a.segment_size,
        target_id,
        fw_version,
        hw_id: a.hw_id,
        sign_seed,
        block_size: a.block_size,
        force: a.force,
    })?;

    // sanity: our own output must verify.
    let problems = verify(&built.bytes);
    if !problems.is_empty() {
        bail!(
            "internal error: built .mota fails verification: {}",
            problems.join("; ")
        );
    }

    let out_path = match &a.out {
        Some(p) => {
            if let Some(parent) = Path::new(p).parent() {
                if !parent.as_os_str().is_empty() {
                    std::fs::create_dir_all(parent).ok();
                }
            }
            p.clone()
        }
        None => {
            std::fs::create_dir_all(&a.out_dir).ok();
            Path::new(&a.out_dir)
                .join(&built.suggested_name)
                .to_string_lossy()
                .into_owned()
        }
    };
    std::fs::write(&out_path, &built.bytes).with_context(|| format!("cannot write {out_path}"))?;

    let m = &built.manifest;
    let kind = kind_label(m);
    let hw = if m.hw_id_str().is_empty() {
        "?".to_string()
    } else {
        m.hw_id_str()
    };
    println!("wrote {out_path}");
    println!(
        "  {kind}  target={:08X}  v{}  hw={hw}  {}",
        m.target_id,
        version_str(m.fw_version),
        if m.is_signed() { "signed" } else { "unsigned" }
    );
    println!(
        "  image={}B  payload={}B  blocks={}  total={}B",
        m.image_size,
        m.payload_size,
        m.block_count,
        built.bytes.len()
    );
    if let Some(memory) = built.inplace_memory {
        println!(
            "  in-place memory=0x{memory:X}  segment={}B",
            a.segment_size
        );
    }
    Ok(())
}

fn cmd_build_bootloader(a: BuildBootloaderArgs) -> Result<()> {
    let (board, storage_profile) = a.board.profile();
    let image = read_bootloader_hex(&a.fw)?;
    let sign_seed = load_key32(&a.sign).context("--sign")?;
    let built = build_bootloader(&BootloaderBuildOpts {
        image,
        board,
        storage_profile,
        sign_seed,
    })?;

    if let Some(asserted) = &a.fw_version {
        let asserted = pack_version(asserted).context("--fw-version")?;
        if asserted != built.manifest.fw_version {
            bail!(
                "--fw-version {} does not match embedded bootloader version {}",
                bootloader_version_str(asserted),
                bootloader_version_str(built.manifest.fw_version)
            );
        }
    }
    let problems = verify(&built.bytes);
    if !problems.is_empty() {
        bail!(
            "internal error: built bootloader .mota fails verification: {}",
            problems.join("; ")
        );
    }

    let out_path = match &a.out {
        Some(path) => {
            if let Some(parent) = Path::new(path).parent() {
                if !parent.as_os_str().is_empty() {
                    std::fs::create_dir_all(parent).ok();
                }
            }
            path.clone()
        }
        None => {
            std::fs::create_dir_all(&a.out_dir).ok();
            Path::new(&a.out_dir)
                .join(&built.suggested_name)
                .to_string_lossy()
                .into_owned()
        }
    };
    std::fs::write(&out_path, &built.bytes).with_context(|| format!("cannot write {out_path}"))?;

    let manifest = &built.manifest;
    let payload = &built.bytes
        [manifest.payload_off()..manifest.payload_off() + manifest.payload_size as usize];
    let identity = validate_bootloader_image(
        payload,
        manifest.target_id,
        &manifest.hw_id,
        manifest.fw_version,
    )?;
    println!("wrote {out_path}");
    println!(
        "  bootloader  board={}  target={:08X}  v{}  signed",
        board.profile_name(storage_profile).unwrap_or(board.name()),
        manifest.target_id,
        bootloader_version_str(manifest.fw_version)
    );
    println!(
        "  region=0x{start:08X}..0x{end:08X}  image={}B  blocks={}  total={}B",
        manifest.image_size,
        manifest.block_count,
        built.bytes.len(),
        start = motatool::bootloader::IMAGE_START,
        end = motatool::bootloader::IMAGE_START + motatool::bootloader::IMAGE_SIZE as u32
    );
    println!(
        "  continuity=S{} FWID=0x{:04X} app_base=0x{:08X} layout_abi={}",
        identity.softdevice_family,
        identity.softdevice_fwid,
        identity.app_base,
        identity.layout_abi
    );
    Ok(())
}

fn cmd_verify(a: VerifyArgs) -> ExitCode {
    let expect_pub = match a.pub_key.as_deref().map(load_key32).transpose() {
        Ok(p) => p,
        Err(e) => {
            eprintln!("error: {e:#}");
            return ExitCode::FAILURE;
        }
    };

    let mut bad = 0u32;
    for file in &a.files {
        let blob = match std::fs::read(file) {
            Ok(b) => b,
            Err(_) => {
                println!("FAIL  {file} : cannot read");
                bad += 1;
                continue;
            }
        };
        let mut problems = verify(&blob);
        let parsed = Manifest::parse(&blob).ok();

        if let (Some(m), Some(want)) = (&parsed, &expect_pub) {
            if !m.is_signed() {
                problems.push("not signed (but --pub was given)".into());
            } else if &m.signer != want {
                problems.push("signed by a different key than --pub".into());
            }
        }

        match (&parsed, problems.is_empty()) {
            (Some(m), true) => println!(
                "OK    {file} : {} target={:08X} [{}] v{} hw={} {} blocks={} size={}",
                kind_label(m),
                m.target_id,
                package_target_label(m, &blob),
                package_version_str(m),
                if m.hw_id_str().is_empty() {
                    "?".into()
                } else {
                    m.hw_id_str()
                },
                if m.is_signed() { "signed" } else { "unsigned" },
                m.block_count,
                blob.len()
            ),
            _ => {
                bad += 1;
                let joined: String = problems.iter().map(|p| format!(" [{p}]")).collect();
                println!("FAIL  {file} :{joined}");
            }
        }
    }
    if bad == 0 {
        ExitCode::SUCCESS
    } else {
        ExitCode::FAILURE
    }
}

fn cmd_inspect(a: InspectArgs) -> Result<()> {
    let blob = std::fs::read(&a.file).with_context(|| format!("cannot read {}", a.file))?;
    let m = Manifest::parse(&blob).with_context(|| "not a valid .mota")?;

    let codec = m.codec().map(Codec::label).unwrap_or("?");
    println!("total_size     : {}", blob.len());
    println!("package_kind   : {}", kind_label(&m));
    println!("format_ver     : {}", m.format_ver);
    println!(
        "flags          : 0x{:02x}  FULL={} SIGNED={} BOOTLOADER={}",
        m.flags,
        m.is_full(),
        m.is_signed(),
        m.is_bootloader()
    );
    println!("hash_algo      : 0x{:02x} (sha2-256)", m.hash_algo);
    println!(
        "target_id      : 0x{:08x}  ({})",
        m.target_id,
        package_target_label(&m, &blob)
    );
    println!(
        "fw_version     : {}  (0x{:08x})",
        package_version_str(&m),
        m.fw_version
    );
    println!("image_size     : {}", m.image_size);
    println!("payload_size   : {}", m.payload_size);
    println!(
        "block_size     : {}  (log2={})  block_count={}",
        m.block_size(),
        m.block_size_log2,
        m.block_count
    );
    println!("codec_id       : {} ({codec})", m.codec_id);
    println!("merkle_root    : {}", hex::encode_upper(m.merkle_root));
    println!("image_hash     : {}", hex::encode_upper(m.image_hash));
    println!(
        "hw_id          : {}",
        if m.hw_id_str().is_empty() {
            "(none)".into()
        } else {
            m.hw_id_str()
        }
    );
    if !m.is_full() {
        let zero = m.base_hash.iter().all(|&b| b == 0);
        println!(
            "base_hash      : {}{}",
            hex::encode_upper(m.base_hash),
            if zero { "  (zero)" } else { "" }
        );
    }
    if m.is_signed() {
        println!("signer_pubkey  : {}", hex::encode_upper(m.signer));
        println!("signature      : {}", hex::encode_upper(m.signature));
    }
    if m.is_bootloader() {
        let payload = &blob[m.payload_off()..m.payload_off() + m.payload_size as usize];
        let identity = motatool::bootloader::validate_bootloader_image(
            payload,
            m.target_id,
            &m.hw_id,
            m.fw_version,
        )?;
        let board = BootloaderBoard::from_identity(identity.board_id, &identity.device_name);
        println!(
            "bootloader_profile: {}",
            board
                .and_then(|value| value.profile_name(identity.storage_flags))
                .unwrap_or("unsupported")
        );
        println!("bootloader_offset: 0x{:04x}", identity.manifest_offset);
        println!("bootloader_board: 0x{:08x}", identity.board_id);
        println!("bootloader_name : {}", identity.device_name);
        println!(
            "bootloader_version: {}  (0x{:08x})",
            bootloader_version_str(identity.boot_version),
            identity.boot_version
        );
        println!(
            "bootloader_cont : S{} fwid=0x{:04x} app=0x{:x} ABI{}",
            identity.softdevice_family,
            identity.softdevice_fwid,
            identity.app_base,
            identity.layout_abi
        );
        println!("bootloader_store: 0x{:02x}", identity.storage_flags);
    }
    println!(
        "approval       : {}  ({})",
        hex::encode_upper(m.approval),
        if m.is_approved() {
            "APPROVED"
        } else {
            "not approved"
        }
    );
    println!("leaves[]       : {} x 4 bytes", m.block_count);
    Ok(())
}

fn cmd_keygen(a: KeygenArgs) -> Result<()> {
    let (seed, public) = ed25519_keygen();
    let (seed_hex, pub_hex) = (hex::encode_upper(seed), hex::encode_upper(public));
    if let Some(out) = &a.out {
        std::fs::write(out, format!("{seed_hex}\n")).with_context(|| format!("writing {out}"))?;
        std::fs::write(format!("{out}.pub"), format!("{pub_hex}\n"))
            .with_context(|| format!("writing {out}.pub"))?;
        println!("private -> {out}");
        println!("public  -> {out}.pub");
    }
    println!("pubkey: {pub_hex}");
    Ok(())
}

fn cmd_serve(a: ServeArgs) -> Result<()> {
    let dir = PathBuf::from(&a.dir);
    let folder = Folder::scan(&dir, !a.no_recursive, |p, why| {
        eprintln!("  ! skip {} : {why}", p.display());
    });
    println!(
        "motatool serve: {} valid .mota in {}{}",
        folder.count(),
        a.dir,
        if a.no_recursive { "" } else { " (recursive)" }
    );
    for s in folder.all() {
        let m = &s.manifest;
        println!(
            "  - {} : mid={} target={:08X} [{}] v{} {} {} blocks={} size={}",
            s.path.file_name().unwrap_or_default().to_string_lossy(),
            hex::encode_upper(m.merkle_root),
            m.target_id,
            package_target_label(m, &s.bytes),
            package_version_str(m),
            if m.is_bootloader() {
                "bootloader"
            } else {
                m.codec().map(Codec::name_tag).unwrap_or("?")
            },
            if m.is_signed() { "signed" } else { "unsigned" },
            m.block_count,
            s.bytes.len()
        );
    }
    if folder.count() == 0 {
        eprintln!("  (nothing valid to serve)");
    }

    // The same folder doubles as the pull-to-folder capture store.
    let mut core = SeederCore::new(folder, Some(dir));
    if let Some(seed_path) = &a.seed {
        let bytes =
            std::fs::read(seed_path).with_context(|| format!("cannot read seed {seed_path}"))?;
        let m = Manifest::parse(&bytes).context("bad seed .mota")?;
        let payload = bytes[m.payload_off()..m.payload_off() + m.payload_size as usize].to_vec();
        println!(
            "seed: {} mid={} blocks={} payload={} (staged into each capture for `ota pull … validate`)",
            Path::new(seed_path).file_name().unwrap_or_default().to_string_lossy(),
            hex::encode_upper(m.merkle_root),
            m.block_count,
            m.payload_size
        );
        core.set_seed(payload, m.block_count);
    }

    // Pick the transport: WiFi seeder port (host[:port], default 5001) or a serial port.
    let use_tcp = a.tcp.is_some();
    let (mut link, target) = if let Some(hp) = &a.tcp {
        let (host, port) = match hp.rsplit_once(':') {
            Some((h, p)) => (h.to_string(), p.parse().context("bad --tcp port")?),
            None => (hp.clone(), 5001u16),
        };
        (open_tcp(&host, port)?, format!("{host}:{port}"))
    } else {
        let dev = a.serial.as_ref().expect("required_unless_present tcp");
        (open_serial(dev, a.baud)?, format!("{dev} @ {}", a.baud))
    };

    let stop = Arc::new(AtomicBool::new(false));
    ctrlc::set_handler({
        let stop = stop.clone();
        move || stop.store(true, std::sync::atomic::Ordering::Relaxed)
    })
    .context("installing Ctrl-C handler")?;

    // The serial console shares the wire, so auto-toggle `ota folder on/off`; the TCP seeder port
    // auto-enables relaying on connect, so there's nothing to send.
    let enable = !use_tcp && !a.no_enable;
    if enable {
        if let Err(err) = attach_serial_folder(
            &mut *link,
            &core,
            a.verbose,
            |l| println!("  [dev] {l}"),
            &stop,
        ) {
            // Fail closed: if the first command did reach the node, make a best-effort attempt to
            // leave its serial console out of mOTA passthrough before returning the handshake error.
            let _ = detach_serial_folder(&mut *link);
            return Err(err.context("serial folder source did not attach"));
        }
        println!("serial folder source attached");
    }
    println!("serving on {target} — Ctrl-C to stop");

    serve_loop(
        &mut *link,
        &core,
        a.verbose,
        |l| println!("  [dev] {l}"),
        &stop,
    );

    if enable {
        detach_serial_folder(&mut *link)?;
    }
    println!("\nbye");
    Ok(())
}

fn kind_label(m: &Manifest) -> &'static str {
    if m.is_bootloader() {
        return "bootloader";
    }
    match m.codec() {
        Some(Codec::Full) | None if m.is_full() => "full",
        Some(Codec::DetoolsInplace) => "in-place delta",
        _ => "sequential delta",
    }
}

fn package_version_str(m: &Manifest) -> String {
    if m.is_bootloader() {
        bootloader_version_str(m.fw_version)
    } else {
        version_str(m.fw_version)
    }
}

fn package_target_label(m: &Manifest, blob: &[u8]) -> &'static str {
    if !m.is_bootloader() {
        return targets::label(m.target_id);
    }
    let Some(payload_end) = m.payload_off().checked_add(m.payload_size as usize) else {
        return "unsupported bootloader";
    };
    let Some(payload) = blob.get(m.payload_off()..payload_end) else {
        return "unsupported bootloader";
    };
    let Ok(identity) = validate_bootloader_image(payload, m.target_id, &m.hw_id, m.fw_version)
    else {
        return "unsupported bootloader";
    };
    BootloaderBoard::from_identity(identity.board_id, &identity.device_name)
        .and_then(|board| board.profile_name(identity.storage_flags))
        .unwrap_or("unsupported bootloader")
}
