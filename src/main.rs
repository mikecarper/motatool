//! motatool CLI.

use anyhow::{bail, Context, Result};
use clap::{Args, Parser, Subcommand, ValueEnum};
use motatool::crypto::{ed25519_keygen, load_key32};
use motatool::endf::{pack_version, target_id_for_env, version_str};
use motatool::input::read_input;
use motatool::serve::{open_serial, open_tcp, serve_loop, Folder, SeederCore};
use motatool::{build, targets, verify, BuildOpts, Codec, Manifest, PatchType};

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
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::sync::atomic::AtomicBool;
use std::sync::Arc;

#[derive(Parser)]
#[command(
    name = "motatool",
    version,
    about = "Build, verify, inspect, and serve MeshCore .mota firmware-update containers.",
    long_about = "A .mota is a signed, self-verifying package of a firmware update that MeshCore nodes \
                  fetch over LoRa, block by block. This tool makes those packages, checks them, and (soon) \
                  serves a folder of them to a node."
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Package a firmware as a .mota (a full image; delta support is coming).
    Build(BuildArgs),
    /// Validate .mota files (block hashes, merkle root, image hash, signature).
    Verify(VerifyArgs),
    /// Print every field of a .mota's manifest.
    Inspect(InspectArgs),
    /// Generate an Ed25519 signing keypair.
    Keygen(KeygenArgs),
    /// Serve a folder of .mota to a node over USB serial or WiFi, and capture pull-to-folder downloads.
    Serve(ServeArgs),
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
    /// In-place apply window override. By default it is derived from the firmware's embedded nRF52
    /// layout record; older firmware without one uses the conservative 0x98000 window.
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
    /// Payload block size (default 1024).
    #[arg(long = "block-size", default_value_t = 1024)]
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
    /// Warm-start: stage this similar build's payload into each captured .part (for `ota pull … validate`).
    #[arg(long)]
    seed: Option<String>,
    /// Log each request the node makes.
    #[arg(short, long)]
    verbose: bool,
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    let result = match cli.command {
        Command::Build(a) => cmd_build(a),
        Command::Verify(a) => return cmd_verify(a),
        Command::Inspect(a) => cmd_inspect(a),
        Command::Keygen(a) => cmd_keygen(a),
        Command::Serve(a) => cmd_serve(a),
    };
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("error: {e:#}");
            ExitCode::FAILURE
        }
    }
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
                if m.is_full() { "full" } else { "delta" },
                m.target_id,
                targets::label(m.target_id),
                version_str(m.fw_version),
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
    println!("format_ver     : {}", m.format_ver);
    println!(
        "flags          : 0x{:02x}  FULL={} SIGNED={}",
        m.flags,
        m.is_full(),
        m.is_signed()
    );
    println!("hash_algo      : 0x{:02x} (sha2-256)", m.hash_algo);
    println!(
        "target_id      : 0x{:08x}  ({})",
        m.target_id,
        targets::label(m.target_id)
    );
    println!(
        "fw_version     : {}  (0x{:08x})",
        version_str(m.fw_version),
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
            targets::label(m.target_id),
            version_str(m.fw_version),
            m.codec().map(Codec::name_tag).unwrap_or("?"),
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
        let _ = link.write_all(b"ota folder on\r\n");
        println!("sent `ota folder on`");
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
        let _ = link.write_all(b"ota folder off\r\n");
    }
    println!("\nbye");
    Ok(())
}

fn kind_label(m: &Manifest) -> &'static str {
    match m.codec() {
        Some(Codec::Full) | None if m.is_full() => "full",
        Some(Codec::DetoolsInplace) => "in-place delta",
        _ => "sequential delta",
    }
}
