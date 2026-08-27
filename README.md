# motatool

Build, verify, inspect, and serve **MeshCore `.mota` firmware-update containers**.

A `.mota` is a self-verifying, optionally signed package of a firmware update that [MeshCore](https://github.com/meshcore-dev/MeshCore)
nodes fetch over LoRa, block by block. This tool makes those packages, checks them, serves a folder of them
to a node, and diffs firmware into tiny delta updates. It is a Rust rewrite of the C++ `motatool` that used
to live in the MeshCore tree, kept **byte-for-byte compatible** with the firmware's on-wire format.

## Status

| Command | State |
|---|---|
| `build` (full image) | ✅ byte-identical to the firmware's own output |
| `build-bootloader` (application-preserving nRF52840 OTAFIX) | ✅ signed, exact-manifest v3 package |
| `build --base` sequential (ESP32) | ✅ **pure Rust** delta (no runtime detools) — see [Deltas](#deltas) |
| `build --base` in-place (nRF52) | ✅ **pure Rust** delta (no runtime detools) — see [Deltas](#deltas) |
| `verify` | ✅ structure, block hashes, merkle root, full-image hash, optional Ed25519 signature |
| `inspect` | ✅ dump every manifest field |
| `keygen` | ✅ Ed25519 signing keypair |
| `serve` (USB serial + WiFi TCP) | ✅ folder relay + pull-to-folder capture + `--seed` warm-start — see [Serve](#serve) |

The full feature set of the old C++ tool, plus pure-Rust delta encoding (which the C++ tool never had).

## Build

```sh
cargo build --release      # -> target/release/motatool   (pure Rust; no Python/detools needed)
cargo test                 # unit + round-trip tests
make dev-setup             # OPTIONAL: build the detools test oracle so the delta tests run (see Deltas)
```

The shipped binary has **no Python or detools dependency** for anything — `make dev-setup` is only needed to
run the delta correctness tests, which decode our patches with the real detools decoder. Without it those
tests skip cleanly.

## Usage

```sh
# package a firmware (identity — target/version/hardware — is read from its EndF trailer)
motatool build --fw firmware.hex --out-dir ./motas
motatool build --fw firmware.bin --sign signer.key --out-dir ./motas   # signed
motatool build --fw https://example.org/RAK_4631_repeater.bin          # straight from a URL

# package an OTAFIX bootloader (the version is derived from embedded build metadata)
motatool build-bootloader --fw xiao_bootloader.hex --board xiao_nrf52840_ble \
  --sign signer.key --out-dir ./motas
motatool build-bootloader --fw rak3401_bootloader.hex --board wiscore_rak3401 \
  --sign signer.key --out-dir ./motas
motatool build-bootloader --fw tower_sd_bootloader.hex --board heltec_mesh_tower_v2_sdcard \
  --sign signer.key --out-dir ./motas

# check containers (per-file OK / FAIL; non-zero exit if any fails)
motatool verify ./motas/*.mota
motatool verify update.mota --pub signer.key.pub

# dump every manifest field
motatool inspect ./motas/RAK4631_04D413FD_v1.17.0_full_ABCD1234.mota

# make an Ed25519 signing keypair
motatool keygen --out signer.key   # writes signer.key + signer.key.pub (hex)

# serve a folder of .mota to a node (relay updates to the mesh / capture a device's firmware)
motatool serve --dir ./motas --serial /dev/ttyACM0 -v          # over USB serial
motatool serve --dir ./motas --tcp 192.168.1.50:5001 -v        # over WiFi (ESP32 companion)
```

`--fw` accepts a file path or an `http(s)://` URL; a `.hex` (nRF52/STM32 build) is parsed to its flat image
first. Firmware identity comes from the image's `EndF` trailer, overridable with `--target-env` /
`--target-id`, `--fw-version`, `--hw-id`.

## Bootloader packages

`build-bootloader` is a deliberately strict path for application-preserving OTAFIX nRF52840 updates. It
accepts an Intel HEX, extracts exactly `0xF4000..0xFE000` into a 40 KiB payload (filling HEX gaps with
erased-flash `0xFF`), and refuses to write a package unless all privileged-update gates pass:

- `--sign` and a finite, nonzero embedded bootloader version are mandatory; the package is format **v3** with flags exactly
  `FULL|SIGNED|BOOTLOADER`, `CODEC_FULL`, and exactly 40 blocks of 1024 bytes. Ordinary application
  packages remain format v2. The complete bootloader container is exactly 41,330 bytes. This makes older
  v2-only firmware reject bootloader bytes instead of treating them as an application image. The package
  version is copied from the bootloader image, never invented at packaging time. Optional `--fw-version`
  is only a four-byte dotted assertion (`2.4.1.12` for preview 12 or `2.4.1.255` for stable); a mismatch is
  rejected.
- OTAFIX release ordering is encoded as `X<<24 | Y<<16 | Z<<8 | channel`: preview N uses channel 1..254,
  while a stable X.Y.Z release uses `0xFF`, so stable sorts after every preview of the same release. Channel
  zero, an all-ones version, or a component outside one byte is invalid.
- The nRF52840 initial stack pointer must be 8-byte aligned and in RAM, and the reset vector must be a
  Thumb address inside the bootloader region. An erased image is rejected.
- The 44-byte OTAFIX `bootloader_update_manifest` v1 must be unique, declare the exact region geometry,
  match the selected board's complete `(board_id, 16-byte DEVICE_NAME field)` identity, and carry the correct
  whole-region IEEE CRC-32 (with its CRC field treated as zero during calculation). `board_id` by itself
  is deliberately insufficient because several boards share the same USB VID/UF2 PID. The deployed v1
  updater scans the complete region, so keeping this 44-byte layout unchanged lets eligible internal/QSPI
  update paths accept the canonical final-offset envelope for a one-way bootstrap. MeshTower SD does not
  use a raw-sector legacy handoff and must be provisioned locally with a BLM2/preview.13-or-newer bootloader
  before remote SD updates are enabled.
- The complete 76-byte envelope is fixed at raw-image offset `0x9FB4`, the final 76 bytes of the 40 KiB
  bootloader region. A valid envelope at any other offset is rejected. The 32-byte `BLM2`/`SOFT`
  extension must immediately follow the legacy header. It records the actual packed
  bootloader version, SoftDevice family and FWID, application base, and layout ABI. Compatibility flags and
  reserved bytes must be zero. The legacy whole-image CRC covers this extension, and the signed package
  `fw_version` must exactly equal its embedded version. That CRC also covers the CF2 configuration, so do
  not post-process a bootloader HEX/UF2 with a CF2 patcher: rebuild the exact board profile from source,
  then package the resulting immutable image.
- The image must contain exactly one structurally valid privileged `MOTABLDR` continuity marker advertising
  apply ABI 3 or newer, both full and in-place codecs (`codec_mask & 0x0005 == 0x0005`), and `BOOT_UPDATE`.
  Every aligned marker meeting those rules counts toward ambiguity even if its otherwise-known storage flags
  do not name the selected profile; malformed or unknown-bit literal-pool decoys do not. The sole marker must
  use the board's exact successor-storage profile:
  `0x0E` (stage ceiling + QSPI + boot update) for
  XIAO, `0x09` (SD + boot update) for `heltec_mesh_tower_v2_sdcard`, or `0x0A` (stage ceiling + boot update,
  with the normal internal store) for internal-only boards. `heltec_mesh_tower_v2` and
  `heltec_mesh_tower_v2_sdcard` are separate exact selections, not aliases: choosing either one rejects an
  image carrying the other profile. All other identities accept only their listed profile. This prevents
  installing an older bootloader that could not accept its own signed successor.
- The two Tower profiles intentionally retain the same physical signed `target_id` and `hw_id`. A device
  therefore rejects the wrong profile safely at install time, but an on-air catalog cannot distinguish them
  before fetching the package. Avoid publishing both profiles in the same unattended serve folder.
- The embedded compatibility tuple must match the selected board inventory. XIAO, Minewsemi MX25LE01, and
  T1000-E use S140 7.3.0 (`family=140`, `FWID=0x0123`, `app_base=0x27000`); the other listed boards use S140
  6.1.1 (`family=140`, `FWID=0x00B6`, `app_base=0x26000`). Every current profile requires layout ABI 1.
  On-device policy permits an eligible internal/QSPI legacy-v1 bootloader to bootstrap once, then requires
  every candidate's embedded version to be strictly newer than the installed extended version. MeshTower SD
  requires local BLM2 provisioning first. There is no remote rollback or compatibility-migration override.

The compatibility extension is byte-pinned relative to the start of the legacy BLMF header:

| Offset | Size | Field |
|---:|---:|---|
| 44 | 4 | little-endian magic `0x324D4C42` (`BLM2`) |
| 48 | 4 | little-endian magic `0x54464F53` (`SOFT`) |
| 52 | 2 | extension version 2 |
| 54 | 2 | extension size 32 |
| 56 | 4 | packed OTAFIX bootloader version |
| 60 | 2 | SoftDevice family |
| 62 | 2 | SoftDevice FWID |
| 64 | 4 | application base |
| 68 | 2 | layout ABI 1 |
| 70 | 2 | compatibility flags, currently zero |
| 72 | 4 | reserved, zero |

The supported routing identities are fixed and signed:

| `--board` | embedded `board_id` | package `target_id` | canonical `hw_id` / `DEVICE_NAME` |
|---|---:|---:|---|
| `xiao_nrf52840_ble` | `0x28860044` | `0x28860044` | `XIAO_BL_28860044` / `XIAO_DFU` |
| `xiao_nrf52840_ble_sense` | `0x28860045` | `0x28860045` | `XIAO_BL_28860045` / `XIAO_DFU` |
| `heltec_mesh_pocket` | `0x239A0071` | `0x059277F4` | `NRF_BL_239A0071_MESH_POCKET_OTA` / `MESH_POCKET_OTA` |
| `heltec_mesh_tower_v2` (internal profile `0x0A`) | `0x239A0071` | `0x1150F50E` | `NRF_BL_239A0071_TOWER_V2_OTA` / `TOWER_V2_OTA` |
| `heltec_mesh_tower_v2_sdcard` (SD profile `0x09`) | `0x239A0071` | `0x1150F50E` | `NRF_BL_239A0071_TOWER_V2_OTA` / `TOWER_V2_OTA` |
| `heltec_t096` | `0x239A0071` | `0x42354C85` | `NRF_BL_239A0071_T096_DFU` / `T096_DFU` |
| `heltec_t1` | `0x239A0071` | `0xFC556FFC` | `NRF_BL_239A0071_T1_DFU` / `T1_DFU` |
| `heltec_t114` | `0x239A0071` | `0x0C3F2902` | `NRF_BL_239A0071_T114_DFU` / `T114_DFU` |
| `keepteen_lt1` | `0x239A00B3` | `0xDB2E7B51` | `NRF_BL_239A00B3_KeepteenLT1_OTA` / `KeepteenLT1_OTA` |
| `minewsemi_mx25le01` | `0x239A0029` | `0x026AA982` | `NRF_BL_239A0029_MX25_DFU` / `MX25_DFU` |
| `promicro_nrf52840` | `0x239A00B3` | `0xAF79E8CC` | `NRF_BL_239A00B3_PROM_DFU` / `PROM_DFU` |
| `t1000_e` | `0x28860057` | `0xE6F5F03F` | `NRF_BL_28860057_T1KE_DFU` / `T1KE_DFU` |
| `thinknode_m3` | `0x239A00DA` | `0x0CA41DB2` | `NRF_BL_239A00DA_TNM3_DFU` / `TNM3_DFU` |
| `wiscore_rak3401` | `0x239A0029` | `0x23818A80` | `NRF_BL_239A0029_3401_DFU` / `3401_DFU` |
| `wiscore_rak4631_board` | `0x239A0029` | `0x2D0DF000` | `NRF_BL_239A0029_4631_DFU` / `4631_DFU` |
| `wismesh_tag` | `0x239A0029` | `0xC72E9C9C` | `NRF_BL_239A0029_RTAG_DFU` / `RTAG_DFU` |

Generic manifest names are 1–15 non-space printable ASCII bytes (`0x21..=0x7E`) followed by NUL padding. The generic hardware ID is
the lossless ASCII identity `NRF_BL_<BOARDID8>_<DEVICE_NAME>`, padded with
NULs to 32 bytes. Its package `target_id` is the little-endian first 32 bits of SHA-256 over those complete
32 bytes. The checked-in inventory is audited for duplicate identities, hardware IDs, target hashes, and
collisions with known application targets on every build and verification. The two XIAO identities retain
their original routing IDs for compatibility. The collision snapshot explicitly includes all 21 MeshCore
application targets in `tools/mota/nrf52_internal_bootloader_targets.txt`; update both lists together when
qualifying another internal-flash target.

`verify` repeats every package, signature, vector, capability-marker, embedded-manifest, version,
SoftDevice/layout, exact-profile, geometry, and CRC gate. `inspect` labels the package as `bootloader` and
prints the physical board, exact storage profile, legacy manifest, compatibility extension, and `MOTABLDR`
capability values.

## Serve

`serve` turns your computer into a **seeder** for a connected node, over its **USB serial** console or, for
an ESP32 WiFi companion, over **WiFi (TCP)** — speaking the same `mota-seeder` protocol as the firmware:

```sh
motatool serve --dir ./firmware/ --serial /dev/ttyACM0 -v      # USB
motatool serve --dir ./firmware/ --tcp 192.168.1.50:5001 -v    # WiFi seeder port (default 5001)
```

It does two things at once on that one link:

- **Relay** — hands out every valid `.mota` in `--dir` to the node, which then advertises those updates to
  its neighbours (who can `ota get` them like any other). No storage needed on the node.
- **Capture (pull-to-folder)** — when the node runs `ota pull <#> folder`, it streams the fetched image
  back; `serve` writes it as `<mid>.mota.part` and publishes it to `<mid>.mota` when complete. This is how
  you pull a *remote* device's exact firmware down to your computer over the mesh.

**Warm-start** (`--seed <similar.mota>`) makes capture fast: it stages a similar build's payload into each
`.part`, so `ota pull <#> folder validate` on the node diffs it against the target's authenticated merkle
leaves and pulls only the **differing** blocks over LoRa — a byte-exact capture in seconds instead of a full
slow transfer. Other flags: `--baud` (serial speed), `--no-recursive` (don't descend into sub-folders),
`--no-enable` (don't auto-send `ota folder on`/`off` on the serial console), `-v` (log each request).

The transport is decoupled from the protocol (a `SeederCore` turns each `(op, args)` request into a reply,
framed separately for serial/TCP), so the same core could back a future BLE/GATT path.

## Compatibility

The container format, merkle tree (MMR of 4-byte truncated-SHA-256 leaves), `EndF` identity trailer, and
hash truncation are held **byte-identical** to the MeshCore firmware — the spec is
[`docs/ota_protocol.md`](https://github.com/meshcore-dev/MeshCore/blob/main/docs/ota_protocol.md) plus
`src/helpers/ota/OtaFormat.h` / `MerkleTree.cpp` in the firmware tree. Ed25519 signing is deterministic
(RFC 8032), so signed containers match the firmware's / OpenSSL's output exactly.

Byte-exact equivalence was validated during the port against the reference C++ `motatool` (same firmware
built with both tools → byte-for-byte-identical `.mota`, each verifying the other's), and the delta encoders
are validated on every test run against the real detools decoder (see [Deltas](#deltas)). The C++ tool has
since been removed from the MeshCore tree in favour of this one; the shared contract is the `.mota` spec, not
any code dependency — MeshCore does not depend on motatool, nor motatool on MeshCore.

`src/targets.rs` is a vendored snapshot of the firmware's generated `OtaTargets.h`
(`target_id = sha2-256:4(env_name)`); regenerate it from there when the OTA-capable env set changes:

```sh
make sync-targets              # reads ../MeshCore/src/helpers/ota/OtaTargets.h
make check-targets             # fails if the vendored table has drifted
```

Pass an explicit checkout when the repositories are not siblings:

```sh
python3 scripts/sync_meshcore_targets.py --header /path/to/MeshCore/src/helpers/ota/OtaTargets.h
```

## Deltas

```sh
# diff a NEW firmware against the device's current image -> a tiny delta .mota
motatool build --base running_firmware.bin --fw new_firmware.bin --out-dir ./motas                 # sequential (ESP32)
motatool build --base running_firmware.bin --fw new_firmware.bin --patch-type in-place --out-dir . # in-place (nRF52)
```

`--base` must be the device's **real running image, with its `EndF` trailer** — the delta is applied to
exactly that image on-device, and its 8-byte `base_hash` is checked against the running firmware before apply.
The delta payload is a **detools** patch (`--compression crle`, matching the firmware's compile-time decoder
config). For `--patch-type in-place`, current nRF52 firmware embeds its resolved app base, storage type,
and safe staging ceiling immediately before `EndF`; motatool uses that record plus the actual patch size
to choose the largest safe `memory_size`. SD- and QSPI-backed layouts stage externally, so they use the
full linked application region without reserving internal flash for the container. The QSPI layout flag
is exclusive with SD and internal ExtraFS. Older firmware without the record keeps the conservative
`0x98000` default. Expanded auto-sized packages require an OTAFIX bootloader with staging-ceiling handoff
support; use `--inplace-memory 0x98000` when deliberately packaging for an older bootloader and both images
fit. XIAO bootloader-update layout records use flags `QSPI|BOOTLOADER_SCRATCH = 0x0C`,
`linked_app_end=0xE0000`, and the external staging ceiling `0xED000`; motatool requires that exact invariant
and derives the in-place apply window only through `0xE0000`. Boards without external storage use the normal
flags-0 layout with `linked_app_end=stage_ceiling=0xED000`. An ordinary application delta and a bootloader
package use the same internal update slot (never both at once), bottom-aligned beneath that ceiling. Ordinary
deltas may therefore exceed 44 KiB; motatool iterates the encoded container size until its detools apply
window ends at or below the actual staged source. The exact 41,330-byte generic bootloader package starts at
`0xE2000`; after verification, OTAFIX compacts its 40 KiB payload in place to `0xE2000..0xEC000` before the
Nordic MBR copy. Firmware rejects that boot package unless its live, valid `EndF` proves the application ends
at or below `0xE2000`. `--inplace-memory` remains an explicit override, but it is still checked against the
embedded layout and actual encoded source; `--segment-size` defaults to 4096.

**Both patch types are pure Rust** — [`src/encode.rs`](src/encode.rs) implements the detools
`sequential` + `crle` (ESP32 A/B) and `in-place` + `crle` (nRF52 single-slot) formats (canonical bsdiff +
conditional-RLE + the shift/segment layout), so `build --base` needs **no Python or detools at runtime** for
either. The full-image `build`/`verify`/`inspect`/`serve` paths never did.

detools is therefore a **development/test-only** dependency — the independent oracle the encoder is proven
against, nothing the shipped binary calls. Install it once to run the delta tests:

```sh
make dev-setup     # inits the third_party/detools submodule + builds a local .venv with detools 0.53.0
```

### Correctness: apply-equivalence, not byte-identity

A delta is correct when the **real detools C decoder** (the one on the device), fed our patch, reconstructs
the target **byte-for-byte** — *not* when our patch bytes equal detools'. Because a single wrong bit corrupts
a firmware image, the encoders are held to that directly:

- `tests/encode.rs` runs a **deterministic sweep** (seeded PRNG + fixed edit scripts across lengths 0…20 k:
  identical, scattered edits, insert/delete/append/prepend, truncate/grow, wholly-different, empty edges,
  run-heavy), for **both patch types**. Every generated patch is decoded by real detools and **hash-compared**
  to the exact target, and cross-checked so `apply(base, our_patch) == apply(base, detools_patch) == target`.
- The `crle` compressor is round-tripped through the real detools decompressor; `pack_size`/`crle` framing
  have unit tests; both encoders are proven deterministic and thread-safe under concurrent load.
- Validated at scale with real device params: a ~500 KB image with ~55 edits → an **829-byte** sequential
  delta (~0.2 s), and an in-place delta in the actual nRF52 window (memory `0x98000`, 4096-byte segments),
  both reconstructed byte-exact by detools.

The detools oracle lives entirely in `tests/` ([`tests/common/mod.rs`](tests/common/mod.rs)); tests skip
cleanly on a checkout without `make dev-setup`.

## License

GPL-3.0-or-later. Derived from the MeshCore project.
