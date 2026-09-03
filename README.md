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
| `build-bootloader` (application-preserving nRF52840 OTAFIX) | supported: signed, exact-manifest v3 package |
| `build --base` sequential (ESP32) | ✅ **pure Rust** delta (no runtime detools) — see [Deltas](#deltas) |
| `build --base` in-place (nRF52) | ✅ **pure Rust** delta (no runtime detools) — see [Deltas](#deltas) |
| `verify` | ✅ application v2 + strict signed nRF52 bootloader v3 contract |
| `inspect` | ✅ manifest fields + embedded v3 bootloader identity/capabilities |
| `keygen` | ✅ Ed25519 signing keypair |
| `serve` (USB serial + WiFi TCP) | ✅ folder relay + pull-to-folder capture + `--seed` warm-start — see [Serve](#serve) |
| `transport-size` | ✅ exact 171-byte-packet estimate using the live DEFLATE encoder |

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
motatool transport-size --payload update.patch                         # 2 KiB DEFLATE blocks by default

# package a qualified OTAFIX bootloader; its version comes from embedded metadata
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

`build-bootloader` is the deliberately narrow, privileged path for application-preserving OTAFIX updates on
qualified nRF52840 boards. It is not a general bootloader wrapper and does not authorize an update on a
device. Use the exact board-specific OTAFIX Intel HEX produced by the MeshCore release flow and protect the
signing key as production material.

The command accepts `--fw`, `--board`, mandatory `--sign`, and either `--out-dir` or `--out`. It extracts
exactly `0xF4000..0xFE000` from the Intel HEX as a 40 KiB image, fills gaps with erased-flash `0xFF`, and
ignores records outside that bootloader region. Optional `--fw-version X.Y.Z.CHANNEL` is an assertion against
the version embedded in the image; it never overrides that version. Preview channels are 1 through 254 and
a stable release uses channel 255. Zero, an all-ones version, and mismatched assertions are rejected.

Every output has the strict MeshCore bootloader profile:

- Format v3 with flags exactly `FULL|SIGNED|BOOTLOADER`, `CODEC_FULL`, a zero base hash, and an erased
  approval field. Ordinary application packages remain format v2.
- A 40 KiB image and payload split into exactly 40 blocks of 1024 bytes. Including framing, the signed
  manifest, and leaves, the complete container is exactly 41,330 bytes.
- A sane nRF52840 vector table: an aligned stack pointer in RAM and a Thumb reset vector inside the
  bootloader region.
- Exactly one aligned, CRC-valid 44-byte `BLMFCRC1` identity record followed immediately by the required
  32-byte `BLM2SOFT` continuity extension. The complete 76-byte envelope must start at image offset
  `0x9FB4`, and its version must equal the signed outer version. The whole-image CRC also covers the CF2
  board configuration: do not post-process a bootloader HEX or UF2 with a CF2 patcher. Rebuild the exact
  board profile from source and package that immutable artifact.
- Exactly one aligned `MOTABLDR` marker with apply ABI 3 or newer, both application codecs in mask `0x0005`,
  boot-update support, no reserved bits, and the exact storage profile selected by `--board`.
- An exact match between the selected board, embedded `(board_id, DEVICE_NAME)`, SoftDevice family/FWID,
  application base, layout ABI, storage profile, signed `target_id`, and signed `hw_id`.

The compatibility tuple is S140 7.3.0 (`family=140`, `FWID=0x0123`, `app_base=0x27000`) for both XIAO
variants, Minewsemi MX25LE01, and T1000-E. Every other current profile uses S140 6.1.1 (`family=140`,
`FWID=0x00B6`, `app_base=0x26000`). All current profiles require layout ABI 1. The exact selectors and signed
routing identities are:

| `--board` | embedded `board_id` | package `target_id` | canonical `hw_id` / `DEVICE_NAME` | storage |
|---|---:|---:|---|---:|
| `xiao_nrf52840_ble` | `0x28860044` | `0x28860044` | `XIAO_BL_28860044` / `XIAO_DFU` | `0x0E` QSPI |
| `xiao_nrf52840_ble_sense` | `0x28860045` | `0x28860045` | `XIAO_BL_28860045` / `XIAO_DFU` | `0x0E` QSPI |
| `gat562` | `0x239A0029` | `0xD50D2D44` | `NRF_BL_239A0029_GAT562_DFU` / `GAT562_DFU` | `0x0A` internal |
| `heltec_mesh_pocket` | `0x239A0071` | `0x059277F4` | `NRF_BL_239A0071_MESH_POCKET_OTA` / `MESH_POCKET_OTA` | `0x0A` internal |
| `heltec_mesh_tower_v2` | `0x239A0071` | `0x1150F50E` | `NRF_BL_239A0071_TOWER_V2_OTA` / `TOWER_V2_OTA` | `0x0A` internal |
| `heltec_mesh_tower_v2_sdcard` | `0x239A0071` | `0x1150F50E` | `NRF_BL_239A0071_TOWER_V2_OTA` / `TOWER_V2_OTA` | `0x09` SD |
| `heltec_t096` | `0x239A0071` | `0x42354C85` | `NRF_BL_239A0071_T096_DFU` / `T096_DFU` | `0x0A` internal |
| `heltec_t1` | `0x239A0071` | `0xFC556FFC` | `NRF_BL_239A0071_T1_DFU` / `T1_DFU` | `0x0A` internal |
| `heltec_t114` | `0x239A0071` | `0x0C3F2902` | `NRF_BL_239A0071_T114_DFU` / `T114_DFU` | `0x0A` internal |
| `keepteen_lt1` | `0x239A00B3` | `0xDB2E7B51` | `NRF_BL_239A00B3_KeepteenLT1_OTA` / `KeepteenLT1_OTA` | `0x0A` internal |
| `minewsemi_mx25le01` | `0x239A0029` | `0x026AA982` | `NRF_BL_239A0029_MX25_DFU` / `MX25_DFU` | `0x0A` internal |
| `promicro_nrf52840` | `0x239A00B3` | `0xAF79E8CC` | `NRF_BL_239A00B3_PROM_DFU` / `PROM_DFU` | `0x0A` internal |
| `t1000_e` | `0x28860057` | `0xE6F5F03F` | `NRF_BL_28860057_T1KE_DFU` / `T1KE_DFU` | `0x0A` internal |
| `thinknode_m3` | `0x239A00DA` | `0x0CA41DB2` | `NRF_BL_239A00DA_TNM3_DFU` / `TNM3_DFU` | `0x0A` internal |
| `wiscore_rak3401` | `0x239A0029` | `0x23818A80` | `NRF_BL_239A0029_3401_DFU` / `3401_DFU` | `0x0A` internal |
| `wiscore_rak4631_board` | `0x239A0029` | `0x2D0DF000` | `NRF_BL_239A0029_4631_DFU` / `4631_DFU` | `0x0A` internal |
| `wismesh_tag` | `0x239A0029` | `0xC72E9C9C` | `NRF_BL_239A0029_RTAG_DFU` / `RTAG_DFU` | `0x0A` internal |

Generic `DEVICE_NAME` values are 1 through 15 non-space printable ASCII bytes followed by NUL padding. Their
canonical hardware ID is `NRF_BL_<BOARDID8>_<DEVICE_NAME>`, NUL-padded to 32 bytes, and their wire target is
the little-endian first four bytes of SHA-256 over all 32 hardware-ID bytes. XIAO retains its deployed raw
board-ID target and `XIAO_BL_*` hardware ID.

The two MeshTower selectors deliberately share one signed physical identity. Their storage markers remain
different and are checked at install time, but an over-the-air catalog cannot distinguish them before
fetching. Do not publish both profiles in one unattended serve folder.

`verify` repeats the container, signature, vector, embedded identity/CRC, continuity, version, capability,
platform, and storage-profile checks. `inspect` prints the embedded board identity, compatibility tuple, and
storage marker. The device still applies its installed-version, running-layout, local-key, and explicit
confirmation policy. Eligible internal/QSPI legacy-v1 installations can bootstrap once; the MeshTower SD
path requires local provisioning with a BLM2/preview.13-or-newer bootloader first. Remote rollback and
compatibility migration are intentionally unsupported.

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
The legacy `--companion-terminal` option remains as a deprecated no-op for OTAFIX helper compatibility;
serial attachment now enters folder mode directly from either Companion USB startup mode.

Newer nodes can also request a logical 2 KiB payload block as an independent raw RFC 1951 DEFLATE stream.
The host does the compression, so the embedded seeder carries no encoder; blocks which do not shrink
automatically use the negotiated 171-byte raw DATA profile. OTA-capable receiver firmware accepts stored,
fixed-Huffman, and dynamic-Huffman DEFLATE blocks. Older nodes continue to use `READ` with legacy 1 KiB
containers; packages intended to start on those receivers must still be built with `--block-size 1024`.
Support is advertised in the existing descriptor's reserved capability byte, so newer firmware does not
wait on operation `0x09` when connected to an older host daemon.

New application containers use 2 KiB payload/Merkle blocks by default, reducing leaf-table overhead and
giving DEFLATE a larger independent compression window. Existing format-2 containers with 1 KiB blocks
remain valid and can still be verified, inspected, and served; pass `build --block-size 1024` when creating
one deliberately. The strict format-3 bootloader profile is unchanged and continues to require exactly
40 one-KiB blocks.

On serial links, `serve` asserts DTR/RTS, lets USB CDC settle, and waits for the node to confirm that its
folder source attached. A command lost during port-open is retried a bounded number of times; once binary
seeder traffic begins, it is never mixed with another text command. Failure to attach stops the server
instead of reporting a seeder that the node cannot use.

The transport is decoupled from the protocol (a `SeederCore` turns each `(op, args)` request into a reply,
framed separately for serial/TCP), so the same core could back a future BLE/GATT path.

## Compatibility

The container format, merkle tree (MMR of 4-byte truncated-SHA-256 leaves), `EndF` identity trailer, and
hash truncation are held **byte-identical** to the MeshCore firmware — the spec is
[`docs/ota_protocol.md`](https://github.com/meshcore-dev/MeshCore/blob/main/docs/ota_protocol.md) plus
`src/helpers/ota/OtaFormat.h` / `MerkleTree.cpp` in the firmware tree. Ed25519 signing is deterministic
(RFC 8032), so signed containers match the firmware's / OpenSSL's output exactly.

Application containers use format 2. `build-bootloader`, `verify`, `inspect`, and `serve` implement
MeshCore's deliberately narrow format-3 nRF52840 bootloader profile. A v3 container that misses any part of
that contract is rejected instead of being treated as a general full image. Ordinary `build` continues to
create only application containers.

Byte-exact equivalence was validated during the port against the reference C++ `motatool` (same firmware
built with both tools → byte-for-byte-identical `.mota`, each verifying the other's), and the delta encoders
are validated on every test run against the real detools decoder (see [Deltas](#deltas)). The C++ tool has
since been removed from the MeshCore tree in favour of this one; the shared contract is the `.mota` spec, not
any code dependency — MeshCore does not depend on motatool, nor motatool on MeshCore.

`src/targets.rs` is a vendored snapshot of MeshCore's generated
`src/helpers/ota/OtaTargets.h` (`target_id = LE32(SHA-256(env_name)[0..4])`). The MeshCore generator owns the
catalog; motatool imports it so `verify`, `inspect`, and `serve` can label wire IDs without inventing another
source of truth. The current snapshot contains all 612 OTA-capable application targets, including qualified
release-only aliases.

With `motatool` and `MeshCore` as sibling checkouts, update or check the generated Rust table with:

```sh
make sync-targets
make check-targets
```

After changing MeshCore environments or release aliases, run MeshCore's `tools/mota/gen_targets.py` first to
regenerate the canonical header; do not hand-edit either generated table. `sync-targets` validates every
name/hash pair and rejects inconsistent duplicates or target-ID collisions before it updates the generated
portion of `src/targets.rs`. `check-targets` performs the same import in read-only mode and exits nonzero if
the checked-in Rust table has drifted; use it in CI and before a release. The separate bootloader-relevant
application subset is retained so its collision audit remains explicit.

Pass another MeshCore checkout explicitly when the repositories are not siblings:

```sh
python3 scripts/sync_meshcore_targets.py \
  --header /path/to/MeshCore/src/helpers/ota/OtaTargets.h
python3 scripts/sync_meshcore_targets.py --check \
  --header /path/to/MeshCore/src/helpers/ota/OtaTargets.h
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
config). For `--patch-type in-place`, current nRF52 firmware embeds an authenticated `mOTALay1` record
immediately before `EndF`; motatool reads its app base, staging ceiling, and storage flags, then derives the
smallest safe page-aligned apply window from the complete base and target images. It also proves that an
internal-flash container, rounded to whole erase pages, fits above that window. This avoids board-name tables
and lets larger images such as T096 use their actual layout safely.

Firmware predating the layout record retains the conservative `0x98000` window. If either image is too large
for that fallback, the build fails with the required minimum instead of emitting a doomed patch. Use
`--inplace-memory` only as an explicit compatibility override after verifying the installed bootloader and
storage ceiling; `--segment-size` defaults to the nRF52 4096-byte flash page.

XIAO bootloader-update layout records use `QSPI|BOOTLOADER_SCRATCH`, `linked_app_end=0xE0000`, and an
external staging ceiling of `0xED000`; the in-place application window stops at `0xE0000`. Internal-storage
application deltas and bootloader packages share one temporary update slot and cannot coexist there. The
41,330-byte bootloader package starts at `0xE2000`; after verification, OTAFIX compacts its 40 KiB payload
in place through `0xEC000` before the Nordic MBR copy, so the live application must end at or below
`0xE2000`.

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
