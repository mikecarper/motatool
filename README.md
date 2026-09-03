# motatool

Build, verify, inspect, and serve **MeshCore `.mota` firmware-update containers**.

A `.mota` is a signed, self-verifying package of a firmware update that [MeshCore](https://github.com/meshcore-dev/MeshCore)
nodes fetch over LoRa, block by block. This tool makes those packages, checks them, serves a folder of them
to a node, and diffs firmware into tiny delta updates. It is a Rust rewrite of the C++ `motatool` that used
to live in the MeshCore tree, kept **byte-for-byte compatible** with the firmware's on-wire format.

## Status

| Command | State |
|---|---|
| `build` (full image) | ✅ byte-identical to the firmware's own output |
| `build --base` sequential (ESP32) | ✅ **pure Rust** delta (no runtime detools) — see [Deltas](#deltas) |
| `build --base` in-place (nRF52) | ✅ **pure Rust** delta (no runtime detools) — see [Deltas](#deltas) |
| `verify` | ✅ structure, block hashes, merkle root, image hash, Ed25519 signature |
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

Newer nodes can also request a logical 1 KiB payload block as an independent raw RFC 1951 DEFLATE stream.
The host does the compression, so the embedded seeder carries no encoder; blocks which do not shrink
automatically use the negotiated 171-byte raw DATA profile. OTA-capable receiver firmware accepts stored,
fixed-Huffman, and dynamic-Huffman DEFLATE blocks. Older nodes continue to use `READ` unchanged.
Support is advertised in the existing descriptor's reserved capability byte, so newer firmware does not
wait on operation `0x09` when connected to an older host daemon.

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
(`target_id = sha2-256:4(env_name)`); regenerate it from there when the OTA-capable env set changes.

## Deltas

```sh
# diff a NEW firmware against the device's current image -> a tiny delta .mota
motatool build --base running_firmware.bin --fw new_firmware.bin --out-dir ./motas                 # sequential (ESP32)
motatool build --base running_firmware.bin --fw new_firmware.bin --patch-type in-place --out-dir . # in-place (nRF52)
```

`--base` must be the device's **real running image, with its `EndF` trailer** — the delta is applied to
exactly that image on-device, and its 8-byte `base_hash` is checked against the running firmware before apply.
The delta payload is a **detools** patch (`--compression crle`, matching the firmware's compile-time decoder
config); `--patch-type in-place` also takes `--inplace-memory` (nRF52 default `0x98000`) and `--segment-size`.

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
