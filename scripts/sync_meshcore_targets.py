#!/usr/bin/env python3
"""Synchronize src/targets.rs with MeshCore's generated OtaTargets.h."""

from __future__ import annotations

import argparse
import hashlib
from pathlib import Path
import re
import sys


ROOT = Path(__file__).resolve().parents[1]
TARGETS_RS = ROOT / "src" / "targets.rs"
DEFAULT_HEADER = ROOT.parent / "MeshCore" / "src" / "helpers" / "ota" / "OtaTargets.h"
TABLE_RE = re.compile(
    r"#\[rustfmt::skip\]\nstatic TABLE: &\[\(u32, &str\)\] = &\[\n.*?\n\];",
    re.DOTALL,
)
PAIR_RE = re.compile(r'\{\s*(0x[0-9A-Fa-f]+)u?\s*,\s*"([^"]+)"\s*\}')
RUST_PAIR_RE = re.compile(
    r'\(\s*(0x[0-9A-Fa-f_]+)\s*,\s*"([^"]+)"\s*,?\s*\)'
)
DECLARED_COUNT_RE = re.compile(r"//\s*([0-9]+)\s+OTA-capable build targets\.")


def target_id(env_name: str) -> int:
    return int.from_bytes(hashlib.sha256(env_name.encode("ascii")).digest()[:4], "little")


def generated_table(header_text: str, targets_text: str) -> str:
    marker = targets_text.index("#[rustfmt::skip]\nstatic TABLE")
    pinned_pairs = {
        (int(value.replace("_", ""), 16), name)
        for value, name in RUST_PAIR_RE.findall(targets_text[:marker])
    }
    pairs = [(int(value, 16), name) for value, name in PAIR_RE.findall(header_text)]
    if not pairs:
        raise ValueError("no OTA target entries found in the MeshCore header")
    header_pairs = set(pairs)
    if len(header_pairs) != len(pairs):
        raise ValueError("duplicate OTA target entry in the MeshCore header")
    declared = DECLARED_COUNT_RE.search(header_text)
    if declared is None:
        raise ValueError("MeshCore header has no declared OTA target count")
    if len(header_pairs) != int(declared.group(1)):
        raise ValueError(
            f"parsed {len(header_pairs)} OTA targets, but the MeshCore header declares "
            f"{declared.group(1)}"
        )
    missing_pins = pinned_pairs - header_pairs
    if missing_pins:
        names = ", ".join(sorted(name for _, name in missing_pins))
        raise ValueError(f"pinned bootloader target missing from MeshCore header: {names}")

    seen_ids: dict[int, str] = {}
    seen_names: dict[str, int] = {}
    for value, name in pairs:
        expected = target_id(name)
        if value != expected:
            raise ValueError(
                f"target hash mismatch for {name}: header has 0x{value:08x}, "
                f"expected 0x{expected:08x}"
            )
        if value in seen_ids and seen_ids[value] != name:
            raise ValueError(
                f"target hash collision: {seen_ids[value]} and {name} use 0x{value:08x}"
            )
        if name in seen_names and seen_names[name] != value:
            raise ValueError(f"duplicate target name with different hashes: {name}")
        seen_ids[value] = name
        seen_names[name] = value

    table_pairs = sorted(header_pairs - pinned_pairs, key=lambda item: item[1].casefold())
    lines = ["#[rustfmt::skip]", "static TABLE: &[(u32, &str)] = &["]
    lines.extend(f'    (0x{value:08x}, "{name}"),' for value, name in table_pairs)
    lines.append("];")
    return "\n".join(lines)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--header", type=Path, default=DEFAULT_HEADER)
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()

    header_text = args.header.read_text(encoding="ascii")
    targets_text = TARGETS_RS.read_text(encoding="ascii")
    replacement = generated_table(header_text, targets_text)
    updated, count = TABLE_RE.subn(replacement, targets_text, count=1)
    if count != 1:
        raise ValueError("could not locate the generated TABLE in src/targets.rs")

    if args.check:
        if updated != targets_text:
            print("src/targets.rs is out of sync with MeshCore OtaTargets.h", file=sys.stderr)
            return 1
        print("src/targets.rs matches MeshCore OtaTargets.h")
        return 0

    TARGETS_RS.write_text(updated, encoding="ascii")
    print(f"updated {TARGETS_RS} from {args.header}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
